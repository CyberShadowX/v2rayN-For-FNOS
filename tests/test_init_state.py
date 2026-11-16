import contextlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from runtime.init_state import certificate_subject_alt_name, ensure_tls_certificate, initialize_user


class CertificateAddressTests(unittest.TestCase):
    def discover(self, value):
        result=Mock(stdout=json.dumps(value))
        with patch('runtime.init_state.subprocess.run',return_value=result) as command:
            extension=certificate_subject_alt_name()
        command.assert_called_once_with(['ip','-j','address','show'],check=True,capture_output=True,
                                        text=True,encoding='utf-8',timeout=5)
        return extension

    def test_assigned_addresses_are_normalized_deduplicated_and_sorted(self):
        entries=[{'family':'inet6','local':'2001:0db8::5'},
                 {'family':'inet','local':'198.51.100.8'},
                 {'family':'inet','local':'192.0.2.10'},
                 {'family':'inet6','local':'2001:db8:0:0::5'},
                 {'family':'inet','local':'127.0.0.1'}]
        expected='subjectAltName=DNS:localhost,IP:127.0.0.1,IP:192.0.2.10,IP:198.51.100.8,IP:::1,IP:2001:db8::5'
        self.assertEqual(self.discover([{'addr_info':entries}]),expected)
        self.assertEqual(self.discover([{'addr_info':list(reversed(entries))}]),expected)

    def test_invalid_scoped_non_unicast_and_injection_values_are_excluded(self):
        entries=[{'family':'inet','local':'192.0.2.10,DNS:example.invalid'},
                 {'family':'inet','local':'192.0.2.10\nDNS:example.invalid'},
                 {'family':'inet','local':'--config=untrusted'},
                 {'family':'inet6','local':'fe80::1%interface'},
                 {'family':'inet','local':'0.0.0.0'},
                 {'family':'inet6','local':'::'},
                 {'family':'inet','local':'224.0.0.1'},
                 {'family':'inet6','local':'ff02::1'},
                 {'family':'inet','local':'255.255.255.255'},
                 {'family':'inet','local':3221225994},
                 {'family':'inet6','local':'192.0.2.11'},
                 {'family':'unknown','local':'192.0.2.12'},None]
        self.assertEqual(self.discover([{'addr_info':entries}]),
                         'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1')

    def test_missing_failing_and_timed_out_ip_command_keep_loopback(self):
        failures=[FileNotFoundError('ip unavailable'),
                  subprocess.CalledProcessError(1,['ip']),
                  subprocess.TimeoutExpired(['ip'],5),
                  UnicodeDecodeError('utf-8',b'\xff',0,1,'bad output')]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with patch('runtime.init_state.subprocess.run',side_effect=failure):
                    self.assertEqual(certificate_subject_alt_name(),
                                     'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1')

    def test_malformed_json_and_shapes_keep_loopback(self):
        for output in ['not JSON','null','{}','"value"','[null, {"addr_info": null}, {"addr_info": {}}]']:
            with self.subTest(output=output):
                with patch('runtime.init_state.subprocess.run',return_value=Mock(stdout=output)):
                    self.assertEqual(certificate_subject_alt_name(),
                                     'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1')


class CertificateStateTests(unittest.TestCase):
    def setUp(self):
        work=Path(__file__).resolve().parents[1]/'work'
        work.mkdir(exist_ok=True)
        self.temporary=tempfile.TemporaryDirectory(prefix='tls-test-',dir=work)
        self.addCleanup(self.temporary.cleanup)
        self.ui=Path(self.temporary.name)

    def fake_openssl(self,command,**options):
        self.assertEqual(command[:3],['openssl','req','-x509'])
        self.assertIn('subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1',command)
        self.assertNotIn('shell',options)
        Path(command[command.index('-keyout')+1]).write_bytes(b'new fixture key')
        Path(command[command.index('-out')+1]).write_bytes(b'new fixture certificate')
        return Mock(returncode=0)

    def generate(self):
        with patch('runtime.init_state.certificate_subject_alt_name',
                   return_value='subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'):
            with patch('runtime.init_state.subprocess.run',side_effect=self.fake_openssl):
                ensure_tls_certificate(self.ui)

    def test_generated_pair_is_published_and_private_staging_removed(self):
        self.generate()
        self.assertEqual((self.ui/'tls.key').read_bytes(),b'new fixture key')
        self.assertEqual((self.ui/'tls.crt').read_bytes(),b'new fixture certificate')
        self.assertFalse(any(self.ui.glob('.tls-*')))
        if os.name=='posix':
            self.assertEqual((self.ui/'tls.key').stat().st_mode & 0o777,0o600)
            self.assertEqual((self.ui/'tls.crt').stat().st_mode & 0o777,0o600)

    def test_existing_pair_and_portal_credentials_are_unchanged(self):
        key=self.ui/'tls.key';key.write_bytes(b'existing fixture key')
        certificate=self.ui/'tls.crt';certificate.write_bytes(b'existing fixture certificate')
        portal=self.ui/'portal.json';portal.write_bytes(b'{"password_hash":"fixture hash"}')
        with patch('runtime.init_state.subprocess.run') as command:
            with patch.object(Path,'symlink_to'),contextlib.redirect_stdout(io.StringIO()) as output:
                initialize_user(self.ui,{'app':'fixture','title':'Fixture'})
        command.assert_not_called()
        self.assertEqual(key.read_bytes(),b'existing fixture key')
        self.assertEqual(certificate.read_bytes(),b'existing fixture certificate')
        self.assertEqual(portal.read_bytes(),b'{"password_hash":"fixture hash"}')
        self.assertEqual(json.loads(output.getvalue()),{'password':None})

    def test_partial_existing_pair_is_retained_and_not_overwritten(self):
        for name in ('tls.key','tls.crt'):
            with self.subTest(name=name):
                existing=self.ui/name;existing.write_bytes(b'existing fixture')
                with patch('runtime.init_state.subprocess.run') as command:
                    with self.assertRaises(FileExistsError):ensure_tls_certificate(self.ui)
                command.assert_not_called()
                self.assertEqual(existing.read_bytes(),b'existing fixture')
                self.assertEqual(set(p.name for p in self.ui.iterdir()),{name})
                existing.unlink()

    def test_openssl_failure_leaves_no_final_or_staging_files(self):
        with patch('runtime.init_state.certificate_subject_alt_name',return_value='subjectAltName=DNS:localhost'):
            with patch('runtime.init_state.subprocess.run',side_effect=subprocess.CalledProcessError(1,['openssl'])):
                with self.assertRaises(subprocess.CalledProcessError):ensure_tls_certificate(self.ui)
        self.assertEqual(list(self.ui.iterdir()),[])

    def test_tls_failure_does_not_persist_inaccessible_first_login_credentials(self):
        with patch.object(Path,'symlink_to'):
            with patch('runtime.init_state.certificate_subject_alt_name',return_value='subjectAltName=DNS:localhost'):
                with patch('runtime.init_state.subprocess.run',side_effect=subprocess.CalledProcessError(1,['openssl'])):
                    with patch('runtime.init_state.secrets.token_urlsafe') as password:
                        with self.assertRaises(subprocess.CalledProcessError):
                            initialize_user(self.ui,{'app':'fixture','title':'Fixture'})
        password.assert_not_called()
        self.assertFalse((self.ui/'portal.json').exists())
        self.assertEqual(list(self.ui.iterdir()),[])

    def test_competing_key_creation_is_never_replaced(self):
        def publish(source,destination):
            Path(destination).write_bytes(b'competing fixture key')
            raise FileExistsError('key was created concurrently')
        with patch('runtime.init_state.os.link',side_effect=publish):
            with self.assertRaises(FileExistsError):self.generate()
        self.assertEqual((self.ui/'tls.key').read_bytes(),b'competing fixture key')
        self.assertFalse((self.ui/'tls.crt').exists())
        self.assertFalse(any(self.ui.glob('.tls-*')))

    def test_failed_second_publish_retains_competing_certificate(self):
        real_link=os.link
        def publish(source,destination):
            if Path(destination).name=='tls.crt':
                Path(destination).write_bytes(b'competing fixture certificate')
                raise FileExistsError('certificate was created concurrently')
            return real_link(source,destination)
        with patch('runtime.init_state.os.link',side_effect=publish):
            with self.assertRaises(FileExistsError):self.generate()
        self.assertFalse((self.ui/'tls.key').exists())
        self.assertEqual((self.ui/'tls.crt').read_bytes(),b'competing fixture certificate')
        self.assertFalse(any(self.ui.glob('.tls-*')))

    @unittest.skipUnless(shutil.which('openssl'),'OpenSSL is required for a real certificate check')
    def test_real_certificate_contains_discovered_ipv4_ipv6_and_localhost(self):
        extension='subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1,IP:192.0.2.10,IP:2001:db8::5'
        with patch('runtime.init_state.certificate_subject_alt_name',return_value=extension):
            ensure_tls_certificate(self.ui)
        result=subprocess.run(['openssl','x509','-in',str(self.ui/'tls.crt'),'-noout','-ext','subjectAltName'],
                              check=True,capture_output=True,text=True,timeout=5)
        self.assertIn('DNS:localhost',result.stdout)
        self.assertIn('IP Address:192.0.2.10',result.stdout)
        actual={ipaddress.ip_address(value.strip()) for value in re.findall(r'IP Address:([^,\n]+)',result.stdout)}
        self.assertIn(ipaddress.ip_address('2001:db8::5'),actual)
        self.assertIn(ipaddress.ip_address('::1'),actual)


if __name__=='__main__':unittest.main()
