"""Public build selection, old-delivery protection and pinned-input checks."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.request

from tools import build_packages as builder
from tools import prepare_public_build as preparation

ROOT = Path(__file__).resolve().parents[1]


class Response(io.BytesIO):
    def __init__(self, data, url, length=None):
        super().__init__(data)
        self.url = url
        self.headers = {} if length is None else {'Content-Length': length}

    def geturl(self):
        return self.url


class PublicBuildTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / 'work'
        scratch.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='public-build-test-', dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.root = self.workspace / 'repo'
        self.root.mkdir()

    def publication(self, **updates):
        value = {'app': 'v2rayn', 'owner': 'CyberShadowX',
                 'repository': 'v2rayN-For-FNOS', 'version': '1.0.5'}
        value.update(updates)
        (self.root / 'publication.json').write_text(json.dumps(value), encoding='utf-8')
        return value

    def asset(self, data=b'verified upstream archive'):
        return {'name': 'fixture.zip', 'url': 'https://github.com/2dust/v2rayN/releases/download/test/fixture.zip',
                'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    def symlink(self, target, path, *, directory=False):
        try:
            path.symlink_to(target, target_is_directory=directory)
        except (NotImplementedError, OSError) as error:
            self.skipTest('Symlink test unavailable: ' + str(error))

    def test_publication_selects_one_default_and_maintainer(self):
        self.assertEqual(builder.default_apps(self.root), ['v2rayn', 'clash'])
        self.publication()
        self.assertEqual(builder.default_apps(self.root), ['v2rayn'])
        self.assertEqual(builder.publisher('v2rayn', self.root),
                         {'owner': 'CyberShadowX', 'repository': 'v2rayN-For-FNOS'})
        with self.assertRaises(ValueError):
            builder.publisher('clash', self.root)

    def test_publication_rejects_unknown_version_injection_and_extra_fields(self):
        for updates in ({'app': 'other'}, {'owner': 'user\nversion=9'}, {'repository': '../other'},
                        {'version': '1.0.4'}, {'app': ['v2rayn']}, {'extra': 'unchecked'}):
            with self.subTest(updates=updates):
                self.publication(**updates)
                with self.assertRaises(ValueError):
                    builder.publication_config(self.root)

    def test_output_locations_are_portable_and_confined(self):
        self.assertEqual(builder.validate_output(self.root / 'dist', self.root), self.root / 'dist')
        output = self.workspace / 'outputs/github-v1.0.5'
        self.assertEqual(builder.validate_output(output, self.root), output)
        for outside in (self.workspace, self.workspace / 'other', self.root):
            with self.subTest(outside=outside), self.assertRaises(ValueError):
                builder.validate_output(outside, self.root)

    def test_old_delivery_inventory_and_checksums_are_preserved(self):
        output = self.workspace / 'outputs'
        output.mkdir()
        metadata = output / 'build-inventory.json'
        previous = b'{"wrapper_version":"1.0.4"}'
        metadata.write_bytes(previous)
        with self.assertRaises(ValueError):
            builder.validate_output(output, self.root)
        self.assertEqual(metadata.read_bytes(), previous)
        metadata.unlink()
        sums = output / 'SHA256SUMS.txt'
        old_sums = 'a' * 64 + '  fnv2rayn-1.0.4-x86.fpk\n'
        sums.write_text(old_sums, encoding='utf-8')
        with self.assertRaises(ValueError):
            builder.validate_output(output, self.root)
        self.assertEqual(sums.read_text(encoding='utf-8'), old_sums)

    def test_current_release_metadata_can_be_rebuilt(self):
        output = self.root / 'dist'
        output.mkdir()
        (output / 'build-inventory.json').write_text('{"wrapper_version":"1.0.5"}', encoding='utf-8')
        (output / 'SHA256SUMS.txt').write_text('a' * 64 + '  fnclash-1.0.5-x86.fpk\n', encoding='utf-8')
        self.assertEqual(builder.validate_output(output, self.root), output)

    def test_output_and_publication_symlinks_are_rejected(self):
        destination = self.workspace / 'outside'
        destination.mkdir()
        link = self.root / 'linked'
        self.symlink(destination, link, directory=True)
        with self.assertRaises(ValueError):
            builder.validate_output(link / 'dist', self.root)
        config = self.workspace / 'config.json'
        config.write_text('{}', encoding='utf-8')
        self.symlink(config, self.root / 'publication.json')
        with self.assertRaises(ValueError):
            builder.publication_config(self.root)

    def test_pins_are_complete_and_official(self):
        self.assertEqual(set(preparation.ASSETS), {'v2rayn', 'clash', 'mihomo', 'fnpack'})
        for asset in preparation.ASSETS.values():
            self.assertIs(preparation.validate_asset(asset), asset)
        for changes in ({'size': True}, {'sha256': 'unchecked'}, {'name': '../input'},
                        {'url': 'http://github.com/file'}, {'url': 'https://github.com.evil/file'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                preparation.validate_asset({**self.asset(), **changes})

    def test_redirects_cannot_leave_official_https(self):
        handler = preparation.OfficialRedirects()
        request = urllib.request.Request(self.asset()['url'])
        for url in ('http://github.com/file', 'https://example.com/file',
                    'https://user:password@github.com/file', 'https://github.com:444/file'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, 'Found', {}, url)

    def test_verified_download_and_cache_reuse(self):
        body = b'verified upstream archive'
        asset = self.asset(body)
        target = self.root / 'work/downloads' / asset['name']
        response = Response(body, asset['url'], str(len(body)))
        with patch.object(preparation, 'open_url', return_value=response) as network:
            self.assertEqual(preparation.download(asset, target, self.root), target)
            network.assert_called_once_with(asset['url'])
        self.assertEqual(target.read_bytes(), body)
        with patch.object(preparation, 'open_url', side_effect=AssertionError('No network expected')):
            preparation.download(asset, target, self.root, offline=True)

    def test_bad_download_never_publishes_or_leaves_staging(self):
        body = b'verified upstream archive'
        asset = self.asset(body)
        target = self.root / 'cache' / asset['name']
        for data, length, url in ((body[:-1], None, asset['url']), (body + b'x', None, asset['url']),
                                  (b'x' * len(body), None, asset['url']),
                                  (body, '999', asset['url']), (body, None, 'https://example.com/file')):
            with self.subTest(data=data, length=length, url=url):
                with patch.object(preparation, 'open_url', return_value=Response(data, url, length)):
                    with self.assertRaises(ValueError):
                        preparation.download(asset, target, self.root)
                self.assertFalse(target.exists())
                self.assertEqual(list(target.parent.iterdir()), [])

    def test_invalid_existing_cache_is_not_overwritten(self):
        target = self.root / 'fixture.zip'
        target.write_bytes(b'keep this existing file')
        with patch.object(preparation, 'open_url', side_effect=AssertionError('No network expected')):
            with self.assertRaises(ValueError):
                preparation.download(self.asset(), target, self.root)
        self.assertEqual(target.read_bytes(), b'keep this existing file')

    def test_offline_missing_and_linked_downloads_fail_closed(self):
        with self.assertRaises(ValueError):
            preparation.download(self.asset(), self.root / 'missing.zip', self.root, offline=True)
        outside = self.workspace / 'outside.zip'
        outside.write_bytes(b'unchanged')
        link = self.root / 'fixture.zip'
        self.symlink(outside, link)
        with self.assertRaises(ValueError):
            preparation.download(self.asset(), link, self.root)
        self.assertEqual(outside.read_bytes(), b'unchanged')

    def test_payload_preparation_reuses_only_identical_trees(self):
        class Adapter:
            @staticmethod
            def extract(archive, destination):
                (destination / 'bin').mkdir()
                (destination / 'bin/program').write_bytes(b'fixture program')
        body = b'verified upstream archive'
        archive = self.root / 'fixture.zip'
        archive.write_bytes(body)
        target = self.root / 'work/payload'
        preparation.extract_verified(self.asset(body), archive, target, Adapter, self.root)
        self.assertEqual((target / 'bin/program').read_bytes(), b'fixture program')
        preparation.extract_verified(self.asset(body), archive, target, Adapter, self.root)
        (target / 'bin/program').write_bytes(b'local change')
        with self.assertRaises(ValueError):
            preparation.extract_verified(self.asset(body), archive, target, Adapter, self.root)
        self.assertEqual((target / 'bin/program').read_bytes(), b'local change')
        self.assertEqual(list(target.parent.glob('.payload-prepare-*')), [])

    def test_fnpack_setup_has_explicit_non_windows_boundary(self):
        with patch.object(preparation.sys, 'platform', 'linux'):
            with self.assertRaisesRegex(ValueError, 'Windows only'):
                preparation.prepare_fnpack(self.root)
        self.assertIsNone(preparation.prepare_fnpack(self.root, skip=True))
        tool = self.workspace / 'verified-fnpack'
        body = b'explicit trusted native tool'
        tool.write_bytes(body)
        with self.assertRaises(ValueError):
            preparation.prepare_fnpack(self.root, supplied=tool)
        selected = preparation.prepare_fnpack(self.root, supplied=tool,
                                              supplied_sha256=hashlib.sha256(body).hexdigest())
        self.assertEqual(selected, tool.resolve())
        with self.assertRaises(ValueError):
            preparation.prepare_fnpack(self.root, supplied=tool, skip=True)

    def test_forged_fnpack_version_banner_is_rejected_before_help(self):
        tool = self.root / 'fnpack.exe'
        tool.write_bytes(b'forged tool printing Version 1.2.3')
        arguments = ['build_packages.py', '--fnpack', str(tool), '--prepare-only',
                     '--output-dir', str(self.root / 'dist')]
        with patch.object(builder, 'ROOT', self.root), patch.object(builder.sys, 'argv', arguments), \
                patch.object(builder.subprocess, 'run', return_value=SimpleNamespace(stdout='Version 1.2.3')) as execute:
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                builder.main()
            execute.assert_not_called()
        self.assertFalse((self.root / 'build').exists())

    def test_direct_prepare_cannot_execute_an_unpinned_create(self):
        tool = self.root / 'fnpack.exe'
        tool.write_bytes(b'forged tool printing Version 1.2.3')
        with patch.object(builder, 'ROOT', self.root), patch.object(builder.subprocess, 'run') as execute:
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                builder.prepare('v2rayn', tool)
            execute.assert_not_called()
        self.assertFalse((self.root / 'build').exists())

    def test_explicit_fnpack_hash_is_rechecked_before_build(self):
        tool = self.root / 'trusted-fnpack'
        body = b'explicitly trusted native tool'
        tool.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        with patch.object(builder.subprocess, 'run', return_value=SimpleNamespace(stdout='Version 1.2.3')) as execute:
            builder.run_fnpack(tool, '--help', expected_sha256=digest, capture_output=True, text=True)
            self.assertEqual(execute.call_args.args[0], [str(tool.resolve()), '--help'])
            tool.write_bytes(b'changed after help')
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                builder.run_fnpack(tool, 'build', expected_sha256=digest)
            self.assertEqual(execute.call_count, 1)

    def test_fnpack_hash_override_requires_a_complete_digest(self):
        tool = self.root / 'fnpack.exe'
        tool.write_bytes(b'not executed')
        for expected in ('', 'not-a-hash', '0' * 63, True):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                builder.verified_fnpack(tool, expected)

    def test_prepare_hint_preserves_selected_app_and_explicit_tool_hash(self):
        tool = self.workspace / 'trusted-fnpack'
        tool.write_bytes(b'provided tool')
        digest = hashlib.sha256(tool.read_bytes()).hexdigest()
        arguments = ['prepare_public_build.py', '--apps', 'clash', '--fnpack', str(tool),
                     '--fnpack-sha256', digest]
        output = io.StringIO()
        with patch.object(preparation.sys, 'argv', arguments), patch.object(preparation.sys, 'stdout', output), \
                patch.object(preparation, 'prepare_apps', return_value={'applications': ['clash']}) as prepare, \
                patch.object(builder.subprocess, 'run') as execute:
            preparation.main()
            self.assertEqual(prepare.call_args.args[0], ['clash'])
            self.assertEqual(prepare.call_args.kwargs['fnpack_sha256'], digest)
            execute.assert_not_called()
        self.assertIn('--apps clash', output.getvalue())
        self.assertIn('--fnpack-sha256 ' + digest, output.getvalue())
        self.assertIn(str(tool.resolve()), output.getvalue())

    def test_single_application_offline_preparation_uses_only_its_gui_and_helper(self):
        self.publication(app='clash', repository='Clash-Verge-For-FNOS')
        assets = {}
        for component in ('clash', 'mihomo'):
            body = (component + ' pinned fixture').encode()
            asset = self.asset(body)
            asset['name'] = component + '.archive'
            assets[component] = asset
            cached = self.root / 'work/downloads' / asset['name']
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(body)

        def extract_gui(archive, destination):
            (destination / 'gui').write_bytes(b'gui payload')

        def extract_helper(archive, destination):
            (destination / 'mihomo').write_bytes(b'helper payload')

        with patch.dict(preparation.ASSETS, assets), \
                patch.object(preparation.clash, 'extract', side_effect=extract_gui), \
                patch.object(preparation.mihomo, 'extract', side_effect=extract_helper), \
                patch.object(preparation, 'open_url', side_effect=AssertionError('No network expected')):
            result = preparation.prepare_apps(['clash'], self.root, offline=True, skip_fnpack=True)
            self.assertEqual(result['applications'], ['clash'])
            self.assertEqual([item['component'] for item in result['inputs']], ['clash', 'mihomo'])
            self.assertFalse((self.root / 'work/v2rayn').exists())
            self.assertTrue((self.root / 'work/clash/extracted/gui').is_file())
            self.assertTrue((self.root / 'work/mihomo/mihomo').is_file())
            with self.assertRaises(ValueError):
                preparation.prepare_apps(['v2rayn'], self.root, offline=True, skip_fnpack=True)


if __name__ == '__main__':
    unittest.main()
