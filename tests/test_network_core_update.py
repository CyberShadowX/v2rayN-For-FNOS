import hashlib
import os
from pathlib import Path
import tempfile
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
from runtime import updater


class GuiAdapter:
    def extract(self,archive,destination):
        destination.mkdir();(destination/'gui').write_bytes(b'new GUI')


class CompleteReleaseStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.releases=Path(self.temp.name)
        self.gui={'version':'7.25.6','name':'gui.zip','size':11,'sha256':'a'*64}
        self.core={'version':'1.19.34','name':'mihomo.gz','size':12,'sha256':'b'*64}

    @staticmethod
    def download(asset,destination,*args,**kwargs):destination.write_bytes(b'archive')

    @staticmethod
    def extract_core(archive,destination):
        destination.mkdir();binary=destination/'mihomo';binary.write_bytes(b'verified ELF bytes')
        return {'executable':str(binary)}

    def test_gui_and_helper_are_one_versioned_candidate(self):
        with patch.object(updater,'latest',side_effect=[self.gui,self.core]),patch.object(updater,'download',side_effect=self.download),patch('adapters.mihomo.extract',side_effect=self.extract_core):
            result=updater.stage(GuiAdapter(),self.releases)
        gui=Path(result['path']);helper=Path(result['network_core']['path'])
        self.assertEqual(gui.parent,helper.parent.parent)
        self.assertEqual((gui/'gui').read_bytes(),b'new GUI')
        self.assertEqual(result['network_core']['version'],'1.19.34')
        self.assertEqual(result['network_core']['sha256'],hashlib.sha256(helper.read_bytes()).hexdigest())
        self.assertTrue((helper.parent/'source.json').is_file())
        self.assertFalse(any(gui.parent.glob('*.gz')));self.assertFalse(any(gui.parent.glob('*.zip')))

    def test_failed_helper_download_discards_whole_candidate_only(self):
        current=self.releases/'current';current.mkdir();(current/'nodes').write_text('keep')
        def download(asset,destination,*args,**kwargs):
            if asset is self.core:raise OSError('helper unavailable')
            self.download(asset,destination)
        with patch.object(updater,'latest',side_effect=[self.gui,self.core]),patch.object(updater,'download',side_effect=download):
            with self.assertRaisesRegex(OSError,'helper unavailable'):updater.stage(GuiAdapter(),self.releases)
        self.assertEqual(list(self.releases.iterdir()),[current]);self.assertEqual((current/'nodes').read_text(),'keep')

    def test_bad_helper_extract_discards_gui_and_partial_helper(self):
        def invalid(archive,destination):
            destination.mkdir();(destination/'partial').write_text('bad');raise ValueError('invalid helper ELF')
        with patch.object(updater,'latest',side_effect=[self.gui,self.core]),patch.object(updater,'download',side_effect=self.download),patch('adapters.mihomo.extract',side_effect=invalid):
            with self.assertRaisesRegex(ValueError,'invalid helper ELF'):updater.stage(GuiAdapter(),self.releases)
        self.assertEqual(list(self.releases.iterdir()),[])

    @unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0 and shutil.which('setfacl') and shutil.which('runuser'),'Requires Linux root and POSIX ACL tools')
    def test_inherited_app_acl_cannot_modify_unverified_download(self):
        import pwd
        user=pwd.getpwnam('nobody')
        self.releases.chmod(0o755)
        subprocess.run(['setfacl','-m',f'd:u:{user.pw_uid}:rwx,d:m:rwx',str(self.releases)],check=True)
        attempts=[]
        def protected_download(asset,destination,*args,**kwargs):
            self.download(asset,destination)
            attempt=subprocess.run(['runuser','-u',user.pw_name,'--','python3','-c',
                'import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b"tampered")',str(destination)],capture_output=True)
            attempts.append(attempt.returncode)
            self.assertNotEqual(attempt.returncode,0)
            self.assertEqual(destination.read_bytes(),b'archive')
        with patch.object(updater,'latest',side_effect=[self.gui,self.core]),patch.object(updater,'download',side_effect=protected_download),patch('adapters.mihomo.extract',side_effect=self.extract_core):
            result=updater.stage(GuiAdapter(),self.releases)
        self.assertEqual(len(attempts),2)
        helper=Path(result['network_core']['path'])
        attempt=subprocess.run(['runuser','-u',user.pw_name,'--','python3','-c',
            'import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b"tampered")',str(helper)],capture_output=True)
        self.assertNotEqual(attempt.returncode,0)


if __name__=='__main__':unittest.main()
