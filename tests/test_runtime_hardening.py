import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

@unittest.skipUnless(sys.platform=='linux' and hasattr(os,'geteuid') and os.geteuid()==0,'Linux root filesystem/ACL verification')
class RuntimeHardeningTests(unittest.TestCase):
    def setUp(self):
        from runtime.init_state import harden_runtime
        self.harden=harden_runtime
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'app';self.root.mkdir()

    def test_named_write_and_default_acls_are_removed(self):
        if not shutil.which('setfacl'):self.skipTest('setfacl unavailable')
        nested=self.root/'runtime';nested.mkdir();code=nested/'server.py';code.write_text('print(1)')
        subprocess.run(['setfacl','-m','u:65534:rwx,d:u:65534:rwx',str(self.root)],check=True)
        subprocess.run(['setfacl','-m','u:65534:rwx,d:u:65534:rwx',str(nested)],check=True)
        subprocess.run(['setfacl','-m','u:65534:rwx',str(code)],check=True)
        self.harden(self.root)
        for path in (self.root,nested,code):
            self.assertEqual(path.stat().st_mode & 0o022,0)
            self.assertNotIn('system.posix_acl_access',os.listxattr(path))
            self.assertNotIn('system.posix_acl_default',os.listxattr(path))
        created=nested/'new-cache';created.mkdir(mode=0o700)
        self.assertNotIn('system.posix_acl_access',os.listxattr(created))

    def test_symbolic_link_never_changes_external_target(self):
        target=Path(self.temp.name)/'outside';target.write_text('private');target.chmod(0o600)
        (self.root/'bad').symlink_to(target)
        with self.assertRaises(ValueError):self.harden(self.root)
        self.assertEqual(target.stat().st_mode & 0o777,0o600)

    def test_non_root_runtime_file_is_rejected(self):
        path=self.root/'server';path.write_text('untrusted');os.chown(path,65534,65534)
        with self.assertRaises(PermissionError):self.harden(self.root)
        self.assertEqual(path.stat().st_uid,65534)


if __name__=='__main__':unittest.main()
