"""Private SQLite compatibility tests; never load or replace system libraries."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("v2rayn_compat_adapter", ROOT / "adapters" / "v2rayn.py")
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)
VENDORED = ROOT / "vendor" / "sqlite" / "e_sqlite3.so"


class RuntimeCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = VENDORED.read_bytes()
        if hashlib.sha256(cls.payload).hexdigest() != adapter.SQLITE_COMPAT_SHA256:
            raise AssertionError("The vendored compatibility library is not the pinned payload")

    def setUp(self):
        # Keep Windows scratch files under this repository, never TEMP on C:.
        self.temporary = tempfile.TemporaryDirectory(prefix="sqlite-compat-test-", dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app = self.root / "release"
        self.compat = self.root / "compat"
        self.app.mkdir()
        self.compat.mkdir()
        self.source = self.compat / "e_sqlite3.so"
        self.source.write_bytes(self.payload)
        self.original = self.app / "libe_sqlite3.so"
        self.original.write_bytes(b"original upstream library remains untouched")
        self.other = self.app / "v2rayN"
        self.other.write_bytes(b"original upstream executable remains untouched")

    def link_or_skip(self, source, destination, *, directory=False):
        try:
            os.symlink(source, destination, target_is_directory=directory)
        except (OSError, NotImplementedError) as error:
            self.skipTest("This platform cannot create the test symlink: " + str(error))

    def test_adds_pinned_private_alias_and_preserves_upstream(self):
        original = self.original.read_bytes()
        executable = self.other.read_bytes()
        metadata = adapter.prepare_runtime(self.app, self.compat)
        self.assertTrue(metadata["created"])
        self.assertTrue(metadata["health_check_required"])
        self.assertEqual(metadata["package_version"], "3.40.1-2+deb12u2")
        self.assertEqual((self.app / "e_sqlite3.so").read_bytes(), self.payload)
        self.assertEqual(self.original.read_bytes(), original)
        self.assertEqual(self.other.read_bytes(), executable)
        self.assertEqual(self.source.read_bytes(), self.payload)
        self.assertEqual(list(self.app.glob(".e_sqlite3.*.tmp")), [])

    def test_repeat_is_idempotent_without_rewriting_the_alias(self):
        adapter.prepare_runtime(self.app, self.compat)
        alias = self.app / "e_sqlite3.so"
        before = alias.stat()
        metadata = adapter.prepare_runtime(self.app, self.compat)
        after = alias.stat()
        self.assertFalse(metadata["created"])
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))

    def test_source_hash_mismatch_does_not_publish_any_alias(self):
        altered = bytearray(self.payload)
        altered[-1] ^= 1
        self.source.write_bytes(altered)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            adapter.prepare_runtime(self.app, self.compat)
        self.assertFalse((self.app / "e_sqlite3.so").exists())

    def test_non_amd64_or_non_shared_object_is_rejected(self):
        for offset, value in ((18, 183), (16, 2)):
            with self.subTest(offset=offset):
                altered = bytearray(self.payload)
                altered[offset] = value
                self.source.write_bytes(altered)
                with self.assertRaisesRegex(ValueError, "ELF64 amd64 shared object"):
                    adapter.prepare_runtime(self.app, self.compat)
        self.assertFalse((self.app / "e_sqlite3.so").exists())

    def test_source_symlink_is_rejected(self):
        self.source.unlink()
        self.link_or_skip(VENDORED, self.source)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            adapter.prepare_runtime(self.app, self.compat)
        self.assertFalse((self.app / "e_sqlite3.so").exists())

    def test_destination_symlink_cannot_modify_an_external_file(self):
        outside = self.root / "outside.so"
        outside.write_bytes(b"must not change")
        alias = self.app / "e_sqlite3.so"
        self.link_or_skip(outside, alias)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            adapter.prepare_runtime(self.app, self.compat)
        self.assertTrue(alias.is_symlink())
        self.assertEqual(outside.read_bytes(), b"must not change")

    def test_symlink_directories_are_rejected(self):
        for name, source, app, compat in (("release-link", self.app, None, self.compat),
                                          ("compat-link", self.compat, self.app, None)):
            link = self.root / name
            self.link_or_skip(source, link, directory=True)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "directories"):
                adapter.prepare_runtime(app or link, compat or link)

    def test_existing_different_alias_is_not_overwritten(self):
        alias = self.app / "e_sqlite3.so"
        alias.write_bytes(b"a future upstream alias must be reviewed")
        with self.assertRaises(ValueError):
            adapter.prepare_runtime(self.app, self.compat)
        self.assertEqual(alias.read_bytes(), b"a future upstream alias must be reviewed")

    def test_concurrent_destination_is_not_overwritten(self):
        alias = self.app / "e_sqlite3.so"
        def concurrent_creation(source, destination, **kwargs):
            Path(destination).write_bytes(b"concurrent file must survive")
            raise FileExistsError("another writer published this name")
        with patch.object(adapter.os, "link", side_effect=concurrent_creation):
            with self.assertRaises(ValueError):
                adapter.prepare_runtime(self.app, self.compat)
        self.assertEqual(alias.read_bytes(), b"concurrent file must survive")
        self.assertEqual(list(self.app.glob(".e_sqlite3.*.tmp")), [])

    def test_failed_sync_does_not_leave_a_partial_alias_or_temp_file(self):
        with patch.object(adapter.os, "fsync", side_effect=OSError("storage failure")):
            with self.assertRaisesRegex(OSError, "storage failure"):
                adapter.prepare_runtime(self.app, self.compat)
        self.assertFalse((self.app / "e_sqlite3.so").exists())
        self.assertEqual(list(self.app.glob(".e_sqlite3.*.tmp")), [])

    def test_provenance_matches_binary_and_pinned_code(self):
        metadata = json.loads((VENDORED.parent / "SOURCE.json").read_text())
        self.assertEqual(metadata["file_sha256"], adapter.SQLITE_COMPAT_SHA256)
        self.assertEqual(metadata["file_size"], len(self.payload))
        self.assertEqual(metadata["package_version"], adapter.SQLITE_COMPAT_PACKAGE_VERSION)
        self.assertEqual(metadata["package_url"], adapter.SQLITE_COMPAT_PACKAGE_URL)
        self.assertTrue((VENDORED.parent / metadata["debian_copyright_file"]).is_file())


if __name__ == "__main__":
    unittest.main()
