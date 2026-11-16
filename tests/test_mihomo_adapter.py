"""Release identity and safe gzip/ELF staging; never execute the native helper."""
import copy
import gzip
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mihomo_adapter", ROOT / "adapters" / "mihomo.py")
mihomo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mihomo)


def release(version="1.19.34"):
    name = f"mihomo-linux-amd64-compatible-v{version}.gz"
    initial = version == mihomo.INITIAL_VERSION
    return {"tag_name": "v" + version, "draft": False, "prerelease": False, "assets": [{
        "name": name, "size": mihomo.INITIAL_ARCHIVE_SIZE if initial else 1024,
        "digest": "sha256:" + (mihomo.INITIAL_ARCHIVE_SHA256 if initial else "a" * 64),
        "browser_download_url": f"https://github.com/MetaCubeX/mihomo/releases/download/v{version}/{name}",
    }]}


def elf(payload=b"native-helper-fixture", kind=2):
    total = 64 + 56 + len(payload)
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, kind, 62, 1, 0x400000, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, total, total, 4096)
    return header + program + payload


class ReleaseTests(unittest.TestCase):
    def test_initial_release_is_pinned_and_version_is_bare(self):
        selected = mihomo.release_asset(release())
        self.assertEqual(selected["version"], "1.19.34")
        self.assertEqual(selected["sha256"], mihomo.INITIAL_ARCHIVE_SHA256)
        self.assertEqual(selected["size"], mihomo.INITIAL_ARCHIVE_SIZE)
        self.assertEqual(selected["repository"], "MetaCubeX/mihomo")

    def test_future_stable_release_uses_exact_compatible_asset(self):
        selected = mihomo.release_asset(release("1.20.0"))
        self.assertEqual(selected["version"], "1.20.0")
        self.assertEqual(selected["name"], "mihomo-linux-amd64-compatible-v1.20.0.gz")

    def test_old_and_nonstable_versions_are_rejected(self):
        for version in ("1.19.33", "1.18.99", "0.99.99", "1.19.34-rc1", "01.19.34", "1.19", "../../other"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                mihomo.release_asset(release(version))
        for flag in ("draft", "prerelease"):
            document = release()
            document[flag] = True
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                mihomo.release_asset(document)

    def test_release_identity_cannot_point_at_another_host_tag_or_variant(self):
        document = release()
        original = document["assets"][0]["browser_download_url"]
        for url in (original.replace("github.com", "example.com"), original.replace("/v1.19.34/", "/v1.19.35/"),
                    original + "?redirect=other", original.replace("https://", "http://"),
                    original.replace("MetaCubeX/mihomo", "other/mihomo")):
            altered = copy.deepcopy(document)
            altered["assets"][0]["browser_download_url"] = url
            with self.subTest(url=url), self.assertRaises(ValueError):
                mihomo.release_asset(altered)
        altered = release()
        altered["assets"][0]["name"] = "mihomo-linux-arm64-v1.19.34.gz"
        with self.assertRaises(ValueError):
            mihomo.release_asset(altered)

    def test_digest_size_duplicate_and_initial_pin_changes_are_rejected(self):
        cases = []
        for digest in (None, "", "md5:" + "a" * 32, "sha256:" + "z" * 64):
            altered = release(); altered["assets"][0]["digest"] = digest; cases.append(altered)
        for size in (0, -1, True, "1024", mihomo.MAX_ARCHIVE_SIZE + 1):
            altered = release(); altered["assets"][0]["size"] = size; cases.append(altered)
        altered = release(); altered["assets"].append(copy.deepcopy(altered["assets"][0])); cases.append(altered)
        altered = release(); altered["assets"][0]["digest"] = "sha256:" + "b" * 64; cases.append(altered)
        altered = release(); altered["assets"][0]["size"] += 1; cases.append(altered)
        for document in cases:
            with self.subTest(document=document), self.assertRaises(ValueError):
                mihomo.release_asset(document)


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mihomo-test-", dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "upstream.gz"
        self.destination = self.root / "network-core"
        self.payload = elf()
        self.archive.write_bytes(gzip.compress(self.payload, mtime=0))

    def assert_output_empty(self):
        if self.destination.exists():
            self.assertEqual(list(self.destination.iterdir()), [])

    def link_or_skip(self, source, destination, *, directory=False):
        try:
            os.symlink(source, destination, target_is_directory=directory)
        except (OSError, NotImplementedError) as error:
            self.skipTest("This platform cannot create a test symlink: " + str(error))

    def test_extracts_one_binary_and_returns_written_elf_hash(self):
        result = mihomo.extract(self.archive, self.destination)
        binary = Path(result["executable"])
        self.assertEqual(binary, self.destination.resolve() / "mihomo")
        self.assertEqual(binary.read_bytes(), self.payload)
        self.assertEqual(result["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(result["size"], len(self.payload))
        self.assertEqual(result["archive_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual(result["archive_size"], self.archive.stat().st_size)
        self.assertEqual([entry.name for entry in self.destination.iterdir()], ["mihomo"])
        if os.name == "posix":
            self.assertEqual(binary.stat().st_mode & 0o777, 0o755)

    def test_et_dyn_is_supported_without_executing_it(self):
        self.archive.write_bytes(gzip.compress(elf(kind=3)))
        self.assertEqual(mihomo.extract(self.archive, self.destination)["format"], "ELF64")

    def test_gzip_filename_is_ignored_as_a_filesystem_path(self):
        compressed = bytearray(self.archive.read_bytes())
        compressed[3] |= 8  # FNAME; the gzip data CRC remains unchanged.
        self.archive.write_bytes(compressed[:10] + b"../../escape\0" + compressed[10:])
        mihomo.extract(self.archive, self.destination)
        self.assertTrue((self.destination / "mihomo").is_file())
        self.assertFalse((self.root.parent / "escape").exists())

    def test_truncation_bad_checksum_and_extra_gzip_members_are_rejected(self):
        valid = self.archive.read_bytes()
        corrupted = bytearray(valid); corrupted[-8] ^= 1
        for malformed in (valid[:-1], valid[:8], bytes(corrupted), valid + gzip.compress(self.payload), valid + b"junk", valid + b"\0"):
            self.archive.write_bytes(malformed)
            with self.subTest(malformed_size=len(malformed)), self.assertRaises(ValueError):
                mihomo.extract(self.archive, self.destination)
            self.assert_output_empty()

    def test_invalid_or_truncated_elf_is_rejected(self):
        cases = [b"not ELF", self.payload[:20]]
        for offset, value in ((4, 1), (5, 2), (16, 1), (18, 183), (52, 0), (56, 255)):
            altered = bytearray(self.payload); altered[offset] = value; cases.append(bytes(altered))
        for body in cases:
            self.archive.write_bytes(gzip.compress(body))
            with self.subTest(header=body[:20].hex()), self.assertRaises(ValueError):
                mihomo.extract(self.archive, self.destination)
            self.assert_output_empty()

    def test_download_and_decompression_limits_are_enforced(self):
        with patch.object(mihomo, "MAX_ARCHIVE_SIZE", self.archive.stat().st_size - 1):
            with self.assertRaisesRegex(ValueError, "compressed asset"):
                mihomo.extract(self.archive, self.destination)
        self.archive.write_bytes(gzip.compress(elf(b"0" * 10000)))
        with patch.object(mihomo, "MAX_UNPACKED_SIZE", 256):
            with self.assertRaisesRegex(ValueError, "unpacked size"):
                mihomo.extract(self.archive, self.destination)
        self.assert_output_empty()

    def test_existing_files_are_never_overwritten(self):
        self.destination.mkdir()
        existing = self.destination / "source.json"
        existing.write_bytes(b"existing metadata")
        with self.assertRaisesRegex(ValueError, "empty"):
            mihomo.extract(self.archive, self.destination)
        self.assertEqual(existing.read_bytes(), b"existing metadata")

    def test_probe_rejects_a_missing_binary(self):
        self.destination.mkdir()
        with self.assertRaisesRegex(ValueError, "missing"):
            mihomo.probe(self.destination)

    def test_linked_archive_or_destination_is_rejected(self):
        linked_archive = self.root / "linked.gz"
        self.link_or_skip(self.archive, linked_archive)
        with self.assertRaises(ValueError):
            mihomo.extract(linked_archive, self.destination)
        outside = self.root / "outside"; outside.mkdir()
        self.link_or_skip(outside, self.destination, directory=True)
        with self.assertRaises(ValueError):
            mihomo.extract(self.archive, self.destination)
        self.assertEqual(list(outside.iterdir()), [])

    def test_probe_allows_wrapper_metadata_but_rejects_other_files_and_links(self):
        mihomo.extract(self.archive, self.destination)
        for name in ("source.json", "LICENSE"):
            (self.destination / name).write_bytes(b"wrapper metadata")
        mihomo.probe(self.destination)
        unexpected = self.destination / "unexpected.py"; unexpected.write_bytes(b"pass")
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            mihomo.probe(self.destination)
        unexpected.unlink()
        binary = self.destination / "mihomo"; binary.unlink()
        outside = self.root / "outside-elf"; outside.write_bytes(self.payload)
        self.link_or_skip(outside, binary)
        with self.assertRaises(ValueError):
            mihomo.probe(self.destination)

    def test_sync_failure_leaves_no_partial_binary_or_temp_file(self):
        with patch.object(mihomo.os, "fsync", side_effect=OSError("storage failed")):
            with self.assertRaises(OSError):
                mihomo.extract(self.archive, self.destination)
        self.assert_output_empty()


if __name__ == "__main__":
    unittest.main()
