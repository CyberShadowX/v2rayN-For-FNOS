"""Official compatible-amd64 Mihomo releases for the shared network helper.

The caller verifies the gzip asset's release digest before extraction. This
module never runs the downloaded program or changes system network state.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
from typing import Any, Mapping
import zlib

REPOSITORY = "MetaCubeX/mihomo"
MIN_VERSION = (1, 19, 34)
INITIAL_VERSION = "1.19.34"
INITIAL_ARCHIVE_SIZE = 22766457
INITIAL_ARCHIVE_SHA256 = "2763f5b414527f7baf6dc57e3f82f3ab561eedf34bfd7c2f2cde1f7e592efe06"
INITIAL_BINARY_SIZE = 61948030
INITIAL_BINARY_SHA256 = "5b6644c487e5dffae86b0e0e9bb5cec445579a3a9d03977c09576fee2aeefc01"
MAX_ARCHIVE_SIZE = 100 * 1024 * 1024
MAX_UNPACKED_SIZE = 128 * 1024 * 1024
_CHUNK = 1024 * 1024


def release_asset(release_json: Mapping[str, Any]) -> dict[str, Any]:
    """Select exactly one official stable compatible-amd64 gzip, >=1.19.34."""
    if not isinstance(release_json, Mapping) or release_json.get("draft") or release_json.get("prerelease"):
        raise ValueError("Mihomo updates require a published stable release")
    tag = release_json.get("tag_name", "")
    if not isinstance(tag, str) or len(tag) > 64:
        raise ValueError("Unsupported Mihomo release version")
    match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
    if match is None or tuple(int(value) for value in match.groups()) < MIN_VERSION:
        raise ValueError("Mihomo stable version must be at least v1.19.34")
    version = tag[1:]
    name = f"mihomo-linux-amd64-compatible-{tag}.gz"
    assets = release_json.get("assets", [])
    if not isinstance(assets, list) or any(not isinstance(asset, dict) for asset in assets):
        raise ValueError("Invalid Mihomo release assets")
    matching = [asset for asset in assets if asset.get("name") == name]
    if len(matching) != 1:
        raise ValueError("Expected exactly one official compatible-amd64 Mihomo asset")
    asset = dict(matching[0])
    url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
    if asset.get("browser_download_url") != url:
        raise ValueError("Mihomo asset URL does not match the official repository and tag")
    digest = asset.get("digest", "")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
        raise ValueError("Mihomo release asset needs a SHA-256 digest")
    if type(asset.get("size")) is not int or not 0 < asset["size"] <= MAX_ARCHIVE_SIZE:
        raise ValueError("Mihomo compressed asset exceeds its size limit")
    sha256 = digest[7:].lower()
    if version == INITIAL_VERSION and (asset["size"] != INITIAL_ARCHIVE_SIZE or sha256 != INITIAL_ARCHIVE_SHA256):
        raise ValueError("The initial Mihomo release differs from its verified fixed pin")
    asset.update(version=version, sha256=sha256, url=url, repository=REPOSITORY)
    return asset


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _open_regular(path: Path):
    if _is_link(path) or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Mihomo inputs must be regular files, not links")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    stream = os.fdopen(os.open(path, flags), "rb")
    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
        stream.close()
        raise ValueError("Mihomo input changed to a non-regular file")
    return stream


def _binary_metadata(path: Path) -> dict[str, Any]:
    with _open_regular(path) as stream:
        metadata = os.fstat(stream.fileno())
        if not 64 <= metadata.st_size <= MAX_UNPACKED_SIZE:
            raise ValueError("Mihomo ELF is truncated or exceeds the unpacked size limit")
        header = stream.read(64)
        if len(header) != 64:
            raise ValueError("Truncated Mihomo ELF header")
        fields = struct.unpack("<16sHHIQQQIHHHHHH", header)
        if (header[:7] != b"\x7fELF\x02\x01\x01" or fields[1] not in (2, 3)
                or fields[2] != 62 or fields[3] != 1 or fields[8] != 64):
            raise ValueError("Mihomo must be an ELF64 little-endian amd64 ET_EXEC/ET_DYN program")
        if fields[9] != 56 or fields[10] < 1 or fields[5] < 64 or fields[5] + fields[9] * fields[10] > metadata.st_size:
            raise ValueError("Mihomo ELF has a truncated or invalid program header table")
        digest = hashlib.sha256(header)
        size = len(header)
        while chunk := stream.read(_CHUNK):
            size += len(chunk)
            if size > MAX_UNPACKED_SIZE:
                raise ValueError("Mihomo exceeds the unpacked size limit")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        current = path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
        if size != metadata.st_size or identity(metadata) != identity(after) or identity(after) != identity(current):
            raise ValueError("Mihomo ELF changed while being verified")
    return {"size": size, "sha256": digest.hexdigest(), "architecture": "amd64", "format": "ELF64"}


def probe(app_root: str | os.PathLike[str]) -> dict[str, Any]:
    """Verify the helper without executing it; wrapper source/license may coexist."""
    requested = Path(app_root)
    if _is_link(requested) or not requested.is_dir():
        raise ValueError("Mihomo runtime root must be a non-symlink directory")
    root = requested.resolve()
    for entry in root.iterdir():
        if entry.name not in {"mihomo", "source.json", "LICENSE"} or _is_link(entry) or not entry.is_file():
            raise ValueError("Unexpected file or link in the Mihomo runtime directory")
    binary = root / "mihomo"
    if not binary.is_file() or _is_link(binary):
        raise ValueError("Mihomo runtime is missing its regular native binary")
    return {"repository": REPOSITORY, "root": str(root), "executable": str(binary),
            **_binary_metadata(binary)}


def extract(archive_path: str | os.PathLike[str], destination: str | os.PathLike[str]) -> dict[str, Any]:
    """Expand one gzip member to an empty root's ``mihomo`` child, capped at 128MiB.

    The gzip filename is never used as a path. Concatenated members, trailing
    data, invalid checksums, truncation, links and existing output files fail
    closed. Publication is atomic and cannot overwrite a concurrently created
    file. The returned SHA-256 describes the actual written ELF, not the gzip.
    """
    requested = Path(destination)
    if _is_link(requested) or (requested.exists() and (not requested.is_dir() or any(requested.iterdir()))):
        raise ValueError("Mihomo extraction requires an empty, non-symlink directory")
    with _open_regular(Path(archive_path)) as source:
        source_metadata = os.fstat(source.fileno())
        source_size = source_metadata.st_size
        if not 0 < source_size <= MAX_ARCHIVE_SIZE:
            raise ValueError("Mihomo compressed asset exceeds its size limit")
        root = requested.resolve()
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".mihomo.", suffix=".tmp", dir=root)
        temporary = Path(temporary_name)
        archive_digest = hashlib.sha256()
        archive_size = unpacked_size = 0
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            with os.fdopen(descriptor, "wb") as output:
                while chunk := source.read(_CHUNK):
                    archive_size += len(chunk)
                    if archive_size > MAX_ARCHIVE_SIZE:
                        raise ValueError("Mihomo compressed asset exceeds its size limit")
                    archive_digest.update(chunk)
                    if decoder.eof:
                        raise ValueError("Unexpected data after the single Mihomo gzip member")
                    pending = chunk
                    while pending:
                        try:
                            block = decoder.decompress(pending, min(_CHUNK, MAX_UNPACKED_SIZE - unpacked_size + 1))
                        except zlib.error as error:
                            raise ValueError("Invalid Mihomo gzip stream or checksum") from error
                        unpacked_size += len(block)
                        if unpacked_size > MAX_UNPACKED_SIZE:
                            raise ValueError("Mihomo exceeds the unpacked size limit")
                        output.write(block)
                        pending = decoder.unconsumed_tail
                        if decoder.eof:
                            if decoder.unused_data:
                                raise ValueError("Unexpected data after the single Mihomo gzip member")
                            break
                after = os.fstat(source.fileno())
                if (not decoder.eof or archive_size != source_size or after.st_size != source_size
                        or after.st_mtime_ns != source_metadata.st_mtime_ns):
                    raise ValueError("Truncated or changed Mihomo gzip stream")
                output.flush()
                os.fsync(output.fileno())
            _binary_metadata(temporary)
            temporary.chmod(0o755)
            if any(entry != temporary for entry in root.iterdir()):
                raise ValueError("Mihomo extraction directory acquired an unexpected file")
            try:
                os.link(temporary, root / "mihomo", follow_symlinks=False)
            except FileExistsError as error:
                raise ValueError("Mihomo output already exists") from error
        finally:
            temporary.unlink(missing_ok=True)
    return {**probe(root), "archive_size": archive_size, "archive_sha256": archive_digest.hexdigest()}
