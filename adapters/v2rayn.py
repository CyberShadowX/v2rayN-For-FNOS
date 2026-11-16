"""v2rayN's upstream Linux desktop release, without container or GUI patches.

The shared launcher supplies X11/DBus.  The shared updater downloads/verifies
the asset before extraction and owns version switching and rollback.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from typing import Any, Mapping
from urllib.parse import quote, urlsplit
import zipfile


APP_ID = "v2rayn"
REPOSITORY = "2dust/v2rayN"
ASSET_NAME = "v2rayN-linux-64.zip"
DEFAULT_SOCKS_PORT = 10808
SQLITE_COMPAT_SHA256 = "2e6eef9a727f081f0d453b4e5e6cbd8b9ef8b6f86cbf7681cbad444d3b0b55c8"
SQLITE_COMPAT_SIZE = 1437848
SQLITE_COMPAT_PACKAGE_VERSION = "3.40.1-2+deb12u2"
SQLITE_COMPAT_PACKAGE_URL = "https://deb.debian.org/debian/pool/main/s/sqlite3/libsqlite3-0_3.40.1-2+deb12u2_amd64.deb"
_MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
_MAX_UNPACKED_BYTES = 2 * 1024 * 1024 * 1024
_MAX_ENTRIES = 10000
_REQUIRED = (
    "v2rayN",
    "AmazTool",
    "libSkiaSharp.so",
    "libHarfBuzzSharp.so",
    "libe_sqlite3.so",
    "bin/xray/xray",
    "bin/sing_box/sing-box",
    "bin/mihomo/mihomo",
)


def release_asset(release: Mapping[str, Any]) -> dict[str, Any]:
    """Select the official amd64 ZIP and require its GitHub SHA-256 digest.

    Original asset keys are retained for the shared downloader.  The extra
    ``url``, ``sha256``, ``version`` and ``repository`` keys are normalized.
    Prereleases and unrecognized layouts fail closed rather than replacing a
    working installation with an unchecked payload.
    """
    tag = release.get("tag_name", "")
    if not isinstance(tag, str) or not re.fullmatch(r"v?\d+(?:\.\d+){1,3}", tag):
        raise ValueError("Unrecognized v2rayN stable release tag")
    if release.get("draft") or release.get("prerelease"):
        raise ValueError("Only published stable v2rayN releases are supported")
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ValueError("Release has no asset list")
    matches = [a for a in assets if isinstance(a, dict) and a.get("name") == ASSET_NAME]
    if len(matches) != 1:
        raise ValueError("Expected exactly one Linux amd64 v2rayN ZIP")
    asset = dict(matches[0])
    url = asset.get("browser_download_url", "")
    expected = f"https://github.com/{REPOSITORY}/releases/download/{quote(tag, safe='')}/{ASSET_NAME}"
    if not isinstance(url, str) or url != expected or urlsplit(url).username:
        raise ValueError("Release asset does not belong to the official repository")
    size = asset.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= _MAX_DOWNLOAD_BYTES:
        raise ValueError("Unexpected v2rayN asset size")
    digest = asset.get("digest", "")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
        raise ValueError("Release is missing a usable SHA-256 digest")
    asset.update(url=url, sha256=digest[7:].lower(), version=tag.lstrip("v"), repository=REPOSITORY)
    return asset


def _parts(info: zipfile.ZipInfo) -> tuple[str, ...]:
    name = info.filename
    if (not name or "\\" in name or "\x00" in info.orig_filename
            or ":" in name or name.startswith("/")):
        raise ValueError("Unsafe ZIP member name")
    pieces = name.rstrip("/").split("/")
    if any(piece in ("", ".", "..") for piece in pieces):
        raise ValueError("ZIP member traverses its extraction directory")
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise ValueError("ZIP links and special files are not allowed")
    if kind == stat.S_IFDIR and not info.is_dir():
        raise ValueError("ZIP directory attributes disagree with its name")
    if info.flag_bits & 1:
        raise ValueError("Encrypted ZIP members are unsupported")
    return tuple(pieces)


def _amd64_elf(path: Path) -> None:
    with path.open("rb") as stream:
        header = stream.read(20)
    if (len(header) < 20 or header[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(header[18:20], "little") != 62):
        raise ValueError("Expected a Linux amd64 ELF executable: " + path.name)


def probe(app_root: str | os.PathLike[str]) -> dict[str, Any]:
    """Check the extracted release's required files; does not execute the GUI."""
    root = Path(app_root).resolve()
    for relative in _REQUIRED:
        candidate = root / relative
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError("Incomplete v2rayN release: " + relative)
        if not candidate.resolve().is_relative_to(root):
            raise ValueError("Release file escapes its directory")
        _amd64_elf(candidate)
    return {
        "app_id": APP_ID,
        "repository": REPOSITORY,
        "root": str(root),
        "executable": str(root / "v2rayN"),
        "bundled_bin": str(root / "bin"),
        "required_files": list(_REQUIRED),
    }


def extract(archive_path: str | os.PathLike[str], destination: str | os.PathLike[str]) -> dict[str, Any]:
    """Extract into an empty private staging directory, flattening one wrapper.

    All members are checked before writing.  Symlinks, duplicate paths,
    traversal, encrypted files and oversized releases are rejected.  Setuid
    and group/world-write permissions are never retained.  The caller may
    discard the staging directory after any error; existing files are never
    replaced by this function.
    """
    requested = Path(destination)
    if requested.is_symlink():
        raise ValueError("Staging directory must not be a symlink")
    root = requested.resolve()
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError("Staging directory must be empty")
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        if not entries or len(entries) > _MAX_ENTRIES:
            raise ValueError("Unexpected ZIP member count")
        if sum(i.file_size for i in entries) > _MAX_UNPACKED_BYTES:
            raise ValueError("Unpacked v2rayN release is too large")
        checked = [(info, _parts(info)) for info in entries]
        non_dirs = [(info, parts) for info, parts in checked if not info.is_dir()]
        if not non_dirs:
            raise ValueError("Empty release archive")
        executable_paths = [parts for _, parts in non_dirs if parts[-1] == "v2rayN"]
        if len(executable_paths) != 1 or len(executable_paths[0]) not in (1, 2):
            raise ValueError("Unrecognized v2rayN release layout")
        prefix = executable_paths[0][:-1]
        planned: list[tuple[zipfile.ZipInfo, Path]] = []
        seen: set[str] = set()
        for info, parts in checked:
            if prefix and parts[:len(prefix)] != prefix:
                raise ValueError("Release archive has unexpected top-level files")
            relative = parts[len(prefix):]
            if not relative:
                if not info.is_dir():
                    raise ValueError("Invalid ZIP wrapper directory")
                continue
            key = "/".join(relative).casefold()
            if key in seen:
                raise ValueError("Duplicate ZIP extraction path")
            seen.add(key)
            target = root.joinpath(*relative)
            if not target.is_relative_to(root):
                raise ValueError("ZIP member escapes its extraction directory")
            planned.append((info, target))
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for info, target in planned:
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True, mode=0o755)
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with archive.open(info, "r") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            mode = (info.external_attr >> 16) & 0o111
            target.chmod(0o755 if mode else 0o644)
    result = probe(root)
    for relative in ("v2rayN", "AmazTool", "bin/xray/xray", "bin/sing_box/sing-box", "bin/mihomo/mihomo"):
        (root / relative).chmod(0o755)
    result["files"] = len(non_dirs)
    return result


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _sqlite_compat_payload(path: Path) -> bytes:
    """Read once through a regular-file descriptor; never follow an alias link."""
    if _is_link(path):
        raise ValueError("SQLite compatibility files must not be symlinks")
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("SQLite compatibility files must be regular files")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                         | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != SQLITE_COMPAT_SIZE:
            raise ValueError("Unexpected SQLite compatibility file type or size")
        content = source.read(SQLITE_COMPAT_SIZE + 1)
    if (len(content) != SQLITE_COMPAT_SIZE or content[:7] != b"\x7fELF\x02\x01\x01"
            or int.from_bytes(content[16:18], "little") != 3
            or int.from_bytes(content[18:20], "little") != 62):
        raise ValueError("SQLite compatibility library must be an ELF64 amd64 shared object")
    if hashlib.sha256(content).hexdigest() != SQLITE_COMPAT_SHA256:
        raise ValueError("SQLite compatibility SHA-256 mismatch")
    return content


def prepare_runtime(app_root: str | os.PathLike[str], compat_root: str | os.PathLike[str]) -> dict[str, Any]:
    """Add the pinned Debian 12 SQLite as a private ``e_sqlite3.so`` alias.

    Call after extraction/probe and before a candidate is activated. Upstream
    ``libe_sqlite3.so`` and all other release files remain untouched. Existing
    aliases must already match the pinned payload; a future upstream file at
    this name is never silently overwritten. Real GUI/database health still
    determines whether an update is accepted or rolled back.
    """
    requested_root, requested_compat = Path(app_root), Path(compat_root)
    for directory in (requested_root, requested_compat):
        if _is_link(directory) or not directory.is_dir():
            raise ValueError("SQLite runtime directories must be regular directories, not symlinks")
    root, compatibility = requested_root.resolve(), requested_compat.resolve()
    payload = _sqlite_compat_payload(compatibility / "e_sqlite3.so")
    destination = root / "e_sqlite3.so"
    created = False
    if destination.exists() or _is_link(destination):
        _sqlite_compat_payload(destination)
    else:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".e_sqlite3.", suffix=".tmp", dir=root)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            temporary.chmod(0o644)
            _sqlite_compat_payload(temporary)
            try:
                # Atomic no-replace publication: a concurrently created file
                # or symlink cannot be overwritten, even on POSIX.
                os.link(temporary, destination, follow_symlinks=False)
                created = True
            except FileExistsError:
                _sqlite_compat_payload(destination)
        finally:
            temporary.unlink(missing_ok=True)
        _sqlite_compat_payload(destination)
    return {
        "component": "sqlite", "alias": "e_sqlite3.so", "path": str(destination),
        "sha256": SQLITE_COMPAT_SHA256, "size": SQLITE_COMPAT_SIZE,
        "package": "libsqlite3-0", "package_version": SQLITE_COMPAT_PACKAGE_VERSION,
        "sqlite_version": "3.40.1", "source_url": SQLITE_COMPAT_PACKAGE_URL,
        "license": "public-domain", "created": created, "health_check_required": True,
    }


def profile_paths(profile_dir: str | os.PathLike[str]) -> dict[str, str]:
    root = Path(profile_dir).resolve()
    startup = root / "v2rayN"
    return {
        "root": str(root),
        "startup": str(startup),
        "config": str(startup / "guiConfigs" / "guiNConfig.json"),
        "bin": str(startup / "bin"),
        "bin_configs": str(startup / "binConfigs"),
        "logs": str(startup / "guiLogs"),
    }


def launch_environment(profile_dir: str | os.PathLike[str]) -> dict[str, str]:
    """Overlay these values on the shared non-root X11/DBus environment."""
    root = str(Path(profile_dir).resolve())
    return {
        "V2RAYN_LOCAL_APPLICATION_DATA_V2": "1",
        "XDG_DATA_HOME": root,
        "XDG_CONFIG_HOME": str(Path(root) / "xdg-config"),
        "XDG_CACHE_HOME": str(Path(root) / "xdg-cache"),
    }


def launch_command(app_root: str | os.PathLike[str], profile_dir: str | os.PathLike[str]) -> list[str]:
    """v2rayN has no required --config switch; use launch_environment too."""
    return [str(Path(app_root).resolve() / "v2rayN")]


def configure_profile(profile_dir: str | os.PathLike[str], *, port: int = DEFAULT_SOCKS_PORT) -> dict[str, Any]:
    """Seed a new desktop profile only; never replace existing user settings.

    TUN stays off and system proxy stays unchanged.  The shared privileged
    forwarding component connects to the GUI-selected node through loopback
    SOCKS on ``port``.  No node, account or subscription belongs in this seed.
    """
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65514:
        raise ValueError("Invalid local SOCKS port")
    paths = profile_paths(profile_dir)
    config = Path(paths["config"])
    for directory in (Path(paths["root"]), Path(paths["startup"]), config.parent):
        if directory.is_symlink():
            raise ValueError("Profile directories must not be symlinks")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if config.is_symlink():
        raise ValueError("Profile config must not be a symlink")
    if config.exists():
        if not config.is_file():
            raise ValueError("Profile config is not a regular file")
        return {"created": False, **paths}
    initial = {
        "Inbound": [{
            "LocalPort": port, "Protocol": "socks", "UdpEnabled": True,
            "SniffingEnabled": True, "RouteOnly": False,
            "AllowLANConn": False, "NewPort4LAN": False,
            "SecondLocalPortEnabled": False,
        }],
        "TunModeItem": {"EnableTun": False, "Mtu": 9000, "IcmpRouting": "rule", "EnableLegacyProtect": True},
        "SystemProxyItem": {"SysProxyType": 2, "NotProxyLocalAddress": True},
        "UiItem": {"CurrentLanguage": "zh-Hans", "AutoHideStartup": False, "Hide2TrayWhenClose": False},
        "GuiItem": {"AutoRun": False, "EnableHWA": False, "EnableLog": True, "AutoUpdateInterval": 0},
    }
    try:
        descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return {"created": False, **paths}
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(initial, output, ensure_ascii=False, indent=2)
        output.write("\n")
    return {"created": True, **paths}
