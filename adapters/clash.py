"""Clash Verge Rev's Linux desktop bundle, relocated without executing dpkg scripts.

The process supervisor owns DISPLAY, DBus, privileges, network exclusivity and
update rollback. This adapter never installs a system service or changes routes.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import tarfile
import time
from typing import Any

REPOSITORY = "clash-verge-rev/clash-verge-rev"
APP_ID = "io.github.clash-verge-rev.clash-verge-rev"
MAX_DEB_SIZE = 512 * 1024 * 1024
MAX_UNPACKED_SIZE = 1536 * 1024 * 1024


def release_asset(release_json: dict[str, Any]) -> dict[str, Any]:
    """Select one official stable Linux amd64 .deb, including its pinned digest."""
    if release_json.get("draft") or release_json.get("prerelease"):
        raise ValueError("Clash updates require a published stable release")
    tag = release_json.get("tag_name", "")
    if not isinstance(tag, str):
        raise ValueError("Unsupported Clash release version")
    version = tag.removeprefix("v")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Unsupported Clash release version")
    name = f"Clash.Verge_{version}_amd64.deb"
    assets = release_json.get("assets", [])
    if not isinstance(assets, list) or any(not isinstance(a, dict) for a in assets):
        raise ValueError("Invalid Clash release assets")
    candidates = [a for a in assets if a.get("name") == name]
    if len(candidates) != 1:
        raise ValueError("Release does not contain exactly one Linux amd64 .deb")
    asset = dict(candidates[0])
    expected = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
    if asset.get("browser_download_url") != expected:
        raise ValueError("Clash asset URL does not match the official release")
    digest = asset.get("digest", "")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
        raise ValueError("Clash release asset has no supported SHA256 digest")
    if type(asset.get("size")) is not int or not 0 < asset["size"] <= MAX_DEB_SIZE:
        raise ValueError("Clash release asset has an invalid size")
    asset["sha256"] = digest.split(":", 1)[1].lower()
    asset["version"] = version
    return asset


def _data_tar(archive_path: Path) -> bytes:
    if archive_path.stat().st_size > MAX_DEB_SIZE:
        raise ValueError("Clash .deb exceeds the download size limit")
    payload: bytes | None = None
    debian_binary: bytes | None = None
    with archive_path.open("rb") as stream:
        if stream.read(8) != b"!<arch>\n":
            raise ValueError("Not a Debian ar archive")
        while header := stream.read(60):
            if len(header) != 60 or header[58:] != b"`\n":
                raise ValueError("Malformed Debian ar member")
            try:
                name = header[:16].decode("ascii").strip().removesuffix("/")
                size_field = header[48:58].decode("ascii").strip()
                if not size_field.isdecimal():
                    raise ValueError("Invalid ar size")
                size = int(size_field)
            except (UnicodeError, ValueError) as exc:
                raise ValueError("Malformed Debian ar metadata") from exc
            if size > MAX_DEB_SIZE:
                raise ValueError("Debian ar member exceeds the size limit")
            body = stream.read(size)
            if len(body) != size or (size % 2 and stream.read(1) != b"\n"):
                raise ValueError("Truncated Debian ar archive")
            if name == "debian-binary":
                if debian_binary is not None:
                    raise ValueError("Duplicate Debian version member")
                debian_binary = body
            elif name.startswith("data.tar"):
                if payload is not None or name not in {"data.tar", "data.tar.gz", "data.tar.xz", "data.tar.bz2"}:
                    raise ValueError("Duplicate or unsupported Debian data archive")
                payload = body
    if debian_binary != b"2.0\n" or payload is None:
        raise ValueError("Missing Debian version or data archive")
    return payload


def _member_path(root: Path, name: str) -> Path:
    if "\\" in name or "\0" in name or ":" in name:
        raise ValueError("Unsafe archive member name")
    part = PurePosixPath(name)
    if part.is_absolute() or ".." in part.parts:
        raise ValueError("Archive path traversal rejected")
    target = root.joinpath(*part.parts)
    if not target.resolve().is_relative_to(root):
        raise ValueError("Archive member escaped the extraction root")
    return target


def _validate_amd64_elf(path: Path) -> None:
    with path.open("rb") as stream:
        header = stream.read(20)
    if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
        raise ValueError(f"Expected an x86_64 Linux ELF: {path.name}")


def probe(app_root: str | os.PathLike[str]) -> dict[str, str]:
    """Validate the relocatable layout and return absolute paths for supervision."""
    root = Path(app_root).resolve()
    bins = root / "usr" / "bin"
    names = {
        "executable": "clash-verge",
        "core": "verge-mihomo",
        "alpha_core": "verge-mihomo-alpha",
        "service": "clash-verge-service",
        "service_install": "clash-verge-service-install",
        "service_uninstall": "clash-verge-service-uninstall",
    }
    result = {"root": str(root)}
    for key, name in names.items():
        candidate = bins / name
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError(f"Clash bundle is missing {name}")
        _validate_amd64_elf(candidate)
        result[key] = str(candidate)
    resources = root / "usr" / "lib" / "Clash Verge" / "resources"
    for name in ("geoip.dat", "geosite.dat", "Country.mmdb", "ASN.mmdb"):
        if not (resources / name).is_file():
            raise ValueError(f"Clash bundle is missing resource {name}")
    result["resources"] = str(resources)
    return result


def extract(archive_path: str | os.PathLike[str], destination: str | os.PathLike[str]) -> dict[str, str]:
    """Unpack into an empty staging directory, rejecting links and special files.

    Never runs control.tar's postinst/prerm. The caller verifies the release
    SHA256 before calling this and deletes failed staging after rollback.
    """
    target = Path(destination)
    if target.is_symlink() or (target.exists() and (not target.is_dir() or any(target.iterdir()))):
        raise ValueError("Clash extraction requires an empty, non-symlink staging directory")
    root = target.resolve()
    payload = _data_tar(Path(archive_path))
    root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
        members = archive.getmembers()
        total = 0
        file_paths: set[Path] = set()
        # Validate the complete manifest before writing the first file.
        for member in members:
            member_target = _member_path(root, member.name)
            if not member.isdir() and not member.isreg():
                raise ValueError("Clash archives may only contain directories and regular files")
            if member.isreg():
                total += member.size
                if member.size < 0 or total > MAX_UNPACKED_SIZE:
                    raise ValueError("Clash archive exceeds the extracted size limit")
                if member_target == root or member_target in file_paths:
                    raise ValueError("Duplicate or invalid archive file")
                file_paths.add(member_target)
        for member in members:
            output = _member_path(root, member.name)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("Missing archive member contents")
            with source, output.open("xb") as handle:
                shutil.copyfileobj(source, handle)
            output.chmod(member.mode & 0o755)
    return probe(root)


def launch_command(app_root: str | os.PathLike[str], profile_dir: str | os.PathLike[str]) -> list[str]:
    # No --config switch: Tauri/dirs resolve the environment below.
    del profile_dir
    return [probe(app_root)["executable"]]


def launch_environment(profile_dir: str | os.PathLike[str]) -> dict[str, str]:
    root = Path(profile_dir).resolve()
    return {
        "HOME": str(root),
        "XDG_DATA_HOME": str(root / "data"),
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "XDG_RUNTIME_DIR": str(root / "runtime"),
        "GDK_BACKEND": "x11",
        "LIBGL_ALWAYS_SOFTWARE": "1",
    }


def profile_paths(profile_dir: str | os.PathLike[str]) -> dict[str, str]:
    data = Path(profile_dir).resolve() / "data" / APP_ID
    return {
        "app_data": str(data),
        "profiles_index": str(data / "profiles.yaml"),
        "profiles": str(data / "profiles"),
        "verge_config": str(data / "verge.yaml"),
        "clash_config": str(data / "config.yaml"),
    }


def _private_create(path: Path, content: str) -> None:
    # Existing profiles/configs are never silently replaced by an update.
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
    path.chmod(0o600)


def initialize_profile(
    profile_dir: str | os.PathLike[str],
    yaml_content: str | None = None,
    *,
    mixed_port: int = 17897,
    controller_port: int = 19097,
) -> dict[str, str]:
    """Initialize a new private profile; optional node YAML is runtime-only data.

    Call only while the GUI is stopped. Refuses an existing profiles index;
    existing installations should import subscriptions inside the GUI instead.
    """
    if not 1024 <= mixed_port <= 65535 or not 1024 <= controller_port <= 65535 or mixed_port == controller_port:
        raise ValueError("Choose distinct unprivileged proxy and controller ports")
    paths = profile_paths(profile_dir)
    root = Path(profile_dir).resolve()
    for directory in (root, root / "data", root / "config", root / "cache", root / "runtime",
                      Path(paths["app_data"]), Path(paths["profiles"])):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
    for key in ("profiles_index", "verge_config", "clash_config"):
        if Path(paths[key]).exists():
            raise FileExistsError("Clash profile already exists; refusing to overwrite user data")
    uid = "nas-native-local"
    index: dict[str, Any] = {"current": None, "items": []}
    if yaml_content is not None:
        if not yaml_content.strip():
            raise ValueError("The imported Clash profile is empty")
        profile_file = Path(paths["profiles"]) / f"{uid}.yaml"
        _private_create(profile_file, yaml_content)
        index = {"current": uid, "items": [{"uid": uid, "type": "local", "name": "NAS 节点",
                 "file": profile_file.name, "updated": int(time.time())}]}
    verge = {
        "language": "zh", "enable_auto_launch": False, "enable_silent_start": False,
        "enable_system_proxy": False, "enable_proxy_guard": False,
        "enable_tun_mode": False, "auto_check_update": False,
        "verge_mixed_port": mixed_port, "verge_socks_enabled": False,
        "verge_http_enabled": False, "verge_redir_enabled": False,
        "verge_tproxy_enabled": False, "enable_external_controller": False,
    }
    clash = {"mixed-port": mixed_port, "allow-lan": False, "ipv6": False, "mode": "rule",
             "external-controller": f"127.0.0.1:{controller_port}",
             "secret": secrets.token_urlsafe(32), "tun": {"enable": False}, "log-level": "info"}
    # JSON is valid YAML and avoids an additional parser dependency here.
    for key, value in (("verge_config", verge), ("clash_config", clash), ("profiles_index", index)):
        _private_create(Path(paths[key]), json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    return paths
