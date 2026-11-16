"""Prepare hash-pinned official inputs for the public fnOS packages.

No downloaded application is executed. This tool never contacts a NAS, imports
nodes, or installs software globally. Existing verified inputs may be reused;
different files and links are refused rather than overwritten.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from urllib.parse import urlsplit
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from adapters import clash, mihomo, v2rayn
from tools import build_packages

ASSETS = {
    'v2rayn': {
        'name': 'v2rayN-linux-64-7.25.6.zip',
        'url': 'https://github.com/2dust/v2rayN/releases/download/7.25.6/v2rayN-linux-64.zip',
        'size': 142814357,
        'sha256': '7f1b35e01ea59fd418fedb11b81ca1346bdcb3aa8121b628561f9d59c6f3a205',
    },
    'clash': {
        'name': 'Clash.Verge_2.5.10_amd64.deb',
        'url': 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.10/Clash.Verge_2.5.10_amd64.deb',
        'size': 103408266,
        'sha256': 'add8564811ba4d2305da443288d23a26c5ed19674b676a0bb58b99ec4f7d13cf',
    },
    'mihomo': {
        'name': 'mihomo-linux-amd64-compatible-v1.19.34.gz',
        'url': 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-linux-amd64-compatible-v1.19.34.gz',
        'size': 22766457,
        'sha256': '2763f5b414527f7baf6dc57e3f82f3ab561eedf34bfd7c2f2cde1f7e592efe06',
    },
    'fnpack': {
        'name': 'fnpack-1.2.3-windows-amd64',
        'url': 'https://static2.fnnas.com/fnpack/fnpack-1.2.3-windows-amd64',
        'size': 3963904,
        'sha256': 'd7af4bd716b009c58f5bcd931615f39db121e7d4b75dc759e575c4fb2879b6ee',
    },
}
ALLOWED_HOSTS = frozenset({'github.com', 'release-assets.githubusercontent.com',
                           'objects.githubusercontent.com', 'static2.fnnas.com'})
CHUNK = 1024 * 1024


def validate_url(url: str) -> str:
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in ALLOWED_HOSTS
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443) or parsed.fragment
            or not parsed.path.startswith('/') or '\\' in url or any(ord(c) < 32 for c in url)):
        raise ValueError('Downloads and redirects must use approved official HTTPS hosts')
    return url


def validate_asset(asset: dict) -> dict:
    if (not isinstance(asset, dict) or set(asset) != {'name', 'url', 'size', 'sha256'}
            or not isinstance(asset.get('name'), str)
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,179}', asset['name']) is None
            or asset['name'] in {'.', '..'} or type(asset.get('size')) is not int
            or not 0 < asset['size'] <= 512 * 1024 * 1024
            or not isinstance(asset.get('sha256'), str)
            or re.fullmatch(r'[a-f0-9]{64}', asset['sha256']) is None
            or not isinstance(asset.get('url'), str)):
        raise ValueError('Invalid pinned build asset metadata')
    validate_url(asset['url'])
    return asset


class OfficialRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(request, fp, code, message, headers, newurl)


def open_url(url: str):
    validate_url(url)
    opener = urllib.request.build_opener(OfficialRedirects())
    request = urllib.request.Request(url, headers={'User-Agent': 'fnOS-native-proxy-build/1.0.5',
                                                  'Accept-Encoding': 'identity'})
    return opener.open(request, timeout=90)


def checked_path(path: Path, root: Path) -> Path:
    build_packages.reject_link_components(path)
    if not path.resolve().is_relative_to(root.resolve()) or path.resolve() == root.resolve():
        raise ValueError('Prepared inputs must stay below this repository')
    return path


def regular_digest(path: Path) -> tuple[int, str]:
    build_packages.reject_link_components(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('Build inputs must be regular files')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError('Build input became a special file')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(opened) or identity(opened) != identity(after) or identity(after) != identity(path.lstat()):
        raise ValueError('Build input changed during verification')
    return opened.st_size, digest


def verify(path: Path, asset: dict) -> None:
    build_packages.reject_link_components(path)
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size != asset['size']:
        raise ValueError('Build input type or size differs from its pin')
    if regular_digest(path) != (asset['size'], asset['sha256']):
        raise ValueError('Existing or downloaded input does not match its pinned size and SHA-256')


def download(asset: dict, destination: Path, root: Path, *, offline: bool = False) -> Path:
    """Download to private staging and publish with a no-overwrite hard link."""
    validate_asset(asset)
    checked_path(destination, root)
    if destination.exists():
        verify(destination, asset)
        return destination
    if offline:
        raise ValueError('Offline preparation is missing a pinned input: ' + asset['name'])
    destination.parent.mkdir(parents=True, exist_ok=True)
    checked_path(destination, root)
    descriptor, temporary_name = tempfile.mkstemp(prefix='.download-', suffix='.tmp', dir=destination.parent)
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    total = 0
    try:
        with os.fdopen(descriptor, 'wb') as target, open_url(asset['url']) as response:
            validate_url(response.geturl())
            length = response.headers.get('Content-Length')
            if length is not None and (not length.isdecimal() or int(length) != asset['size']):
                raise ValueError('Unexpected HTTP content length')
            while chunk := response.read(CHUNK):
                total += len(chunk)
                if total > asset['size']:
                    raise ValueError('Download exceeds its pinned size')
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        if total != asset['size'] or digest.hexdigest() != asset['sha256']:
            raise ValueError('Download size or SHA-256 did not match the pinned release')
        verify(temporary, asset)
        checked_path(destination, root)
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError:
            verify(destination, asset)
        verify(destination, asset)
        return destination
    finally:
        temporary.unlink(missing_ok=True)


def tree_digest(root: Path) -> dict[str, tuple[str, str]]:
    build_packages.reject_link_components(root)
    if not root.is_dir():
        raise ValueError('Expected a prepared payload directory')
    result = {}
    for entry in sorted(root.rglob('*')):
        build_packages.reject_link_components(entry)
        name = entry.relative_to(root).as_posix()
        if entry.is_dir():
            result[name] = ('directory', '')
        elif entry.is_file():
            result[name] = ('file', regular_digest(entry)[1])
        else:
            raise ValueError('Prepared payload contains a special file')
    return result


def extract_verified(asset: dict, archive: Path, destination: Path, adapter, root: Path) -> Path:
    """Use the existing safe adapters, refusing a different prepared tree."""
    verify(archive, validate_asset(asset))
    checked_path(destination, root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.' + destination.name + '-prepare-', dir=destination.parent))
    try:
        adapter.extract(archive, staging)
        prepared_digest = tree_digest(staging)
        checked_path(destination, root)
        if destination.exists():
            if tree_digest(destination) != prepared_digest:
                raise ValueError('Existing prepared payload differs; it was not overwritten')
        else:
            # mkdir and link are no-overwrite operations on Windows and Linux.
            # Avoid rename-over-empty-directory behavior on POSIX. If interrupted,
            # a partial destination fails the next exact-tree comparison.
            destination.mkdir()
            for entry in sorted(staging.rglob('*')):
                target = destination / entry.relative_to(staging)
                checked_path(target, root)
                if entry.is_dir():
                    target.mkdir()
                else:
                    os.link(entry, target, follow_symlinks=False)
            if tree_digest(destination) != prepared_digest:
                raise ValueError('Prepared payload changed during publication')
        return destination
    finally:
        if staging.exists():
            checked_path(staging, root)
            shutil.rmtree(staging)


def prepare_fnpack(root: Path, *, supplied: Path | None = None, supplied_sha256: str | None = None,
                   offline: bool = False, skip: bool = False) -> Path | None:
    if skip:
        if supplied is not None or supplied_sha256 is not None:
            raise ValueError('--skip-fnpack cannot be combined with a supplied tool')
        return None
    if supplied is not None:
        build_packages.reject_link_components(supplied)
        size, digest = regular_digest(supplied)
        expected = ASSETS['fnpack']['sha256'] if supplied_sha256 is None else supplied_sha256
        if not isinstance(expected, str) or re.fullmatch(r'[a-f0-9]{64}', expected) is None or digest != expected:
            raise ValueError('Supplied fnpack requires its verified SHA-256; no tool was executed')
        if supplied_sha256 is None and size != ASSETS['fnpack']['size']:
            raise ValueError('Supplied Windows fnpack size differs from its pin')
        return supplied.resolve()
    if supplied_sha256 is not None:
        raise ValueError('--fnpack-sha256 requires --fnpack')
    if sys.platform != 'win32':
        raise ValueError('Automatic fnpack setup supports Windows only. Use --fnpack with --fnpack-sha256 '
                         'for an already verified native tool, or --skip-fnpack to prepare payloads only.')
    return download(ASSETS['fnpack'], root / 'work/tools/fnpack.exe', root, offline=offline)


def prepare_apps(apps: list[str], root: Path | None = None, *, offline: bool = False,
                 fnpack: Path | None = None, fnpack_sha256: str | None = None,
                 skip_fnpack: bool = False) -> dict:
    root = ROOT if root is None else Path(root)
    build_packages.reject_link_components(root)
    if not apps or len(set(apps)) != len(apps) or any(app not in ('v2rayn', 'clash') for app in apps):
        raise ValueError('Select one or both supported applications without duplicates')
    for app in apps:
        build_packages.publisher(app, root)
    tool = prepare_fnpack(root, supplied=fnpack, supplied_sha256=fnpack_sha256, offline=offline, skip=skip_fnpack)
    prepared = []
    for app in [*apps, 'mihomo']:
        asset = ASSETS[app]
        archive = download(asset, root / 'work/downloads' / asset['name'], root, offline=offline)
        target = root / ('work/' + app + ('/unpacked' if app == 'v2rayn' else '/extracted' if app == 'clash' else ''))
        extract_verified(asset, archive, target, {'v2rayn': v2rayn, 'clash': clash, 'mihomo': mihomo}[app], root)
        prepared.append({'component': app, 'archive_sha256': asset['sha256'], 'archive_size': asset['size'],
                         'payload': target.relative_to(root).as_posix()})
    return {'wrapper_version': build_packages.WRAPPER_VERSION, 'applications': apps,
            'inputs': prepared, 'fnpack': str(tool) if tool else None,
            'note': 'Inputs verified; no NAS installation or runtime acceptance was performed.'}


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description='下载并校验固定版本的官方构建输入，不连接 NAS。')
    parser.add_argument('--apps', nargs='+', choices=('v2rayn', 'clash'), default=build_packages.default_apps())
    parser.add_argument('--offline', action='store_true', help='仅使用已经缓存且校验通过的下载文件')
    parser.add_argument('--fnpack', type=Path, help='复用已有工具；非固定 Windows 工具还需提供 --fnpack-sha256')
    parser.add_argument('--fnpack-sha256', help='显式提供的可信 fnpack 的 SHA-256，小写十六进制')
    parser.add_argument('--skip-fnpack', action='store_true', help='只准备应用载荷，不下载或执行 fnpack')
    args = parser.parse_args()
    result = prepare_apps(args.apps, offline=args.offline, fnpack=args.fnpack,
                          fnpack_sha256=args.fnpack_sha256, skip_fnpack=args.skip_fnpack)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.fnpack is not None:
        command = ('Build with: python tools/build_packages.py --apps ' + ' '.join(args.apps)
                   + ' --fnpack "' + str(args.fnpack.resolve()) + '"')
        if args.fnpack_sha256 is not None:
            command += ' --fnpack-sha256 ' + args.fnpack_sha256
        print(command)


if __name__ == '__main__':
    main()
