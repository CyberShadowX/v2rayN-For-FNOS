"""Official release staging and verification; all mutable release paths are root-owned."""
from __future__ import annotations

import hashlib
import errno
import json
import os
from pathlib import Path
import shutil
import ssl
import sys
import time
import urllib.request
import uuid


def fetch_json(url: str, proxy_port: int | None = None) -> dict:
    with open_url(url, proxy_port) as response:
        body = response.read(4 * 1024 * 1024 + 1)
        if len(body) > 4 * 1024 * 1024:
            raise ValueError('Upstream metadata exceeds limit')
        return json.loads(body)


def open_url(url: str, proxy_port: int | None = None):
    if not url.startswith(('https://api.github.com/repos/', 'https://github.com/')):
        raise ValueError('Only official GitHub HTTPS upstream URLs are accepted')
    # Downloads happen before the desktop is stopped. The local mixed listener is
    # the preferred path on networks where direct GitHub access is unavailable.
    proxies = {'http': f'http://127.0.0.1:{proxy_port}', 'https': f'http://127.0.0.1:{proxy_port}'} if proxy_port else {}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    req = urllib.request.Request(url, headers={'User-Agent': 'fnOS-Native-Proxy-Apps/1.0', 'Accept': 'application/vnd.github+json'})
    return opener.open(req, timeout=20)


def latest(adapter, proxy_port=None):
    url = f'https://api.github.com/repos/{adapter.REPOSITORY}/releases/latest'
    try:
        release = fetch_json(url, proxy_port)
    except Exception:
        if not proxy_port:
            raise
        release = fetch_json(url)
    return adapter.release_asset(release)


def download(asset: dict, destination: Path, proxy_port=None, cancel=None):
    digest = hashlib.sha256()
    expected_size = asset['size']
    received = 0
    try:
        response = open_url(asset['browser_download_url'], proxy_port)
    except Exception:
        if not proxy_port:
            raise
        response = open_url(asset['browser_download_url'])
    with response, destination.open('xb') as out:
        while chunk := response.read(1024 * 1024):
            if cancel is not None and cancel.is_set():raise RuntimeError('Application is stopping')
            received += len(chunk)
            if received > expected_size:
                raise ValueError('Download exceeds declared release size')
            digest.update(chunk)
            out.write(chunk)
    if received != expected_size or digest.hexdigest() != asset['sha256']:
        raise ValueError('Official release SHA256/size verification failed')
    destination.chmod(0o600)


def stage(adapter, releases_dir: Path, proxy_port=None, cancel=None,compatibility_dir=None):
    asset = latest(adapter, proxy_port)
    stage_dir = releases_dir / (asset['version'] + '-' + uuid.uuid4().hex[:10])
    stage_dir.mkdir(mode=0o700)
    archive = stage_dir / asset['name']
    try:
        # fnOS data directories may have inheritable named-user ACLs. Keep
        # unverified downloads inaccessible and prevent those ACLs propagating.
        if sys.platform=='linux':
            descriptor=os.open(stage_dir,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                for attribute in ('system.posix_acl_default','system.posix_acl_access'):
                    try:os.removexattr(descriptor,attribute)
                    except OSError as error:
                        if error.errno not in (errno.ENODATA,errno.ENOTSUP,errno.EOPNOTSUPP):raise
                os.fchmod(descriptor,0o700)
            finally:os.close(descriptor)
        download(asset, archive, proxy_port,cancel=cancel)
        extracted = stage_dir / 'payload'
        adapter.extract(archive, extracted)
        if hasattr(adapter,'prepare_runtime'):
            if compatibility_dir is None:raise ValueError('Missing native compatibility resources')
            adapter.prepare_runtime(extracted,compatibility_dir)
        archive.unlink()
        network_core=stage_network_core(stage_dir,proxy_port,cancel)
        # Root owns release directories; users can execute but cannot replace
        # any binary that the supervisor may subsequently use with privileges.
        for directory, dirs, files in os.walk(extracted):
            Path(directory).chmod(0o755)
            for name in files:
                p = Path(directory) / name
                p.chmod(0o755 if p.stat().st_mode & 0o111 else 0o644)
        (stage_dir / 'release.json').write_text(json.dumps({k: asset[k] for k in ('version','name','size','sha256')}), encoding='utf-8')
        stage_dir.chmod(0o755)
        return {'path': str(extracted), 'version': asset['version'], 'sha256': asset['sha256'],
                'network_core': network_core}
    except BaseException:
        shutil.rmtree(stage_dir)
        raise


def stage_network_core(stage_dir: Path, proxy_port=None, cancel=None):
    from adapters import mihomo
    asset=latest(mihomo,proxy_port)
    archive=stage_dir/asset['name']
    download(asset,archive,proxy_port,cancel=cancel)
    folder=stage_dir/'network-core'
    result=mihomo.extract(archive,folder)
    binary=Path(result['executable'])
    with binary.open('rb') as source:digest=hashlib.file_digest(source,'sha256').hexdigest()
    archive.unlink()
    folder.chmod(0o755);binary.chmod(0o755)
    (folder/'source.json').write_text(json.dumps({k:asset[k] for k in ('version','name','size','sha256')}),encoding='utf-8')
    (folder/'source.json').chmod(0o644)
    return {'path':str(binary),'version':asset['version'],'sha256':digest}
