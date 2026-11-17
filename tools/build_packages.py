"""Build public fnOS native packages from verified upstream payloads."""
from __future__ import annotations

import argparse
import ast
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import gzip
import io
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FNOS_ROOT = ROOT.parent
WRAPPER_VERSION = '1.0.6'
FNPACK_SHA256 = 'd7af4bd716b009c58f5bcd931615f39db121e7d4b75dc759e575c4fb2879b6ee'
PUBLIC_REPOSITORIES = {'v2rayn': 'v2rayN-For-FNOS', 'clash': 'Clash-Verge-For-FNOS'}
APPS = {
    'v2rayn': {'id': 'fnv2rayn', 'title': 'v2rayN', 'port': 18111, 'vnc_port': 5911,
               'display': 91, 'socks_port': 10808, 'upstream_version': '7.25.6',
               'source': '2dust/v2rayN', 'tag': '7.25.6', 'payload': 'work/v2rayn/unpacked',
               'executable': 'v2rayN', 'license': 'v2rayN-LICENSE.txt'},
    'clash': {'id': 'fnclash', 'title': 'Clash Verge Rev', 'port': 18112, 'vnc_port': 5912,
              'display': 92, 'socks_port': 17897, 'upstream_version': '2.5.10',
              'source': 'clash-verge-rev/clash-verge-rev', 'tag': 'v2.5.10', 'payload': 'work/clash/extracted',
              'executable': 'usr/bin/clash-verge', 'license': 'clash-verge-rev-LICENSE.txt'},
}
HOOKS = ('main', 'install_init', 'install_callback', 'uninstall_init', 'uninstall_callback',
         'upgrade_init', 'upgrade_callback', 'config_init', 'config_callback')
STATE_NAMES = {'portal.json', 'access.txt', 'tls.key', 'tls.crt', 'guiNConfig.json', 'guiNDB.db',
               'profiles.yaml', 'verge.yaml', 'supervisor.pid', 'current.json', 'transaction.json'}


def is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction())


def reject_link_components(path: Path) -> None:
    """Do not let a build path follow symlinks or Windows junctions."""
    requested = Path(os.path.abspath(path))
    for part in (requested, *requested.parents):
        if is_link(part):
            raise ValueError(f'Build paths cannot contain links or junctions: {part}')


def publication_config(root: Path | None = None) -> dict:
    """An exported repository selects one application without patching runtime code."""
    root = ROOT if root is None else Path(root)
    path = root / 'publication.json'
    reject_link_components(path)
    if not path.exists():
        return {}
    if not path.is_file() or path.stat().st_size > 4096:
        raise ValueError('publication.json must be a small regular JSON file')
    value = json.loads(path.read_text(encoding='utf-8'))
    if (not isinstance(value, dict) or set(value) != {'app', 'owner', 'repository', 'version'}
            or not isinstance(value.get('app'), str) or value.get('app') not in APPS
            or value.get('version') != WRAPPER_VERSION
            or not isinstance(value.get('owner'), str)
            or re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?', value['owner']) is None
            or not isinstance(value.get('repository'), str)
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', value['repository']) is None
            or value['repository'] in {'.', '..'}):
        raise ValueError('Invalid publication.json application, publisher or wrapper version')
    return value


def default_apps(root: Path | None = None) -> list[str]:
    config = publication_config(root)
    return [config['app']] if config else list(APPS)


def publisher(app: str, root: Path | None = None) -> dict[str, str]:
    config = publication_config(root)
    if config and config['app'] != app:
        raise ValueError('This public repository builds only its configured application')
    return {'owner': config.get('owner', 'CyberShadowX'),
            'repository': config.get('repository', PUBLIC_REPOSITORIES[app])}


def validate_output(output: Path, root: Path | None = None) -> Path:
    """Allow repository outputs or the adjacent workspace's outputs, preserving old releases."""
    root = ROOT if root is None else Path(root)
    reject_link_components(output)
    destination = Path(output).resolve()
    source_root = root.resolve()
    workspace_outputs = (source_root.parent / 'outputs').resolve()
    if destination == source_root or not (destination.is_relative_to(source_root)
                                          or destination.is_relative_to(workspace_outputs)):
        raise ValueError('Build outputs must be below the repository or its adjacent workspace outputs')
    if destination.exists() and not destination.is_dir():
        raise ValueError('Build output must be a directory')
    inventory = destination / 'build-inventory.json'
    sums = destination / 'SHA256SUMS.txt'
    for existing in (inventory, sums):
        reject_link_components(existing)
        if existing.exists() and not existing.is_file():
            raise ValueError('Output metadata must be regular files')
    if inventory.exists():
        current = json.loads(inventory.read_text(encoding='utf-8'))
        if not isinstance(current, dict) or current.get('wrapper_version') != WRAPPER_VERSION:
            raise ValueError('Output contains another release; choose a new output directory')
    if sums.exists():
        for line in sums.read_text(encoding='utf-8').splitlines():
            if line.strip() and not re.fullmatch(r'[a-fA-F0-9]{64}  fn(?:v2rayn|clash)-'
                                                + re.escape(WRAPPER_VERSION) + r'-x86\.fpk', line):
                raise ValueError('Output checksums contain another release; choose a new output directory')
    return destination


def sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verified_fnpack(path: Path, expected_sha256: str | None = None) -> Path:
    """Hash the tool before executing even --help; a version banner is not trust."""
    expected = FNPACK_SHA256 if expected_sha256 is None else expected_sha256
    if not isinstance(expected, str) or re.fullmatch(r'[a-fA-F0-9]{64}', expected) is None:
        raise ValueError('fnpack expected SHA-256 must be 64 hexadecimal characters')
    reject_link_components(path)
    requested = path.resolve()
    before = requested.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('fnpack must be a regular, non-linked file')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(requested, flags), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError('fnpack became a non-regular file')
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(opened) or identity(opened) != identity(after) or identity(after) != identity(requested.lstat()):
        raise ValueError('fnpack changed during SHA-256 verification')
    if actual != expected.lower():
        raise ValueError('fnpack SHA-256 differs from its trusted pin; no tool was executed')
    return requested


def run_fnpack(path: Path, *arguments: str, expected_sha256: str | None = None, **kwargs):
    """Recheck before each tool invocation, including create/build after --help."""
    tool = verified_fnpack(path, expected_sha256)
    return subprocess.run([str(tool), *arguments], check=True, **kwargs)


def write(path: Path, value: str | dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    path.write_bytes(value.replace('\r\n', '\n').encode('utf-8'))


def clear_generated(path: Path, package: Path) -> None:
    # Only regenerated subtrees below this app's staging directory may be removed.
    resolved = path.resolve()
    if not resolved.is_relative_to(package.resolve()) or resolved == package.resolve() or path.is_symlink():
        raise ValueError(f'Unsafe generated build path: {path}')
    if path.exists():
        shutil.rmtree(path)


def copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir() or is_link(source):
        raise ValueError(f'Missing or unsafe build source: {source}')
    for entry in source.rglob('*'):
        if is_link(entry):
            raise ValueError(f'Symlinks are not permitted in package inputs: {entry}')
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store'))


def normalize_tree(path: Path) -> None:
    path.chmod(0o755)
    for entry in path.rglob('*'):
        if entry.is_dir():
            entry.chmod(0o755)
        elif entry.is_file():
            with entry.open('rb') as stream:
                executable = stream.read(4) == b'\x7fELF'
            entry.chmod(0o755 if executable else 0o644)


def icons(app: str, package: Path) -> str:
    from PIL import Image
    if app == 'v2rayn':
        source = ROOT / 'packaging/icons/v2rayn.ico'
        if not source.exists():
            source = ROOT / 'work/v2rayn/unpacked/v2rayN.png'
        attribution = '2dust/v2rayN/7.25.6, unchanged upstream icon resized for fnOS'
    else:
        source = ROOT / 'work/clash/extracted/usr/share/icons/hicolor/256x256@2/apps/clash-verge.png'
        attribution = 'clash-verge-rev/clash-verge-rev/v2.5.10 Debian package icon resized for fnOS'
    with Image.open(source) as original:
        image = original.convert('RGBA')
        for size, name in ((64, 'ICON.PNG'), (256, 'ICON_256.PNG')):
            resized = image.resize((size, size), Image.Resampling.LANCZOS)
            resized.save(package / name)
            target = package / f'app/ui/images/icon_{size}.png'
            target.parent.mkdir(parents=True, exist_ok=True)
            resized.save(target)
    return attribution


def scan_for_secrets(package: Path) -> None:
    violations = []
    for entry in package.rglob('*'):
        if not entry.is_file():
            continue
        relative = entry.relative_to(package).as_posix()
        if entry.name in STATE_NAMES or entry.suffix.lower() in {'.key', '.pem', '.sqlite', '.db'}:
            violations.append(relative)
        if entry.name.lower() in {'docker-compose.yml', 'docker-compose.yaml', 'dockerfile'}:
            violations.append(relative + ' (Docker definition)')
        if entry.stat().st_size > 4 * 1024 * 1024:
            continue
        raw = entry.read_bytes()
        if b'\0' in raw[:8192]:
            continue
        try:
            text = raw.decode('utf-8')
        except UnicodeError:
            continue
        if (re.search(r'vless://[0-9a-fA-F-]{36}@', text)
                or re.search(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----', text)
                or re.search(r'"(?:password_hash|password_salt|vnc_password)"\s*:\s*"[^"\n]+"', text)):
            violations.append(relative + ' (credential-like content)')
    if violations:
        raise ValueError('Package contains private state or unsupported content: ' + ', '.join(violations))


def validate_wizard(document, name: str) -> None:
    # fnOS 1.2.1010 rejects a present wizard file containing [] even though
    # fnpack accepts it. Omit unused files rather than creating empty arrays.
    if not isinstance(document, list) or not document:
        raise ValueError(f'Wizard must contain at least one valid step: {name}')
    for step in document:
        if (not isinstance(step, dict) or not isinstance(step.get('stepTitle'), str)
                or not step['stepTitle'].strip() or not isinstance(step.get('items'), list)
                or not step['items']):
            raise ValueError(f'Wizard step needs a title and nonempty items: {name}')
        for item in step['items']:
            if not isinstance(item, dict) or not isinstance(item.get('type'), str):
                raise ValueError(f'Invalid wizard field: {name}')
            if item['type'] == 'tips':
                if not isinstance(item.get('helpText'), str) or not item['helpText'].strip():
                    raise ValueError(f'Wizard tips need helpText: {name}')
            elif not isinstance(item.get('field'), str) or not item['field'].strip():
                raise ValueError(f'Wizard input needs a field name: {name}')


def retire_rejected_candidates(output: Path) -> None:
    rejected = ROOT / 'work/rejected/wizard-empty-1.0.0'
    if not rejected.resolve().is_relative_to(ROOT.resolve()) or rejected.is_symlink():
        raise ValueError('Unsafe rejected-candidate archive directory')
    names = ['fnv2rayn-1.0.0-x86.fpk', 'fnclash-1.0.0-x86.fpk']
    inventory = output / 'build-inventory.json'
    if inventory.is_file() and json.loads(inventory.read_text(encoding='utf-8')).get('wrapper_version') == '1.0.0':
        names.append(inventory.name)
    sums = output / 'SHA256SUMS.txt'
    if sums.is_file() and '-1.0.0-x86.fpk' in sums.read_text(encoding='utf-8') and '-1.0.1-x86.fpk' not in sums.read_text(encoding='utf-8'):
        names.append(sums.name)
    for name in names:
        source = output / name
        if not source.exists():
            continue
        if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(output.resolve()):
            raise ValueError('Unsafe rejected-candidate source path')
        rejected.mkdir(parents=True, exist_ok=True)
        destination = rejected / name
        number = 1
        while destination.exists():
            destination = rejected / f'{Path(name).stem}-{number}{Path(name).suffix}'
            number += 1
        if not destination.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError('Rejected-candidate destination escaped the project')
        shutil.move(str(source), str(destination))
        print(f'Archived rejected 1.0.0 candidate: {destination.name}')


def prepare(app: str, fnpack: Path, *, fnpack_sha256: str | None = None) -> Path:
    meta = APPS[app]
    publishing = publisher(app)
    fnpack = verified_fnpack(fnpack, fnpack_sha256)
    package = ROOT / 'build' / meta['id']
    if not package.exists():
        package.parent.mkdir(parents=True, exist_ok=True)
        run_fnpack(fnpack, 'create', meta['id'], expected_sha256=fnpack_sha256, cwd=package.parent)
    for required in ('app', 'cmd', 'config', 'wizard'):
        (package / required).mkdir(exist_ok=True)
    for name in ('runtime', 'adapters', 'web'):
        destination = package / 'app' / name
        clear_generated(destination, package)
        copy_tree(ROOT / name, destination)
    payload = ROOT / meta['payload']
    if not (payload / meta['executable']).is_file():
        raise ValueError(f'Verified {app} upstream payload is missing')
    clear_generated(package / 'app/payload', package)
    copy_tree(payload, package / 'app/payload')
    compat = package / 'app/compat'
    clear_generated(compat, package)
    if app == 'v2rayn':
        copy_tree(ROOT / 'vendor/sqlite', compat)
        spec = importlib.util.spec_from_file_location('fnos_build_v2rayn', ROOT / 'adapters/v2rayn.py')
        adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adapter)
        adapter.prepare_runtime(package / 'app/payload', compat)
        normalize_tree(compat)
    normalize_tree(package / 'app/payload')
    core_source=json.loads((ROOT/'vendor/mihomo/SOURCE.json').read_text(encoding='utf-8'))
    core_binary=ROOT/'work/mihomo/mihomo'
    if core_binary.stat().st_size!=core_source['binary_size'] or sha256(core_binary)!=core_source['binary_sha256']:
        raise ValueError('The pinned official network helper does not match its verified provenance')
    network_core=package/'app/network-core'
    clear_generated(network_core,package);network_core.mkdir()
    shutil.copyfile(core_binary,network_core/'mihomo');(network_core/'mihomo').chmod(0o755)
    write(network_core/'source.json',core_source)
    shutil.copyfile(ROOT/'packaging/licenses/mihomo-LICENSE.txt',network_core/'LICENSE')
    support = package / 'app/support'
    clear_generated(support, package)
    support.mkdir()
    shutil.copyfile(ROOT / 'packaging/lifecycle_guard.py', support / 'lifecycle_guard.py')
    bundled_tools = package / 'app/tools'
    clear_generated(bundled_tools, package);bundled_tools.mkdir()
    shutil.copyfile(ROOT / 'tools/reset_portal_password.py', bundled_tools / 'reset_portal_password.py')
    bundled_docs = package / 'app/docs'
    clear_generated(bundled_docs, package);bundled_docs.mkdir()
    for guide in ('USER_GUIDE.md', 'ACCESS.md'):
        shutil.copyfile(ROOT / 'docs' / guide, bundled_docs / guide)
    info = {'app': app, 'wrapper_version': WRAPPER_VERSION, **{key: meta[key] for key in ('title', 'port', 'vnc_port', 'display',
                                                   'socks_port', 'upstream_version')}}
    info.update(network_core_version=core_source['version'],network_core_sha256=core_source['binary_sha256'])
    write(package / 'app/package.json', info)
    manifest = {
        'appname': meta['id'], 'version': WRAPPER_VERSION, 'display_name': meta['title'],
        'desc': '原生 Linux 桌面客户端，HTTPS 图形入口，独立用户运行，支持手动上游更新和统一 NAS 网络接管。',
        'platform': 'x86', 'source': 'thirdparty', 'maintainer': publishing['owner'],
        'distributor': publishing['owner'],
        'maintainer_url': f'https://github.com/{publishing["owner"]}/{publishing["repository"]}',
        'os_min_version': '1.2.1010', 'ctl_stop': 'true', 'desktop_uidir': 'ui',
        'desktop_applaunchname': meta['id'] + '.Application', 'service_port': str(meta['port']),
        'checkport': 'true', 'disable_authorization_path': 'true',
    }
    write(package / 'manifest', ''.join(f'{key:<26}= {value}\n' for key, value in manifest.items()))
    write(package / 'config/privilege', {'defaults': {'run-as': 'root'},
                                       'username': meta['id'], 'groupname': meta['id']})
    write(package / 'config/resource', {})
    write(package / 'app/ui/config', {'.url': {meta['id'] + '.Application': {
        'title': meta['title'], 'icon': 'images/icon_{0}.png', 'type': 'url', 'protocol': 'https',
        'port': str(meta['port']), 'url': '/', 'allUsers': False,
        'control': {'accessPerm': 'readonly'},
    }}})
    for hook in HOOKS:
        source = ROOT / 'packaging/hooks' / hook
        if not source.exists():
            source = ROOT / 'packaging/hooks/noop'
        write(package / 'cmd' / hook, source.read_text(encoding='utf-8'))
        (package / 'cmd' / hook).chmod(0o755)
    for wizard in ('install', 'uninstall', 'upgrade', 'config'):
        old = package / 'wizard' / wizard
        if old.is_symlink():
            raise ValueError('Wizard files must not be symlinks')
        if old.is_file() and json.loads(old.read_text(encoding='utf-8')) == []:
            old.unlink()  # These empty files were generated by our rejected 1.0.0 builder.
    write(package / 'wizard/install', [{'stepTitle': '安装说明', 'items': [
        {'type': 'tips', 'helpText': '客户端在 NAS 上原生运行。安装后从飞牛桌面打开独立 HTTPS 图形入口；初始登录信息由 NAS 生成，保存在应用私有目录，由管理员读取。安装包不包含预设密码。'}
    ]}])
    for wizard in (package / 'wizard').rglob('*'):
        if wizard.is_file():
            validate_wizard(json.loads(wizard.read_text(encoding='utf-8')), wizard.name)
    license_text = (ROOT / 'packaging/licenses' / meta['license']).read_text(encoding='utf-8')
    write(package / 'LICENSE', license_text)
    write(package / 'app/LICENSE', license_text)
    attribution = icons(app, package)
    third_party = (ROOT / 'packaging/THIRD_PARTY.md').read_text(encoding='utf-8')
    third_party += f'\nThis package: {meta["title"]}\nUpstream: https://github.com/{meta["source"]}/tree/{meta["tag"]}\n'
    third_party += f'Icon source: {attribution}\n'
    write(package / 'app/THIRD_PARTY.md', third_party)
    for python in (package / 'app').rglob('*.py'):
        ast.parse(python.read_text(encoding='utf-8'), filename=str(python))
    for metadata in (package / 'app').rglob('.DS_Store'):
        if metadata.is_file() and not metadata.is_symlink():
            metadata.unlink()
    scan_for_secrets(package)
    return package


class PrefixReader:
    def __init__(self, prefix, stream):
        self.prefix = prefix
        self.stream = stream

    def read(self, size=-1):
        if size < 0:
            prefix, self.prefix = self.prefix, b''
            return prefix + self.stream.read()
        prefix, self.prefix = self.prefix[:size], self.prefix[size:]
        return prefix + self.stream.read(size - len(prefix))


def canonical_member(member, mode):
    result = copy.copy(member)
    result.mode = mode
    result.mtime = 0
    result.uid = result.gid = 0
    result.uname = result.gname = ''
    result.pax_headers = {}
    return result


def normalize_fpk(path: Path) -> None:
    """Correct Unix permissions lost by official fnpack on Windows.

    Only tar metadata and manifest LF/checksum change. GUI and core file bytes
    remain identical. The observed fnpack MD5(app.tgz) checksum is verified
    before transformation, recomputed after transformation and verified again.
    """
    with tempfile.TemporaryDirectory(prefix='unix-fpk-', dir=path.parent) as temporary:
        work = Path(temporary)
        replacement = work / 'normalized.fpk'
        app_path = work / 'app.tgz'
        with tarfile.open(path, mode='r:*') as original:
            members = original.getmembers()
            names = {m.name.removeprefix('./'): m for m in members}
            app_member = names['app.tgz']
            manifest = original.extractfile(names['manifest']).read().decode('utf-8').replace('\r', '')
            checksum = re.search(r'(?m)^checksum\s*=\s*([a-fA-F0-9]{32})\s*$', manifest)
            if checksum is None:
                raise ValueError('Unsupported fnpack app checksum format')
            digest = hashlib.md5()
            with original.extractfile(app_member) as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            if digest.hexdigest() != checksum[1].lower():
                raise ValueError('Original fnpack checksum did not match app.tgz')
            with app_path.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.GNU_FORMAT) as output:
                    with original.extractfile(app_member) as app_stream:
                        with tarfile.open(fileobj=app_stream, mode='r|*') as source:
                            for member in source:
                                if Path(member.name).name == '.DS_Store':
                                    continue
                                if member.isdir():
                                    output.addfile(canonical_member(member, 0o755))
                                elif member.isfile():
                                    stream = source.extractfile(member)
                                    prefix = stream.read(4)
                                    mode = 0o755 if prefix == b'\x7fELF' else 0o644
                                    output.addfile(canonical_member(member, mode), PrefixReader(prefix, stream))
                                else:
                                    raise ValueError('Unsupported member in native application payload')
            with app_path.open('rb') as stream:
                replacement_checksum = hashlib.file_digest(stream, 'md5').hexdigest()
            manifest = re.sub(r'(?m)^checksum\s*=\s*[a-fA-F0-9]{32}\s*$',
                              'checksum                  = ' + replacement_checksum, manifest).rstrip() + '\n'
            manifest_bytes = manifest.encode('utf-8')
            with replacement.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.GNU_FORMAT) as output:
                    for member in members:
                        name = member.name.removeprefix('./')
                        if member.isdir():
                            output.addfile(canonical_member(member, 0o755))
                        elif not member.isfile():
                            raise ValueError('Unsupported member in FPK outer archive')
                        elif name == 'app.tgz':
                            info = canonical_member(member, 0o644)
                            info.size = app_path.stat().st_size
                            with app_path.open('rb') as stream:
                                output.addfile(info, stream)
                        elif name == 'manifest':
                            info = canonical_member(member, 0o644)
                            info.size = len(manifest_bytes)
                            output.addfile(info, io.BytesIO(manifest_bytes))
                        else:
                            mode = 0o755 if name.startswith('cmd/') else 0o644
                            with original.extractfile(member) as stream:
                                output.addfile(canonical_member(member, mode), stream)
        replacement.replace(path)


def validate_fpk(path: Path, app: str) -> dict:
    meta = APPS[app]
    with tarfile.open(path, 'r:*') as outer:
        entries = outer.getmembers()
        names = {member.name.removeprefix('./'): member for member in entries}
        required = ('manifest', 'app.tgz', 'ICON.PNG', 'ICON_256.PNG', 'config/privilege', 'config/resource')
        if not all(name in names for name in required):
            raise ValueError('Incomplete FPK outer structure')
        for hook in HOOKS:
            member = names.get('cmd/' + hook)
            if member is None or not member.mode & 0o111:
                raise ValueError('FPK lifecycle script is not executable: ' + hook)
            script = outer.extractfile(member).read()
            if not script.startswith(b'#!/bin/bash\n') or b'\r\n' in script:
                raise ValueError('FPK lifecycle scripts must use LF and a Bash shebang')
        privilege = json.load(outer.extractfile(names['config/privilege']))
        if privilege != {'defaults': {'run-as': 'root'}, 'username': meta['id'], 'groupname': meta['id']}:
            raise ValueError('Unexpected FPK privilege declaration')
        if json.load(outer.extractfile(names['config/resource'])) != {}:
            raise ValueError('FPK resources must not declare Docker or shared data')
        if 'wizard/install' not in names:
            raise ValueError('FPK must include the valid nonempty installation notice')
        for name, member in names.items():
            if name.startswith('wizard/') and member.isfile():
                validate_wizard(json.load(outer.extractfile(member)), name)
        blob = outer.extractfile(names['app.tgz']).read()
        manifest = outer.extractfile(names['manifest']).read().decode('utf-8')
        manifest_fields = {key.strip(): value.strip() for line in manifest.splitlines() if '=' in line
                           for key, value in [line.split('=', 1)]}
        if manifest_fields.get('version') != WRAPPER_VERSION:
            raise ValueError('FPK wrapper version does not match this build')
        if manifest_fields.get('display_name') != meta['title']:
            raise ValueError('FPK display name does not match the requested desktop title')
        checksum = re.search(r'(?m)^checksum\s*=\s*([a-fA-F0-9]{32})\s*$', manifest)
        if '\r' in manifest or checksum is None or checksum[1].lower() != hashlib.md5(blob).hexdigest():
            raise ValueError('FPK manifest LF or app.tgz checksum validation failed')
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:*') as inner:
        inner_names = {m.name.removeprefix('./'): m for m in inner.getmembers()}
        prefix = '' if 'package.json' in inner_names else 'app/'
        required_inner = ('package.json', 'runtime/supervisor.py', 'runtime/portal.py', 'runtime/network.py',
                          'runtime/init_state.py', 'runtime/updater.py', 'runtime/desktop.py',
                          'support/lifecycle_guard.py', 'web/index.html', 'web/app.js', 'ui/config',
                          'adapters/v2rayn.py', 'adapters/clash.py', 'adapters/mihomo.py',
                          'network-core/mihomo','network-core/source.json','network-core/LICENSE',
                          'payload/' + meta['executable'])
        if not all(prefix + name in inner_names for name in required_inner):
            raise ValueError('FPK is missing native runtime, desktop or GUI payload files')
        if app == 'v2rayn':
            sqlite_paths = [prefix + 'compat/e_sqlite3.so', prefix + 'payload/e_sqlite3.so']
            if not all(name in inner_names for name in sqlite_paths):
                raise ValueError('v2rayN FPK is missing its NAS SQLite compatibility library or private alias')
            sqlite_hashes = [hashlib.sha256(inner.extractfile(inner_names[name]).read()).hexdigest()
                             for name in sqlite_paths]
            if sqlite_hashes[0] != sqlite_hashes[1]:
                raise ValueError('v2rayN SQLite private alias differs from its verified compatibility payload')
        wrong_modes = []
        for name, member in inner_names.items():
            pure = Path(name)
            if pure.is_absolute() or '..' in pure.parts or member.issym() or member.islnk():
                raise ValueError('Unsafe FPK payload archive')
            if member.isdir() and member.mode & 0o055 != 0o055:
                wrong_modes.append(name)
            if member.isfile():
                data = inner.extractfile(member).read(4)
                if data == b'\x7fELF' and member.mode & 0o055 != 0o055:
                    wrong_modes.append(name)
        if wrong_modes:
            raise ValueError('FPK does not preserve Unix payload permissions: ' + ', '.join(wrong_modes[:5]))
        info = json.load(inner.extractfile(inner_names[prefix + 'package.json']))
        core_source=json.load(inner.extractfile(inner_names[prefix+'network-core/source.json']))
        core=inner.extractfile(inner_names[prefix+'network-core/mihomo'])
        core_digest=hashlib.file_digest(core,'sha256').hexdigest()
        if (core_digest!=core_source['binary_sha256'] or core_digest!=info.get('network_core_sha256')
                or info.get('network_core_version')!=core_source['version']
                or inner_names[prefix+'network-core/mihomo'].size!=core_source['binary_size']):
            raise ValueError('FPK network helper does not match its verified provenance')
        if (info['app'] != app or info['upstream_version'] != meta['upstream_version']
                or info.get('wrapper_version') != WRAPPER_VERSION or info.get('title') != meta['title']):
            raise ValueError('Unexpected packaged upstream identity')
        ui_config = json.load(inner.extractfile(inner_names[prefix + 'ui/config']))
        if ui_config.get('.url', {}).get(meta['id'] + '.Application', {}).get('title') != meta['title']:
            raise ValueError('FPK desktop entry title does not match the requested name')
        for required in ('tools/reset_portal_password.py','docs/USER_GUIDE.md','docs/ACCESS.md',
                         'web/help.html','ui/images/icon_64.png','ui/images/icon_256.png'):
            member=inner_names.get(prefix+required)
            if member is None or not member.isfile() or member.size==0:
                raise ValueError('FPK user-facing resources are incomplete: '+required)
    return {'outer_entries': len(entries), 'payload_entries': len(inner_names), 'native_runtime': True,
            'gui_payload': True, 'docker_definitions': False, 'unix_permissions': True,
            'app_checksum': True, 'manifest_lf': True, 'nonempty_wizards': True,
            'wrapper_version': WRAPPER_VERSION}


class DigestReader:
    """Hash the complete compressed app.tgz while its tar members are read."""

    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.size = 0

    def read(self, size=-1):
        data = self.stream.read(size)
        self.digest.update(data)
        self.size += len(data)
        return data


def inventory_name(member: tarfile.TarInfo) -> str:
    name = member.name.removeprefix('./').rstrip('/')
    if not name or name == '.':
        if member.isdir():
            return ''
        raise ValueError('A regular archive member needs a filename')
    if (PurePosixPath(name).is_absolute() or '\\' in name or '\0' in name or ':' in name
            or any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('Unsafe or ambiguous path in final FPK inventory')
    if not member.isdir() and not member.isfile():
        raise ValueError('Links and special files cannot be inventoried as native package files')
    return name


def stream_inventory_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> dict:
    digest = hashlib.sha256()
    size = 0
    with archive.extractfile(member) as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    if size != member.size:
        raise ValueError('Final FPK file size does not match its tar member: ' + member.name)
    return {'size': size, 'sha256': digest.hexdigest()}


def final_fpk_inventory(path: Path) -> dict:
    """Inventory final output bytes, including files injected by fnpack.

    ``files`` remains relative to app/ for existing inventory consumers.
    ``outer_files`` additionally records the normalized manifest, config,
    scripts and compressed app.tgz. Nothing is read from the staging tree.
    """
    if path.is_symlink() or not path.is_file():
        raise ValueError('Final FPK inventory requires a regular package file')
    outer_files, payload_files = {}, {}
    seen_outer, seen_payload = set(), set()
    with path.open('rb') as raw:
        before = os.fstat(raw.fileno())
        with tarfile.open(fileobj=raw, mode='r|*') as outer:
            for member in outer:
                name = inventory_name(member)
                if not name:
                    continue
                if name in seen_outer:
                    raise ValueError('Duplicate final FPK outer path: ' + name)
                seen_outer.add(name)
                if member.isdir():
                    continue
                if name != 'app.tgz':
                    outer_files[name] = stream_inventory_member(outer, member)
                    continue
                with outer.extractfile(member) as compressed:
                    reader = DigestReader(compressed)
                    with tarfile.open(fileobj=reader, mode='r|*') as inner:
                        for item in inner:
                            payload_name = inventory_name(item)
                            if not payload_name:
                                continue
                            if payload_name in seen_payload:
                                raise ValueError('Duplicate final FPK application path: ' + payload_name)
                            seen_payload.add(payload_name)
                            if item.isfile():
                                payload_files[payload_name] = stream_inventory_member(inner, item)
                    # tar parsing can stop before compressed trailing padding.
                    # Hash every byte recorded for this outer member as well.
                    while reader.read(1024 * 1024):
                        pass
                    if reader.size != member.size:
                        raise ValueError('Final app.tgz byte count differs from its outer tar header')
                    outer_files[name] = {'size': reader.size, 'sha256': reader.digest.hexdigest()}
        raw.seek(0)
        package_hash = hashlib.file_digest(raw, 'sha256').hexdigest()
        after = os.fstat(raw.fileno())
    fingerprint = lambda metadata: (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
    if fingerprint(before) != fingerprint(after) or fingerprint(after) != fingerprint(path.stat()):
        raise ValueError('Final FPK changed while its inventory was being calculated')
    if 'app.tgz' not in outer_files or not payload_files:
        raise ValueError('Final FPK is missing an application archive')
    if 'package.json' in payload_files:
        prefix = ''
    elif 'app/package.json' in payload_files and all(name.startswith('app/') for name in payload_files):
        prefix = 'app/'
    else:
        raise ValueError('Unrecognized final FPK application layout')
    files = {name.removeprefix(prefix): payload_files[name] for name in sorted(payload_files)}
    return {'inventory_source': 'final-fpk', 'size': after.st_size, 'sha256': package_hash,
            'payload_prefix': prefix, 'files': files,
            'outer_files': {name: outer_files[name] for name in sorted(outer_files)}}


def verify_fpk_inventory(path: Path, record: dict) -> None:
    """Freshly re-read the final artifact and require exact inventory equality."""
    actual = final_fpk_inventory(path)
    for field, value in actual.items():
        if record.get(field) != value:
            raise ValueError('Build inventory does not match the final FPK: ' + field)


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apps', nargs='+', choices=APPS, default=default_apps(),
                        help='要构建的应用；公开仓库默认使用 publication.json 中的单应用')
    parser.add_argument('--fnpack', type=Path, default=ROOT / 'work/tools/fnpack.exe',
                        help='已核验的 fnpack 1.2.3 可执行文件')
    parser.add_argument('--fnpack-sha256',
                        help='显式可信工具的 SHA-256；省略时只接受固定的 Windows 1.2.3 工具哈希')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist',
                        help='输出目录；默认为本仓库 dist，旧版本交付目录受到保护')
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    fnpack = verified_fnpack(args.fnpack, args.fnpack_sha256)
    output = validate_output(args.output_dir)
    for app in args.apps:
        publisher(app)
    tool_info = run_fnpack(fnpack, '--help', expected_sha256=args.fnpack_sha256,
                          capture_output=True, text=True).stdout
    if 'Version 1.2.3' not in tool_info:
        raise ValueError('This build requires the verified fnpack 1.2.3 tool')
    inventory = {'wrapper_version': WRAPPER_VERSION, 'fnos_min_version': '1.2.1010', 'architecture': 'x86_64',
                 'built_at': datetime.now(timezone(timedelta(hours=8))).isoformat(),
                 'fnpack_version': '1.2.3', 'fnpack_sha256': sha256(fnpack), 'packages': []}
    for app in args.apps:
        package = prepare(app, fnpack, fnpack_sha256=args.fnpack_sha256)
        print(f'Prepared {APPS[app]["id"]}: native desktop, runtime, no private state')
        if args.prepare_only:
            continue
        run_fnpack(fnpack, 'build', expected_sha256=args.fnpack_sha256, cwd=package)
        candidates = [package / (APPS[app]['id'] + '.fpk'), package.parent / (APPS[app]['id'] + '.fpk')]
        generated = next((p for p in candidates if p.is_file()), None)
        if generated is None:
            raise ValueError('fnpack did not produce the expected FPK')
        normalize_fpk(generated)
        checks = validate_fpk(generated, app)
        output.mkdir(parents=True, exist_ok=True)
        target = output / f'{APPS[app]["id"]}-{WRAPPER_VERSION}-x86.fpk'
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError('Final FPK output must not replace a link or special path')
        shutil.copyfile(generated, target)
        record = {'app': app, 'wrapper_version': WRAPPER_VERSION,
            'file': target.name, 'upstream_version': APPS[app]['upstream_version'],
            'upstream_source': f'https://github.com/{APPS[app]["source"]}/tree/{APPS[app]["tag"]}',
            'verification': checks, **final_fpk_inventory(target)}
        verify_fpk_inventory(target, record)
        checks['final_archive_inventory'] = True
        inventory['packages'].append(record)
        print(f'Validated {target.name}: {target.stat().st_size} bytes')
    if not args.prepare_only:
        write(output / 'build-inventory.json', inventory)
        write(output / 'SHA256SUMS.txt', ''.join(f'{p["sha256"]}  {p["file"]}\n' for p in inventory['packages']))


if __name__ == '__main__':
    main()
