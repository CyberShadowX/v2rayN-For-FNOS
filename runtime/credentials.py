"""Local portal credential rotation. Runtime secrets never enter the package.

Only the root supervisor or root administrator CLI may mutate credentials.
The private journal makes the two legacy files recoverable after interruption.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import time

try:
    import fcntl
except ImportError:
    fcntl = None

_ROOT_UID = 0
_CONFIG_LIMIT = 32 * 1024
_ACCESS_LIMIT = 4096
_JOURNAL_LIMIT = 128 * 1024
_JOURNAL = "credentials-transaction.json"
_APPS = {"v2rayn": ("v2rayN", 18111), "clash": ("Clash Verge Rev", 18112)}


class CredentialError(ValueError):
    """A safe, non-secret description suitable for the fixed control API."""


def validate_new_password(value: str) -> str:
    if not isinstance(value, str):
        raise CredentialError("新密码须为 12–128 个字符")
    try:
        valid = (12 <= len(value) <= 128 and len(value.encode("utf-8")) <= 512
                 and bool(value.strip()) and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value))
    except UnicodeError:
        valid = False
    if not valid:
        raise CredentialError("新密码须为 12–128 个字符，不能包含换行或控制字符")
    return value


def validate_current_password(value: str) -> str:
    try:
        valid = isinstance(value, str) and 1 <= len(value.encode("utf-8")) <= 2048
    except UnicodeError:
        valid = False
    if not valid:
        raise CredentialError("请输入当前访问密码")
    return value


def validate_config(config: dict, app: str | None = None) -> dict:
    try:
        if not isinstance(config, dict) or config.get("app") not in _APPS or (app and config["app"] != app):
            raise ValueError()
        salt = bytes.fromhex(config["password_salt"])
        digest = bytes.fromhex(config["password_hash"])
        vnc = config["vnc_password"]
        if not 16 <= len(salt) <= 64 or len(digest) != 32 or not isinstance(vnc, str) or len(vnc.encode("ascii")) != 8:
            raise ValueError()
        if any(ord(c) < 33 or ord(c) > 126 for c in vnc):
            raise ValueError()
        revision = config.get("password_revision", "")
        if not isinstance(revision, str) or len(revision) > 128:
            raise ValueError()
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise CredentialError("访问凭据无效，请由 NAS 管理员检查本应用的凭据文件") from None
    return config


def credential_revision(config: dict) -> str:
    validate_config(config)
    data = bytes.fromhex(config["password_salt"]) + bytes.fromhex(config["password_hash"])
    return hashlib.sha256(data + config.get("password_revision", "").encode("utf-8")).hexdigest()


def verify_password(config: dict, password: str) -> bool:
    validate_config(config)
    validate_current_password(password)
    calculated = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(config["password_salt"]),
                                n=16384, r=8, p=1, dklen=32)
    return hmac.compare_digest(calculated, bytes.fromhex(config["password_hash"]))


def _identity(metadata):
    identity = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
    # On Windows Python's path stat and handle fstat expose different ctime
    # semantics. Root mutations are POSIX-only and retain the strict ctime check.
    return (*identity, metadata.st_ctime_ns) if os.name == "posix" else identity


def _metadata(metadata, *, owner: int, directory: bool = False):
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected(metadata.st_mode) or metadata.st_uid != owner
            or metadata.st_mode & 0o077 or (not directory and metadata.st_nlink != 1)):
        raise CredentialError("凭据路径的类型、所有者或访问权限不安全")


def _read_at(directory: int, name: str, owner: int, maximum: int, *, optional=False) -> bytes | None:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        if optional:
            return None
        raise CredentialError("本应用的访问凭据文件不存在") from None
    except OSError:
        raise CredentialError("无法安全读取本应用的访问凭据") from None
    try:
        before = os.fstat(descriptor)
        _metadata(before, owner=owner)
        if before.st_size > maximum:
            raise CredentialError("访问凭据文件过大")
        chunks = bytearray()
        while len(chunks) <= maximum:
            chunk = os.read(descriptor, min(8192, maximum + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if len(chunks) > maximum or _identity(before) != _identity(after) or _identity(after) != _identity(current):
            raise CredentialError("访问凭据在读取期间发生变化，请重试")
        return bytes(chunks)
    finally:
        os.close(descriptor)


def read_portal_config(path: Path, app: str | None = None) -> dict:
    """Unprivileged portal reads only its own bounded regular config file."""
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file():
            raise CredentialError("访问凭据文件类型不安全")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _CONFIG_LIMIT:
                raise CredentialError("访问凭据文件类型或大小不安全")
            if os.name == "posix" and before.st_mode & 0o077:
                raise CredentialError("访问凭据文件权限不安全")
            data = stream.read(_CONFIG_LIMIT + 1)
            after = os.fstat(stream.fileno())
        if len(data) > _CONFIG_LIMIT or _identity(before) != _identity(after) or _identity(after) != _identity(path.lstat()):
            raise CredentialError("访问凭据读取未完成，请重试")
        return validate_config(json.loads(data), app)
    except CredentialError:
        raise
    except (OSError, ValueError, UnicodeError):
        raise CredentialError("无法读取本应用的访问凭据，请联系 NAS 管理员") from None


def _write_at(directory: int, name: str, data: bytes, uid: int, gid: int):
    temporary = ".credentials-" + secrets.token_hex(16)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(os.dup(descriptor), "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        original = os.fstat(descriptor)
        candidate = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
        if (original.st_dev, original.st_ino) != (candidate.st_dev, candidate.st_ino):
            raise CredentialError("凭据暂存路径发生变化")
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


@contextmanager
def _locked_state(var: Path):
    require_administrator()
    var = Path(var).resolve(strict=True)
    descriptors = []
    try:
        root = os.open(var, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(root)
        metadata = os.fstat(root)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != _ROOT_UID or metadata.st_mode & 0o022:
            raise CredentialError("应用运行数据目录不安全")
        private = os.open("private", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        descriptors.append(private)
        _metadata(os.fstat(private), owner=_ROOT_UID, directory=True)
        ui = os.open("ui", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        descriptors.append(ui)
        ui_metadata = os.fstat(ui)
        _metadata(ui_metadata, owner=ui_metadata.st_uid, directory=True)
        lock = os.open("credentials.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=private)
        descriptors.append(lock)
        _metadata(os.fstat(lock), owner=_ROOT_UID)
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise CredentialError("另一个密码操作正在进行，请稍后重试") from None
                time.sleep(0.05)
        yield private, ui, ui_metadata.st_uid, ui_metadata.st_gid
    except OSError:
        raise CredentialError("无法安全打开本应用的凭据目录") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def require_administrator():
    if os.name != "posix" or fcntl is None or not hasattr(os, "geteuid") or os.geteuid() != _ROOT_UID:
        raise PermissionError("修改访问密码需要 NAS 管理员 root 权限")


def _decode_config(data: bytes, app: str) -> dict:
    try:
        return validate_config(json.loads(data), app)
    except (UnicodeError, json.JSONDecodeError):
        raise CredentialError("本应用的凭据格式无效") from None


def _restore_access(private, data):
    if data is None:
        try:
            os.unlink("access.txt", dir_fd=private)
            os.fsync(private)
        except FileNotFoundError:
            pass
    else:
        _write_at(private, "access.txt", data, _ROOT_UID, _ROOT_UID)


def _recover_locked(private, ui, uid, gid, app):
    data = _read_at(private, _JOURNAL, _ROOT_UID, _JOURNAL_LIMIT, optional=True)
    if data is None:
        return False
    try:
        journal = json.loads(data)
        if set(journal) != {"schema", "app", "old_config", "new_config", "old_access", "new_access"} or journal["schema"] != 1 or journal["app"] != app:
            raise ValueError()
        values = {key: base64.b64decode(journal[key], validate=True) if journal[key] is not None else None
                  for key in ("old_config", "new_config", "old_access", "new_access")}
        old_config = _decode_config(values["old_config"], app)
        new_config = _decode_config(values["new_config"], app)
        if (len(values["old_config"]) > _CONFIG_LIMIT or len(values["new_config"]) > _CONFIG_LIMIT
                or len(values["new_access"]) > _ACCESS_LIMIT
                or (values["old_access"] is not None and len(values["old_access"]) > _ACCESS_LIMIT)):
            raise ValueError()
    except (ValueError, TypeError, KeyError, CredentialError):
        raise CredentialError("密码恢复记录无效，请保留现场并由 NAS 管理员检查") from None
    current = _read_at(ui, "portal.json", uid, _CONFIG_LIMIT)
    config = _decode_config(current, app)
    committed = hmac.compare_digest(credential_revision(config), credential_revision(new_config))
    chosen = "new" if committed else "old"
    _restore_access(private, values[chosen + "_access"])
    _write_at(ui, "portal.json", values[chosen + "_config"], uid, gid)
    os.unlink(_JOURNAL, dir_fd=private)
    os.fsync(private)
    return True


def recover_pending(var: Path, app: str) -> bool:
    if app not in _APPS:
        raise CredentialError("未知应用")
    with _locked_state(var) as state:
        return _recover_locked(*state, app)


def _rotate(var, app, new_password, *, current_password=None, expected_revision=None, administrator=False):
    if app not in _APPS:
        raise CredentialError("未知应用")
    validate_new_password(new_password)
    with _locked_state(var) as state:
        private, ui, uid, gid = state
        _recover_locked(*state, app)
        old_data = _read_at(ui, "portal.json", uid, _CONFIG_LIMIT)
        config = _decode_config(old_data, app)
        if not administrator:
            if not isinstance(expected_revision, str) or not hmac.compare_digest(credential_revision(config), expected_revision):
                raise CredentialError("访问密码已变更，请重新登录后重试")
            if not verify_password(config, current_password):
                raise CredentialError("当前访问密码不正确")
        if verify_password(config, new_password):
            raise CredentialError("新密码不能与当前密码相同")
        access = _read_at(private, "access.txt", _ROOT_UID, _ACCESS_LIMIT, optional=True)
        new_config = dict(config)
        salt = secrets.token_bytes(16)
        new_config.update(password_salt=salt.hex(), password_hash=hashlib.scrypt(new_password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32).hex(), password_revision=secrets.token_hex(16))
        title, port = _APPS[app]
        new_data = (json.dumps(new_config, ensure_ascii=False) + "\n").encode("utf-8")
        new_access = (title + "\nHTTPS port: " + str(port) + "\nPassword: " + new_password + "\n").encode("utf-8")
        journal = {"schema": 1, "app": app, **{key: base64.b64encode(value).decode("ascii") if value is not None else None for key, value in {
            "old_config": old_data, "new_config": new_data, "old_access": access, "new_access": new_access}.items()}}
        _write_at(private, _JOURNAL, json.dumps(journal).encode("ascii"), _ROOT_UID, _ROOT_UID)
        committed = False
        try:
            _restore_access(private, new_access)
            _write_at(ui, "portal.json", new_data, uid, gid)
            committed = True
            os.unlink(_JOURNAL, dir_fd=private)
            os.fsync(private)
        except BaseException:
            if committed:
                # Both durable files contain the new credential. A retained
                # journal is completed on the next startup/credential operation.
                return {"ok": True, "reauthenticate": True}
            if not committed:
                # The public password is the commit point. On ordinary write
                # failures restore the exact old access file; retain a journal
                # when recovery itself fails so startup can safely finish it.
                try:
                    _restore_access(private, access)
                    _write_at(ui, "portal.json", old_data, uid, gid)
                    os.unlink(_JOURNAL, dir_fd=private)
                    os.fsync(private)
                except BaseException:
                    pass
            raise CredentialError("访问密码更新未完成，请由 NAS 管理员检查后重试") from None
    return {"ok": True, "reauthenticate": True}


def change_password(var: Path, app: str, current_password: str, new_password: str, *, expected_revision: str | None = None) -> dict:
    validate_current_password(current_password)
    return _rotate(var, app, new_password, current_password=current_password, expected_revision=expected_revision)


def reset_password(var: Path, app: str, new_password: str) -> dict:
    """Root administrator recovery; no node, TLS or profile paths are touched."""
    return _rotate(var, app, new_password, administrator=True)
