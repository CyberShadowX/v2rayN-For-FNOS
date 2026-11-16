"""Identify the root supervisor before recording its PID or delivering SIGTERM."""
import argparse
import json
import os
from pathlib import Path
import signal
import stat
import sys


def identity(pid, base, var, user):
    if type(pid) is not int or pid <= 1:
        raise ValueError("Invalid supervisor PID")
    proc = Path('/proc') / str(pid)
    if proc.stat().st_uid != 0:
        raise ValueError("Supervisor must be root owned")
    arguments = (proc / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
    expected = [str(Path(base) / 'runtime' / 'supervisor.py'), '--base', base,
                '--var', var, '--user', user]
    if len(arguments) != len(expected) + 1 or arguments[1:] != [os.fsencode(a) for a in expected]:
        raise ValueError("PID does not identify this application's supervisor")
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    return fields[19]  # /proc stat field 22, after the parenthesized process name.


def load_record(pid_file):
    info = pid_file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size > 256:
        raise ValueError("Unsafe supervisor PID record")
    record = json.loads(pid_file.read_text())
    if (not isinstance(record, dict) or type(record.get('pid')) is not int or record['pid'] <= 1
            or not isinstance(record.get('starttime'), str) or not record['starttime'].isdecimal()):
        raise ValueError("Invalid supervisor PID record")
    return record


def clean_shutdown(private):
    """A dead process is clean only with its exact root-owned shutdown receipt."""
    path = private / 'supervisor.pid'
    marker = private / 'ever-started'
    acknowledgement_path = private / 'clean-shutdown.json'
    try:
        marked = marker.exists() or marker.is_symlink()
        if marked:
            info = marker.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size > 64:
                return False
        if not path.exists() and not path.is_symlink():
            return not marked and not acknowledgement_path.exists() and not acknowledgement_path.is_symlink()
        record = load_record(path)
        acknowledgement = load_record(acknowledgement_path)
        return (acknowledgement['pid'] == record['pid']
                and acknowledgement['starttime'] == record['starttime']
                and acknowledgement.get('clean') is True)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return False


def record_run(private, pid, base, var, user):
    starttime = identity(pid, base, var, user)
    path = private / 'supervisor.pid'
    temporary = private / 'supervisor.pid.new'
    marker = private / 'ever-started'
    acknowledgement = private / 'clean-shutdown.json'
    for entry in (path, temporary, marker, acknowledgement):
        if entry.is_symlink():
            raise ValueError('Lifecycle state must not contain symlinks')
    # A partial record transaction must remain visibly started and unclean.
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write('recorded\n')
        stream.flush()
        os.fsync(stream.fileno())
    acknowledgement.unlink(missing_ok=True)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump({'pid': pid, 'starttime': starttime}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', required=True)
    parser.add_argument('--var', required=True)
    parser.add_argument('--user', required=True)
    parser.add_argument('--pid', type=int)
    parser.add_argument('action', choices=('record', 'status', 'signal', 'clean'))
    args = parser.parse_args()
    private = Path(args.var) / 'private'
    path = private / 'supervisor.pid'
    try:
        if private.is_symlink() or private.stat().st_uid != 0 or stat.S_IMODE(private.stat().st_mode) & 0o077:
            return 3
        if args.action == 'clean':
            return 0 if clean_shutdown(private) else 3
        if args.action == 'record':
            record_run(private, args.pid, args.base, args.var, args.user)
            return 0
        record = load_record(path)
        descriptor = None
        try:
            if args.action == 'signal':
                # A pidfd prevents a process exit/PID-reuse race after validation.
                descriptor = os.pidfd_open(record['pid'])
            if identity(record['pid'], args.base, args.var, args.user) != record['starttime']:
                return 3
            if args.action == 'signal':
                signal.pidfd_send_signal(descriptor, signal.SIGTERM)
            else:
                print(record['pid'])
            return 0
        finally:
            if descriptor is not None:
                os.close(descriptor)
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError):
        return 3


if __name__ == '__main__':
    sys.exit(main())
