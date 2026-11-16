"""First-install state initialization. Credentials never enter the distributable."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import stat
import errno
import tempfile


def harden_runtime(base):
    """Revoke fnOS's installed-package write ACLs before package users run code.

    This touches only the application destination, never its mutable var/profile.
    FD-relative traversal refuses symlinks, special files and non-root owners.
    """
    def secure(fd,is_directory):
        metadata=os.fstat(fd)
        if metadata.st_uid!=0:raise PermissionError('Runtime object is not root owned')
        if not (stat.S_ISDIR(metadata.st_mode) if is_directory else stat.S_ISREG(metadata.st_mode)):
            raise ValueError('Runtime object type changed')
        attributes=('system.posix_acl_default','system.posix_acl_access') if is_directory else ('system.posix_acl_access',)
        for attribute in attributes:
            try:os.removexattr(fd,attribute)
            except OSError as error:
                if error.errno not in (errno.ENODATA,errno.ENOTSUP,errno.EOPNOTSUPP):raise
        os.fchmod(fd,0o755 if is_directory or metadata.st_mode & 0o111 else 0o644)
        if is_directory:
            for name in os.listdir(fd):
                entry=os.stat(name,dir_fd=fd,follow_symlinks=False)
                if stat.S_ISDIR(entry.st_mode):flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
                elif stat.S_ISREG(entry.st_mode):flags=os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW
                else:raise ValueError('Runtime tree contains a link or special file')
                child=os.open(name,flags,dir_fd=fd)
                try:secure(child,stat.S_ISDIR(entry.st_mode))
                finally:os.close(child)
    descriptor=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:secure(descriptor,True)
    finally:os.close(descriptor)


def certificate_subject_alt_name():
    """Use this installation's assigned IPs, with a loopback-only fallback."""
    addresses={ipaddress.ip_address('127.0.0.1'),ipaddress.ip_address('::1')}
    try:
        result=subprocess.run(['ip','-j','address','show'],check=True,capture_output=True,
                              text=True,encoding='utf-8',timeout=5)
        interfaces=json.loads(result.stdout)
    except (OSError,subprocess.SubprocessError,UnicodeError,TypeError,ValueError):
        interfaces=[]
    if not isinstance(interfaces,list):interfaces=[]
    for interface in interfaces:
        if not isinstance(interface,dict):continue
        entries=interface.get('addr_info',[])
        if not isinstance(entries,list):continue
        for entry in entries:
            if not isinstance(entry,dict):continue
            value=entry.get('local')
            family=entry.get('family')
            if not isinstance(value,str) or '%' in value or family not in ('inet','inet6'):continue
            try:address=ipaddress.ip_address(value)
            except ValueError:continue
            if (family=='inet')!=(address.version==4):continue
            if address.is_unspecified or address.is_multicast or value=='255.255.255.255':continue
            addresses.add(address)
    ordered=sorted(addresses,key=lambda address:(address.version,int(address)))
    return 'subjectAltName=DNS:localhost,'+','.join('IP:'+str(address) for address in ordered)


def ensure_tls_certificate(ui):
    """Create a fresh pair without replacing existing keys or certificates."""
    ui=Path(ui)
    key,certificate=ui/'tls.key',ui/'tls.crt'
    if key.exists() or certificate.exists() or key.is_symlink() or certificate.is_symlink():
        if key.is_symlink() or certificate.is_symlink() or not key.is_file() or not certificate.is_file():
            raise FileExistsError('Existing TLS state is incomplete or linked; retain it for manual recovery')
        return
    with tempfile.TemporaryDirectory(prefix='.tls-',dir=ui) as stage:
        staged_key,staged_certificate=Path(stage)/'tls.key',Path(stage)/'tls.crt'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','825','-subj','/CN=fnOS native proxy',
                        '-addext',certificate_subject_alt_name(),
                        '-keyout',str(staged_key),'-out',str(staged_certificate)],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        for path in (staged_key,staged_certificate):path.chmod(0o600)
        # Hard links publish each regular file exclusively, including on a race.
        os.link(staged_key,key)
        try:os.link(staged_certificate,certificate)
        except BaseException:
            staged_metadata=staged_key.stat()
            try:published=key.lstat()
            except FileNotFoundError:published=None
            if published and stat.S_ISREG(published.st_mode) and (published.st_dev,published.st_ino)==(staged_metadata.st_dev,staged_metadata.st_ino):
                key.unlink()
            raise


def initialize_user(ui,meta):
    """Runs only after dropping to the package user, including openssl writes."""
    config=ui/'portal.json'
    control=ui/'control.sock'
    if not control.is_symlink():
        control.unlink(missing_ok=True)
        control.symlink_to(ui.parent/'control'/'control.sock')
    # Do not persist a first-login password hash before TLS initialization can fail.
    ensure_tls_certificate(ui)
    password=None
    if not config.exists():
        password=os.environ.get('wizard_portal_password') or secrets.token_urlsafe(20)
        salt=secrets.token_bytes(16)
        values={'password_salt':salt.hex(),'password_hash':hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32).hex(),
                'vnc_password':secrets.token_urlsafe(8)[:8],'app':meta['app'],'title':meta['title']}
        with config.open('x',encoding='utf-8') as f:json.dump(values,f)
        config.chmod(0o600)
    print(json.dumps({'password':password}))


def initialize(base, var, user):
    import pwd

    base, var = Path(base), Path(var)
    harden_runtime(base)
    meta = json.loads((base / 'package.json').read_text())
    account = pwd.getpwnam(user)
    var.mkdir(parents=True, exist_ok=True)
    var.chmod(0o755)
    for name, mode, owner in [('private',0o700,0),('releases',0o755,0),('p',0o700,account.pw_uid),('ui',0o700,account.pw_uid),('logs',0o750,account.pw_uid)]:
        d = var / name
        if d.is_symlink():
            raise ValueError('State directories cannot be symlinks')
        d.mkdir(exist_ok=True)
        d.chmod(mode)
        os.chown(d, owner, account.pw_gid if owner else 0)
    control=var/'control'
    if control.is_symlink():raise ValueError('Control directory cannot be a symlink')
    control.mkdir(exist_ok=True);control.chmod(0o710);os.chown(control,0,account.pw_gid)
    ui = var / 'ui'
    result=subprocess.run(['runuser','-u',user,'--','python3',str(Path(__file__).resolve()),'--user-init','--base',str(base),'--var',str(var),'--user',user],check=True,capture_output=True,text=True)
    password=json.loads(result.stdout)['password']
    if password:
        credentials = var / 'private' / 'access.txt'
        credentials.write_text(meta['title']+'\nHTTPS port: '+str(meta['port'])+'\nPassword: '+password+'\n',encoding='utf-8')
        credentials.chmod(0o600)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--base',required=True);p.add_argument('--var',required=True);p.add_argument('--user',required=True);p.add_argument('--user-init',action='store_true')
    a=p.parse_args()
    if a.user_init:initialize_user(Path(a.var)/'ui',json.loads((Path(a.base)/'package.json').read_text()))
    else:initialize(a.base,a.var,a.user)
