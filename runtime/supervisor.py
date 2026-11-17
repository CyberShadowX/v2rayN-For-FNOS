"""Root lifecycle supervisor; web and both native desktop programs run unprivileged."""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import importlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime,timezone

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from runtime import updater
from runtime.init_state import initialize


def atom_json(path, value):
    temp=path.with_suffix('.new')
    with temp.open('w',encoding='utf-8') as f:
        json.dump(value,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
    temp.chmod(0o600);temp.replace(path)


def copy_profile(source,destination):
    """Copy persistent profile data, excluding stale IPC endpoints left on disk."""
    def ignore_ipc(directory,names):
        ignored=[]
        for name in names:
            mode=(Path(directory)/name).lstat().st_mode
            if stat.S_ISSOCK(mode) or stat.S_ISFIFO(mode):ignored.append(name)
        return ignored
    return shutil.copytree(source,destination,symlinks=True,ignore=ignore_ipc)


class Supervisor:
    def __init__(self,base,var,user):
        self.base=Path(base).resolve();self.var=Path(var).resolve();self.user=user
        self.account=pwd.getpwnam(user)
        self.meta=json.loads((self.base/'package.json').read_text())
        self.app=self.meta['app'];self.adapter=importlib.import_module('adapters.'+self.app)
        from runtime.credentials import recover_pending
        recover_pending(self.var,self.app)
        self.ui=self.var/'ui';self.profile=self.var/'p';self.private=self.var/'private'
        self.lock=threading.RLock();self.processes={};self.network=None;self.updating=False;self.closing=threading.Event();self.message='原生应用已启动';self.last_update=None;self.network_operation=None
        self.current_file=self.private/'current.json'
        transaction=self.private/'transaction.json'
        if transaction.exists():
            recovery=json.loads(transaction.read_text())
            snapshot=Path(recovery['profile'])
            if snapshot.parent!=self.private or not snapshot.is_dir() or snapshot.is_symlink():
                raise ValueError('Invalid interrupted-update recovery snapshot')
            self.restore_profile(snapshot)
            atom_json(self.current_file,recovery['release'])
            transaction.unlink()
        self.current=json.loads(self.current_file.read_text()) if self.current_file.exists() else {'path':str(self.base/'payload'),'version':self.meta['upstream_version']}
        self.env=os.environ.copy()
        self.env.update({'HOME':str(self.profile),'USER':user,'LOGNAME':user,'DISPLAY':':'+str(self.meta['display']),
                         'XAUTHORITY':str(self.ui/'Xauthority'),'XDG_RUNTIME_DIR':str(self.profile/'runtime'),
                         'LIBGL_ALWAYS_SOFTWARE':'1','GDK_BACKEND':'x11','NO_AT_BRIDGE':'1','LANG':'C.UTF-8'})
        self.env.update(self.adapter.launch_environment(self.profile))
        for key in ('XDG_RUNTIME_DIR','XDG_CONFIG_HOME','XDG_CACHE_HOME','XDG_DATA_HOME'):
            self.as_user(['python3','-c','import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.mkdir(parents=True,exist_ok=True,mode=0o700)',self.env[key]])

    def as_user(self,args,**kwargs):
        return subprocess.run(['runuser','-u',self.user,'--preserve-environment','--',*map(str,args)],env=self.env,check=True,**kwargs)

    def spawn(self,name,args):
        fd=os.open(self.var/'logs'/f'{name}.log',os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):os.close(fd);raise ValueError('Unsafe log destination')
        log=os.fdopen(fd,'ab')
        process=subprocess.Popen(['runuser','-u',self.user,'--preserve-environment','--',*map(str,args)],env=self.env,stdout=log,stderr=log,start_new_session=True)
        log.close();self.processes[name]=process;return process

    def stop_process(self,name):
        process=self.processes.get(name)
        if process is None:return
        def living_group():
            for entry in Path('/proc').iterdir():
                if not entry.name.isdigit():continue
                try:
                    fields=(entry/'stat').read_text().rsplit(')',1)[1].split()
                    if int(fields[2])==process.pid and fields[0]!='Z':return True
                except (OSError,ValueError,IndexError):continue
            return False
        try:os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        until=time.monotonic()+15
        while living_group() and time.monotonic()<until:time.sleep(.1)
        if living_group():
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            until=time.monotonic()+5
            while living_group() and time.monotonic()<until:time.sleep(.1)
        if living_group():raise RuntimeError('Desktop process group did not exit; refusing to modify its profile')
        process.wait(timeout=5)
        self.processes.pop(name,None)

    def seed_profile(self):
        code='import sys;sys.path.insert(0,sys.argv[1]);from adapters import '+self.app+' as a;'
        if self.app=='v2rayn':code+='a.configure_profile(sys.argv[2])'
        else:code+='\ntry:a.initialize_profile(sys.argv[2])\nexcept FileExistsError:pass'
        self.as_user(['python3','-c',code,self.base,self.profile])

    def start_desktop(self):
        command=self.adapter.launch_command(self.current['path'],self.profile)
        self.spawn('desktop',['dbus-run-session','--','python3',self.base/'runtime/desktop.py','--command',json.dumps(command),'--state',self.ui])

    def start(self):
        self.seed_profile()
        auth=self.ui/'Xauthority'
        self.as_user(['python3','-c','import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.unlink(missing_ok=True);p.touch(mode=0o600)',auth])
        self.as_user(['xauth','-f',auth,'add',self.env['DISPLAY'],'.',secrets.token_hex(16)],stdout=subprocess.DEVNULL)
        self.spawn('xvfb',['Xvfb',self.env['DISPLAY'],'-screen','0','1440x900x24','-nolisten','tcp','-auth',auth])
        for _ in range(80):
            try:self.as_user(['xdpyinfo'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);break
            except subprocess.CalledProcessError:time.sleep(.1)
        else:raise RuntimeError('Virtual desktop did not start')
        vnc_password=json.loads((self.ui/'portal.json').read_text())['vnc_password']
        self.as_user(['x11vnc','-storepasswd',vnc_password,str(self.ui/'vnc.pass')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.spawn('vnc',['x11vnc','-display',self.env['DISPLAY'],'-auth',auth,'-rfbport',str(self.meta['vnc_port']),'-localhost','-rfbauth',self.ui/'vnc.pass','-forever','-shared','-noxdamage','-repeat'])
        self.start_desktop()
        self.spawn('portal',['python3',self.base/'runtime/portal.py','--state',self.ui,'--port',str(self.meta['port']),'--title',self.meta['title'],'--vnc-port',str(self.meta['vnc_port'])])

    def resume_network(self):
        try:enabled=json.loads((self.private/'network-enabled.json').read_text()).get('enabled')
        except (OSError,ValueError):enabled=False
        if not enabled:return
        for _ in range(60):
            if self.closing.wait(1):return
            if self.proxy_ready():
                with self.lock:
                    if self.closing.is_set():return
                    try:self.network_on()
                    except Exception:self.message='已启动客户端；网络接管未恢复，请检查节点后重新开启'
                return

    def status(self):
        gui=False
        try:
            pid=int((self.ui/'gui.pid').read_text())
            executable=Path(f'/proc/{pid}/exe').resolve()
            gui=(Path(f'/proc/{pid}').stat().st_uid==self.account.pw_uid and executable==Path(self.adapter.launch_command(self.current['path'],self.profile)[0]).resolve())
        except (OSError,ValueError):pass
        ns=self.network_controller().status()
        phase=getattr(self,'network_operation',None) or ns.get('phase','unknown')
        owner=ns.get('owner',ns.get('network_owner')) if (ns.get('active') or ns.get('needs_recovery') or ns.get('phase')=='starting') else None
        message=self.message
        if owner and owner!=self.app and ('直连已恢复' in message or message=='本机与 Docker 网络接管已启动'):
            message='当前由 '+('v2rayN' if owner=='v2rayn' else 'Clash Verge Rev')+' 接管网络，本应用保持待命'
        return {'app':self.app,'title':self.meta['title'],'version':self.current['version'],'gui_running':gui,
                'network_active':bool(ns.get('running',ns.get('active',False)) and ns.get('owned',owner==self.app)),'network_owner':owner,
                'network_phase':phase,'network_cleanup_verified':bool(ns.get('cleanup_verified',False)),
                'network_needs_recovery':bool(ns.get('needs_recovery',False)),'network_error':ns.get('last_error'),
                'updating':self.updating,'message':message,'last_update':self.last_update}

    def network_controller(self):
        from runtime.network import NetworkController
        if self.network is None:
            # GUI bundles can contain older kernels incompatible with this NAS.
            # This separately verified helper is updated in the same transaction.
            binary=Path(self.network_release()['path'])
            uids=[]
            for name in ('fnv2rayn','fnclash'):
                try:uids.append(pwd.getpwnam(name).pw_uid)
                except KeyError:pass
            self.network=NetworkController(self.app,self.private/'network',binary,self.meta['socks_port'],excluded_uids=tuple(uids))
        return self.network

    def network_release(self):
        return self.current.get('network_core') or {
            'path':str(self.base/'network-core'/'mihomo'),
            'version':self.meta.get('network_core_version',''),
            'sha256':self.meta.get('network_core_sha256','')}

    def network_on(self):
        controller=self.network_controller()
        state=controller.status()
        if state.get('active') and state.get('owned'):return self.status()
        # A second client may have been installed since this process started.
        # Rebuild an inactive controller so both current GUI UIDs are excluded.
        self.network_operation='starting'
        try:
            self.network=None
            self.network_controller().start()
            atom_json(self.private/'network-enabled.json',{'enabled':True})
            self.message='本机与 Docker 网络接管已启动'
        finally:self.network_operation=None
        return self.status()

    def network_off(self,preserve=False):
        self.network_operation='stopping'
        try:
            controller=self.network_controller()
            if controller.status().get('owned'):controller.stop()
            if not preserve:atom_json(self.private/'network-enabled.json',{'enabled':False})
            self.message='本应用的网络接管已关闭'
        finally:self.network_operation=None
        return self.status()

    def check_update(self):
        from adapters import mihomo
        asset=updater.latest(self.adapter,self.meta['socks_port'])
        helper=updater.latest(mihomo,self.meta['socks_port'])
        core_version=self.network_release()['version']
        core_available=helper['version']!=core_version
        return {'current':self.current['version'],'latest':asset['version'],
                'available':asset['version']!=self.current['version'] or core_available,
                'network_available':core_available,'network_current':core_version,'network_latest':helper['version']}

    def sync_v2rayn_bin(self):
        if self.app!='v2rayn':return
        target=self.profile/'v2rayN'/'bin'
        if target.parent.is_symlink() or not target.parent.resolve().is_relative_to(self.profile):raise ValueError('Unsafe profile layout')
        code='import pathlib,shutil,sys;t=pathlib.Path(sys.argv[2]);t.unlink() if t.is_symlink() else (shutil.rmtree(t) if t.exists() else None);shutil.copytree(sys.argv[1],t)'
        self.as_user(['python3','-c',code,Path(self.current['path'])/'bin',target])

    def restore_profile(self,snapshot):
        snapshot=Path(snapshot)
        if snapshot.parent!=self.private or snapshot.is_symlink():raise ValueError('Unsafe profile snapshot')
        stage=self.private/('restore-'+secrets.token_hex(8))
        copy_profile(snapshot,stage)
        # This tree is still under root-private storage. Package processes cannot
        # replace an ancestor while ownership is assigned before atomic publish.
        for directory,dirs,files in os.walk(stage,followlinks=False):
            os.chown(directory,self.account.pw_uid,self.account.pw_gid,follow_symlinks=False)
            for n in dirs+files:os.chown(Path(directory)/n,self.account.pw_uid,self.account.pw_gid,follow_symlinks=False)
        old=self.private/('discarded-'+secrets.token_hex(8))
        had_profile=self.profile.exists()
        if self.profile.is_symlink():raise ValueError('Profile root cannot be a symlink')
        if had_profile:self.profile.rename(old)
        try:stage.rename(self.profile)
        except BaseException:
            if had_profile:old.rename(self.profile)
            raise
        if had_profile:shutil.rmtree(old)

    def proxy_ready(self):
        try:
            with socket.create_connection(('127.0.0.1',self.meta['socks_port']),timeout=2) as connection:
                connection.sendall(b'\x05\x01\x00');return connection.recv(2)==b'\x05\x00'
        except OSError:return False

    def transaction(self,target,apply_changes):
        """Quiesce, snapshot, journal, apply, verify; every failure recovers or reports recovery failure."""
        old=self.current.copy();was_active=self.status()['network_active'];require_proxy=self.proxy_ready()
        backup=None;changed=False
        try:
            self.network_off(preserve=True);self.stop_process('desktop')
        except Exception as error:
            self.message='操作准备未完成；配置未更改，请检查客户端和网络接管状态'
            raise RuntimeError(self.message) from error
        try:
            backup=self.private/('profile-backup-'+str(time.time_ns()))
            copy_profile(self.profile,backup)
            atom_json(self.private/'transaction.json',{'release':old,'profile':str(backup),'network':was_active})
            self.current=dict(target);self.network=None;changed=True;apply_changes()
            self.start_desktop();self.verify_desktop(require_proxy=require_proxy)
            if self.closing.is_set():raise RuntimeError('Application is stopping')
            if was_active:self.network_on()
            self.current['previous']={'release':old,'profile':str(backup)}
            atom_json(self.current_file,self.current)
            (self.private/'transaction.json').unlink()
        except Exception as failure:
            try:
                self.network_off(preserve=True);self.stop_process('desktop')
                if changed and backup:self.restore_profile(backup)
                self.current=old;self.network=None;atom_json(self.current_file,old)
                self.start_desktop();self.verify_desktop(require_proxy=require_proxy)
                if was_active and not self.closing.is_set():self.network_on()
                (self.private/'transaction.json').unlink(missing_ok=True)
            except Exception as recovery:
                self.message='操作失败，自动恢复未完成；保留恢复快照，网络接管保持关闭'
                raise RuntimeError('Operation failed and recovery failed: '+str(recovery)[:180]) from failure
            raise RuntimeError('操作失败，旧程序及配置已恢复：'+str(failure)[:180]) from failure

    def update_job(self,force=False):
        try:
            self.message='正在下载并校验官方上游发行包'
            # Long downloads never hold the mutation lock: the independent
            # two-second network recovery monitor must remain able to run.
            staged=updater.stage(self.adapter,self.var/'releases',self.meta['socks_port'],cancel=self.closing,compatibility_dir=self.base/'compat')
            with self.lock:
                if (staged['version']==self.current['version']
                        and staged['network_core']['version']==self.network_release()['version'] and not force):
                    shutil.rmtree(Path(staged['path']).parent);self.message='当前已是上游最新稳定版';return
                if self.closing.is_set():raise RuntimeError('Application is stopping')
                self.transaction(staged,self.sync_v2rayn_bin)
                self.message='上游程序、内核和资源更新完成，用户配置已保留';self.last_update={'success':True,'version':self.current['version'],'network_version':self.network_release()['version'],'finished_at':datetime.now(timezone.utc).isoformat()}
        except Exception as error:
            # Download failures have made no changes and do not stop a healthy desktop.
            self.message=str(error)[:300] if '恢复' in str(error) else '更新未完成，当前版本未切换：'+str(error)[:240]
            self.last_update={'success':False,'error':str(error)[:300],'finished_at':datetime.now(timezone.utc).isoformat()}
        finally:self.updating=False

    def verify_desktop(self,require_proxy=False):
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            if self.status()['gui_running']:
                time.sleep(4)
                if self.status()['gui_running'] and (not require_proxy or self.proxy_ready()):return
            time.sleep(.5)
        raise RuntimeError('Updated desktop failed startup health check')

    def rollback(self):
        previous=self.current.get('previous')
        if not previous:raise ValueError('没有可回滚版本')
        snapshot=Path(previous['profile'])
        if snapshot.parent!=self.private or snapshot.is_symlink() or not snapshot.is_dir():raise ValueError('Invalid rollback snapshot')
        self.transaction(previous['release'],lambda:self.restore_profile(snapshot))
        self.message='已回滚到上一个版本和配置';return self.status()

    def import_nodes(self,request):
        content=request.get('content','')
        if not isinstance(content,str) or not 0<len(content.encode())<=1024*1024:raise ValueError('导入内容为空或超过限制')
        fmt=request.get('format','share-links' if self.app=='v2rayn' else 'clash')
        if self.app=='v2rayn':
            if fmt not in ('share-links','vless'):raise ValueError('此客户端需要节点分享链接，请在原版客户端中导入其他配置格式')
            links=[line.strip() for line in content.splitlines() if line.strip()]
            if not links or any(not re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://\S',line) for line in links):
                raise ValueError('请填写节点分享链接，每行一条；不要在此粘贴 YAML 配置')
            self.as_user(['xclip','-selection','clipboard'],input=content.encode(),stdout=subprocess.DEVNULL)
            p=self.as_user(['xdotool','search','--name','v2rayN'],capture_output=True,text=True)
            window=p.stdout.splitlines()[0]
            self.as_user(['xdotool','windowactivate','--sync',window])
            self.as_user(['xdotool','key','--clearmodifiers','ctrl+v'])
            self.message='节点链接已发送至 v2rayN，请在原版窗口确认导入结果';return {**self.status(),'format':'share-links'}
        if fmt!='clash':raise ValueError('此客户端需要 Clash / Mihomo YAML 配置')
        import yaml
        try:data=yaml.safe_load(content)
        except yaml.YAMLError as error:
            mark=getattr(error,'problem_mark',None)
            location=f'（第 {mark.line+1} 行）' if mark is not None else ''
            raise ValueError('YAML 配置格式不正确'+location+'，请检查缩进和内容') from None
        if not isinstance(data,dict) or not isinstance(data.get('proxies'),list):raise ValueError('需要含 proxies 列表的 Mihomo YAML 配置')
        selected={k:data[k] for k in ('proxies','proxy-groups','rules','proxy-providers','rule-providers') if k in data}
        selected.update({'mixed-port':self.meta['socks_port'],'allow-lan':False,'tun':{'enable':False}})
        paths=self.adapter.profile_paths(self.profile);folder=Path(paths['profiles']);index=Path(paths['profiles_index'])
        for path in (folder,index):
            if path.is_symlink() or not path.resolve().is_relative_to(self.profile):raise ValueError('Unsafe profile import path')
        def apply_import():
            script='import sys,json,pathlib,yaml,secrets,time;d=json.load(sys.stdin);index=pathlib.Path(d["index"]);v=yaml.safe_load(index.read_text()) or {};uid="nas-"+secrets.token_hex(6);p=pathlib.Path(d["folder"])/(uid+".yaml");p.write_text(yaml.safe_dump(d["profile"],allow_unicode=True));p.chmod(0o600);v.setdefault("items",[]).append({"uid":uid,"type":"local","name":"NAS 节点","file":p.name,"updated":int(time.time())});v["current"]=uid;index.write_text(yaml.safe_dump(v,allow_unicode=True))'
            self.as_user(['python3','-c',script],input=json.dumps({'folder':str(folder),'index':str(index),'profile':selected}).encode(),stdout=subprocess.DEVNULL)
        self.transaction(self.current,apply_import)
        self.message='Mihomo 配置已导入原生客户端';return self.status()

    def action(self,request):
        action=request.get('action')
        if action=='status':return self.status()
        if action=='check_update':return self.check_update()
        with self.lock:
            if self.closing.is_set():raise ValueError('应用正在停止')
            if self.updating:raise ValueError('更新进行中，请稍后操作')
            if action=='change_password':
                from runtime.credentials import change_password
                return change_password(self.var,self.app,request.get('current_password'),request.get('new_password'),expected_revision=request.get('expected_revision'))
            if action=='update':
                self.updating=True;threading.Thread(target=self.update_job,args=(bool(request.get('force',False)),)).start();return {'updating':True,'message':'已开始更新'}
            if action=='restart':
                was=self.status()['network_active']
                try:
                    self.network_off(preserve=True);self.stop_process('desktop');self.start_desktop()
                    self.verify_desktop(require_proxy=was)
                    if self.closing.is_set():raise RuntimeError('Application is stopping')
                    if was:self.network_on()
                except Exception as error:
                    self.message='客户端重启未完成，请检查客户端和网络接管状态：'+str(error)[:180]
                    raise RuntimeError(self.message) from error
                self.message='客户端已重启，网络接管已恢复' if was else '客户端已重启'
                return self.status()
            if action=='network_on':return self.network_on()
            if action=='network_off':return self.network_off()
            if action=='rollback':return self.rollback()
            if action=='import':return self.import_nodes(request)
            raise ValueError('Unknown control action')

    async def control(self,reader,writer):
        try:
            peer=writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)
            _,uid,_=struct.unpack('3i',peer)
            if uid not in (0,self.account.pw_uid):raise PermissionError('Unauthorized local control peer')
            raw=await asyncio.wait_for(reader.readline(),timeout=15)
            request=json.loads(raw)
            if not isinstance(request,dict):raise ValueError('Invalid request')
            response=await asyncio.to_thread(self.action,request)
        except Exception as e:response={'ok':False,'error':str(e)[:400]}
        writer.write((json.dumps(response,ensure_ascii=False)+'\n').encode());await writer.drain();writer.close();await writer.wait_closed()

    def maintain_network(self):
        if not self.lock.acquire(blocking=False):return
        try:
            result=self.network_controller().maintain()
            if result.get('phase')=='error':
                self.message=('网络接管已停止，直连已恢复：' if result.get('cleanup_verified') else '网络恢复未完成：')+str(result.get('last_error',''))[:150]
            elif result.get('recovered') and result.get('cleanup_verified'):
                self.message='网络接管已停止，直连已恢复'
        except Exception as error:self.message='网络恢复未完成：'+str(error)[:180]
        finally:self.lock.release()

    async def network_watch(self):
        while not self.closing.is_set():
            await asyncio.to_thread(self.maintain_network)
            await asyncio.sleep(2)

    def shutdown_ack(self,clean):
        starttime=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
        atom_json(self.private/'clean-shutdown.json',{'pid':os.getpid(),'starttime':starttime,'clean':bool(clean)})

    def shutdown_resources(self,path,errors=()):
        # Wait for any active mutation before cleanup and receipt publication.
        # Acquisition and release run on the same worker, never the event loop.
        errors=list(errors)
        with self.lock:
            try:self.network_off(preserve=True)
            except Exception as error:errors.append(error)
            for name in reversed(list(self.processes)):
                try:self.stop_process(name)
                except Exception as error:errors.append(error)
            try:path.unlink(missing_ok=True)
            except Exception as error:errors.append(error)
            self.shutdown_ack(not errors)
            if errors:raise RuntimeError('Shutdown cleanup incomplete: '+str(errors[0]))

    async def serve(self):
        path=self.var/'control'/'control.sock'
        server=None;watch=None;errors=[]
        stop=asyncio.Event();loop=asyncio.get_running_loop()
        for sig in (signal.SIGTERM,signal.SIGINT):loop.add_signal_handler(sig,stop.set)
        try:
            if path.exists():path.unlink()
            server=await asyncio.start_unix_server(self.control,path=path,limit=1024*1024+4096)
            path.chmod(0o660);os.chown(path,0,self.account.pw_gid)
            # Recover a dead predecessor before starting a desktop, regardless
            # of proxy readiness or the saved network enable preference.
            await asyncio.to_thread(self.maintain_network)
            self.start()
            watch=asyncio.create_task(self.network_watch())
            threading.Thread(target=self.resume_network,daemon=True).start()
            await stop.wait()
        finally:
            if server:server.close()
            self.closing.set()
            if watch:
                watch.cancel()
                try:await watch
                except asyncio.CancelledError:pass
            while self.updating:await asyncio.sleep(.2)
            if server:
                try:await server.wait_closed()
                except Exception as error:errors.append(error)
            await asyncio.to_thread(self.shutdown_resources,path,errors)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--base',required=True);p.add_argument('--var',required=True);p.add_argument('--user',required=True)
    a=p.parse_args();initialize(a.base,a.var,a.user)
    asyncio.run(Supervisor(a.base,a.var,a.user).serve())
