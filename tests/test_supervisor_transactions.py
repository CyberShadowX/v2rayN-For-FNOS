import json
import asyncio
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch,AsyncMock

try:import pwd
except ImportError:sys.modules.setdefault('pwd',types.SimpleNamespace())
from runtime.supervisor import Supervisor


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        s=self.s=Supervisor.__new__(Supervisor)
        root=Path(self.temp.name);s.base=root/'base';s.profile=root/'p';s.private=root/'private';s.profile.mkdir();s.private.mkdir()
        (s.profile/'nodes').write_text('original secret config')
        s.current={'path':'old-release','version':'1.0.0'};s.current_file=s.private/'current.json'
        s.closing=threading.Event();s.lock=threading.RLock();s.meta={'socks_port':10808};s.adapter=Mock();s.var=root
        s.network=None;s.updating=True;s.last_update=None;s.message='';s.account=types.SimpleNamespace(pw_uid=1,pw_gid=1)
        s.active=True;s.desktop=True
        s.status=Mock(side_effect=lambda:{'network_active':s.active,'gui_running':s.desktop})
        s.proxy_ready=Mock(return_value=True)
        s.network_off=Mock(side_effect=lambda **kw:setattr(s,'active',False))
        s.network_on=Mock(side_effect=lambda:setattr(s,'active',True))
        s.stop_process=Mock(side_effect=lambda *args:setattr(s,'desktop',False))
        s.start_desktop=Mock(side_effect=lambda:setattr(s,'desktop',True))
        s.verify_desktop=Mock();s.sync_v2rayn_bin=Mock()

    def restore(self,snapshot):
        if self.s.profile.exists():shutil.rmtree(self.s.profile)
        shutil.copytree(snapshot,self.s.profile)

    def test_download_failure_never_stops_healthy_program(self):
        with patch('runtime.supervisor.updater.stage',side_effect=OSError('unreachable')):
            self.s.update_job()
        self.s.network_off.assert_not_called();self.s.stop_process.assert_not_called()
        self.assertTrue(self.s.active);self.assertTrue(self.s.desktop);self.assertEqual(self.s.current['version'],'1.0.0')

    def test_helper_only_release_change_runs_complete_transaction(self):
        self.s.current['network_core']={'path':'old-helper','version':'1.19.34'}
        staged={'path':'new-gui','version':'1.0.0','network_core':{'path':'new-helper','version':'1.19.35'}}
        self.s.transaction=Mock()
        with patch('runtime.supervisor.updater.stage',return_value=staged):self.s.update_job()
        self.s.transaction.assert_called_once_with(staged,self.s.sync_v2rayn_bin)
        self.assertTrue(self.s.last_update['success'])

    def test_same_gui_and_helper_versions_do_not_stop_desktop(self):
        stage=self.s.var/'candidate';(stage/'payload').mkdir(parents=True)
        self.s.current['network_core']={'path':'old-helper','version':'1.19.34'}
        staged={'path':str(stage/'payload'),'version':'1.0.0','network_core':{'path':'new-helper','version':'1.19.34'}}
        self.s.transaction=Mock()
        with patch('runtime.supervisor.updater.stage',return_value=staged):self.s.update_job()
        self.s.transaction.assert_not_called();self.s.stop_process.assert_not_called()
        self.assertFalse(stage.exists())

    def test_failed_change_restores_config_and_network(self):
        self.s.current['network_core']={'path':'old-helper','version':'1.19.34'}
        self.s.restore_profile=Mock(side_effect=self.restore)
        def broken():
            (self.s.profile/'nodes').write_text('migrated');raise RuntimeError('new program failed')
        with self.assertRaisesRegex(RuntimeError,'旧程序及配置已恢复'):
            self.s.transaction({'path':'new','version':'2.0.0','network_core':{'path':'new-helper','version':'1.19.35'}},broken)
        self.assertEqual((self.s.profile/'nodes').read_text(),'original secret config')
        self.assertTrue(self.s.active);self.assertEqual(self.s.current['version'],'1.0.0')
        self.assertEqual(self.s.network_release(),{'path':'old-helper','version':'1.19.34'})
        self.assertFalse((self.s.private/'transaction.json').exists())

    def test_failed_rollback_preserves_pre_rollback_state(self):
        previous=self.s.private/'profile-old';previous.mkdir();(previous/'nodes').write_text('older')
        self.s.current['previous']={'release':{'path':'older','version':'0.9.0'},'profile':str(previous)}
        calls=[]
        def fail_once(snapshot):
            calls.append(snapshot)
            if len(calls)==1:raise OSError('disk error')
            self.restore(snapshot)
        self.s.restore_profile=Mock(side_effect=fail_once)
        with self.assertRaisesRegex(RuntimeError,'旧程序及配置已恢复'):self.s.rollback()
        self.assertEqual((self.s.profile/'nodes').read_text(),'original secret config');self.assertTrue(self.s.active)
        self.assertEqual(self.s.current['version'],'1.0.0')

    def test_failed_network_restore_is_reported_and_journal_retained(self):
        self.s.restore_profile=Mock(side_effect=self.restore)
        self.s.network_on.side_effect=OSError('network unavailable')
        with self.assertRaisesRegex(RuntimeError,'recovery failed'):
            self.s.transaction({'path':'new','version':'2.0.0'},lambda:None)
        self.assertFalse(self.s.active);self.assertTrue((self.s.private/'transaction.json').exists())
        self.assertEqual(json.loads(self.s.current_file.read_text())['version'],'1.0.0')

    def test_restore_after_crash_between_profile_renames(self):
        snapshot=self.s.private/'profile-backup-test';shutil.copytree(self.s.profile,snapshot)
        shutil.rmtree(self.s.profile)
        with patch('os.chown',create=True):Supervisor.restore_profile(self.s,snapshot)
        self.assertEqual((self.s.profile/'nodes').read_text(),'original secret config')

    def test_snapshot_failure_keeps_original_profile(self):
        with patch('runtime.supervisor.shutil.copytree',side_effect=OSError('disk full')):
            with self.assertRaisesRegex(RuntimeError,'旧程序及配置已恢复'):
                self.s.transaction({'path':'new','version':'2.0.0'},lambda:None)
        self.assertTrue(self.s.active);self.assertTrue(self.s.desktop)
        self.assertEqual((self.s.profile/'nodes').read_text(),'original secret config')

    @unittest.skipUnless(os.name=='posix','Requires POSIX socket, FIFO and symlink support')
    def test_transaction_snapshots_nested_ipc_without_losing_config_or_symlinks(self):
        nested=self.s.profile/'data';nested.mkdir()
        config=nested/'verge-mihomo.sock.config';config.write_text('persistent config')
        (nested/'config-link').symlink_to(config.name)
        (nested/'dangling-link').symlink_to('not-present')
        (nested/'socket-link').symlink_to('verge-mihomo.sock')
        os.mkfifo(nested/'control.fifo')
        with socket.socket(socket.AF_UNIX) as endpoint:
            endpoint.bind(str(nested/'verge-mihomo.sock'))
            self.s.transaction({'path':'new','version':'2.0.0'},lambda:None)
        snapshot=Path(self.s.current['previous']['profile'])
        self.assertEqual((snapshot/'nodes').read_text(),'original secret config')
        self.assertEqual((snapshot/'data'/config.name).read_text(),'persistent config')
        self.assertEqual(os.readlink(snapshot/'data'/'config-link'),config.name)
        self.assertEqual(os.readlink(snapshot/'data'/'dangling-link'),'not-present')
        self.assertEqual(os.readlink(snapshot/'data'/'socket-link'),'verge-mihomo.sock')
        self.assertFalse((snapshot/'data'/'control.fifo').exists())
        self.assertFalse((snapshot/'data'/'verge-mihomo.sock').exists())
        self.assertTrue((nested/'control.fifo').exists())
        self.assertTrue((nested/'verge-mihomo.sock').exists())
        self.assertTrue(self.s.active);self.assertTrue(self.s.desktop)

    @unittest.skipUnless(os.name=='posix','Requires POSIX socket, FIFO and symlink support')
    def test_restore_legacy_snapshot_with_ipc_preserves_files_and_links(self):
        snapshot=self.s.private/'profile-backup-legacy';snapshot.mkdir()
        nested=snapshot/'runtime';nested.mkdir()
        (snapshot/'nodes').write_text('previous config')
        (nested/'file').write_text('nested config')
        (nested/'link').symlink_to('file')
        os.mkfifo(nested/'old.fifo')
        with socket.socket(socket.AF_UNIX) as endpoint:
            endpoint.bind(str(nested/'old.sock'))
            with patch('os.chown',create=True):Supervisor.restore_profile(self.s,snapshot)
        self.assertEqual((self.s.profile/'nodes').read_text(),'previous config')
        self.assertEqual((self.s.profile/'runtime'/'file').read_text(),'nested config')
        self.assertEqual(os.readlink(self.s.profile/'runtime'/'link'),'file')
        self.assertFalse((self.s.profile/'runtime'/'old.fifo').exists())
        self.assertFalse((self.s.profile/'runtime'/'old.sock').exists())

    def test_partial_startup_failure_cleans_all_groups_and_ipc(self):
        s=self.s;s.updating=False;s.processes={'xvfb':Mock(),'desktop':Mock()}
        (s.var/'control').mkdir()
        s.start=Mock(side_effect=RuntimeError('VNC startup failed'))
        s.shutdown_ack=Mock()
        s.stop_process=Mock(side_effect=[RuntimeError('first stop failed'),None])
        server=Mock();server.wait_closed=AsyncMock()
        async def bind(*args,**kwargs):Path(kwargs['path']).touch();return server
        async def exercise():
            with patch.object(asyncio.get_running_loop(),'add_signal_handler'),patch('asyncio.start_unix_server',side_effect=bind,create=True),patch('os.chown',create=True):
                with self.assertRaisesRegex(RuntimeError,'Shutdown cleanup incomplete'):await s.serve()
        asyncio.run(exercise())
        self.assertEqual(s.stop_process.call_count,2);s.network_off.assert_called_once()
        server.close.assert_called_once();server.wait_closed.assert_awaited_once()
        self.assertFalse((s.var/'control'/'control.sock').exists())
        s.shutdown_ack.assert_called_once_with(False)

    def test_guardian_recovery_runs_without_existing_controller_or_proxy(self):
        self.s.network=None
        controller=Mock();controller.maintain.return_value={'phase':'stopped','cleanup_verified':True}
        self.s.network_controller=Mock(return_value=controller)
        self.s.maintain_network()
        controller.maintain.assert_called_once();self.s.proxy_ready.assert_not_called()

    def test_long_download_does_not_block_recovery_watchdog(self):
        entered=threading.Event();release=threading.Event()
        controller=Mock();controller.maintain.return_value={'phase':'stopped','cleanup_verified':True}
        self.s.network_controller=Mock(return_value=controller)
        def downloading(*args,**kwargs):
            entered.set();release.wait(timeout=4);raise OSError('cancelled test download')
        with patch('runtime.supervisor.updater.stage',side_effect=downloading):
            thread=threading.Thread(target=self.s.update_job);thread.start()
            try:
                self.assertTrue(entered.wait(timeout=2))
                for _ in range(3):self.s.maintain_network()
                self.assertEqual(controller.maintain.call_count,3)
            finally:release.set();thread.join(timeout=3)
            self.assertFalse(thread.is_alive())

    def test_other_client_owner_is_not_this_clients_active_network(self):
        self.s.ui=self.s.profile;self.s.app='v2rayn';self.s.meta['title']='test'
        self.s.network=Mock();self.s.network.status.return_value={'active':True,'owned':False,'owner':'clash'}
        result=Supervisor.status(self.s)
        self.assertFalse(result['network_active']);self.assertEqual(result['network_owner'],'clash')

    def test_stopped_journal_is_not_reported_as_an_active_owner(self):
        self.s.ui=self.s.profile;self.s.app='v2rayn';self.s.meta['title']='test'
        self.s.network=Mock();self.s.network.status.return_value={'active':False,'owned':False,'owner':'clash','phase':'stopped','cleanup_verified':True}
        result=Supervisor.status(self.s)
        self.assertFalse(result['network_active']);self.assertIsNone(result['network_owner'])

    def test_verified_error_cleanup_reports_direct_network_restored(self):
        controller=Mock();controller.maintain.return_value={'phase':'error','cleanup_verified':True,'last_error':'proxy stopped'}
        self.s.network_controller=Mock(return_value=controller);self.s.maintain_network()
        self.assertIn('直连已恢复',self.s.message);self.assertNotIn('恢复未完成',self.s.message)

    def test_restart_waits_for_delayed_proxy_before_restoring_active_network(self):
        s=self.s;s.updating=False;events=[];clock=[0.0]
        preference=s.private/'network-enabled.json';preference.write_text('{"enabled": true}')
        s.network=Mock();s.network.status.return_value={'owned':True}
        s.network.stop.side_effect=lambda:setattr(s,'active',False)
        def off(**kwargs):
            events.append(('off',kwargs));return Supervisor.network_off(s,**kwargs)
        def stop(name):events.append(('stop',name));s.desktop=False
        def start():events.append(('start',));s.desktop=True
        def verify(**kwargs):
            events.append(('verify',kwargs));return Supervisor.verify_desktop(s,**kwargs)
        def ready():
            value=clock[0]>=9;events.append(('proxy',value));return value
        def on():
            self.assertGreaterEqual(clock[0],9);events.append(('on',));s.active=True
        s.network_off.side_effect=off;s.stop_process.side_effect=stop;s.start_desktop.side_effect=start
        s.verify_desktop.side_effect=verify;s.proxy_ready.side_effect=ready;s.network_on.side_effect=on
        with patch('runtime.supervisor.time.monotonic',side_effect=lambda:clock[0]), \
             patch('runtime.supervisor.time.sleep',side_effect=lambda seconds:clock.__setitem__(0,clock[0]+seconds)):
            result=s.action({'action':'restart'})
        self.assertEqual(events,[('off',{'preserve':True}),('stop','desktop'),('start',),
                                 ('verify',{'require_proxy':True}),('proxy',False),('proxy',False),('proxy',True),('on',)])
        self.assertTrue(result['network_active']);self.assertTrue(json.loads(preference.read_text())['enabled'])
        self.assertIn('网络接管已恢复',s.message)

    def test_restart_proxy_timeout_leaves_network_off_and_preserves_enabled_preference(self):
        s=self.s;s.updating=False;clock=[0.0]
        preference=s.private/'network-enabled.json';preference.write_text('{"enabled": true}')
        s.network=Mock();s.network.status.return_value={'owned':True}
        s.network.stop.side_effect=lambda:setattr(s,'active',False)
        s.network_off.side_effect=lambda **kwargs:Supervisor.network_off(s,**kwargs)
        s.verify_desktop.side_effect=lambda **kwargs:Supervisor.verify_desktop(s,**kwargs)
        s.proxy_ready.return_value=False
        with patch('runtime.supervisor.time.monotonic',side_effect=lambda:clock[0]), \
             patch('runtime.supervisor.time.sleep',side_effect=lambda seconds:clock.__setitem__(0,clock[0]+seconds)):
            with self.assertRaisesRegex(RuntimeError,'客户端重启未完成'):s.action({'action':'restart'})
        s.network_on.assert_not_called();self.assertFalse(s.active)
        self.assertTrue(json.loads(preference.read_text())['enabled'])
        self.assertIn('startup health check',s.message)
        self.assertGreaterEqual(clock[0],60);self.assertLessEqual(clock[0],65)

    def test_restart_desktop_start_failure_reports_error_without_reactivating_network(self):
        s=self.s;s.updating=False
        preference=s.private/'network-enabled.json';preference.write_text('{"enabled": true}')
        s.network=Mock();s.network.status.return_value={'owned':True}
        s.network.stop.side_effect=lambda:setattr(s,'active',False)
        s.network_off.side_effect=lambda **kwargs:Supervisor.network_off(s,**kwargs)
        s.start_desktop.side_effect=RuntimeError('desktop spawn failed')
        with self.assertRaisesRegex(RuntimeError,'客户端重启未完成'):s.action({'action':'restart'})
        s.verify_desktop.assert_not_called();s.network_on.assert_not_called()
        self.assertFalse(s.active);self.assertFalse(s.desktop)
        self.assertTrue(json.loads(preference.read_text())['enabled'])
        self.assertIn('desktop spawn failed',s.message)

    def test_restart_inactive_client_does_not_stop_or_claim_foreign_network_owner(self):
        s=self.s;s.updating=False;s.active=False
        preference=s.private/'network-enabled.json';preference.write_text('{"enabled": false}')
        s.network=Mock();s.network.status.return_value={'owned':False,'active':True,'owner':'clash'}
        s.network_off.side_effect=lambda **kwargs:Supervisor.network_off(s,**kwargs)
        s.status.side_effect=lambda:{'network_active':s.active,'gui_running':s.desktop,'network_owner':'clash'}
        result=s.action({'action':'restart'})
        s.network.stop.assert_not_called();s.network_on.assert_not_called()
        s.verify_desktop.assert_called_once_with(require_proxy=False)
        self.assertEqual(result['network_owner'],'clash');self.assertFalse(result['network_active'])
        self.assertFalse(json.loads(preference.read_text())['enabled'])

    def test_shutdown_waits_for_inflight_restart_before_cleanup_and_clean_receipt(self):
        s=self.s;s.updating=False;s.active=False;s.processes={}
        (s.var/'control').mkdir()
        removed=threading.Event();release=threading.Event();teardown_entered=threading.Event()
        events=[];action_errors=[];receipt=s.private/'clean-shutdown.json'
        s.maintain_network=Mock();s.resume_network=Mock()
        def stop(name):
            generation=s.processes.pop(name,None)
            if generation is None:return
            events.append('stop-'+generation);s.desktop=False
            if generation=='old':
                removed.set()
                if not release.wait(5):raise RuntimeError('Test restart was not released')
        def start_desktop():
            s.processes['desktop']='new';s.desktop=True;events.append('start-new')
        def acknowledge(clean):
            events.append('receipt')
            receipt.write_text(json.dumps({'clean':clean,'processes':dict(s.processes),'thread':threading.get_ident()}))
        def restart():
            try:s.action({'action':'restart'})
            except Exception as error:action_errors.append(error)
        # Wrap a real RLock so the event records the teardown's lock attempt,
        # rather than relying on sleeps or assuming a worker has been scheduled.
        actual_lock=s.lock;shutdown_thread=[None]
        class ObservedLock:
            def __enter__(self):
                if threading.get_ident()==shutdown_thread[0]:teardown_entered.set()
                return actual_lock.__enter__()
            def __exit__(self,*args):return actual_lock.__exit__(*args)
        s.lock=ObservedLock()
        shutdown=s.shutdown_resources
        def observed_shutdown(*args):
            shutdown_thread[0]=threading.get_ident();return shutdown(*args)
        s.stop_process.side_effect=stop;s.start_desktop.side_effect=start_desktop
        s.shutdown_ack=Mock(side_effect=acknowledge)
        s.shutdown_resources=Mock(side_effect=observed_shutdown)
        server=Mock();server.wait_closed=AsyncMock()
        async def bind(*args,**kwargs):Path(kwargs['path']).touch();return server
        async def exercise():
            started=asyncio.Event();callbacks={};loop_thread=threading.get_ident()
            def start():s.processes['desktop']='old';started.set()
            s.start=Mock(side_effect=start)
            loop=asyncio.get_running_loop()
            with patch.object(loop,'add_signal_handler',side_effect=lambda sig,callback:callbacks.__setitem__(sig,callback)), \
                 patch('asyncio.start_unix_server',side_effect=bind,create=True),patch('os.chown',create=True):
                serving=asyncio.create_task(s.serve());action=threading.Thread(target=restart,daemon=True)
                try:
                    await asyncio.wait_for(started.wait(),2)
                    action.start()
                    self.assertTrue(await asyncio.to_thread(removed.wait,2))
                    callbacks[next(iter(callbacks))]()
                    self.assertTrue(await asyncio.to_thread(teardown_entered.wait,2))
                    self.assertTrue(s.closing.is_set());self.assertFalse(serving.done())
                    self.assertFalse(receipt.exists());s.shutdown_ack.assert_not_called()
                finally:
                    release.set()
                    if action.ident is not None:await asyncio.to_thread(action.join,2)
                    if callbacks:callbacks[next(iter(callbacks))]()
                    await asyncio.wait_for(serving,3)
                self.assertFalse(action.is_alive())
                saved=json.loads(receipt.read_text())
                self.assertTrue(saved['clean']);self.assertEqual(saved['processes'],{})
                self.assertNotEqual(saved['thread'],loop_thread)
        asyncio.run(exercise())
        self.assertEqual(events,['stop-old','start-new','stop-new','receipt'])
        self.assertEqual(len(action_errors),1)
        self.assertIn('Application is stopping',str(action_errors[0]))
        self.assertEqual(s.processes,{})
        s.shutdown_ack.assert_called_once_with(True);s.network_on.assert_not_called()
        self.assertFalse((s.var/'control'/'control.sock').exists())
        with self.assertRaisesRegex(ValueError,'应用正在停止'):s.action({'action':'restart'})


if __name__=='__main__':unittest.main()
