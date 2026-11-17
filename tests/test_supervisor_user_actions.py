"""User-facing state and import contracts without processes or kernel writes."""
from pathlib import Path
import json
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock

try:
    import pwd
except ImportError:
    sys.modules.setdefault('pwd', types.SimpleNamespace())
from runtime.supervisor import Supervisor


class UserActionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        s = self.s = Supervisor.__new__(Supervisor)
        s.var = Path(temporary.name);s.private = s.var / 'private';s.private.mkdir()
        s.ui = s.var / 'ui';s.profile = s.var / 'p';s.base = s.var / 'base'
        s.app = 'v2rayn';s.meta = {'title': 'v2rayN', 'socks_port': 10808}
        s.current = {'path': 'payload', 'version': '7.25.6'}
        s.account = types.SimpleNamespace(pw_uid=1);s.message = '';s.last_update = None
        s.network_operation = None;s.updating = False;s.lock = threading.RLock();s.closing = threading.Event()
        self.state = {'active': False, 'owned': True, 'owner': 'v2rayn', 'phase': 'stopped',
                      'cleanup_verified': True, 'needs_recovery': False, 'last_error': None}
        self.controller = Mock();self.controller.status.side_effect = lambda: dict(self.state)
        s.network = self.controller;s.network_controller = Mock(return_value=self.controller)

    def test_start_reports_pending_then_only_confirmed_active_state(self):
        observed = []
        def start():
            observed.append(self.s.status())
            self.state.update(active=True, phase='active', cleanup_verified=False)
        self.controller.start.side_effect = start
        result = self.s.network_on()
        self.assertEqual(observed[0]['network_phase'], 'starting')
        self.assertFalse(observed[0]['network_active'])
        self.assertTrue(result['network_active']);self.assertEqual(result['network_phase'], 'active')
        self.assertEqual(json.loads((self.s.private/'network-enabled.json').read_text()), {'enabled': True})

    def test_failed_start_does_not_publish_enabled_preference_or_fake_success(self):
        def fail():
            self.state.update(phase='error', needs_recovery=True, cleanup_verified=False, last_error='cleanup pending')
            raise RuntimeError('activation failed')
        self.controller.start.side_effect = fail
        with self.assertRaises(RuntimeError):self.s.network_on()
        result=self.s.status()
        self.assertFalse(result['network_active']);self.assertTrue(result['network_needs_recovery'])
        self.assertEqual(result['network_phase'], 'error');self.assertIsNone(self.s.network_operation)
        self.assertFalse((self.s.private/'network-enabled.json').exists())

    def test_stop_stays_active_while_pending_and_returns_confirmed_off(self):
        self.state.update(active=True, phase='active', cleanup_verified=False)
        observed=[]
        def stop():
            observed.append(self.s.status())
            self.state.update(active=False, phase='stopped', cleanup_verified=True)
        self.controller.stop.side_effect=stop
        result=self.s.network_off()
        self.assertTrue(observed[0]['network_active']);self.assertEqual(observed[0]['network_phase'],'stopping')
        self.assertFalse(result['network_active']);self.assertEqual(result['network_phase'],'stopped')

    def test_stop_does_not_touch_other_client_owner(self):
        self.state.update(active=True, owned=False, owner='clash', phase='active', cleanup_verified=False)
        result=self.s.network_off()
        self.controller.stop.assert_not_called()
        self.assertFalse(result['network_active']);self.assertEqual(result['network_owner'],'clash')

    def test_recovered_guardian_replaces_stale_enabled_summary(self):
        self.s.message='本机与 Docker 网络接管已启动'
        self.controller.maintain.return_value={'phase':'stopped','cleanup_verified':True,'recovered':True}
        self.s.maintain_network()
        self.assertEqual(self.s.message,'网络接管已停止，直连已恢复')

    def test_other_owner_cannot_be_described_as_global_direct_networking(self):
        self.state.update(active=True, owned=False, owner='clash', phase='active', cleanup_verified=False)
        self.s.message='网络接管已停止，直连已恢复：old error'
        result=self.s.status()
        self.assertEqual(result['network_owner'],'clash')
        self.assertNotIn('直连已恢复',result['message'])
        self.assertIn('Clash Verge Rev',result['message'])

    def test_vmess_link_is_forwarded_to_native_clipboard_without_protocol_restriction(self):
        self.s.as_user=Mock(return_value=types.SimpleNamespace(stdout='123\n'))
        content='vmess://eyJ2IjoiMiJ9'
        result=self.s.import_nodes({'format':'share-links','content':content})
        self.assertEqual(self.s.as_user.call_args_list[0].kwargs['input'],content.encode())
        self.assertEqual(result['format'],'share-links')
        self.assertIn('确认导入结果',result['message'])

    def test_cross_client_import_formats_fail_before_any_dispatch(self):
        self.s.as_user=Mock()
        for app,fmt,content in [('v2rayn','clash','proxies: []'),('clash','share-links','vmess://example')]:
            self.s.app=app
            with self.subTest(app=app),self.assertRaises(ValueError):
                self.s.import_nodes({'format':fmt,'content':content})
        self.s.as_user.assert_not_called()

    def test_invalid_yaml_error_never_echoes_node_content(self):
        self.s.app='clash';self.s.transaction=Mock()
        secret='unit-test-configuration-marker'
        with self.assertRaises(ValueError) as result:
            self.s.import_nodes({'format':'clash','content':'proxies: [\n  '+secret+': ['})
        self.assertNotIn(secret,str(result.exception));self.assertIn('YAML 配置格式不正确',str(result.exception))
        self.s.transaction.assert_not_called()


if __name__=='__main__':
    unittest.main()
