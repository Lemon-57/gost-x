import importlib.util
from pathlib import Path
import tempfile
import types
import unittest

from recovery_manager import manager_class


class FakeBaseManager:
    def __init__(self, config):
        self.cfg = config
        self.root = Path(config['root'])
        self.entry = {'port': 24001}
        self.snapshot = {'slots': {24001: self.entry}}
        self.inventory = {'fixed': {'port': 24001, 'listener_port': 10001}}
        self.service = self.specs(self.entry)[1] | {'status': {'state': 'closed'}}
        self.present = True
        self.active = 0
        self.calls = []

    def specs(self, entry):
        return 'fixed', {'name': 'fixed', 'addr': '127.0.0.1:10001',
                         'interface': '::1', 'handler': {'type': 'http'},
                         'listener': {'type': 'tcp'}, 'climiter': 'fixed'}, {}, {}

    def pid(self):
        return 1

    def counts(self, pid):
        return {10001: self.active}, set()

    def api(self, path, method='GET', body=None):
        if method == 'GET':
            return {'services': [self.service] if self.present else []}
        self.calls.append((method, path))
        if method == 'DELETE':
            self.present = False
        else:
            self.service = body | {'status': {'state': 'ready'}}
            self.present = True
        return {'msg': 'OK'}

    def ready(self):
        return {'ready': True}


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = types.SimpleNamespace(Manager=FakeBaseManager,
                                     service_name=lambda e: 'fixed')
        self.manager = manager_class(base)({'root': self.temp.name})

    def tearDown(self):
        self.temp.cleanup()

    def test_closed_listener_recovers_after_four_empty_observations(self):
        m = self.manager
        for _ in range(3):
            m.inspect_health()
        self.assertFalse(m.calls)
        self.assertFalse(m.ready()['ready'])
        m.inspect_health()
        self.assertEqual([c[0] for c in m.calls], ['DELETE', 'POST'])
        m.inspect_health()
        self.assertTrue(m.ready()['ready'])

    def test_live_tunnels_prevent_replacement(self):
        m = self.manager
        m.active = 1
        for _ in range(8):
            m.inspect_health()
        self.assertFalse(m.calls)
        m.active = 0
        for _ in range(3):
            m.inspect_health()
        self.assertFalse(m.calls)
        m.active = 1
        m.inspect_health()
        m.active = 0
        m.inspect_health()
        self.assertFalse(m.calls)

    def test_ready_service_is_never_recreated(self):
        m = self.manager
        m.service['status']['state'] = 'ready'
        for _ in range(8):
            m.inspect_health()
        self.assertFalse(m.calls)
        self.assertTrue(m.ready()['ready'])

    def test_unknown_state_and_configuration_drift_fail_closed(self):
        m = self.manager
        m.service['status']['state'] = 'failed'
        for _ in range(8):
            m.inspect_health()
        self.assertFalse(m.calls)
        m.service['status']['state'] = 'closed'
        m.service['interface'] = '::2'
        for _ in range(8):
            m.inspect_health()
        self.assertFalse(m.calls)
        self.assertFalse(m.ready()['ready'])

    def test_budget_defaults_to_1024(self):
        self.assertEqual(self.manager.specs(self.manager.entry)[3]['limits'], ['$ 1024'])


if __name__ == '__main__':
    unittest.main()
