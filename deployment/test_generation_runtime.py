import json
from pathlib import Path
import tempfile
import types
import unittest

from generation_runtime import Runtime


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        aliases = self.root / 'aliases.json'
        aliases.write_text(json.dumps({'4001': 24001, '4002': 24002}))
        self.runtime = object.__new__(Runtime)
        self.runtime.cfg = {
            'old_offset': -16000, 'deny_port': 19699,
            'aliases_path': str(aliases), 'host': '192.0.2.1',
            'auth_alias_port': 19591, 'route_table': 'fixture_proxy',
            'priority': -125, 'interface': 'fixture0', 'sources': ['192.0.2.2'],
        }
        self.runtime.manager_cfg = {'offset': -14000, 'auth_port': 19593}
        self.state = {'slots': {24001: {'ipv6': '2001:db8::1'},
                                24002: {'ipv6': '2001:db8::2'}},
                      'retired': set(), 'denied': set()}

    def tearDown(self):
        self.temp.cleanup()

    def test_canary_only_moves_selected_identity_and_its_aliases(self):
        text = self.runtime.routes(self.state, {'phase': 'canary', 'ports': [24001]})
        for source in [24001, 8001, 4001]:
            self.assertIn(f'{source} : 192.0.2.1 . 10001', text)
        self.assertNotIn('24002 :', text)
        self.assertNotIn('19591 :', text)
        self.assertNotIn('conntrack', text)

    def test_committed_routes_all_aliases_and_preserves_auth_endpoint(self):
        self.state['retired'].add('2001:db8::2')
        text = self.runtime.routes(self.state, {'phase': 'committed'})
        for source in [24002, 8002, 4002]:
            self.assertIn(f'{source} : 192.0.2.1 . 19699', text)
        self.assertIn('19591 : 192.0.2.1 . 19593', text)

    def test_route_target_alias_collision_is_rejected(self):
        Path(self.runtime.cfg['aliases_path']).write_text(json.dumps({'10001': 24002}))
        with self.assertRaises(AssertionError):
            self.runtime.routes(self.state, {'phase': 'committed'})

    def test_empty_canary_uses_an_empty_map_without_empty_elements_syntax(self):
        text = self.runtime.routes(self.state, {'phase': 'canary', 'ports': []})
        self.assertIn('map endpoints { type inet_service : ipv4_addr . inet_service;', text)
        self.assertNotIn('elements =', text)

    def test_rollback_preserves_explicitly_protected_failed_legacy_identity(self):
        text = self.runtime.routes(self.state, {'phase': 'rollback', 'ports': [24002]})
        self.assertIn('24002 : 192.0.2.1 . 10002', text)
        self.assertNotIn('24001 :', text)
        self.assertNotIn('19591 :', text)


if __name__ == '__main__':
    unittest.main()
