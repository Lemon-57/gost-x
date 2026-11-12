"""Route only new TCP connections to a validated proxy generation.

All topology is runtime configuration. Ownership ledgers are read, never
rolled back. Existing conntrack entries and active sockets are preserved.
"""
import argparse
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib import request


class Runtime:
    def __init__(self, path):
        self.path = Path(path)
        self.cfg = json.loads(self.path.read_text())
        self.root = Path(self.cfg['root'])
        self.private = self.root / 'private'
        sys.path.insert(0, self.cfg['base_root'])
        self.base = importlib.import_module('gost_manager')
        self.manager_cfg = json.loads(Path(self.cfg['manager_config']).read_text())
        self.manager = self.base.Manager(self.manager_cfg)
        assert re.fullmatch(r'[a-zA-Z_][a-zA-Z_0-9]*', self.cfg['route_table'])

    def run(self, args, timeout=15):
        return self.base.run(args, timeout)

    def marker(self):
        return json.loads((self.private / 'deployment.json').read_text())

    def state(self):
        self.manager.refresh()
        return self.manager.snapshot

    def routes(self, state, marker):
        slots = state['slots']
        selected = set(slots) if marker['phase'] == 'committed' else set(marker.get('ports', []))
        selected &= set(slots)
        mapping = {p: p + self.manager_cfg['offset'] for p in selected}
        for p in selected:
            if slots[p]['ipv6'] in state['retired'] | state['denied']:
                mapping[p] = self.cfg['deny_port']
        aliases = json.loads(Path(self.cfg['aliases_path']).read_text())
        aliases.update({str(p + self.cfg['old_offset']): p for p in slots})
        for physical, logical in aliases.items():
            if int(logical) in mapping:
                assert int(physical) not in mapping or int(physical) == int(logical)
                mapping[int(physical)] = mapping[int(logical)]
        # The original auth endpoint remains an alias, preserving clients and
        # inherited health probes while old authenticated flows drain.
        if marker['phase'] == 'committed':
            mapping[self.cfg['auth_alias_port']] = self.manager_cfg['auth_port']
        targets = {p + self.manager_cfg['offset'] for p in slots}
        assert not targets & set(mapping), 'new listener collides with a legacy route key'
        host = self.cfg['host']
        entries = ', '.join(f'{p} : {host} . {target}' for p, target in sorted(mapping.items()))
        elements = f'elements = {{ {entries} }}; ' if entries else ''
        table = self.cfg['route_table']
        priority = int(self.cfg['priority'])
        sources = ', '.join(self.cfg['sources'])
        interface = self.cfg['interface']
        return f'''destroy table ip {table}
table ip {table} {{
 map endpoints {{ type inet_service : ipv4_addr . inet_service; {elements}}}
 chain output {{ type nat hook output priority {priority}; policy accept;
  ip daddr {host} dnat ip to tcp dport map @endpoints
 }}
 chain prerouting {{ type nat hook prerouting priority {priority}; policy accept;
  iifname "{interface}" ip saddr {{ {sources} }} ip daddr {host} dnat ip to tcp dport map @endpoints
 }}
}}
'''

    def validate_targets(self, state, marker):
        services = {v['name']: v for v in self.manager.api('/config').get('services') or []}
        ports = set(state['slots']) if marker['phase'] == 'committed' else set(marker.get('ports', []))
        for p in ports:
            entry = state['slots'].get(p)
            if not entry or entry['ipv6'] in state['retired'] | state['denied']:
                continue
            name, expected, _, _ = self.manager.specs(entry)
            current = services[name]
            assert all(current.get(k) == expected[k] for k in
                       ('addr', 'interface', 'handler', 'listener', 'climiter'))
            assert current.get('status', {}).get('state') == 'ready', 'target service is not ready'

    def apply(self):
        state = self.state()
        marker = self.marker()
        assert marker['phase'] in ('canary', 'committed', 'rollback')
        text = self.routes(state, marker)
        signature = hashlib.sha256(text.encode()).hexdigest()
        self.validate_targets(state, marker)
        path = self.private / 'routes.nft'
        # Validate every generation before the kernel's atomic transaction.
        path.write_text(text)
        path.chmod(0o600)
        self.run(['nft', '-c', '-f', str(path)])
        self.run(['nft', '-f', str(path)])
        self.base.atomic(self.root / 'route-status.json', {
            'utc': time.time(), 'error': None, 'signature': signature,
            'phase': marker['phase'], 'slots': len(state['slots']),
        })
        return signature

    def watch(self):
        last = None
        while True:
            try:
                state, marker = self.state(), self.marker()
                if marker['phase'] in ('canary', 'committed', 'rollback'):
                    signature = hashlib.sha256(self.routes(state, marker).encode()).hexdigest()
                    if signature != last:
                        last = self.apply()
                    else:
                        self.validate_targets(state, marker)
                        self.base.atomic(self.root / 'route-status.json', {
                            'utc': time.time(), 'error': None, 'signature': signature,
                            'phase': marker['phase'], 'slots': len(state['slots']),
                        })
            except Exception as error:
                # Keep the last verified route on failures; never remove routes
                # or touch conntrack as an automatic fallback.
                self.base.atomic(self.root / 'route-status.json', {
                    'utc': time.time(), 'error': type(error).__name__,
                })
            time.sleep(3)

    def bootstrap(self):
        assert self.marker()['phase'] in ('committed', 'rollback')
        old = importlib.import_module('gost_runtime')
        old.guard()
        old.restore_addresses()
        self.run(['nft', '-f', str(self.private / 'access.nft')])
        self.ensure_guard()
        if self.marker()['phase'] == 'rollback':
            legacy = json.loads(self.run(self.manager_cfg['docker'] +
                                        ['inspect', self.cfg['old_container_id']]))[0]
            if not legacy['State']['Running']:
                self.run(self.manager_cfg['docker'] + ['start', self.cfg['old_container_id']])
        cid = (self.private / 'container.id').read_text().strip()
        meta = json.loads(self.run(self.manager_cfg['docker'] + ['inspect', cid]))[0]
        if not meta['State']['Running']:
            self.run(self.manager_cfg['docker'] + ['start', cid])
        self.run(['systemctl', 'start', self.cfg['manager_unit']])
        deadline = time.monotonic() + 75
        while True:
            try:
                self.state()
                self.validate_targets(self.manager.snapshot, self.marker())
                break
            except Exception:
                assert time.monotonic() < deadline, 'new generation is not ready'
                time.sleep(.5)
        self.apply()

    def ensure_guard(self):
        guard = self.cfg.get('shared_guard')
        if not guard:
            return
        raw = self.run(['nft', '-j', 'list', 'chain', guard['family'],
                        guard['table'], guard['chain']])
        if guard['comment'] not in raw:
            ports = self.cfg['guard_ports']
            self.run(['nft', 'insert', 'rule', guard['family'], guard['table'],
                      guard['chain'], 'iifname', self.cfg['interface'], 'ip',
                      'saddr', '{', ', '.join(self.cfg['sources']), '}', 'ip',
                      'daddr', self.cfg['host'], 'tcp', 'dport', '{', ports,
                      '}', 'accept', 'comment', guard['comment']])

    def rollback(self):
        # Operator-only recovery. Do not roll back ownership or kill the new
        # generation: its already established tunnels must finish naturally.
        old = json.loads(self.run(self.manager_cfg['docker'] +
                                 ['inspect', self.cfg['old_container_id']]))[0]
        assert old['State']['Running'], 'stage and verify the old generation before rollback'
        for unit in self.cfg.get('old_control_units', []):
            self.run(['systemctl', 'start', unit])
        legacy_cfg = json.loads(Path(self.cfg['old_manager_config']).read_text())
        legacy = self.base.Manager(legacy_cfg)
        state = self.state()
        services = {v['name']: v for v in legacy.api('/config').get('services') or []}
        keep = set(self.cfg.get('rollback_keep_ports', []))
        for entry in state['slots'].values():
            if entry['ipv6'] not in state['authorized'] or entry['ipv6'] in state['retired'] | state['denied']:
                continue
            name, expected, _, _ = legacy.specs(entry)
            current = services[name]
            if entry['port'] in keep:
                continue
            assert current.get('status', {}).get('state') == 'ready'
            assert all(current.get(k) == expected[k] for k in
                       ('addr', 'interface', 'handler', 'listener', 'climiter'))
        # Stop the route writer through its persisted mode before removing its
        # table. Any concurrent final write is removed by the same transaction.
        self.validate_targets(state, {'phase': 'rollback', 'ports': sorted(keep)})
        self.base.atomic(self.private / 'deployment.json', {
            'phase': 'rollback', 'ports': sorted(keep), 'utc': time.time(),
        })
        self.run(['systemctl', 'stop', self.cfg['watch_unit']])
        # Keep already-failed legacy listeners on the validated generation.
        # Falling back must never restore a known unavailable endpoint.
        self.apply()

    def drain(self):
        zeros = 0
        old_id = self.cfg['old_container_id']
        while True:
            try:
                assert self.marker()['phase'] == 'committed'
                self.state()
                self.validate_targets(self.manager.snapshot, self.marker())
                self.run(['nft', 'list', 'table', 'ip', self.cfg['route_table']])
                old = json.loads(self.run(self.manager_cfg['docker'] + ['inspect', old_id]))[0]
                if not old['State']['Running']:
                    self.base.atomic(self.root / 'drain-status.json', {
                        'utc': time.time(), 'phase': 'drained', 'active_sockets': 0,
                    })
                    return
                counts, ips = self.manager.counts(old['State']['Pid'])
                slots = self.manager.snapshot['slots']
                inbound = sum(counts.get(p + self.cfg['old_offset'], 0) for p in slots)
                # Outbound IPv6 sockets are also protected, including handlers
                # that no longer retain an inbound fd during shutdown.
                active = inbound + len(ips)
                zeros = zeros + 1 if active == 0 else 0
                self.base.atomic(self.root / 'drain-status.json', {
                    'utc': time.time(), 'phase': 'draining',
                    'active_sockets': active, 'consecutive_zero': zeros,
                })
                if zeros >= 4:
                    # No kill/forced deadline. A second check closes the race
                    # with any legacy client missed by routing.
                    check = self.manager.counts(old['State']['Pid'])
                    if any(check[0].get(p + self.cfg['old_offset'], 0) for p in slots) or check[1]:
                        zeros = 0
                        continue
                    if self.cfg.get('retain_old_for_rollback', False):
                        self.base.atomic(self.root / 'drain-status.json', {
                            'utc': time.time(), 'phase': 'drained_retained',
                            'active_sockets': 0, 'old_container': old_id,
                        })
                        return
                    self.run(self.manager_cfg['docker'] + ['stop', '--time', '30', old_id], 40)
                    self.base.atomic(self.root / 'drain-status.json', {
                        'utc': time.time(), 'phase': 'drained', 'active_sockets': 0,
                        'old_container': old_id,
                    })
                    return
            except Exception as error:
                zeros = 0
                self.base.atomic(self.root / 'drain-status.json', {
                    'utc': time.time(), 'phase': 'retained', 'error': type(error).__name__,
                })
            time.sleep(5)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--config', required=True)
    p.add_argument('mode', choices=['apply', 'watch', 'bootstrap', 'drain', 'rollback'])
    args = p.parse_args()
    runtime = Runtime(args.config)
    getattr(runtime, args.mode)()


if __name__ == '__main__':
    main()
