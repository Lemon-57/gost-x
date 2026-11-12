"""Add runtime-state recovery to an installed authoritative GOST manager.

Ownership, authentication, retirement and fixed identities remain in the
installed manager. Configuration and credentials are supplied only at runtime.
"""
import argparse
import importlib
import json
import os
from pathlib import Path
import sys
import time


def manager_class(base):
    class RecoveryManager(base.Manager):
        def __init__(self, config):
            super().__init__(config)
            self.unhealthy = {}
            self.closed_zeros = {}
            self.recoveries = 0

        def specs(self, entry):
            name, service, auther, limiter = super().specs(entry)
            limit = int(self.cfg.get('budgets', {}).get(str(entry['port']),
                                                       self.cfg.get('default_budget', 1024)))
            assert limit > 0
            limiter['limits'] = ['$ ' + str(limit)]
            return name, service, auther, limiter

        def inspect_health(self):
            config = self.api('/config')
            services = {v['name']: v for v in config.get('services') or []}
            ports, _ = self.counts(self.pid())
            unhealthy = {}
            for name, entry in list(self.inventory.items()):
                current = services.get(name)
                if not current:
                    unhealthy[name] = 'missing'
                    continue
                state = current.get('status', {}).get('state')
                if state == 'ready':
                    self.closed_zeros.pop(name, None)
                    continue
                unhealthy[name] = state or 'unknown'
                # Existing handlers may outlive a failed accept loop. Never
                # replace their listener until accepted sockets have drained.
                if state != 'closed' or ports.get(entry['listener_port'], 0):
                    self.closed_zeros.pop(name, None)
                    continue
                self.closed_zeros[name] = self.closed_zeros.get(name, 0) + 1
                if self.closed_zeros[name] < 4:
                    continue
                expected = self.snapshot['slots'].get(entry['port'])
                if not expected or base.service_name(expected) != name:
                    continue
                _, desired, _, _ = self.specs(expected)
                if any(current.get(k) != desired[k] for k in
                       ('addr', 'interface', 'handler', 'listener', 'climiter')):
                    continue
                # Check again immediately before replacing this closed service.
                if self.counts(self.pid())[0].get(entry['listener_port'], 0):
                    self.closed_zeros.pop(name, None)
                    continue
                self.api('/config/services/' + name, 'DELETE')
                try:
                    self.api('/config/services', 'POST', desired)
                finally:
                    actual = {v['name'] for v in self.api('/config').get('services') or []}
                    if name not in actual:
                        self.api('/config/services', 'POST', desired)
                self.closed_zeros.pop(name, None)
                self.recoveries += 1
            self.unhealthy = unhealthy

        def reconcile(self):
            super().reconcile()
            self.inspect_health()
            mirror = self.cfg.get('consumer_mirror')
            source = self.private / 'consumers.json'
            if mirror and source.exists():
                incoming = json.loads(source.read_text())
                target = Path(mirror)
                prior = json.loads(target.read_text()) if target.exists() else {}
                if incoming.get('complete') is True and incoming.get('received', 0) > prior.get('received', 0):
                    # The retained retirement worker must receive the same
                    # fresh consumer witness after the auth endpoint moves.
                    base.atomic(target, incoming)
            base.atomic(self.root / 'runtime-health.json', {
                'utc': time.time(), 'unhealthy': self.unhealthy,
                'recoveries': self.recoveries, 'services': len(self.inventory),
            })

        def ready(self):
            result = super().ready()
            result['ready'] = result['ready'] and not self.unhealthy
            result['unhealthy_services'] = len(self.unhealthy)
            result['recoveries'] = self.recoveries
            return result
    return RecoveryManager


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-root', required=True)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    sys.path.insert(0, args.base_root)
    base = importlib.import_module('gost_manager')
    os.umask(0o077)
    manager_class(base)(json.loads(Path(args.config).read_text())).serve()


if __name__ == '__main__':
    main()
