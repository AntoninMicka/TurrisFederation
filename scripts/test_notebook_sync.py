#!/usr/bin/env python3
"""Notebook protocol tests with disposable databases, identities and loopback TLS."""
import copy
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
for name, path in [('federation', ROOT / 'router/files/usr/lib/turris-federation/federation.py'),
                   ('notebook_sync', ROOT / 'scripts/notebook_sync.py')]:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
f = sys.modules['federation']
n = sys.modules['notebook_sync']

SCHEMA = '''CREATE TABLE nodes(id TEXT PRIMARY KEY,name TEXT,ssh_host TEXT,ssh_port INTEGER,
ssh_user TEXT,lan_cidrs TEXT,zero_tier_address TEXT,public_endpoint TEXT,wireguard_address TEXT,status TEXT,last_audit_at TEXT);
CREATE TABLE app_settings(name TEXT PRIMARY KEY,value TEXT);
CREATE TABLE ssh_host_keys(node_id TEXT,keys TEXT);
CREATE TABLE observations(node_id TEXT,payload TEXT);'''


class NotebookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.identities = []
        for i in range(3):
            store = n.Store(Path(cls.keys.name) / str(i))
            store.init_identity()
            cls.identities.append(store)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stores = []
        for i, identity in enumerate(self.identities):
            store = n.Store(Path(self.temp.name) / str(i))
            for filename in ['key.pem', 'cert.pem']:
                shutil.copy(identity.root / filename, store.root / filename)
            store.init_identity()
            with sqlite3.connect(store.data_dir / 'federation.db') as db:
                db.executescript(SCHEMA)
            self.stores.append(store)
        self.a, self.b, self.c = self.stores
        self.pair(self.a, self.b)
        self.pair(self.b, self.a)

    def pair(self, source, peer):
        peers = source.peers()
        peers[peer.id] = {'name': peer.id[:8], 'cert': peer.cert, 'address': '127.0.0.1'}
        f.atomic(source.root / 'peers.json', peers)

    def node(self, store, name='Prague'):
        with store.db() as db:
            db.execute("INSERT INTO nodes VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name",
                       (str(uuid.UUID(int=1)), name, '192.168.1.1', 22, 'root', '["192.168.1.0/24"]',
                        '10.147.0.1', None, '10.203.0.1', 'healthy', 'previous-audit'))

    def snapshot(self, store):
        with store.db() as db:
            return store.snapshot(db)

    def root_identity(self, store):
        shutil.copy(store.root / 'key.pem', store.fleet / 'root.pem')

    def test_empty_notebook_adopts_configuration_and_management_identity(self):
        self.node(self.a)
        self.root_identity(self.a)
        snapshot = self.snapshot(self.a)
        self.assertEqual('synced', self.b.receive(self.a.id, snapshot))
        self.assertEqual(snapshot, self.snapshot(self.b))
        self.assertEqual((self.a.fleet / 'root.pem').read_bytes(), (self.b.fleet / 'root.pem').read_bytes())
        self.assertEqual(0o600, (self.b.fleet / 'root.pem').stat().st_mode & 0o777)
        self.assertNotEqual(self.a.id, self.b.id)
        self.assertNotIn('PRIVATE KEY', json.dumps(self.b.status()))
        with self.b.db() as db:
            self.assertNotIn('PRIVATE KEY', repr(db.execute('SELECT value FROM app_settings').fetchall()))

    def test_local_edit_returns_to_first_notebook_and_converges(self):
        self.node(self.a)
        self.b.receive(self.a.id, self.snapshot(self.a))
        self.node(self.b, 'Brno')
        changed = self.snapshot(self.b)
        self.assertEqual('synced', self.a.receive(self.b.id, changed))
        self.assertEqual(changed, self.snapshot(self.a))
        for _ in range(3):
            self.b.receive(self.a.id, self.snapshot(self.a))
            self.a.receive(self.b.id, self.snapshot(self.b))
        self.assertEqual(changed, self.snapshot(self.a))

    def test_concurrent_edits_require_explicit_resolution(self):
        self.node(self.a)
        self.b.receive(self.a.id, self.snapshot(self.a))
        self.node(self.a, 'A changed')
        self.node(self.b, 'B changed')
        before = self.snapshot(self.a)
        self.assertEqual('conflict', self.a.receive(self.b.id, self.snapshot(self.b)))
        self.assertEqual(before, self.snapshot(self.a))
        peer = next(p for p in self.a.status()['peers'] if p['id'] == self.b.id)
        self.assertEqual(['B changed'], peer['remoteNodes'])
        n.command(self.a, {'action': 'resolve', 'peer': self.b.id, 'choice': 'remote', 'token': peer['conflictToken']})
        self.b.receive(self.a.id, self.snapshot(self.a))
        self.assertEqual(self.snapshot(self.a), self.snapshot(self.b))
        self.assertEqual('B changed', self.snapshot(self.a)['data']['nodes'][0]['name'])
        self.assertFalse((self.a.root / ('conflict-' + self.b.id + '.json')).exists())

    def test_stale_conflict_confirmation_is_rejected(self):
        self.node(self.a, 'A')
        self.node(self.b, 'B')
        self.a.receive(self.b.id, self.snapshot(self.b))
        token = self.a.status()['peers'][0]['conflictToken']
        self.node(self.a, 'another edit')
        with self.assertRaisesRegex(ValueError, 'změnila'):
            n.command(self.a, {'action': 'resolve', 'peer': self.b.id, 'choice': 'remote', 'token': token})

    def test_foreign_root_is_never_overwritten(self):
        self.node(self.a)
        self.root_identity(self.a)
        self.root_identity(self.b)
        original = (self.b.fleet / 'root.pem').read_bytes()
        self.assertEqual('conflict', self.b.receive(self.a.id, self.snapshot(self.a)))
        peer = self.b.status()['peers'][0]
        with self.assertRaisesRegex(ValueError, 'kotvě důvěry'):
            n.command(self.b, {'action': 'resolve', 'peer': self.a.id, 'choice': 'remote', 'token': peer['conflictToken']})
        self.assertEqual(original, (self.b.fleet / 'root.pem').read_bytes())
        self.assertFalse((self.b.fleet / 'notebook-sync-journal.json').exists())

    def test_sync_keeps_local_trust_and_audits(self):
        self.node(self.a)
        self.b.receive(self.a.id, self.snapshot(self.a))
        with self.b.db() as db:
            db.execute('INSERT INTO ssh_host_keys VALUES(?,?)', ('local', 'LOCAL-HOST-KEY'))
            db.execute('INSERT INTO observations VALUES(?,?)', ('local', 'LOCAL-AUDIT'))
        self.node(self.a, 'renamed')
        self.b.receive(self.a.id, self.snapshot(self.a))
        with self.b.db() as db:
            self.assertEqual('LOCAL-HOST-KEY', db.execute('SELECT keys FROM ssh_host_keys').fetchone()[0])
            self.assertEqual('LOCAL-AUDIT', db.execute('SELECT payload FROM observations').fetchone()[0])
            self.assertEqual('draft', db.execute('SELECT status FROM nodes').fetchone()[0])
        raw = json.dumps(self.snapshot(self.b))
        self.assertNotIn('LOCAL-HOST-KEY', raw)
        self.assertNotIn('LOCAL-AUDIT', raw)

    def test_recovery_completes_interrupted_database_and_identity_update(self):
        self.node(self.a)
        self.root_identity(self.a)
        snapshot = self.snapshot(self.a)
        with patch.object(self.b, 'apply', side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):
                self.b.receive(self.a.id, snapshot)
        self.assertTrue((self.b.fleet / 'notebook-sync-journal.json').exists())
        with self.b.db() as db:
            self.b.recover(db)
        self.assertEqual(snapshot, self.snapshot(self.b))
        self.assertFalse((self.b.fleet / 'notebook-sync-journal.json').exists())

    def test_deploy_refuses_incomplete_sync_journal(self):
        f.atomic(self.a.fleet / 'notebook-sync-journal.json', {})
        with self.assertRaisesRegex(ValueError, 'obnovu synchronizace'):
            f.controller(self.a.fleet, {})

    def test_unpair_prevents_late_incoming_update(self):
        self.node(self.a)
        n.command(self.b, {'action': 'unpair', 'peer': self.a.id})
        with self.assertRaisesRegex(ValueError, 'spárovaný'):
            self.b.receive(self.a.id, self.snapshot(self.a))

    def test_invalid_document_cannot_write_arbitrary_files(self):
        self.node(self.a)
        snapshot = self.snapshot(self.a)
        snapshot['data']['fleet']['../../outside'] = 'bad'
        with self.assertRaisesRegex(ValueError, 'soubory'):
            self.b.receive(self.a.id, snapshot)
        self.assertFalse((self.b.fleet / 'notebook-sync-journal.json').exists())

    def test_signed_discovery_is_untrusted_until_confirmed(self):
        f.atomic(self.b.root / 'peers.json', {})
        raw = n.beacon(self.a, 'Notebook A', '10.4.0.1')
        n.discover(self.b, raw, '10.4.0.1', n.ipaddress.ip_network('10.4.0.0/24'))
        peer = self.b.status()['peers'][0]
        self.assertFalse(peer['trusted'])
        self.assertEqual(self.a.id, peer['id'])
        n.command(self.b, {'action': 'pair', 'peer': self.a.id})
        self.assertTrue(self.b.status()['peers'][0]['trusted'])
        self.assertNotIn('PRIVATE KEY', raw.decode())

    def test_discovery_rejects_wrong_source_expiry_and_tampering(self):
        raw = n.beacon(self.a, 'A', '10.4.0.1')
        n.discover(self.c, raw, '10.4.0.2', n.ipaddress.ip_network('10.4.0.0/24'))
        with patch.object(n.time, 'time', return_value=time.time() + 120):
            n.discover(self.c, raw, '10.4.0.1', n.ipaddress.ip_network('10.4.0.0/24'))
        self.assertFalse(f.read(self.c.root / 'discovered.json', {}))
        packet = json.loads(raw)
        packet['cert'] = self.c.cert
        with self.assertRaises(ValueError):
            n.discover(self.b, f.encode(packet), '10.4.0.1', n.ipaddress.ip_network('10.4.0.0/24'))

    def test_manual_pairing_never_implicitly_trusts(self):
        n.command(self.c, {'action': 'manual', 'invitation': json.dumps({'name': 'A', 'address': '10.4.0.1', 'cert': self.a.cert})})
        self.assertFalse(self.c.status()['peers'][0]['trusted'])
        self.assertFalse(self.c.peers())

    def test_mutual_tls_transfers_secrets_only_to_paired_notebook(self):
        self.node(self.a)
        self.root_identity(self.a)
        with patch.object(n, 'PORT', 0):
            server = n.make_server(self.a, '127.0.0.1')
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with patch.object(n, 'PORT', server.server_address[1]):
                snapshot = n.fetch(self.b, self.b.peers()[self.a.id])
                self.assertEqual((self.a.fleet / 'root.pem').read_text(), snapshot['data']['fleet']['root.pem'])
                # C trusts A, but A never authorized C.
                with self.assertRaises((ssl.SSLError, OSError)):
                    n.fetch(self.c, self.b.peers()[self.a.id])
                n.command(self.a, {'action': 'unpair', 'peer': self.b.id})
                with self.assertRaises((ssl.SSLError, OSError)):
                    n.fetch(self.b, self.b.peers()[self.a.id])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)

    def test_two_running_services_sync_both_directions_without_controller(self):
        self.node(self.a)
        self.root_identity(self.a)
        service_dir = Path(self.temp.name) / 'service'
        service_dir.mkdir()
        shutil.copy(ROOT / 'scripts/notebook_sync.py', service_dir / 'notebook_sync.py')
        shutil.copy(ROOT / 'router/files/usr/lib/turris-federation/federation.py', service_dir / 'federation.py')
        links = [{'addr_info': [{'local': ip, 'prefixlen': 8, 'scope': 'global'}]} for ip in ['127.0.0.2', '127.0.0.3']]
        fake_ip = service_dir / 'ip'
        fake_ip.write_text('#!' + sys.executable + '\nprint(' + repr(json.dumps(links)) + ')\n')
        fake_ip.chmod(0o755)
        with socket.socket() as probe:
            probe.bind(('127.0.0.2', 0))
            port = probe.getsockname()[1]
        processes = []
        try:
            for store, address, other in [(self.a, '127.0.0.2', '127.0.0.3'), (self.b, '127.0.0.3', '127.0.0.2')]:
                f.atomic(store.root / 'config.json', {'name': address, 'address': address, 'enabled': True})
                peers = store.peers()
                for peer in peers.values():
                    peer['address'] = other
                f.atomic(store.root / 'peers.json', peers)
                code = "import sys; sys.path.insert(0,sys.argv[1]); import notebook_sync as n; n.PORT=int(sys.argv[3]); n.INTERVAL=0.2; s=n.Store(sys.argv[2]); s.init_identity(); n.serve(s)"
                processes.append(subprocess.Popen([sys.executable, '-c', code, str(service_dir), str(store.data_dir), str(port)],
                    env=dict(os.environ, PATH=str(service_dir) + ':' + os.environ['PATH']), stdout=subprocess.PIPE, stderr=subprocess.PIPE))

            def wait_name(store, name):
                end = time.monotonic() + 8
                while time.monotonic() < end:
                    for process in processes:
                        if process.poll() is not None:
                            self.fail('Service stopped: ' + process.communicate()[1].decode())
                    with sqlite3.connect(store.data_dir / 'federation.db') as db:
                        row = db.execute('SELECT name FROM nodes').fetchone()
                    if row and row[0] == name:
                        return
                    time.sleep(0.05)
                self.fail('Service did not converge')

            wait_name(self.b, 'Prague')
            self.assertEqual((self.a.fleet / 'root.pem').read_bytes(), (self.b.fleet / 'root.pem').read_bytes())
            self.node(self.b, 'Changed on B')
            wait_name(self.a, 'Changed on B')
        finally:
            for process in processes:
                process.kill()
                process.communicate(timeout=5)

    def test_recovery_does_not_overwrite_intervening_local_edit(self):
        self.node(self.a)
        self.b.receive(self.a.id, self.snapshot(self.a))
        self.node(self.a, 'incoming')
        with patch.object(self.b, 'apply', side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):
                self.b.receive(self.a.id, self.snapshot(self.a))
        self.node(self.b, 'later local edit')
        with self.b.db() as db:
            with self.assertRaisesRegex(ValueError, 'místní úpravy'):
                self.b.recover(db)
            self.assertEqual('later local edit', db.execute('SELECT name FROM nodes').fetchone()[0])

    def test_revision_floor_forces_new_signed_revision(self):
        self.root_identity(self.a)
        config = f.normalize([], 'abcdef0123456789')
        old = f.snapshot(self.a.fleet, config, {})
        f.atomic(self.a.fleet / 'revision-floor.json', 5)
        new = f.snapshot(self.a.fleet, config, {})
        self.assertNotEqual(old, new)
        self.assertEqual(5, f.verify(f.public_key(self.a.fleet / 'root.pem'), new)['revision'])


if __name__ == '__main__':
    unittest.main()
