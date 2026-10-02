#!/usr/bin/env python3
"""Notebook protocol tests with disposable databases, identities and loopback TLS."""
import copy
import contextlib
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
            with contextlib.closing(sqlite3.connect(store.data_dir / 'federation.db')) as db:
                db.executescript(SCHEMA)
            self.stores.append(store)
        self.a, self.b, self.c = self.stores
        self.pair(self.a, self.b)
        self.pair(self.b, self.a)

    def pair(self, source, peer):
        peers = source.peers()
        peers[peer.id] = {'name': peer.id[:8], 'cert': peer.cert, 'address': '127.0.0.1'}
        f.atomic(source.root / 'peers.json', peers)

    def test_nmcli_connections_recognizes_imported_interface_profile(self):
        legacy_uuid = str(uuid.uuid4())

        def connection_show(args, **_kwargs):
            return f'{legacy_uuid}:wireguard\n' if args[-1] == n.VPN_INTERFACE else ''

        with patch.object(n, 'local_command', side_effect=connection_show):
            self.assertEqual(
                {n.VPN_CONNECTION: {'uuid': legacy_uuid, 'type': 'wireguard'}},
                n.nmcli_connections())

    def test_nmcli_connections_rejects_two_current_profiles(self):
        uuids = {n.VPN_CONNECTION: str(uuid.uuid4()), n.VPN_INTERFACE: str(uuid.uuid4())}

        def connection_show(args, **_kwargs):
            profile_uuid = uuids.get(args[-1])
            return f'{profile_uuid}:wireguard\n' if profile_uuid else ''

        with patch.object(n, 'local_command', side_effect=connection_show), \
                self.assertRaisesRegex(ValueError, 'více spravovaných'):
            n.nmcli_connections()

    def admin_command(self, store, request):
        with patch.object(store, 'access_status', return_value={'state': 'valid', 'role': 'administrator'}):
            return n.command(store, request)

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

    def published_federation(self, store):
        self.node(store)
        with store.db() as db:
            settings = {'networkId': 'abcdef0123456789', 'central': 'new',
                        'zeroTierSubnet': '10.147.0.0/24', 'wireguardSubnet': '10.203.0.0/24'}
            db.execute("INSERT INTO app_settings(name,value) VALUES('zerotier',?) "
                       "ON CONFLICT(name) DO UPDATE SET value=excluded.value", (json.dumps(settings),))
        self.root_identity(store)
        config = f.normalize([{'id': str(uuid.UUID(int=1)), 'name': 'Prague',
                              'sshHost': '192.168.1.1', 'sshPort': 22, 'sshUser': 'root',
                              'lanCidrs': ['192.168.1.0/24'], 'zeroTierAddress': '10.147.0.1',
                              'wireguardAddress': '10.203.0.1', 'publicEndpoint': None}],
                             'abcdef0123456789')
        member = {'nodeId': str(uuid.UUID(int=1)), 'identity': f.public_key(store.fleet / 'root.pem'),
                  'wireguardKey': __import__('base64').b64encode(b'r' * 32).decode()}
        f.atomic(store.fleet / 'members.json', {member['nodeId']: member})
        return f.snapshot(store.fleet, config, {member['nodeId']: member})

    def onboard_user(self):
        self.published_federation(self.a)
        self.a.bootstrap_admin_credential()
        request = self.b.enrollment_request('User notebook')
        invitation = self.a.issue_user_invitation(json.dumps(request))
        self.b.accept_user_invitation(json.dumps(invitation))
        return invitation

    def test_admin_credential_requires_explicit_bootstrap_and_verifies_identity(self):
        self.assertEqual('unconnected', self.a.access_status()['state'])
        self.assertFalse(self.a.access_status()['canBootstrapAdmin'])
        self.published_federation(self.a)
        f.atomic(self.a.root / 'config.json', {
            'enabled': True, 'name': 'Administrator', 'address': '10.147.0.2'})
        self.assertTrue(self.a.access_status()['canBootstrapAdmin'])

        # Recover a migration interrupted after pinning the verifier.
        f.atomic(self.a.root / 'federation-root.pub', f.public_key(self.a.fleet / 'root.pem').encode())
        status = n.command(self.a, {'action': 'bootstrap_admin'})['access']
        self.assertEqual(('valid', 'administrator', self.a.id),
                         (status['state'], status['role'], status['subject']))
        document = f.verify(f.public_key(self.a.fleet / 'root.pem'), f.read(self.a.fleet / 'published.json'))
        self.assertEqual(f.NOTEBOOK_WG_VERSION, document['schema'])
        self.assertEqual([self.a.id], [item['id'] for item in document['config']['notebooks']])
        self.assertEqual('administrator', document['config']['notebooks'][0]['role'])
        self.assertEqual(('10.147.0.2', '10.203.0.2'),
                         (document['config']['notebooks'][0]['zeroTierAddress'],
                          document['config']['notebooks'][0]['wireguardAddress']))
        self.assertTrue((self.a.root / 'wireguard.conf').exists())
        self.assertEqual(0o600, (self.a.root / 'credential.json').stat().st_mode & 0o777)
        self.assertEqual(0o600, (self.a.root / 'federation-root.pub').stat().st_mode & 0o777)
        with self.assertRaisesRegex(ValueError, 'již existuje'):
            self.a.bootstrap_admin_credential()

        envelope = f.read(self.a.root / 'credential.json')
        envelope['payload'] = envelope['payload'][:-2] + 'AA'
        f.atomic(self.a.root / 'credential.json', envelope)
        self.assertEqual({'state': 'invalid', 'role': None, 'canBootstrapAdmin': False,
                          'error': 'Podepsané pověření notebooku není platné.'}, self.a.access_status())

    def test_admin_configure_repairs_signed_zerotier_address_and_preserves_identity(self):
        self.published_federation(self.a)
        f.atomic(self.a.root / 'config.json', {
            'enabled': True, 'name': 'Administrator', 'address': '10.147.0.2'})
        self.a.bootstrap_admin_credential()
        public = f.public_key(self.a.fleet / 'root.pem')
        document = f.validate_document(f.verify(public, f.read(self.a.fleet / 'published.json')))
        other = self.a.endpoint_notebook(
            document, self.b.id, 'Second administrator', 'administrator',
            self.b.wireguard_identity(), self.a.network_subnets(), zero_tier_address='10.147.0.3')
        _, before = self.a.publish_notebooks(self.a.fleet / 'root.pem', document, [other])
        endpoint = next(item for item in before['config']['notebooks'] if item['id'] == self.a.id)
        wireguard = (endpoint['wireguardAddress'], endpoint['wireguardKey'])

        with patch.object(n, 'zerotier_interface', return_value=__import__('ipaddress').ip_network('10.147.0.0/24')):
            result = n.command(self.a, {
                'action': 'configure', 'name': 'Administrator', 'address': '10.147.0.9'})

        after = f.validate_document(f.verify(public, f.read(self.a.fleet / 'published.json')))
        repaired = next(item for item in after['config']['notebooks'] if item['id'] == self.a.id)
        self.assertEqual(before['revision'] + 1, after['revision'])
        self.assertEqual('10.147.0.9', repaired['zeroTierAddress'])
        self.assertEqual(wireguard, (repaired['wireguardAddress'], repaired['wireguardKey']))
        self.assertEqual(other, next(item for item in after['config']['notebooks'] if item['id'] == self.b.id))
        self.assertEqual('10.147.0.9', result['config']['address'])

    def test_expired_or_wrong_subject_credential_fails_closed(self):
        envelope = self.published_federation(self.a)
        document = f.verify(f.public_key(self.a.fleet / 'root.pem'), envelope)
        public = f.public_key(self.a.fleet / 'root.pem')
        f.atomic(self.a.root / 'federation-root.pub', public.encode())
        base = {'schema': n.CREDENTIAL_SCHEMA, 'federationId': document['federationId'],
                'subject': self.b.id, 'role': 'administrator', 'issuedAt': int(time.time()) - 10,
                'expiresAt': None, 'serial': str(uuid.uuid4())}
        f.atomic(self.a.root / 'credential.json', f.sign(self.a.fleet / 'root.pem', base))
        self.assertEqual('invalid', self.a.access_status()['state'])
        base.update(subject=self.a.id, expiresAt=time.time() - 1)
        f.atomic(self.a.root / 'credential.json', f.sign(self.a.fleet / 'root.pem', base))
        self.assertEqual('invalid', self.a.access_status()['state'])

    def test_uncredentialed_notebook_cannot_call_admin_sync_actions(self):
        for request in [
            {'action': 'pair', 'peer': self.b.id},
            {'action': 'unpair', 'peer': self.b.id},
            {'action': 'manual', 'invitation': '{}'},
            {'action': 'resolve', 'peer': self.b.id, 'choice': 'local', 'token': 'x'},
            {'action': 'revoke_user_notebook', 'notebookId': self.b.id, 'confirm': True},
            {'action': 'topology_update_export'},
        ]:
            with self.subTest(action=request['action']), self.assertRaisesRegex(ValueError, 'administrátorské pověření'):
                n.command(self.a, request)

    def test_public_status_hides_admin_pairing_data_without_admin_role(self):
        unconnected = self.a.public_status()
        self.assertEqual([], unconnected['peers'])
        self.assertEqual('', unconnected['invitation'])
        self.assertEqual('', unconnected['configurationVersion'])
        self.assertNotIn('address', unconnected['config'])
        with patch.object(self.a, 'access_status', return_value={'state': 'valid', 'role': 'administrator'}):
            administrator = self.a.public_status()
        self.assertTrue(administrator['peers'])
        self.assertTrue(administrator['invitation'])

    def test_admin_sync_rejects_local_lan_and_accepts_stable_zerotier_address(self):
        lan = json.dumps([{'ifname': 'wlan0', 'addr_info': [
            {'family': 'inet', 'local': '192.168.1.20', 'prefixlen': 24, 'scope': 'global'}]}])
        with patch.object(f, 'run', return_value=lan.encode()), \
                self.assertRaisesRegex(ValueError, 'nikoli adresu místní LAN'):
            n.zerotier_interface('192.168.1.20')
        zerotier = json.dumps([{'ifname': 'zt1234', 'addr_info': [
            {'family': 'inet', 'local': '10.147.0.2', 'prefixlen': 24, 'scope': 'global'}]}])
        with patch.object(f, 'run', return_value=zerotier.encode()):
            self.assertEqual('10.147.0.0/24', str(n.zerotier_interface('10.147.0.2')))

    def test_admin_issues_one_time_user_invitation_without_private_root(self):
        self.published_federation(self.a)
        self.a.bootstrap_admin_credential()
        request = self.b.enrollment_request('User notebook')
        invitation = self.a.issue_user_invitation(json.dumps(request))
        raw = json.dumps(invitation)
        self.assertNotIn('PRIVATE KEY', raw)
        self.assertEqual(n.INVITATION_SCHEMA, invitation['schema'])
        published = f.validate_document(f.verify(invitation['rootPublic'], invitation['published']))
        self.assertEqual(f.NOTEBOOK_WG_VERSION, published['schema'])
        self.assertEqual({self.a.id: 'administrator', self.b.id: 'user'},
                         {item['id']: item['role'] for item in published['config']['notebooks']})
        user = next(item for item in published['config']['notebooks'] if item['id'] == self.b.id)
        self.assertEqual(('User notebook', 'user', '10.147.0.3', '10.203.0.3'),
                         (user['name'], user['role'], user['zeroTierAddress'], user['wireguardAddress']))
        self.assertEqual(32, len(__import__('base64').b64decode(user['wireguardKey'])))
        self.assertEqual(invitation['published'], f.read(self.a.fleet / 'published.json'))
        self.assertNotIn(self.b.id, published['members'])

        status = self.b.accept_user_invitation(raw)
        self.assertEqual(('valid', 'user', self.b.id), (status['state'], status['role'], status['subject']))
        self.assertFalse((self.b.fleet / 'root.pem').exists())
        self.assertTrue((self.b.fleet / 'root.pub').exists())
        self.assertTrue((self.b.fleet / 'published.json').exists())
        config = (self.b.root / 'wireguard.conf').read_text()
        self.assertEqual(0o600, (self.b.root / 'wireguard.conf').stat().st_mode & 0o777)
        self.assertEqual(0o600, (self.b.root / 'wireguard.key').stat().st_mode & 0o777)
        self.assertIn('Address = 10.203.0.3/32', config)
        self.assertIn('Endpoint = 10.147.0.1:51830', config)
        self.assertIn('AllowedIPs = 10.203.0.1/32, 192.168.1.0/24', config)
        self.assertNotIn('PostUp', config)
        self.assertNotIn('forward', config.lower())
        self.assertFalse((self.b.root / 'pending-enrollment.json').exists())
        with self.assertRaisesRegex(ValueError, 'již má'):
            self.b.accept_user_invitation(raw)
        with self.assertRaisesRegex(ValueError, 'administrátorské pověření'):
            n.command(self.b, {'action': 'pair', 'peer': self.a.id})

    def test_admin_revokes_user_in_new_revision_without_deleting_local_identity(self):
        invitation = self.onboard_user()
        before = f.validate_document(f.verify(invitation['rootPublic'], invitation['published']))
        credential = (self.b.root / 'credential.json').read_bytes()
        identity = (self.b.root / 'key.pem').read_bytes()
        wireguard = (self.b.root / 'wireguard.key').read_bytes()

        with self.assertRaisesRegex(ValueError, 'výslovné potvrzení'):
            n.command(self.a, {'action': 'revoke_user_notebook', 'notebookId': self.b.id})
        result = n.command(self.a, {'action': 'revoke_user_notebook',
                                    'notebookId': self.b.id, 'confirm': True})
        published = f.read(self.a.fleet / 'published.json')
        document = f.validate_document(f.verify(invitation['rootPublic'], published))
        self.assertEqual(before['revision'] + 1, document['revision'])
        self.assertEqual((self.b.id, 'User notebook', document['revision']),
                         (result['revoked']['id'], result['revoked']['name'], result['revoked']['revision']))
        self.assertNotIn(self.b.id, [item['id'] for item in document['config']['notebooks']])
        self.assertIn(self.a.id, [item['id'] for item in document['config']['notebooks']])

        # Receiving the signed revocation invalidates access, while local
        # credentials and private identities remain available for recovery.
        f.atomic(self.b.fleet / 'published.json', published)
        self.assertEqual('invalid', self.b.access_status()['state'])
        self.assertEqual(credential, (self.b.root / 'credential.json').read_bytes())
        self.assertEqual(identity, (self.b.root / 'key.pem').read_bytes())
        self.assertEqual(wireguard, (self.b.root / 'wireguard.key').read_bytes())
        with self.assertRaisesRegex(ValueError, 'už není členem'):
            self.a.revoke_user_notebook(self.b.id)

    def test_user_revocation_cannot_claim_to_revoke_administrator_root_holder(self):
        self.published_federation(self.a)
        self.a.bootstrap_admin_credential()
        with self.assertRaisesRegex(ValueError, 'Administrátorský notebook'):
            self.a.revoke_user_notebook(self.a.id)

    def test_user_previews_and_atomically_applies_newer_signed_topology(self):
        invitation = self.onboard_user()
        identity = (self.b.root / 'key.pem').read_bytes()
        old_config = (self.b.root / 'wireguard.conf').read_bytes()
        public = invitation['rootPublic']
        current = f.validate_document(f.verify(public, f.read(self.a.fleet / 'published.json')))
        updated_config = copy.deepcopy(current['config'])
        updated_config['nodes'][0]['lanCidrs'] = ['192.168.2.0/24']
        f.snapshot(self.a.fleet, updated_config, current['members'])
        update = self.a.topology_update_export()

        forwarding = {'ipv4': True, 'ipv6': False}
        old_uuid, new_uuid = str(uuid.uuid4()), str(uuid.uuid4())
        managed = {n.VPN_CONNECTION: {'uuid': old_uuid, 'type': 'wireguard'}}
        with patch.object(n.Store, 'forwarding_state', return_value=forwarding), \
                patch.object(n, 'nmcli_connections', return_value=managed), \
                patch.object(n, 'verify_underlay', return_value='zt1234'):
            plan = self.b.topology_refresh_plan(update)
        self.assertEqual(('update', current['revision'], current['revision'] + 1),
                         (plan['kind'], plan['currentRevision'], plan['revision']))
        self.assertEqual(['192.168.2.0/24'], plan['addedRoutes'])
        self.assertEqual(['192.168.1.0/24'], plan['removedRoutes'])
        self.assertEqual(forwarding, plan['forwarding'])
        self.assertNotIn('update', plan)
        self.assertNotIn('configHash', plan)

        f.atomic(self.b.root / 'vpn-state.json', {'state': 'installed', 'activeUuid': old_uuid,
                 'backupUuid': None, 'revision': current['revision'], 'address': '10.203.0.3/32',
                 'routes': ['10.203.0.1/32', '192.168.1.0/24']})
        calls = []
        with patch.object(n.Store, 'forwarding_state', return_value=forwarding), \
                patch.object(n, 'verify_underlay', return_value='zt1234'), \
                patch.object(n, 'nmcli_connections', return_value=managed), \
                patch.object(n, 'nmcli_uuids', side_effect=[{old_uuid}, {old_uuid, new_uuid}]), \
                patch.object(n, 'privileged_nmcli', side_effect=lambda args, **kwargs: calls.append(args) or ''), \
                patch.object(n, 'verify_vpn') as verify:
            result = n.command(self.b, {'action': 'topology_refresh_apply',
                                        'planId': plan['id'], 'confirm': True})
        self.assertEqual(('update', current['revision'] + 1, 'valid', 'installed'),
                         (result['kind'], result['revision'], result['access']['state'], result['vpn']['state']))
        verify.assert_called_once_with('10.203.0.3', ['10.203.0.1/32', '192.168.2.0/24'])
        self.assertNotEqual(old_config, (self.b.root / 'wireguard.conf').read_bytes())
        self.assertEqual(identity, (self.b.root / 'key.pem').read_bytes())
        accepted = f.validate_document(f.verify(public, f.read(self.b.fleet / 'published.json')))
        self.assertEqual(current['revision'] + 1, accepted['revision'])
        self.assertFalse((self.b.root / 'topology-refresh-plan.json').exists())
        self.assertFalse((self.b.root / 'wireguard-refresh.conf').exists())

    def test_topology_refresh_rejects_old_foreign_and_role_changing_documents(self):
        invitation = self.onboard_user()
        with self.assertRaisesRegex(ValueError, 'novější revizi'):
            self.b.topology_refresh_plan(self.a.topology_update_export())

        foreign = json.loads(self.a.topology_update_export())
        foreign['rootPublic'] = f.public_key(self.c.root / 'key.pem')
        with self.assertRaisesRegex(ValueError, 'jinou kotvu'):
            self.b.topology_refresh_plan(json.dumps(foreign))

        public = invitation['rootPublic']
        current = f.validate_document(f.verify(public, f.read(self.a.fleet / 'published.json')))
        changed = copy.deepcopy(current['config'])
        target = next(item for item in changed['notebooks'] if item['id'] == self.b.id)
        target['role'] = 'administrator'
        envelope = f.snapshot(self.a.fleet, changed, current['members'])
        update = json.dumps({'schema': n.TOPOLOGY_UPDATE_SCHEMA,
                             'rootPublic': public, 'published': envelope})
        with self.assertRaisesRegex(ValueError, 'mění roli'):
            self.b.topology_refresh_plan(update)

    def test_topology_refresh_restores_profile_and_revision_after_commit_failure(self):
        invitation = self.onboard_user()
        public = invitation['rootPublic']
        old_envelope = f.read(self.b.fleet / 'published.json')
        old_config = (self.b.root / 'wireguard.conf').read_bytes()
        current = f.validate_document(f.verify(public, old_envelope))
        changed = copy.deepcopy(current['config'])
        changed['nodes'][0]['lanCidrs'] = ['192.168.9.0/24']
        f.snapshot(self.a.fleet, changed, current['members'])
        forwarding = {'ipv4': False, 'ipv6': False}
        old_uuid, new_uuid = str(uuid.uuid4()), str(uuid.uuid4())
        managed = {n.VPN_CONNECTION: {'uuid': old_uuid, 'type': 'wireguard'}}
        with patch.object(n.Store, 'forwarding_state', return_value=forwarding), \
                patch.object(n, 'nmcli_connections', return_value=managed), \
                patch.object(n, 'verify_underlay', return_value='zt1234'):
            plan = self.b.topology_refresh_plan(self.a.topology_update_export())

        real_atomic = f.atomic

        def fail_receipt(path, value):
            if Path(path) == self.b.root / 'vpn-state.json' and value.get('state') == 'installed':
                raise OSError('receipt failed')
            return real_atomic(path, value)

        calls = []
        with patch.object(n.Store, 'forwarding_state', return_value=forwarding), \
                patch.object(n, 'verify_underlay', return_value='zt1234'), \
                patch.object(n, 'nmcli_connections', return_value=managed), \
                patch.object(n, 'nmcli_uuids', side_effect=[{old_uuid}, {old_uuid, new_uuid}]), \
                patch.object(n, 'privileged_nmcli', side_effect=lambda args, **kwargs: calls.append(args) or ''), \
                patch.object(n, 'verify_vpn'), patch.object(f, 'atomic', side_effect=fail_receipt), \
                self.assertRaisesRegex(ValueError, 'předchozí profil byl obnoven'):
            self.b.topology_refresh_apply(plan['id'])
        self.assertEqual(old_envelope, f.read(self.b.fleet / 'published.json'))
        self.assertEqual(old_config, (self.b.root / 'wireguard.conf').read_bytes())
        self.assertIn(['connection', 'delete', 'uuid', new_uuid], calls)
        self.assertIn(['connection', 'modify', 'uuid', old_uuid,
                       'connection.id', n.VPN_CONNECTION], calls)

    def test_signed_revocation_disconnects_vpn_but_preserves_identity(self):
        self.onboard_user()
        identity = (self.b.root / 'key.pem').read_bytes()
        credential = (self.b.root / 'credential.json').read_bytes()
        wireguard = (self.b.root / 'wireguard.key').read_bytes()
        active = str(uuid.uuid4())
        f.atomic(self.b.root / 'vpn-state.json', {'state': 'installed', 'activeUuid': active,
                 'backupUuid': None, 'revision': 3, 'address': '10.203.0.3/32', 'routes': []})
        self.a.revoke_user_notebook(self.b.id)
        backup = str(uuid.uuid4())
        managed = {
            n.VPN_CONNECTION: {'uuid': active, 'type': 'wireguard'},
            n.VPN_BACKUP: {'uuid': backup, 'type': 'wireguard'},
        }
        with patch.object(n, 'nmcli_connections', return_value=managed):
            plan = self.b.topology_refresh_plan(self.a.topology_update_export())
        self.assertEqual('revoked', plan['kind'])
        self.assertNotIn('underlayDevice', plan)
        with self.assertRaisesRegex(ValueError, 'výslovné potvrzení'):
            n.command(self.b, {'action': 'topology_refresh_apply', 'planId': plan['id']})
        calls = []
        with patch.object(n, 'nmcli_connections', return_value=managed), \
                patch.object(n, 'privileged_nmcli', side_effect=lambda args, **kwargs: calls.append(args) or ''):
            result = n.command(self.b, {'action': 'topology_refresh_apply',
                                        'planId': plan['id'], 'confirm': True})
        self.assertEqual(('revoked', 'invalid', 'revoked'),
                         (result['kind'], result['access']['state'], result['vpn']['state']))
        self.assertEqual([['connection', 'delete', 'uuid', backup],
                          ['connection', 'delete', 'uuid', active]], calls)
        self.assertEqual(identity, (self.b.root / 'key.pem').read_bytes())
        self.assertEqual(credential, (self.b.root / 'credential.json').read_bytes())
        self.assertEqual(wireguard, (self.b.root / 'wireguard.key').read_bytes())

    def test_user_credential_fails_if_signed_topology_does_not_contain_notebook(self):
        self.published_federation(self.a)
        self.a.bootstrap_admin_credential()
        request = self.b.enrollment_request('User notebook')
        invitation = self.a.issue_user_invitation(json.dumps(request))
        old_published = self.published_federation(self.c)
        old_public = f.public_key(self.c.fleet / 'root.pem')
        document = f.verify(invitation['rootPublic'], invitation['published'])
        old_document = f.verify(old_public, old_published)
        old_document.update(federationId=document['federationId'], revision=document['revision'] + 1,
                            previous=f.digest(document))
        invitation['published'] = f.sign(self.a.fleet / 'root.pem', old_document)
        with self.assertRaisesRegex(ValueError, 'neodpovídá'):
            self.b.accept_user_invitation(json.dumps(invitation))

    def test_user_invitation_rejects_wrong_notebook_tampering_and_expiry(self):
        self.published_federation(self.a)
        self.a.bootstrap_admin_credential()
        request = self.b.enrollment_request('User notebook')
        invitation = self.a.issue_user_invitation(json.dumps(request))
        self.c.enrollment_request('Other notebook')
        with self.assertRaisesRegex(ValueError, 'neodpovídá'):
            self.c.accept_user_invitation(json.dumps(invitation))
        tampered = copy.deepcopy(invitation)
        tampered['published']['payload'] = tampered['published']['payload'][:-2] + 'AA'
        with self.assertRaises(ValueError):
            self.b.accept_user_invitation(json.dumps(tampered))
        credential = f.verify(invitation['rootPublic'], invitation['credential'])
        with patch.object(n.time, 'time', return_value=credential['acceptBy'] + 1):
            with self.assertRaisesRegex(ValueError, 'neodpovídá'):
                self.b.accept_user_invitation(json.dumps(invitation))

    def test_vpn_install_uses_reviewed_plan_and_never_passes_private_key_in_arguments(self):
        self.onboard_user()
        forwarding = {'ipv4': True, 'ipv6': False}
        with patch.object(n.Store, 'forwarding_state', return_value=forwarding), \
                patch.object(n, 'nmcli_connections', return_value={}), \
                patch.object(n, 'verify_underlay', return_value='zt1234'):
            plan = self.b.vpn_plan()
        self.assertEqual(('tf_notebook', '10.203.0.3/32'), (plan['interfaceName'], plan['address']))
        self.assertEqual(['10.203.0.1/32', '192.168.1.0/24'], plan['routes'])
        self.assertEqual(forwarding, plan['forwarding'])
        self.assertNotIn('configHash', plan)

        new_uuid = str(uuid.uuid4())
        calls = []
        with patch.object(n.Store, 'forwarding_state', return_value=forwarding), \
                patch.object(n, 'nmcli_connections', return_value={}), \
                patch.object(n, 'nmcli_uuids', side_effect=[set(), {new_uuid}]), \
                patch.object(n, 'privileged_nmcli', side_effect=lambda args, **kwargs: calls.append(args) or ''), \
                patch.object(n, 'verify_underlay', return_value='zt1234'), \
                patch.object(n, 'verify_vpn') as verify:
            state = self.b.vpn_install(plan['id'])
        self.assertEqual('installed', state['state'])
        verify.assert_called_once_with('10.203.0.3', plan['routes'])
        arguments = repr(calls)
        self.assertIn("'connection', 'import', 'type', 'wireguard', 'file'", arguments)
        self.assertIn("'ipv4.never-default', 'yes'", arguments)
        self.assertIn("'ipv6.never-default', 'yes'", arguments)
        self.assertIn("'ipv4.route-metric', '2048'", arguments)
        self.assertIn("'ipv6.route-metric', '2048'", arguments)
        self.assertNotIn((self.b.root / 'wireguard.key').read_text().strip(), arguments)

    def test_failed_vpn_activation_restores_previous_profile(self):
        self.onboard_user()
        forwarding = {'ipv4': False, 'ipv6': False}
        old_uuid, new_uuid = str(uuid.uuid4()), str(uuid.uuid4())
        with patch.object(n.Store, 'forwarding_state', return_value=forwarding), \
                patch.object(n, 'nmcli_connections', return_value={n.VPN_CONNECTION: {'uuid': old_uuid, 'type': 'wireguard'}}), \
                patch.object(n, 'verify_underlay', return_value='zt1234'):
            plan = self.b.vpn_plan()
        calls = []
        with patch.object(n.Store, 'forwarding_state', return_value=forwarding), \
                patch.object(n, 'nmcli_connections', return_value={n.VPN_CONNECTION: {'uuid': old_uuid, 'type': 'wireguard'}}), \
                patch.object(n, 'nmcli_uuids', side_effect=[{old_uuid}, {old_uuid, new_uuid}]), \
                patch.object(n, 'privileged_nmcli', side_effect=lambda args, **kwargs: calls.append(args) or ''), \
                patch.object(n, 'verify_underlay', return_value='zt1234'), \
                patch.object(n, 'verify_vpn', side_effect=ValueError('missing route')), \
                self.assertRaisesRegex(ValueError, 'předchozí profil byl obnoven'):
            self.b.vpn_install(plan['id'])
        self.assertIn(['connection', 'modify', 'uuid', old_uuid, 'connection.id', n.VPN_BACKUP], calls)
        self.assertIn(['connection', 'down', 'uuid', old_uuid], calls)
        self.assertIn(['connection', 'delete', 'uuid', new_uuid], calls)
        self.assertIn(['connection', 'modify', 'uuid', old_uuid, 'connection.id', n.VPN_CONNECTION], calls)
        self.assertIn(['connection', 'up', 'uuid', old_uuid], calls)
        self.assertEqual({'state': 'error', 'error': 'Instalace VPN selhala.', 'rollbackComplete': True},
                         {key: self.b.vpn_status()[key] for key in ['state', 'error', 'rollbackComplete']})

    def test_vpn_plan_warns_about_forwarding_and_rollback_requires_confirmation(self):
        self.onboard_user()
        with patch.object(n.Store, 'forwarding_state', return_value={'ipv4': True, 'ipv6': False}), \
                patch.object(n, 'nmcli_connections', return_value={}) as connections, \
                patch.object(n, 'verify_underlay', return_value='zt1234'):
            plan = self.b.vpn_plan()
        self.assertEqual({'ipv4': True, 'ipv6': False}, plan['forwarding'])
        self.assertTrue(any('forwarding' in step for step in plan['steps']))
        connections.assert_called_once_with()
        with self.assertRaisesRegex(ValueError, 'výslovné potvrzení'):
            n.command(self.b, {'action': 'vpn_rollback'})

    def test_disconnect_requires_confirmation_rolls_back_vpn_and_stops_sync(self):
        (self.b.root / 'config.json').write_text(json.dumps({'enabled': True, 'name': 'User'}))
        with self.assertRaisesRegex(ValueError, 'výslovné potvrzení'):
            n.command(self.b, {'action': 'disconnect'})
        with patch.object(n.Store, 'vpn_status', return_value={'state': 'installed'}), \
                patch.object(n.Store, 'vpn_rollback', return_value={'state': 'rolled_back'}) as rollback:
            result = n.command(self.b, {'action': 'disconnect', 'confirm': True})
        rollback.assert_called_once_with()
        self.assertFalse(f.read(self.b.root / 'config.json')['enabled'])
        self.assertFalse(result['config']['enabled'])

    def test_vpn_plan_requires_signed_zerotier_address_and_router_routes_on_underlay(self):
        self.onboard_user()
        document = f.validate_document(f.verify(
            (self.b.root / 'federation-root.pub').read_text(), f.read(self.b.fleet / 'published.json')))
        outputs = [
            json.dumps([{'ifname': 'zt1234', 'addr_info': [
                {'family': 'inet', 'local': '10.147.0.3'}]}]),
            json.dumps([{'dev': 'zt1234'}]),
        ]
        with patch.object(n, 'local_command', side_effect=outputs):
            self.assertEqual('zt1234', n.verify_underlay('10.147.0.3', document))
        with patch.object(n, 'local_command', return_value='[]'), \
                self.assertRaisesRegex(ValueError, 'není jednoznačně'):
            n.verify_underlay('10.147.0.3', document)

    def test_local_vpn_diagnostics_use_only_signed_router_targets(self):
        self.onboard_user()
        profile_uuid = str(uuid.uuid4())
        document = f.validate_document(f.verify(
            (self.b.root / 'federation-root.pub').read_text(), f.read(self.b.fleet / 'published.json')))
        router_id = str(uuid.UUID(int=1))
        router_key = document['members'][router_id]['wireguardKey']
        now = time.time()

        def local(args, **_kwargs):
            if args[:5] == ['/usr/sbin/ip', '-j', 'link', 'show', 'dev']:
                return json.dumps([{'ifname': n.VPN_INTERFACE}])
            if args[:6] == ['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev']:
                return json.dumps([{'addr_info': [{'family': 'inet', 'local': '10.203.0.3'}]}])
            if args[:6] == ['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'dev']:
                return json.dumps([{'dst': '10.203.0.1'}, {'dst': '192.168.1.0/24'}])
            if args[:3] == ['/usr/bin/wg', 'show', n.VPN_INTERFACE]:
                return f'{router_key}\t{int(now)}\n'
            raise AssertionError(args)

        measurement = {'address': '10.203.0.1', 'samples': [True] * 5,
                       'checkedAt': now, 'successPercent': 100}
        with patch.object(n, 'nmcli_connections', return_value={
                    n.VPN_CONNECTION: {'uuid': profile_uuid, 'type': 'wireguard'}}), \
                patch.object(n, 'nmcli_active_uuids', return_value={profile_uuid}), \
                patch.object(n, 'local_command', side_effect=local), \
                patch.object(n.Store, 'forwarding_state', return_value={'ipv4': False, 'ipv6': False}), \
                patch.object(f, 'ping_batch', return_value=measurement) as ping:
            result = n.command(self.b, {'action': 'vpn_diagnostics'})['diagnostics']

        self.assertEqual(('active', True, True),
                         (result['profile'], result['interfacePresent'], result['addressAssigned']))
        self.assertEqual((2, 2, [], []),
                         (result['routesExpected'], result['routesActive'], result['missingRoutes'], result['unknownRoutes']))
        self.assertEqual('recent', result['nodes'][router_id]['handshakeState'])
        self.assertEqual([(('10.203.0.1', n.VPN_INTERFACE), {})],
                         [(call.args, call.kwargs) for call in ping.call_args_list])
        self.assertNotIn(router_key, json.dumps(result))
        self.assertEqual(result, self.b.vpn_status()['diagnostics'])

    def test_local_vpn_diagnostics_report_unknown_handshake_and_missing_routes(self):
        self.onboard_user()

        def local(args, **_kwargs):
            if args[:5] == ['/usr/sbin/ip', '-j', 'link', 'show', 'dev']:
                raise ValueError('missing interface')
            if args[:6] == ['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev']:
                raise ValueError('missing interface')
            if args[:6] == ['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'dev']:
                raise ValueError('missing interface')
            if args[:3] == ['/usr/bin/wg', 'show', n.VPN_INTERFACE]:
                raise ValueError('permission denied')
            if args[:4] == ['/usr/bin/pkexec', '/usr/bin/wg', 'show', n.VPN_INTERFACE]:
                raise ValueError('permission denied')
            raise AssertionError(args)

        unavailable = {'address': '10.203.0.1', 'samples': [],
                       'checkedAt': time.time(), 'successPercent': None}
        with patch.object(n, 'nmcli_connections', return_value={}), \
                patch.object(n, 'nmcli_active_uuids', return_value=set()), \
                patch.object(n, 'local_command', side_effect=local), \
                patch.object(n.Store, 'forwarding_state', return_value={'ipv4': False, 'ipv6': False}), \
                patch.object(f, 'ping_batch', return_value=unavailable):
            result = self.b.vpn_diagnostics()
        self.assertEqual(('missing', None, None),
                         (result['profile'], result['interfacePresent'], result['addressAssigned']))
        self.assertEqual((2, 0), (result['routesExpected'], result['routesActive']))
        self.assertEqual('unknown', next(iter(result['nodes'].values()))['handshakeState'])

    def test_explicit_vpn_rollback_restores_saved_profile(self):
        self.onboard_user()
        active, backup = str(uuid.uuid4()), str(uuid.uuid4())
        f.atomic(self.b.root / 'vpn-state.json', {'state': 'installed', 'activeUuid': active,
                 'backupUuid': backup, 'revision': 3, 'address': '10.203.0.3/32', 'routes': []})
        calls = []
        with patch.object(n, 'privileged_nmcli', side_effect=lambda args, **kwargs: calls.append(args) or ''):
            result = n.command(self.b, {'action': 'vpn_rollback', 'confirm': True})['vpn']
        self.assertEqual('rolled_back', result['state'])
        self.assertEqual([
            ['connection', 'modify', 'uuid', active, 'connection.id', n.VPN_REPLACED],
            ['connection', 'modify', 'uuid', backup, 'connection.id', n.VPN_CONNECTION],
            ['connection', 'up', 'uuid', backup],
            ['connection', 'delete', 'uuid', active],
        ], calls)

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
        self.admin_command(self.a, {'action': 'resolve', 'peer': self.b.id, 'choice': 'remote', 'token': peer['conflictToken']})
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
            self.admin_command(self.a, {'action': 'resolve', 'peer': self.b.id, 'choice': 'remote', 'token': token})

    def test_foreign_root_is_never_overwritten(self):
        self.node(self.a)
        self.root_identity(self.a)
        self.root_identity(self.b)
        original = (self.b.fleet / 'root.pem').read_bytes()
        self.assertEqual('conflict', self.b.receive(self.a.id, self.snapshot(self.a)))
        peer = self.b.status()['peers'][0]
        with self.assertRaisesRegex(ValueError, 'kotvě důvěry'):
            self.admin_command(self.b, {'action': 'resolve', 'peer': self.a.id, 'choice': 'remote', 'token': peer['conflictToken']})
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
        self.admin_command(self.b, {'action': 'unpair', 'peer': self.a.id})
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
        self.admin_command(self.b, {'action': 'pair', 'peer': self.a.id})
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
        self.admin_command(self.c, {'action': 'manual', 'invitation': json.dumps({'name': 'A', 'address': '10.4.0.1', 'cert': self.a.cert})})
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
                self.admin_command(self.a, {'action': 'unpair', 'peer': self.b.id})
                with self.assertRaises((ssl.SSLError, OSError)):
                    n.fetch(self.b, self.b.peers()[self.a.id])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)

    def test_local_backend_socket_is_private_and_read_only(self):
        socket_path = Path(self.temp.name) / 'runtime' / 'backend.sock'
        server = n.make_local_server(self.a, socket_path)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            self.assertEqual(0o600, socket_path.stat().st_mode & 0o777)
            self.assertEqual(0o700, socket_path.parent.stat().st_mode & 0o777)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(socket_path))
                client.sendall(b'{"action":"status"}\n')
                response = json.loads(client.makefile().readline())
            self.assertTrue(response['ok'])
            self.assertTrue(response['backend']['running'])
            self.assertEqual(os.getpid(), response['backend']['pid'])
            self.assertNotIn('PRIVATE KEY', json.dumps(response))
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(socket_path))
                client.sendall(b'{"action":"stop"}\n')
                rejected = json.loads(client.makefile().readline())
            self.assertFalse(rejected['ok'])
            self.assertIn('pouze pro čtení', rejected['error'])
        finally:
            server.shutdown()
            server.server_close()
            socket_path.unlink(missing_ok=True)
            worker.join(2)
        real_runtime = Path(self.temp.name) / 'real-runtime'
        real_runtime.mkdir()
        linked_runtime = Path(self.temp.name) / 'linked-runtime'
        linked_runtime.symlink_to(real_runtime, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symbolický odkaz'):
            n.make_local_server(self.a, linked_runtime / 'backend.sock')

    def test_disabled_backend_stays_alive_and_reports_over_local_socket(self):
        service_dir = Path(self.temp.name) / 'idle-service'
        service_dir.mkdir()
        shutil.copy(ROOT / 'scripts/notebook_sync.py', service_dir / 'notebook_sync.py')
        shutil.copy(ROOT / 'router/files/usr/lib/turris-federation/federation.py', service_dir / 'federation.py')
        socket_path = self.a.root / 'idle-backend.sock'
        process = subprocess.Popen(
            [sys.executable, service_dir / 'notebook_sync.py', 'serve', self.a.data_dir],
            env=dict(os.environ, TF_BACKEND_SOCKET=str(socket_path)),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not socket_path.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertIsNone(process.poll(), process.stderr.read().decode() if process.poll() is not None else '')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(socket_path))
                client.sendall(b'{"action":"status"}\n')
                response = json.loads(client.makefile().readline())
            self.assertTrue(response['ok'])
            self.assertTrue(response['backend']['running'])
            self.assertFalse(response['status']['config'].get('enabled', False))
        finally:
            process.kill()
            process.communicate(timeout=5)

    def test_two_running_services_sync_both_directions_without_controller(self):
        self.node(self.a)
        self.root_identity(self.a)
        service_dir = Path(self.temp.name) / 'service'
        service_dir.mkdir()
        shutil.copy(ROOT / 'scripts/notebook_sync.py', service_dir / 'notebook_sync.py')
        shutil.copy(ROOT / 'router/files/usr/lib/turris-federation/federation.py', service_dir / 'federation.py')
        links = [{'ifname': 'zt' + ip.replace('.', ''),
                  'addr_info': [{'local': ip, 'prefixlen': 8, 'scope': 'global'}]}
                 for ip in ['127.0.0.2', '127.0.0.3']]
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
                    env=dict(os.environ, PATH=str(service_dir) + ':' + os.environ['PATH'],
                             TF_BACKEND_SOCKET=str(store.root / 'backend.sock')),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE))

            def wait_name(store, name):
                end = time.monotonic() + 8
                while time.monotonic() < end:
                    for process in processes:
                        if process.poll() is not None:
                            self.fail('Service stopped: ' + process.communicate()[1].decode())
                    with contextlib.closing(sqlite3.connect(store.data_dir / 'federation.db')) as db:
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
