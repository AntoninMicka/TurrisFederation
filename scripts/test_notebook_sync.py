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
from unittest.mock import Mock, patch
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

    def test_nmcli_connections_recovers_orphan_by_reserved_interface(self):
        orphan_uuid = str(uuid.uuid4())

        def connection_show(args, **_kwargs):
            if args[1:6] == ['-t', '-f', 'UUID,TYPE', 'connection', 'show'] and len(args) == 6:
                return f'{orphan_uuid}:wireguard\n'
            if args[1:4] == ['-g', 'connection.interface-name', 'connection']:
                return n.VPN_INTERFACE + '\n'
            return ''

        with patch.object(n, 'local_command', side_effect=connection_show):
            self.assertEqual(
                {n.VPN_CONNECTION: {'uuid': orphan_uuid, 'type': 'wireguard'}},
                n.nmcli_connections())

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

    def staged_user_invitation(self, target=None, name='User notebook', address='10.147.0.3'):
        target = target or self.b
        if not (self.a.fleet / 'published.json').exists():
            self.published_federation(self.a)
        if self.a.access_status().get('role') != 'administrator':
            self.a.bootstrap_admin_credential()
        request = target.enrollment_request(name)
        grant = self.a.issue_user_join_grant(json.dumps(request))
        target.accept_user_join_grant(json.dumps(grant))
        addresses = json.dumps([{'ifname': 'zt1234', 'addr_info': [
            {'family': 'inet', 'local': address, 'prefixlen': 24, 'scope': 'global'}]}])
        with patch.object(n, 'local_command', return_value=addresses):
            confirmation = target.enrollment_address_confirmation('abcdef1234')
        invitation = self.a.issue_user_invitation(json.dumps(confirmation))
        return request, grant, confirmation, invitation

    def onboard_user(self):
        _, _, _, invitation = self.staged_user_invitation()
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
        service = {'id': 'ollama', 'name': 'Ollama', 'hostAddress': '192.168.1.20',
                   'protocol': 'tcp', 'port': 11434, 'path': None}
        f.atomic(self.a.fleet / 'reports.json', {str(uuid.UUID(int=1)): {
            'services': [service], 'servicesObservedAt': 100,
            'software': {'version': 'a' * 64, 'builtAt': 99}}})
        request, grant, confirmation, invitation = self.staged_user_invitation()
        raw = json.dumps(invitation)
        self.assertNotIn('PRIVATE KEY', raw)
        self.assertNotIn('PRIVATE KEY', json.dumps(grant))
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
        self.assertIn('operational', invitation)
        self.assertEqual(n.software_info(), f.read(self.a.fleet / 'notebook-software.json')[self.b.id])

        status = self.b.accept_user_invitation(raw)
        self.assertEqual(('valid', 'user', self.b.id), (status['state'], status['role'], status['subject']))
        self.assertFalse((self.b.fleet / 'root.pem').exists())
        self.assertTrue((self.b.fleet / 'root.pub').exists())
        self.assertTrue((self.b.fleet / 'published.json').exists())
        overview = f.read_only_notebook_overview(self.b.fleet)
        self.assertEqual('ollama', overview['services'][0]['id'])
        self.assertEqual('a' * 64, overview['nodes'][0]['software']['version'])
        self.assertEqual(n.software_info(),
                         next(item for item in overview['notebooks'] if item['id'] == self.a.id)['software'])
        self.assertEqual(n.software_info(),
                         next(item for item in overview['notebooks'] if item['id'] == self.b.id)['software'])
        config = (self.b.root / 'wireguard.conf').read_text()
        self.assertEqual(0o600, (self.b.root / 'wireguard.conf').stat().st_mode & 0o777)
        self.assertEqual(0o600, (self.b.root / 'wireguard.key').stat().st_mode & 0o777)
        self.assertIn('Address = 10.203.0.3/32', config)
        self.assertIn('Endpoint = 10.147.0.1:51830', config)
        self.assertIn('AllowedIPs = 10.203.0.1/32, 192.168.1.0/24', config)
        self.assertNotIn('PostUp', config)
        self.assertNotIn('forward', config.lower())
        self.assertFalse((self.b.root / 'pending-enrollment.json').exists())
        self.assertFalse((self.b.root / 'pending-join.json').exists())
        self.assertFalse((self.b.root / 'pending-address-confirmation.json').exists())
        with self.assertRaisesRegex(ValueError, 'neodpovídá'):
            self.b.accept_user_invitation(raw)
        with self.assertRaisesRegex(ValueError, 'administrátorské pověření'):
            n.command(self.b, {'action': 'pair', 'peer': self.a.id})

    def test_join_grant_waits_for_observed_address_before_publishing_member(self):
        self.published_federation(self.a)
        self.a.bootstrap_admin_credential()
        original = f.read(self.a.fleet / 'published.json')
        request = self.b.enrollment_request('Travel notebook')
        grant = self.a.issue_user_join_grant(json.dumps(request))
        self.assertEqual(original, f.read(self.a.fleet / 'published.json'))
        self.assertNotIn('credential', grant)
        accepted = self.b.accept_user_join_grant(json.dumps(grant))
        self.assertEqual('abcdef0123456789', accepted['networkId'])
        addresses = json.dumps([{'ifname': 'ztactual1', 'addr_info': [
            {'family': 'inet', 'local': '10.147.0.59'}]}])
        with patch.object(n, 'local_command', return_value=addresses):
            confirmation = self.b.enrollment_address_confirmation('abcdef1234')
        invitation = self.a.issue_user_invitation(json.dumps(confirmation))
        document = f.validate_document(f.verify(invitation['rootPublic'], invitation['published']))
        endpoint = next(item for item in document['config']['notebooks'] if item['id'] == self.b.id)
        self.assertEqual('10.147.0.59', endpoint['zeroTierAddress'])
        self.assertEqual('user', endpoint['role'])

    def test_address_confirmation_requires_one_authorized_zerotier_address_and_device_id(self):
        self.published_federation(self.a)
        self.a.bootstrap_admin_credential()
        request = self.b.enrollment_request('User notebook')
        grant = self.a.issue_user_join_grant(json.dumps(request))
        self.b.accept_user_join_grant(json.dumps(grant))
        with patch.object(n, 'local_command', return_value='[]'), \
                self.assertRaisesRegex(ValueError, 'jednoznačně'):
            self.b.enrollment_address_confirmation('abcdef1234')
        addresses = json.dumps([{'ifname': 'zt1234', 'addr_info': [
            {'family': 'inet', 'local': '10.147.0.59'}]}])
        with patch.object(n, 'local_command', return_value=addresses), \
                self.assertRaisesRegex(ValueError, 'Device ID'):
            self.b.enrollment_address_confirmation('invalid')

    def test_network_enrollment_uses_short_code_and_sends_signed_join_status(self):
        state = self.b.network_enrollment_start('Travel notebook')
        self.assertEqual('requesting', state['session']['stage'])
        self.assertRegex(state['session']['code'], r'^[0-9A-F]{6}$')
        session = f.read(self.b.root / 'network-enrollment.json')
        self.assertEqual(n.pairing_code(session['request']), state['session']['code'])

        self.published_federation(self.a)
        self.a.bootstrap_admin_credential()
        request = session['request']
        payload = self.a.validate_enrollment_request(request)
        f.atomic(self.a.root / 'network-enrollment-candidates.json', {
            payload['subject']: {'name': payload['name'], 'address': '192.168.50.20',
                                 'request': request, 'code': state['session']['code'],
                                 'seenAt': time.time(), 'stage': 'requesting'}})
        with patch.object(n, 'enrollment_post') as post:
            approved = self.a.network_enrollment_approve_request(payload['subject'])
        self.assertEqual('awaiting_address', approved['candidates'][0]['stage'])
        post.assert_not_called()
        grant = f.read(self.a.root / 'network-enrollment-candidates.json')[payload['subject']]['grant']
        self.b.accept_user_join_grant(json.dumps(grant))
        join_status = self.b.enrollment_join_status('abcdef1234')
        claim = self.a.validate_join_status(join_status)
        self.assertEqual((self.b.id, 'abcdef1234'),
                         (claim['subject'], claim['zeroTierDeviceId']))
        self.assertEqual(f.digest(request), claim['requestHash'])

    def test_enrollment_transport_reports_unreachable_peer_without_raw_oserror(self):
        connection = Mock()
        connection.request.side_effect = OSError('connection refused')
        with patch.object(n.http.client, 'HTTPConnection', return_value=connection), \
                self.assertRaisesRegex(ValueError, 'neodpovídá na portu 8857.*firewalld'):
            n.enrollment_post('192.168.50.20', '/join-grant', {'signed': 'test'})
        connection.close.assert_called_once()

    def test_target_pulls_signed_grant_from_administrator(self):
        self.published_federation(self.a)
        self.a.bootstrap_admin_credential()
        request = self.b.enrollment_request('Travel notebook')
        payload = self.a.validate_enrollment_request(request)
        grant = self.a.issue_user_join_grant(json.dumps(request))
        f.atomic(self.a.root / 'network-enrollment-candidates.json', {
            payload['subject']: {'name': payload['name'], 'address': '127.0.0.1',
                                 'request': request, 'code': n.pairing_code(request),
                                 'seenAt': time.time(), 'stage': 'awaiting_address', 'grant': grant}})
        with patch.object(n, 'ENROLLMENT_PORT', 0):
            server = n.make_enrollment_server(self.a)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            connection = n.http.client.HTTPConnection('127.0.0.1', server.server_address[1], timeout=2)
            with patch.object(n, 'direct_lan_source', return_value=True):
                connection.request('POST', '/pull', f.encode({'request': request}),
                                   {'Content-Type': 'application/json'})
                response = connection.getresponse()
                result = json.loads(response.read())
            self.assertEqual(200, response.status)
            self.assertEqual(('join-grant', grant), (result['kind'], result['delivery']))
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            worker.join(2)

    def test_enrollment_http_listener_survives_unavailable_multicast(self):
        server = Mock()
        stopped = threading.Event()
        stopped.set()
        with patch.object(n, 'make_enrollment_server', return_value=server), \
                patch.object(n, 'make_enrollment_udp', side_effect=OSError('no multicast')):
            n.serve_enrollment(self.b, stopped)
        listener = f.read(self.b.root / 'network-enrollment-listener.json')
        self.assertEqual(('http_only', n.ENROLLMENT_PORT),
                         (listener['state'], listener['port']))
        server.shutdown.assert_called_once()
        server.server_close.assert_called_once()

    def test_direct_lan_source_excludes_overlay_and_accepts_physical_subnet(self):
        links = json.dumps([
            {'ifname': 'wlan0', 'addr_info': [
                {'family': 'inet', 'local': '192.168.50.10', 'prefixlen': 24}]},
            {'ifname': 'ztabc', 'addr_info': [
                {'family': 'inet', 'local': '10.147.0.2', 'prefixlen': 24}]},
        ])
        with patch.object(n, 'local_command', return_value=links):
            self.assertTrue(n.direct_lan_source('192.168.50.20'))
            self.assertFalse(n.direct_lan_source('10.147.0.3'))
            self.assertFalse(n.direct_lan_source('203.0.113.1'))

    def test_existing_user_can_reenroll_to_replace_incorrect_signed_zerotier_address(self):
        self.onboard_user()
        _, _, _, invitation = self.staged_user_invitation(
            target=self.b, name='Renamed attempt', address='10.147.0.59')
        status = self.b.accept_user_invitation(json.dumps(invitation))
        self.assertEqual(('valid', 'user'), (status['state'], status['role']))
        document = f.validate_document(f.verify(
            invitation['rootPublic'], f.read(self.b.fleet / 'published.json')))
        endpoint = next(item for item in document['config']['notebooks'] if item['id'] == self.b.id)
        self.assertEqual('10.147.0.59', endpoint['zeroTierAddress'])
        self.assertEqual('User notebook', endpoint['name'])

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
        with patch.object(n.Store, 'forwarding_state', return_value=forwarding), \
                patch.object(n, 'system_network_request', return_value={
                    'ok': True, 'vpn': {'state': 'active', 'revision': current['revision'] + 1,
                                        'changed': True}}) as reconcile:
            result = n.command(self.b, {'action': 'topology_refresh_apply',
                                        'planId': plan['id'], 'confirm': True})
        self.assertEqual(('update', current['revision'] + 1, 'valid', 'installed'),
                         (result['kind'], result['revision'], result['access']['state'], result['vpn']['state']))
        applied = reconcile.call_args.args[0]
        self.assertEqual(['10.203.0.1/32', '192.168.2.0/24'], applied['peers'][0]['allowedIps'])
        self.assertNotEqual(old_config, (self.b.root / 'wireguard.conf').read_bytes())
        self.assertEqual(identity, (self.b.root / 'key.pem').read_bytes())
        accepted = f.validate_document(f.verify(public, f.read(self.b.fleet / 'published.json')))
        self.assertEqual(current['revision'] + 1, accepted['revision'])
        self.assertFalse((self.b.root / 'topology-refresh-plan.json').exists())
        self.assertFalse((self.b.root / 'wireguard-refresh.conf').exists())

    def test_topology_refresh_rejects_old_foreign_and_role_changing_documents(self):
        invitation = self.onboard_user()
        plan = self.b.topology_refresh_plan(self.a.topology_update_export())
        self.assertEqual('operational', plan['kind'])

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

    def test_same_revision_operational_snapshot_refreshes_services_without_vpn_change(self):
        self.onboard_user()
        router_id = str(uuid.UUID(int=1))
        service = {'id': 'home', 'name': 'Home Assistant', 'hostAddress': '192.168.1.30',
                   'protocol': 'http', 'port': 8123, 'path': '/lovelace'}
        f.atomic(self.a.fleet / 'reports.json', {router_id: {
            'services': [service], 'servicesObservedAt': 200,
            'software': {'version': 'b' * 64, 'builtAt': 199}}})
        with patch.object(f, 'refresh_reports', wraps=f.refresh_reports) as refresh:
            plan = self.b.topology_refresh_plan(self.a.topology_update_export())
        refresh.assert_called_once()
        self.assertEqual(('operational', plan['currentRevision'], plan['currentRevision']),
                         (plan['kind'], plan['currentRevision'], plan['revision']))
        result = self.b.topology_refresh_apply(plan['id'])
        self.assertEqual('operational', result['kind'])
        overview = f.read_only_notebook_overview(self.b.fleet)
        self.assertEqual(('home', 'b' * 64),
                         (overview['services'][0]['id'], overview['nodes'][0]['software']['version']))

        tampered = json.loads(self.a.topology_update_export())
        tampered['operational']['payload'] = tampered['operational']['payload'][:-2] + 'AA'
        with self.assertRaises(ValueError):
            self.b.topology_refresh_plan(json.dumps(tampered))

    def test_operational_snapshot_omission_preserves_cached_catalog_and_version(self):
        self.onboard_user()
        router_id = str(uuid.UUID(int=1))
        service = {'id': 'home', 'name': 'Home Assistant', 'hostAddress': '192.168.1.30',
                   'protocol': 'http', 'port': 8123, 'path': '/lovelace'}
        old_user_version = {'version': 'c' * 64, 'builtAt': 198}
        f.atomic(self.b.fleet / 'reports.json', {router_id: {
            'services': [service], 'servicesObservedAt': 200,
            'software': {'version': 'b' * 64, 'builtAt': 199}}})
        f.atomic(self.b.fleet / 'notebook-software.json', {self.b.id: old_user_version})
        f.atomic(self.a.fleet / 'reports.json', {router_id: {
            'state': 'rollback', 'software': {'version': 'd' * 64, 'builtAt': 201}}})
        (self.a.fleet / 'notebook-software.json').unlink(missing_ok=True)

        with patch.object(f, 'refresh_reports'):
            plan = self.b.topology_refresh_plan(self.a.topology_update_export())
        self.b.topology_refresh_apply(plan['id'])
        cached = f.read(self.b.fleet / 'reports.json')[router_id]
        self.assertEqual([service], cached['services'])
        self.assertEqual('d' * 64, cached['software']['version'])
        self.assertEqual(old_user_version,
                         f.read(self.b.fleet / 'notebook-software.json')[self.b.id])

        f.atomic(self.a.fleet / 'reports.json', {router_id: {
            'services': [], 'servicesObservedAt': 202,
            'software': {'version': 'd' * 64, 'builtAt': 201}}})
        with patch.object(f, 'refresh_reports'):
            removal = self.b.topology_refresh_plan(self.a.topology_update_export())
        self.b.topology_refresh_apply(removal['id'])
        self.assertEqual([], f.read(self.b.fleet / 'reports.json')[router_id]['services'])

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

        with patch.object(n.Store, 'forwarding_state', return_value=forwarding), \
                patch.object(n, 'system_network_request', side_effect=lambda request: {
                    'ok': True, 'vpn': {'state': 'active', 'revision': request['revision'],
                                        'changed': True}}) as reconcile, \
                patch.object(f, 'atomic', side_effect=fail_receipt), \
                self.assertRaisesRegex(ValueError, 'předchozí profil byl obnoven'):
            self.b.topology_refresh_apply(plan['id'])
        self.assertEqual(old_envelope, f.read(self.b.fleet / 'published.json'))
        self.assertEqual(old_config, (self.b.root / 'wireguard.conf').read_bytes())
        self.assertEqual(2, reconcile.call_count)

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
        _, _, _, invitation = self.staged_user_invitation()
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
        _, _, _, invitation = self.staged_user_invitation()
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
        self.assertFalse(state['updateAvailable'])
        verify.assert_called_once_with('10.203.0.3', plan['routes'])
        arguments = repr(calls)
        self.assertIn("'connection', 'import', 'type', 'wireguard', 'file'", arguments)
        self.assertIn("'connection.autoconnect', 'yes'", arguments)
        self.assertIn("'ipv4.never-default', 'yes'", arguments)
        self.assertIn("'ipv6.never-default', 'yes'", arguments)
        self.assertIn("'ipv4.route-metric', '2048'", arguments)
        self.assertIn("'ipv6.route-metric', '2048'", arguments)
        self.assertNotIn((self.b.root / 'wireguard.key').read_text().strip(), arguments)

    def test_vpn_plan_rebuilds_stale_config_after_topology_sync(self):
        invitation = self.onboard_user()
        old_config = (self.b.root / 'wireguard.conf').read_text()
        self.assertIn('192.168.1.0/24', old_config)

        public = invitation['rootPublic']
        current = f.validate_document(f.verify(public, f.read(self.a.fleet / 'published.json')))
        updated_config = copy.deepcopy(current['config'])
        updated_config['nodes'][0]['lanCidrs'] = ['192.168.2.0/24']
        published = f.snapshot(self.a.fleet, updated_config, current['members'])
        f.atomic(self.b.fleet / 'published.json', published)
        f.atomic(self.b.root / 'vpn-state.json', {
            'state': 'installed', 'revision': current['revision'],
            'address': '10.203.0.3/32',
            'routes': ['10.203.0.1/32', '192.168.1.0/24'],
        })

        status = self.b.vpn_status()
        self.assertTrue(status['updateAvailable'])
        self.assertEqual(current['revision'] + 1, status['topologyRevision'])
        self.assertEqual(['10.203.0.1/32', '192.168.2.0/24'], status['expectedRoutes'])

        with patch.object(n.Store, 'forwarding_state', return_value={'ipv4': False, 'ipv6': False}), \
                patch.object(n, 'nmcli_connections', return_value={}), \
                patch.object(n, 'verify_underlay', return_value='zt1234'):
            plan = self.b.vpn_plan()

        rebuilt = (self.b.root / 'wireguard.conf').read_text()
        self.assertEqual(current['revision'] + 1, plan['revision'])
        self.assertIn('192.168.2.0/24', plan['routes'])
        self.assertIn('192.168.2.0/24', rebuilt)
        self.assertNotIn('192.168.1.0/24', rebuilt)

    def test_vpn_status_does_not_mark_matching_profile_for_update(self):
        self.onboard_user()
        document, notebook, routes = self.b.verified_vpn_target()
        config_hash = __import__('hashlib').sha256(
            self.b.wireguard_config(document, notebook)).hexdigest()
        f.atomic(self.b.root / 'vpn-state.json', {
            'state': 'installed', 'revision': document['revision'],
            'address': notebook['wireguardAddress'] + '/32', 'routes': routes,
            'configHash': config_hash,
        })

        with patch.object(n, 'nmcli_connections', return_value={
                    n.VPN_CONNECTION: {'uuid': 'current', 'type': 'wireguard'}}), \
                patch.object(n, 'nmcli_active_uuids', return_value={'current'}):
            status = self.b.vpn_status()

        self.assertFalse(status['updateAvailable'])
        self.assertEqual('active', status['profileState'])
        self.assertFalse(status['repairRequired'])
        self.assertEqual(document['revision'], status['topologyRevision'])
        self.assertEqual(routes, status['expectedRoutes'])

    def test_vpn_status_reports_missing_networkmanager_profile(self):
        self.onboard_user()

        with patch.object(n, 'nmcli_connections', return_value={}), \
                patch.object(n, 'nmcli_active_uuids', return_value=set()):
            status = self.b.vpn_status()

        self.assertEqual('missing', status['profileState'])
        self.assertTrue(status['setupRequired'])
        self.assertTrue(status['repairRequired'])

    def test_vpn_status_reports_inactive_networkmanager_profile(self):
        self.onboard_user()

        with patch.object(n, 'nmcli_connections', return_value={
                    n.VPN_CONNECTION: {'uuid': 'inactive', 'type': 'wireguard'}}), \
                patch.object(n, 'nmcli_active_uuids', return_value=set()):
            status = self.b.vpn_status()

        self.assertEqual('inactive', status['profileState'])
        self.assertFalse(status['setupRequired'])
        self.assertTrue(status['repairRequired'])

    def test_system_vpn_reconcile_uses_only_verified_topology(self):
        self.onboard_user()
        f.atomic(self.b.root / 'vpn-diagnostics.json', {'revision': 2, 'state': 'complete'})
        with patch.object(n, 'system_network_request', return_value={
                'ok': True, 'vpn': {'state': 'active', 'revision': 3, 'changed': True}}) as request:
            result = self.b.reconcile_system_vpn()

        plan = request.call_args.args[0]
        self.assertEqual(n.SYSTEM_VPN_SCHEMA, plan['schema'])
        self.assertEqual('10.203.0.3/32', plan['address'])
        self.assertEqual(1, len(plan['peers']))
        self.assertEqual('10.147.0.1:51830', plan['peers'][0]['endpoint'])
        self.assertEqual(['10.203.0.1/32', '192.168.1.0/24'], plan['peers'][0]['allowedIps'])
        self.assertEqual('active', result['state'])
        receipt = f.read(self.b.root / 'vpn-state.json')
        self.assertEqual(('installed', 'system-service', 3),
                         (receipt['state'], receipt['managedBy'], receipt['revision']))
        self.assertFalse((self.b.root / 'vpn-diagnostics.json').exists())

    def test_sync_prefers_peer_zerotier_address_from_signed_topology(self):
        self.onboard_user()
        self.assertEqual('10.147.0.3', self.a.signed_peer_address(self.b.id))
        self.assertEqual('10.147.0.2', self.b.signed_peer_address(self.a.id))
        self.assertIsNone(self.a.signed_peer_address(self.c.id))

    def test_sync_transfer_errors_distinguish_listener_route_and_tls(self):
        peer = {'address': '10.147.0.3'}
        refused = n.transfer_error(peer, ConnectionRefusedError())
        timed_out = n.transfer_error(peer, TimeoutError())
        tls = n.transfer_error(peer, n.ssl.SSLError())
        self.assertIn('10.147.0.3:8856', refused)
        self.assertIn('odmítá spojení', refused)
        self.assertIn('neodpověděl', timed_out)
        self.assertIn('vzájemné TLS', tls)

    def test_system_network_request_reports_socket_and_incomplete_response(self):
        client = Mock()
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=False)
        client.connect.side_effect = PermissionError()
        with patch.object(n.socket, 'socket', return_value=client), \
                self.assertRaisesRegex(ValueError, 'nemá oprávnění'):
            n.system_network_request({'action': 'test'})
        with patch.object(n, 'system_network_request', return_value={'ok': True}):
            self.onboard_user()
            with self.assertRaisesRegex(ValueError, 'neúplný stav VPN'):
                self.b.reconcile_system_vpn()

    def test_vpn_status_requires_one_update_for_legacy_receipt_without_config_hash(self):
        self.onboard_user()
        document, notebook, routes = self.b.verified_vpn_target()
        f.atomic(self.b.root / 'vpn-state.json', {
            'state': 'installed', 'revision': document['revision'],
            'address': notebook['wireguardAddress'] + '/32', 'routes': routes,
        })

        self.assertTrue(self.b.vpn_status()['updateAvailable'])

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
                snapshot, software = n.fetch(self.b, self.b.peers()[self.a.id], include_software=True)
                self.assertEqual((self.a.fleet / 'root.pem').read_text(), snapshot['data']['fleet']['root.pem'])
                self.assertRegex(software['version'], r'^[0-9a-f]{64}$')
                self.assertGreater(software['builtAt'], 0)
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
