#!/usr/bin/env python3
"""Protocol and deployment regressions; no real router/network is modified."""
import base64
import copy
import importlib.util
import json
import os
import re
from pathlib import Path
import shlex
import socket
import threading
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
import uuid

SOURCE = Path(__file__).resolve().parents[1] / 'router/files/usr/lib/turris-federation/federation.py'
spec = importlib.util.spec_from_file_location('federation', SOURCE)
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


def node(index):
    return {'id': str(uuid.UUID(int=index)), 'name': 'Stanoviště ' + str(index),
            'sshHost': '192.168.1.1', 'sshUser': 'root', 'sshPort': 22,
            'lanCidrs': ['192.168.%s.0/24' % index], 'zeroTierAddress': '10.147.0.' + str(index),
            'wireguardAddress': '10.203.0.' + str(index)}


class FederationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.keydir = Path(cls.keys.name)
        cls.public = f.identity(cls.keydir / 'root.pem')
        cls.other = f.identity(cls.keydir / 'other.pem')

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copy(self.keydir / 'root.pem', self.root / 'root.pem')
        f.atomic(self.root / 'root.pub', self.public.encode())
        self.nodes = [node(1), node(2)]
        self.config = f.normalize(self.nodes, 'abcdef0123456789')

    def member(self, index):
        return {'nodeId': node(index)['id'], 'identity': self.public,
                'wireguardKey': base64.b64encode(bytes([index]) * 32).decode()}

    def document(self, revision=1, members=None, config=None):
        return {'schema': 1, 'federationId': str(uuid.UUID(int=900)), 'revision': revision,
                'previous': None, 'config': config or self.config, 'members': members or {node(1)['id']: self.member(1)}}

    def test_two_sites_drafts_corrections_and_return_to_first(self):
        first, second = self.root / 'first', self.root / 'second'
        for site in [first, second]:
            f.atomic(site / 'root.pub', self.public.encode())
        members = {node(1)['id']: self.member(1)}
        v1 = f.snapshot(self.root, self.config, members)
        first_doc = f.accept(first, v1)
        self.assertEqual(2, len(first_doc['config']['nodes']))
        self.assertNotIn(node(2)['id'], first_doc['members'])
        members[node(2)['id']] = self.member(2)
        corrected = copy.deepcopy(self.config)
        corrected['nodes'][1]['lanCidrs'] = ['192.168.20.0/24']
        v2 = f.snapshot(self.root, corrected, members)
        second_doc = f.accept(second, v2)
        self.assertEqual(2, second_doc['revision'])
        self.assertEqual(1, f.verify(self.public, f.read(first / 'accepted.json'))['revision'])
        self.assertEqual(second_doc, f.accept(first, v2))
        # A later correction can be relayed as exactly the same signed envelope.
        corrected['nodes'][0]['name'] = 'Opravený název'
        v3 = f.snapshot(self.root, corrected, members)
        f.accept(second, v3)
        self.assertEqual(3, f.accept(first, f.read(second / 'accepted.json'))['revision'])
        self.assertEqual(v3, f.snapshot(self.root, corrected, members))
        self.assertFalse((first / 'root.pem').exists())

    def test_offline_site_can_skip_revisions_but_not_replay_or_fork(self):
        v1 = f.sign(self.root / 'root.pem', self.document())
        f.accept(self.root, v1)
        v4 = f.sign(self.root / 'root.pem', self.document(4))
        f.accept(self.root, v4)
        self.assertEqual(4, f.accept(self.root, v4)['revision'])
        with self.assertRaisesRegex(ValueError, 'Zastaralá'):
            f.accept(self.root, v1)
        changed = self.document(4)
        changed['config']['nodes'][0]['name'] = 'fork'
        with self.assertRaisesRegex(ValueError, 'Konflikt'):
            f.accept(self.root, f.sign(self.root / 'root.pem', changed))
        self.assertEqual(v4, f.read(self.root / 'accepted.json'))

    def test_signature_tampering_wrong_notebook_and_other_federation(self):
        good = f.sign(self.root / 'root.pem', self.document())
        f.accept(self.root, good)
        bad = copy.deepcopy(good)
        bad['payload'] = base64.b64encode(f.encode(self.document(9))).decode()
        for envelope in [bad, f.sign(self.keydir / 'other.pem', self.document(9))]:
            with self.assertRaises(ValueError):
                f.accept(self.root, envelope)
        other = self.document(9)
        other['federationId'] = str(uuid.uuid4())
        with self.assertRaisesRegex(ValueError, 'Jiná federace'):
            f.accept(self.root, f.sign(self.root / 'root.pem', other))
        self.assertEqual(good, f.read(self.root / 'accepted.json'))

    def test_overlap_duplicates_and_incomplete_draft(self):
        nodes = copy.deepcopy(self.nodes)
        nodes[1]['lanCidrs'] = ['192.168.1.128/25']
        with self.assertRaisesRegex(ValueError, 'Překryv'):
            f.normalize(nodes, 'abcdef0123456789')
        nodes = copy.deepcopy(self.nodes)
        nodes[1]['wireguardAddress'] = nodes[0]['wireguardAddress']
        with self.assertRaisesRegex(ValueError, 'Duplicitní'):
            f.normalize(nodes, 'abcdef0123456789')
        nodes[1]['wireguardAddress'] = None
        nodes[1]['zeroTierAddress'] = None
        nodes[1]['lanCidrs'] = []
        config = f.normalize(nodes, 'abcdef0123456789')
        f.validate_document(self.document(config=config))
        with self.assertRaisesRegex(ValueError, 'kompletní'):
            f.validate_document(self.document(config=config, members={node(2)['id']: self.member(2)}))

    def test_notebook_topology_is_versioned_separately_and_cannot_advertise_lan(self):
        notebook_id = 'a' * 64
        config = f.normalize_with_notebooks(self.nodes, 'abcdef0123456789', [{
            'id': notebook_id, 'name': 'User notebook', 'role': 'user',
            'zeroTierAddress': None, 'wireguardAddress': None,
        }])
        envelope = f.snapshot(self.root, config, {node(1)['id']: self.member(1)})
        document = f.verify(self.public, envelope)
        self.assertEqual(f.NOTEBOOK_VERSION, document['schema'])
        self.assertEqual([], [key for key in document['config']['notebooks'][0] if key == 'lanCidrs'])
        f.validate_document(document)

        invalid = copy.deepcopy(document)
        invalid['config']['notebooks'][0]['lanCidrs'] = ['10.0.0.0/24']
        with self.assertRaisesRegex(ValueError, 'nepodporovaná pole'):
            f.validate_document(invalid)

    def test_notebook_addresses_cannot_collide_with_router_or_lan(self):
        base = {'id': 'b' * 64, 'name': 'User notebook', 'role': 'user',
                'zeroTierAddress': None, 'wireguardAddress': None}
        for field, value in [('zeroTierAddress', '10.147.0.1'),
                             ('wireguardAddress', '10.203.0.1'),
                             ('wireguardAddress', '192.168.1.20')]:
            item = dict(base, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, 'Duplicitní|koliduje'):
                f.normalize_with_notebooks(self.nodes, 'abcdef0123456789', [item])

    def test_notebook_endpoint_requires_complete_unique_wireguard_identity(self):
        endpoint = {'id': 'd' * 64, 'name': 'User notebook', 'role': 'user',
                    'zeroTierAddress': '10.147.0.20', 'wireguardAddress': '10.203.0.20',
                    'wireguardKey': base64.b64encode(b'n' * 32).decode()}
        config = f.normalize_with_notebook_endpoints(self.nodes, 'abcdef0123456789', [endpoint])
        doc = self.document(config=config)
        doc['schema'] = f.NOTEBOOK_WG_VERSION
        f.validate_document(doc)
        incomplete = copy.deepcopy(endpoint)
        incomplete['wireguardAddress'] = None
        with self.assertRaisesRegex(ValueError, 'obě adresy'):
            f.normalize_with_notebook_endpoints(self.nodes, 'abcdef0123456789', [incomplete])
        duplicate = copy.deepcopy(doc)
        duplicate['config']['notebooks'][0]['wireguardKey'] = self.member(1)['wireguardKey']
        with self.assertRaisesRegex(ValueError, 'stejný WireGuard klíč'):
            f.validate_document(duplicate)

    def test_drafts_cannot_enroll_through_publish(self):
        f.atomic(self.root / 'members.json', {node(1)['id']: self.member(1)})
        with patch.object(f, 'request_http', side_effect=ValueError('offline')):
            result = f.controller(self.root, {'action': 'publish', 'nodes': self.nodes, 'networkId': 'abcdef0123456789'})
        self.assertFalse(result['nodes'][node(2)['id']]['enrolled'])
        self.assertNotIn('appliedRevision', result['nodes'][node(1)['id']])
        self.assertFalse(result['nodes'][node(1)['id']]['reachable'])
        self.assertEqual(1, result['revision'])

    def test_router_publish_preserves_signed_notebook_endpoints(self):
        endpoint = {'id': '1' * 64, 'name': 'User notebook', 'role': 'user',
                    'zeroTierAddress': '10.147.0.20', 'wireguardAddress': '10.203.0.20',
                    'wireguardKey': base64.b64encode(b'n' * 32).decode()}
        config = f.normalize_with_notebook_endpoints(self.nodes, self.config['networkId'], [endpoint])
        f.snapshot(self.root, config, {})
        with patch.object(f, 'distribute_bundle'):
            f.controller(self.root, {'action': 'publish', 'nodes': self.nodes,
                                     'networkId': self.config['networkId']})
        document = f.validate_document(f.verify(self.public, f.read(self.root / 'published.json')))
        self.assertEqual(f.NOTEBOOK_WG_VERSION, document['schema'])
        self.assertEqual([endpoint], document['config']['notebooks'])

    def test_uci_private_key_uses_stdin_not_arguments(self):
        with patch.object(f, 'run') as command:
            f.uci_section('network', 'tf_wg', 'interface', {'private_key': 'PRIVATE-SECRET', 'addresses': ['10.203.0.1/32']})
        args, raw = command.call_args.args
        self.assertEqual(['uci', 'batch'], args)
        self.assertNotIn('PRIVATE-SECRET', str(args))
        self.assertIn(b'PRIVATE-SECRET', raw)

    def test_new_revision_cannot_replace_pending_apply(self):
        first = f.sign(self.root / 'root.pem', self.document())
        f.accept(self.root, first)
        f.atomic(self.root / 'pending.json', {'revision': 1})
        self.assertEqual(1, f.accept(self.root, first)['revision'])
        with self.assertRaisesRegex(ValueError, 'čeká na potvrzení'):
            f.accept(self.root, f.sign(self.root / 'root.pem', self.document(2)))
        self.assertEqual(first, f.read(self.root / 'accepted.json'))

    def test_confirmation_must_match_applied_revision(self):
        f.atomic(self.root / 'accepted.json', f.sign(self.root / 'root.pem', self.document(2)))
        f.atomic(self.root / 'pending.json', {'token': 'ok', 'revision': 1, 'deadline': time.time() + 120})
        with patch.object(f, 'health') as health:
            with self.assertRaisesRegex(ValueError, 'Potvrzení'):
                f.confirm(self.root, 'ok')
            health.assert_not_called()
        self.assertTrue((self.root / 'pending.json').exists())

    def test_bootstrap_cannot_replace_root_or_node_id(self):
        with self.assertRaisesRegex(ValueError, 'jiné kotvě'):
            f.bootstrap(self.root, node(1)['id'], self.other)
        f.atomic(self.root / 'node.json', self.member(1))
        with self.assertRaisesRegex(ValueError, 'jiné ID'):
            f.bootstrap(self.root, node(2)['id'], self.public)

    def test_http_refuses_unencrypted_management_route(self):
        with patch.object(f, 'run', return_value=b'10.147.0.1 dev eth0 src 192.168.1.2'), patch.object(f.http.client, 'HTTPConnection') as connection:
            with self.assertRaisesRegex(ValueError, 'ZeroTier'):
                f.request_http('10.147.0.1', 'GET', '/bundle')
            connection.assert_not_called()

    def test_fresh_status_rejects_replay(self):
        envelope = f.sign(self.root / 'root.pem', {'nonce': 'old', 'nodeId': node(1)['id'], 'report': {'state': 'active'}})
        with patch.object(f, 'request_http', return_value=envelope):
            with self.assertRaisesRegex(ValueError, 'neodpovídá'):
                f.peer_status(node(1), self.member(1))

    def test_passive_host_catalog_filters_to_owned_lan_and_omits_mac(self):
        leases = self.root / 'dhcp.leases'
        leases.write_text('999 aa:bb:cc:dd:ee:ff 192.168.1.20 printer.local *\n')
        neighbors = (b'192.168.1.20 dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE\n'
                     b'192.168.1.21 dev br-lan lladdr 11:22:33:44:55:66 FAILED\n'
                     b'192.168.2.20 dev tf_wg lladdr 22:33:44:55:66:77 STALE\n')
        completed = subprocess.CompletedProcess([], 0, neighbors, b'')
        with patch.object(f, 'DHCP_LEASES', leases), patch.object(f.subprocess, 'run', return_value=completed) as run:
            hosts = f.discover_hosts(node(1))
        self.assertEqual([{'address': '192.168.1.20', 'name': 'printer.local'}], hosts)
        self.assertNotIn('aa:bb:cc:dd:ee:ff', json.dumps(hosts))
        self.assertEqual(['ip', '-4', 'neigh', 'show'], run.call_args.args[0])

    def test_signed_host_catalog_is_limited_to_announcing_node_lan(self):
        good = {'hosts': [{'address': '192.168.1.20', 'name': 'printer'}], 'hostsObservedAt': 100}
        self.assertEqual(good, f.validate_hosts(node(1), good))
        for bad in [
            {'hosts': [{'address': '192.168.2.20', 'name': None}], 'hostsObservedAt': 100},
            {'hosts': [{'address': '192.168.1.20', 'name': '<script>'}], 'hostsObservedAt': 100},
            {'hosts': [{'address': '192.168.1.20', 'name': None, 'mac': 'secret'}], 'hostsObservedAt': 100},
        ]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                f.validate_hosts(node(1), bad)

        for malformed in [
            {'hosts': [{'address': None, 'name': None}], 'hostsObservedAt': 100},
            {'hosts': [], 'hostsObservedAt': float('nan')},
        ]:
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                f.validate_hosts(node(1), malformed)

    def test_signed_service_catalog_is_limited_to_announcing_node_lan(self):
        service = {'id': 'camera', 'name': 'Camera', 'hostAddress': '192.168.1.20',
                   'protocol': 'https', 'port': 8443, 'path': '/view'}
        good = {'services': [service], 'servicesObservedAt': 100}
        self.assertEqual(good, f.validate_report_services(node(1), good))
        for bad in [
            {'services': [dict(service, hostAddress='192.168.2.20')], 'servicesObservedAt': 100},
            {'services': [{**service, 'token': 'secret'}], 'servicesObservedAt': 100},
            {'services': [service], 'servicesObservedAt': float('nan')},
            {'services': [service]},
            {'services': [{**service, 'routerPort': 18443}], 'servicesObservedAt': 100},
            {'services': [{**service, 'sourceAddress': '10.147.0.50'}], 'servicesObservedAt': 100},
        ]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                f.validate_report_services(node(1), bad)

        response = f.sign(self.root / 'root.pem', {'nonce': 'a' * 64, 'nodeId': node(1)['id'],
                          'report': {'services': [dict(service, hostAddress='192.168.2.20')],
                                     'servicesObservedAt': 100}})
        with patch.object(f.secrets, 'token_hex', return_value='a' * 64), \
                patch.object(f, 'request_http', return_value=response), self.assertRaises(ValueError):
            f.peer_status(node(1), self.member(1))

    def test_service_endpoint_encodes_http_path_and_never_builds_tcp_url(self):
        service = {'hostAddress': '192.168.1.20', 'protocol': 'https', 'port': 8443,
                   'path': '/česká cesta/%value'}
        self.assertEqual('https://192.168.1.20:8443/%C4%8Desk%C3%A1%20cesta/%25value',
                         f.service_endpoint(service))
        self.assertEqual('192.168.1.20:11434', f.service_endpoint(
            {**service, 'protocol': 'tcp', 'port': 11434, 'path': None}))

    def test_router_catalog_caches_verified_remote_announcements(self):
        doc = self.document(members={node(1)['id']: self.member(1), node(2)['id']: self.member(2)})
        f.atomic(self.root / 'node.json', self.member(1))
        local_service = {'id': 'ollama', 'name': 'Ollama', 'hostAddress': '192.168.1.10',
                         'protocol': 'tcp', 'port': 11434, 'path': None}
        remote_service = {'id': 'camera', 'name': 'Camera', 'hostAddress': '192.168.2.20',
                          'protocol': 'https', 'port': 8443, 'path': '/view'}
        f.atomic(self.root / 'report.json', {'hosts': [{'address': '192.168.1.10', 'name': None}], 'hostsObservedAt': 90,
                 'services': [local_service], 'servicesObservedAt': 91})
        remote = {'hosts': [{'address': '192.168.2.20', 'name': 'camera'}], 'hostsObservedAt': 100,
                  'services': [remote_service], 'servicesObservedAt': 101}
        with patch.object(f, 'peer_status', return_value=remote):
            catalog = f.refresh_catalog(self.root, doc, node(1)['id'])
        self.assertEqual('192.168.1.10', catalog[node(1)['id']]['hosts'][0]['address'])
        self.assertEqual('camera', catalog[node(2)['id']]['hosts'][0]['name'])
        self.assertEqual('ollama', catalog[node(1)['id']]['services'][0]['id'])
        self.assertEqual('camera', catalog[node(2)['id']]['services'][0]['id'])
        self.assertEqual(catalog, f.read(self.root / 'catalog.json'))
        with patch.object(f, 'peer_status', side_effect=ValueError('offline')):
            stale = f.refresh_catalog(self.root, doc, node(1)['id'])
        self.assertEqual(101, stale[node(2)['id']]['servicesObservedAt'])
        software = {'version': 'a' * 64, 'builtAt': 102}
        with patch.object(f, 'peer_status', return_value={'software': software}):
            version_only = f.refresh_catalog(self.root, doc, node(1)['id'])
        self.assertEqual(remote_service, version_only[node(2)['id']]['services'][0])
        self.assertEqual(software, version_only[node(2)['id']]['software'])
        with patch.object(f, 'peer_status', return_value={
                'services': [], 'servicesObservedAt': 103, 'software': software}):
            removed = f.refresh_catalog(self.root, doc, node(1)['id'])
        self.assertEqual([], removed[node(2)['id']]['services'])
        self.assertEqual(103, removed[node(2)['id']]['servicesObservedAt'])
        revoked = self.document(members={node(1)['id']: self.member(1)})
        without_revoked = f.refresh_catalog(self.root, revoked, node(1)['id'])
        self.assertNotIn(node(2)['id'], without_revoked)

    def test_rollback_router_keeps_refreshing_independent_catalog(self):
        doc = self.document(members={node(1)['id']: self.member(1), node(2)['id']: self.member(2)})
        f.atomic(self.root / 'root.pub', f.public_key(self.root / 'root.pem').encode())
        f.atomic(self.root / 'accepted.json', f.sign(self.root / 'root.pem', doc))
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'report.json', {
            'state': 'rollback', 'receivedRevision': doc['revision'], 'appliedRevision': 0})
        with patch.object(f, 'exchange_bundles'), \
                patch.object(f, 'refresh_catalog', side_effect=KeyboardInterrupt) as refresh, \
                self.assertRaises(KeyboardInterrupt):
            f.sync_loop(self.root)
        refresh.assert_called_once_with(self.root, doc, node(1)['id'])

    def test_live_refresh_reads_signed_catalogs_from_enrolled_nodes(self):
        members = {node(1)['id']: self.member(1), node(2)['id']: self.member(2)}
        f.atomic(self.root / 'members.json', members)
        f.snapshot(self.root, self.config, members)
        reports = {
            node(1)['id']: {'state': 'active', 'hosts': [{'address': '192.168.1.20', 'name': 'printer'}], 'hostsObservedAt': 100},
            node(2)['id']: {'state': 'active', 'hosts': [{'address': '192.168.2.30', 'name': 'camera'}], 'hostsObservedAt': 101},
        }
        with patch.object(f, 'peer_status', side_effect=lambda peer, *_: reports[peer['id']]) as status:
            result = f.controller(self.root, {'action': 'refresh', 'nodes': self.nodes,
                                  'networkId': self.config['networkId']})
        self.assertEqual(2, status.call_count)
        self.assertEqual('printer', result['nodes'][node(1)['id']]['hosts'][0]['name'])
        self.assertEqual('camera', result['nodes'][node(2)['id']]['hosts'][0]['name'])
        self.assertTrue(result['nodes'][node(1)['id']]['reachable'])

    def test_live_refresh_preserves_signed_router_error(self):
        doc = self.document(members={node(1)['id']: self.member(1)})
        signed_error = {'state': 'rollback', 'error': 'Změna nebyla potvrzena.'}
        with patch.object(f, 'peer_status', return_value=signed_error):
            reports = f.refresh_reports(self.root, doc)
        self.assertTrue(reports[node(1)['id']]['reachable'])
        self.assertEqual(signed_error['error'], reports[node(1)['id']]['error'])

    def test_live_refresh_populates_desktop_service_directory(self):
        members = {node(1)['id']: self.member(1)}
        f.atomic(self.root / 'members.json', members)
        f.snapshot(self.root, self.config, members)
        service = {'id': 'ollama', 'name': 'Ollama', 'hostAddress': '192.168.1.20',
                   'protocol': 'tcp', 'port': 11434, 'path': None}
        report = {'state': 'active', 'services': [service], 'servicesObservedAt': time.time()}
        with patch.object(f, 'peer_status', return_value=report):
            f.controller(self.root, {'action': 'refresh', 'nodes': self.nodes,
                                     'networkId': self.config['networkId']})
        overview = f.controller(self.root, {'action': 'read_only_overview', 'nodes': self.nodes,
                                            'networkId': self.config['networkId']})
        self.assertEqual('ollama', overview['services'][0]['id'])
        self.assertEqual('Stanoviště 1', overview['services'][0]['routerName'])

    def test_revocation_removes_cached_service_reports(self):
        doc = self.document(members={node(1)['id']: self.member(1)})
        cached = {'services': [{'id': 'camera', 'name': 'Camera', 'hostAddress': '192.168.2.20',
                               'protocol': 'https', 'port': 8443, 'path': None}],
                  'servicesObservedAt': 100}
        local_cached = {'state': 'active', 'services': [{
            'id': 'ollama', 'name': 'Ollama', 'hostAddress': '192.168.1.20',
            'protocol': 'tcp', 'port': 11434, 'path': None}], 'servicesObservedAt': 99}
        f.atomic(self.root / 'reports.json', {node(1)['id']: local_cached, node(2)['id']: cached})
        with patch.object(f, 'peer_status', return_value={'state': 'active'}):
            reports = f.refresh_reports(self.root, doc)
        self.assertEqual({node(1)['id']}, set(reports))
        self.assertEqual('ollama', reports[node(1)['id']]['services'][0]['id'])
        self.assertNotIn(node(2)['id'], f.read(self.root / 'reports.json'))

    def test_mutated_or_expired_plan_cannot_start_deploy(self):
        request = {'action': 'deploy', 'nodes': self.nodes, 'networkId': 'abcdef0123456789',
                   'nodeId': node(1)['id'], 'planId': 'plan', 'credentials': {'hostKey': 'key', 'password': 'test'}}
        plan = {'id': 'plan', 'expiresAt': time.time() - 1, 'configHash': f.digest(self.config), 'hostKeyHash': f.digest('key'),
                'sshHash': f.digest({k: node(1)[k] for k in ['sshHost', 'sshPort', 'sshUser']})}
        f.atomic(self.root / ('plan-' + node(1)['id'] + '.json'), plan)
        with patch.object(f, 'ssh') as ssh:
            with self.assertRaisesRegex(ValueError, 'Plán'):
                f.controller(self.root, request)
            ssh.assert_not_called()
        plan['expiresAt'] = time.time() + 600
        plan['configHash'] = 'wrong'
        f.atomic(self.root / ('plan-' + node(1)['id'] + '.json'), plan)
        with patch.object(f, 'ssh') as ssh:
            with self.assertRaisesRegex(ValueError, 'Plán'):
                f.controller(self.root, request)
            ssh.assert_not_called()

    def lan_fixture(self):
        device = self.root / 'net' / 'eth0'
        (device / 'device').mkdir(parents=True)
        (device / 'type').write_text('1\n')
        target = dict(node(1), sshHost='192.168.1.1')
        route = [{'dev': 'eth0', 'prefsrc': '192.168.1.10'}]
        links = [{'addr_info': [{'family': 'inet', 'local': '192.168.1.10', 'prefixlen': 24}]}]
        return target, route, links

    def test_direct_lan_accepts_physical_on_link_address(self):
        target, route, links = self.lan_fixture()
        with patch.object(f, 'SYS_NET', self.root / 'net'), patch.object(f, 'run', side_effect=[f.encode(route), f.encode(links)]):
            self.assertEqual({'host': '192.168.1.1', 'device': 'eth0', 'source': '192.168.1.10'}, f.direct_lan(target))

    def test_direct_lan_rejects_gateway_vpn_and_unproven_route(self):
        target, route, links = self.lan_fixture()
        bad_routes = [[], [{'dev': 'eth0', 'prefsrc': '192.168.1.10', 'gateway': '192.168.1.254'}],
                      [{'dev': 'zt1234', 'prefsrc': '192.168.1.10'}],
                      [{'dev': 'wg0', 'prefsrc': '192.168.1.10'}],
                      [{'dev': 'eth0', 'type': 'local', 'prefsrc': '192.168.1.10'}]]
        for routes in bad_routes:
            with self.subTest(routes=routes), patch.object(f, 'SYS_NET', self.root / 'net'), patch.object(f, 'run', return_value=f.encode(routes)):
                with self.assertRaisesRegex(ValueError, 'přímé LAN'):
                    f.direct_lan(target)
        # Even an innocently named Ethernet interface is rejected if virtual.
        (self.root / 'net' / 'eth0' / 'device').rmdir()
        with patch.object(f, 'SYS_NET', self.root / 'net'), patch.object(f, 'run', return_value=f.encode(route)):
            with self.assertRaisesRegex(ValueError, 'přímé LAN'):
                f.direct_lan(target)

    def test_direct_lan_rejects_dns_non_lan_and_different_subnet(self):
        target, route, links = self.lan_fixture()
        for host in ['router.local', '10.147.0.1', '127.0.0.1']:
            with self.subTest(host=host), patch.object(f, 'run') as run:
                with self.assertRaises(ValueError):
                    f.direct_lan(dict(target, sshHost=host))
                run.assert_not_called()
        links[0]['addr_info'][0]['prefixlen'] = 32
        with patch.object(f, 'SYS_NET', self.root / 'net'), patch.object(f, 'run', side_effect=[f.encode(route), f.encode(links)]):
            with self.assertRaisesRegex(ValueError, 'přímé LAN'):
                f.direct_lan(target)

    def test_every_deploy_ssh_session_checks_lan_before_launch(self):
        for command in ['validate', 'installer', 'update', 'confirm', 'restart']:
            with self.subTest(command=command), patch.object(f, 'direct_lan', side_effect=ValueError('LAN required')), patch.object(f.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'LAN required'):
                    f.ssh(node(1), {'password': 'test', 'hostKey': 'key'}, command)
                run.assert_not_called()

    def test_ssh_pins_validated_lan_and_rejects_a_changed_connection(self):
        target, _, _ = self.lan_fixture()
        lan = {'host': target['sshHost'], 'device': 'eth0', 'source': '192.168.1.10'}
        credentials = {'password': 'test', 'hostKey': 'key'}
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'ok', b'')) as run:
            self.assertEqual(b'ok', f.ssh(dict(target, _deployLan=lan), credentials, 'true'))
            args = run.call_args.args[0]
            self.assertEqual('eth0', args[args.index('-B') + 1])
            self.assertEqual('192.168.1.10', args[args.index('-b') + 1])
            self.assertIn('-n', args)
            self.assertIsNone(run.call_args.kwargs['input'])
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'ok', b'')) as run:
            self.assertEqual(b'ok', f.ssh(dict(target, _deployLan=lan), credentials, 'consume-stdin', input_data=b'large artifact'))
            self.assertNotIn('-n', run.call_args.args[0])
            self.assertEqual(b'large artifact', run.call_args.kwargs['input'])
        with patch.object(f, 'direct_lan', return_value=dict(lan, source='192.168.1.11')), patch.object(f.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'změnilo'):
                f.ssh(dict(target, _deployLan=lan), credentials, 'update')
            run.assert_not_called()

    def test_update_requires_current_artifact_and_same_lan(self):
        target, _, _ = self.lan_fixture()
        nodes = [target, node(2)]
        config = f.normalize(nodes, 'abcdef0123456789')
        members = {target['id']: self.member(1)}
        f.atomic(self.root / 'members.json', members)
        lan = {'host': target['sshHost'], 'device': 'eth0', 'source': '192.168.1.10'}
        plan = {'id': 'update', 'expiresAt': time.time() + 600, 'configHash': f.digest(config),
                'hostKeyHash': f.digest('key'), 'membersHash': f.digest(members),
                'sshHash': f.digest({k: target[k] for k in ['sshHost', 'sshPort', 'sshUser']}),
                'lan': lan, 'availableModes': ['full'], 'artifactHash': 'old-agent'}
        req = {'action': 'deploy', 'nodes': nodes, 'networkId': config['networkId'], 'nodeId': target['id'],
               'planId': 'update', 'credentials': {'hostKey': 'key', 'password': 'test'}}
        path = self.root / ('plan-' + target['id'] + '.json')
        f.atomic(path, plan)
        with patch.object(f, 'ssh') as ssh:
            with self.assertRaisesRegex(ValueError, 'verzi agenta'):
                f.controller(self.root, req)
            ssh.assert_not_called()
        plan['artifactHash'] = f.artifact_hash()
        plan['artifactComponents'] = f.artifact_components()
        f.atomic(path, plan)
        with patch.object(f, 'direct_lan', return_value=dict(lan, device='wlan0')), patch.object(f, 'ssh') as ssh:
            with self.assertRaisesRegex(ValueError, 'změnilo'):
                f.controller(self.root, req)
            ssh.assert_not_called()

    def test_validation_marks_existing_member_as_lan_update(self):
        target, _, _ = self.lan_fixture()
        f.atomic(self.root / 'members.json', {target['id']: self.member(1)})
        lan = {'host': target['sshHost'], 'device': 'eth0', 'source': '192.168.1.10'}
        probe = ('__BOARD__\n{}\n__ZT__\n' + json.dumps([{'nwid': 'abcdef0123456789', 'status': 'OK', 'portDeviceName': 'zt1234',
                 'assignedAddresses': ['10.147.0.1/24']}]) + '\n__ADDR__\ninet 192.168.1.1/24\n__END__\n').encode()
        req = {'action': 'validate', 'nodes': [target], 'networkId': 'abcdef0123456789',
               'nodeId': target['id'], 'credentials': {'hostKey': 'key', 'password': 'test'}}
        with patch.object(f, 'direct_lan', return_value=lan), \
                patch.object(f, 'ssh', side_effect=[probe, (f.artifact_hash() + '  -').encode(), b'hash']) as ssh, \
                patch.object(f, 'installed_artifact_components', return_value=f.artifact_components()):
            plan = f.controller(self.root, req)
        self.assertEqual('update', plan['operation'])
        self.assertEqual(lan, plan['lan'])
        self.assertEqual(f.artifact_hash(), plan['artifactHash'])
        self.assertTrue(all('opkg install' not in call.args[2] for call in ssh.call_args_list))

    def validation_fixture(self, installed, enrolled=True):
        target = node(1)
        f.atomic(self.root / 'members.json', {target['id']: self.member(1)} if enrolled else {})
        lan = {'host': target['sshHost'], 'device': 'eth0', 'source': '192.168.1.10'}
        probe = ('__BOARD__\n{}\n__ZT__\n' + json.dumps([{'nwid': self.config['networkId'], 'status': 'OK',
                 'assignedAddresses': ['10.147.0.1/24']}]) + '\n__ADDR__\ninet 192.168.1.1/24\n__END__\n').encode()
        req = {'action': 'validate', 'nodes': self.nodes, 'networkId': self.config['networkId'],
               'nodeId': target['id'], 'credentials': {'hostKey': 'key', 'password': 'test'}}
        parts = (f.artifact_components() if installed == f.artifact_hash() else
                 {name: installed for name in f.artifact_components()} if installed else
                 {name: None for name in f.artifact_components()})
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f, 'ssh', side_effect=[probe, b'hash']), \
                patch.object(f, 'installed_artifact_hash', return_value=installed), \
                patch.object(f, 'installed_artifact_components', return_value=parts):
            plan = f.controller(self.root, req)
        return req, plan, lan

    def test_validation_recommends_mode_by_installation_state(self):
        for installed, enrolled, recommended, modes in [
                (f.artifact_hash(), True, 'settings', ['full', 'software', 'settings']),
                ('a' * 64, True, 'software', ['full', 'software', 'settings']),
                (None, True, 'software', ['full', 'software']),
                (f.artifact_hash(), False, 'full', ['full'])]:
            with self.subTest(installed=installed, enrolled=enrolled):
                _, plan, _ = self.validation_fixture(installed, enrolled)
                self.assertEqual(recommended, plan['recommendedMode'])
                self.assertEqual(modes, plan['availableModes'])
                self.assertEqual(installed, plan['installedArtifactHash'])
                self.assertEqual(installed != f.artifact_hash(), plan['versionMismatch'])
                self.assertEqual(f.artifact_components(), plan['artifactComponents'])
                self.assertEqual(not (installed == f.artifact_hash()),
                                 bool(plan['componentMismatches']))
                self.assertNotEqual(plan['stepsByMode']['full'], plan['stepsByMode']['settings'])

    def test_notebook_endpoint_protocol_requires_current_router_agent(self):
        endpoint = {'id': '2' * 64, 'name': 'User notebook', 'role': 'user',
                    'zeroTierAddress': '10.147.0.20', 'wireguardAddress': '10.203.0.20',
                    'wireguardKey': base64.b64encode(b'n' * 32).decode()}
        config = f.normalize_with_notebook_endpoints(self.nodes, self.config['networkId'], [endpoint])
        f.snapshot(self.root, config, {})
        _, plan, _ = self.validation_fixture('a' * 64)
        self.assertEqual(['full', 'software'], plan['availableModes'])
        self.assertEqual('software', plan['recommendedMode'])

    def test_settings_update_preserves_software_and_uses_apply_confirm(self):
        # A version mismatch recommends software-only, but an explicit settings-only choice remains valid.
        req, plan, lan = self.validation_fixture('a' * 64)
        before = (self.root / 'members.json').read_bytes()
        req.update(action='deploy', mode='settings', planId=plan['id'])
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f, 'ssh', return_value=b'hash') as ssh, \
                patch.object(f, 'installed_artifact_hash', return_value='a' * 64), \
                patch.object(f, 'installed_artifact_components', return_value=plan['installedArtifactComponents']), \
                patch.object(f, 'remote', side_effect=[{'token': 'confirm-me'}, {'state': 'active', 'appliedRevision': 1}]) as remote, \
                patch.object(f, 'distribute_bundle') as distribute:
            result = f.controller(self.root, req)
        self.assertEqual(['apply', 'confirm'], [c.args[2] for c in remote.call_args_list])
        self.assertEqual('hash', remote.call_args_list[0].kwargs['expectedRouterHash'])
        self.assertEqual('confirm-me', remote.call_args_list[1].kwargs['token'])
        self.assertEqual(before, (self.root / 'members.json').read_bytes())
        commands = '\n'.join(c.args[2] for c in ssh.call_args_list)
        for forbidden in ['opkg', 'install-web', 'web-check', 'restart', '.new', 'base64 -d']:
            self.assertNotIn(forbidden, commands)
        self.assertEqual(1, result['nodes'][node(1)['id']]['appliedRevision'])
        self.assertFalse((self.root / ('plan-' + node(1)['id'] + '.json')).exists())
        distribute.assert_called_once()

    def test_full_update_installs_software_and_restarts_web(self):
        req, plan, lan = self.validation_fixture('a' * 64)
        req.update(action='deploy', mode='full', planId=plan['id'])
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f, 'ssh', return_value=b'hash') as ssh, \
                patch.object(f, 'installed_artifact_hash', side_effect=['a' * 64, f.artifact_hash()]), \
                patch.object(f, 'installed_artifact_components',
                             side_effect=[plan['installedArtifactComponents'], f.artifact_components()]), \
                patch.object(f, 'remote', side_effect=[self.member(1), {'token': None}, {'state': 'active'}]) as remote, \
                patch.object(f, 'distribute_bundle'):
            f.controller(self.root, req)
        self.assertEqual(['bootstrap', 'apply', 'status'], [c.args[2] for c in remote.call_args_list])
        commands = '\n'.join(c.args[2] for c in ssh.call_args_list)
        for expected in ['opkg', 'install-web', 'web-check', 'restart', 'python3 -c']:
            self.assertIn(expected, commands)
        uploads = [c for c in ssh.call_args_list if c.kwargs.get('input_data') is not None]
        self.assertEqual(1, len(uploads))
        self.assertEqual(SOURCE.read_bytes() + f.INIT.encode(), uploads[0].kwargs['input_data'])
        self.assertLess(len(uploads[0].args[2]), 8192)
        self.assertNotIn(base64.b64encode(SOURCE.read_bytes()).decode(), uploads[0].args[2])

    def test_software_only_update_never_applies_or_distributes_network(self):
        req, plan, lan = self.validation_fixture('a' * 64)
        req.update(action='deploy', mode='software', planId=plan['id'])
        service = {'id': 'home', 'name': 'Home Assistant',
                   'hostAddress': '192.168.1.20', 'protocol': 'http',
                   'port': 8123, 'path': '/'}
        report = {'state': 'rollback', 'receivedRevision': 12, 'appliedRevision': 11,
                  'hosts': [{'address': '192.168.1.20', 'name': 'home.local'}],
                  'hostsObservedAt': 100, 'services': [service], 'servicesObservedAt': 101,
                  'software': f.software_info(), 'components': f.artifact_components()}
        before_members = (self.root / 'members.json').read_bytes()
        with patch.object(f, 'direct_lan', return_value=lan), \
                patch.object(f, 'ssh', return_value=b'hash') as ssh, \
                patch.object(f, 'installed_artifact_hash',
                             side_effect=['a' * 64, f.artifact_hash()]), \
                patch.object(f, 'installed_artifact_components',
                             side_effect=[plan['installedArtifactComponents'],
                                          f.artifact_components()]), \
                patch.object(f, 'remote', side_effect=[self.member(1), report]) as remote, \
                patch.object(f, 'snapshot') as snapshot, \
                patch.object(f, 'distribute_bundle') as distribute:
            result = f.controller(self.root, req)
        self.assertEqual(['bootstrap', 'status'], [call.args[2] for call in remote.call_args_list])
        snapshot.assert_not_called()
        distribute.assert_not_called()
        self.assertEqual(before_members, (self.root / 'members.json').read_bytes())
        commands = '\n'.join(call.args[2] for call in ssh.call_args_list)
        self.assertIn('install-web', commands)
        self.assertIn('turris-federation restart', commands)
        self.assertIn('software-rollback', commands)
        self.assertIn('manifest.json', commands)
        self.assertIn('shutil.rmtree', commands)
        self.assertNotIn('uci commit', commands)
        self.assertEqual('home', result['nodes'][node(1)['id']]['services'][0]['id'])
        self.assertFalse((self.root / ('plan-' + node(1)['id'] + '.json')).exists())

    def test_software_only_failure_restores_all_components_and_service_state(self):
        req, plan, lan = self.validation_fixture('a' * 64)
        req.update(action='deploy', mode='software', planId=plan['id'])

        def ssh_result(_node, _credentials, command, input_data=None):
            if ' web-check ' in command:
                raise ValueError('web check failed')
            return b'hash'

        with patch.object(f, 'direct_lan', return_value=lan), \
                patch.object(f, 'ssh', side_effect=ssh_result) as ssh, \
                patch.object(f, 'installed_artifact_hash',
                             side_effect=['a' * 64, f.artifact_hash()]), \
                patch.object(f, 'installed_artifact_components',
                             side_effect=[plan['installedArtifactComponents'],
                                          f.artifact_components()]), \
                patch.object(f, 'remote', return_value=self.member(1)), \
                patch.object(f, 'snapshot') as snapshot, \
                patch.object(f, 'distribute_bundle') as distribute, \
                self.assertRaisesRegex(ValueError, 'Původní software byl automaticky obnoven'):
            f.controller(self.root, req)

        commands = [call.args[2] for call in ssh.call_args_list]
        rollback = next(command for command in commands if '.rollback' in command)
        for path in f.software_component_paths():
            self.assertIn(path, rollback)
        self.assertIn('turris-federation restart', rollback)
        self.assertIn('shutil.rmtree', rollback)
        self.assertNotIn('uci commit', '\n'.join(commands))
        snapshot.assert_not_called()
        distribute.assert_not_called()
        self.assertTrue((self.root / ('plan-' + node(1)['id'] + '.json')).exists())

    def test_existing_router_activates_new_agent_before_configuration_apply(self):
        req, plan, lan = self.validation_fixture('a' * 64)
        req.update(action='deploy', mode='full', planId=plan['id'])
        with patch.object(f, 'direct_lan', return_value=lan), \
                patch.object(f, 'ssh', return_value=b'hash') as ssh, \
                patch.object(f, 'installed_artifact_hash', side_effect=['a' * 64, f.artifact_hash()]), \
                patch.object(f, 'installed_artifact_components',
                             side_effect=[plan['installedArtifactComponents'], f.artifact_components()]), \
                patch.object(f, 'remote', side_effect=[self.member(1), ValueError('apply failed')]) as remote, \
                self.assertRaisesRegex(ValueError, 'apply failed'):
            f.controller(self.root, req)
        self.assertEqual(['bootstrap', 'apply'], [call.args[2] for call in remote.call_args_list])
        commands = [call.args[2] for call in ssh.call_args_list]
        self.assertTrue(any('turris-federation restart' in command for command in commands))
        self.assertTrue(any('web-check' in command for command in commands))

    def test_deploy_rejects_unavailable_mode_and_changed_remote_version(self):
        req, plan, lan = self.validation_fixture(None, enrolled=False)
        req.update(action='deploy', mode='settings', planId=plan['id'])
        with patch.object(f, 'ssh') as ssh, self.assertRaisesRegex(ValueError, 'režim'):
            f.controller(self.root, req)
        ssh.assert_not_called()
        req, plan, lan = self.validation_fixture('a' * 64)
        req.update(action='deploy', mode='full', planId=plan['id'])
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f, 'ssh', return_value=b'hash') as ssh, \
                patch.object(f, 'installed_artifact_hash', return_value='b' * 64), patch.object(f, 'remote') as remote, \
                self.assertRaisesRegex(ValueError, 'Verze agenta'):
            f.controller(self.root, req)
        remote.assert_not_called()
        self.assertEqual(1, ssh.call_count)
        self.assertTrue((self.root / ('plan-' + node(1)['id'] + '.json')).exists())

    def test_installed_version_probe_accepts_hash_or_missing_only(self):
        for output, expected in [(('a' * 64 + '  -\n').encode(), 'a' * 64), (b'missing\n', None)]:
            with patch.object(f, 'ssh', return_value=output):
                self.assertEqual(expected, f.installed_artifact_hash(node(1), {}))
        for output in [b'', b'permission denied', b'not-a-hash']:
            with patch.object(f, 'ssh', return_value=output), self.assertRaisesRegex(ValueError, 'verzi'):
                f.installed_artifact_hash(node(1), {})

    def test_installed_component_probe_reports_each_file_independently(self):
        expected = {name: (chr(97 + index) * 64)
                    for index, name in enumerate(f.artifact_components())}
        paths = [f.PROGRAM, '/etc/init.d/turris-federation',
                 '/etc/turris-webapps/80-turris-federation.json',
                 '/www/webapps-icons/turris-federation.svg', str(f.WEB_PROXY_PATH)]
        output = ''.join('%s  %s\n' % (version, path)
                         for version, path in zip(expected.values(), paths)).encode()
        with patch.object(f, 'ssh', return_value=output):
            self.assertEqual(expected, f.installed_artifact_components(node(1), {}))
        missing = ''.join('missing %s\n' % path for path in paths).encode()
        with patch.object(f, 'ssh', return_value=missing):
            self.assertEqual({name: None for name in f.artifact_components()},
                             f.installed_artifact_components(node(1), {}))

    def test_publish_only_sends_network_document_and_never_installs(self):
        f.atomic(self.root / 'members.json', {node(1)['id']: self.member(1)})
        with patch.object(f, 'request_http', return_value={}) as http, \
             patch.object(f, 'peer_status', return_value={'state': 'pending'}), patch.object(f, 'ssh') as ssh:
            f.controller(self.root, {'action': 'publish', 'nodes': self.nodes, 'networkId': 'abcdef0123456789'})
        ssh.assert_not_called()
        call = http.call_args.args
        self.assertEqual(('POST', '/bundle'), call[1:3])
        doc = f.verify(self.public, call[3])
        self.assertEqual(self.config, doc['config'])
        f.validate_document(doc)
        self.assertNotIn('artifactHash', doc)

    def test_new_member_pushes_revision_to_first_router_without_notebook(self):
        first, second = self.root / 'first', self.root / 'second'
        for site in [first, second]:
            f.atomic(site / 'root.pub', self.public.encode())
        old = f.snapshot(self.root, self.config, {node(1)['id']: self.member(1)})
        f.accept(first, old)
        latest = f.snapshot(self.root, self.config, {node(i)['id']: self.member(i) for i in [1, 2]})
        current = f.accept(second, latest)
        calls = []

        def transport(ip, method, path, payload=None):
            self.assertEqual(node(1)['zeroTierAddress'], ip)
            self.assertEqual('/bundle', path)
            calls.append(method)
            if method == 'POST':
                with f.locked(first):
                    f.accept(first, payload)
                return {}
            return f.read(first / 'accepted.json')

        with patch.object(f, 'request_http', side_effect=transport), patch.object(f, 'ssh') as ssh:
            f.exchange_bundles(second, current, node(2)['id'])
        ssh.assert_not_called()
        self.assertEqual(['POST', 'GET'], calls)
        self.assertEqual(latest, f.read(first / 'accepted.json'))
        self.assertIn(node(2)['id'], f.verify(self.public, f.read(first / 'accepted.json'))['members'])
        self.assertFalse((first / 'root.pem').exists())
        self.assertEqual('pending', f.read(first / 'report.json')['state'])

    def test_rejected_push_still_pulls_newer_revision(self):
        old = f.snapshot(self.root, self.config, {node(i)['id']: self.member(i) for i in [1, 2]})
        current = f.accept(self.root, old)
        changed = copy.deepcopy(self.config)
        changed['nodes'][0]['name'] = 'New name'
        latest = f.snapshot(self.root, changed, current['members'])
        with patch.object(f, 'request_http', side_effect=[ValueError('older revision'), latest]) as http:
            f.exchange_bundles(self.root, current, node(1)['id'])
        self.assertEqual(2, http.call_count)
        self.assertEqual(latest, f.read(self.root / 'accepted.json'))

    def test_peer_retries_delivery_after_pending_apply_finishes(self):
        old = f.snapshot(self.root, self.config, {node(1)['id']: self.member(1)})
        f.accept(self.root, old)
        f.atomic(self.root / 'pending.json', {'revision': 1})
        latest = f.snapshot(self.root, self.config, {node(i)['id']: self.member(i) for i in [1, 2]})
        second = self.root / 'second'
        f.atomic(second / 'root.pub', self.public.encode())
        current = f.accept(second, latest)

        def transport(ip, method, path, payload=None):
            if method == 'POST':
                f.accept(self.root, payload)
                return {}
            return f.read(self.root / 'accepted.json')

        with patch.object(f, 'request_http', side_effect=transport):
            f.exchange_bundles(second, current, node(2)['id'])
            self.assertEqual(old, f.read(self.root / 'accepted.json'))
            (self.root / 'pending.json').unlink()
            f.exchange_bundles(second, current, node(2)['id'])
        self.assertEqual(latest, f.read(self.root / 'accepted.json'))

    def test_second_deploy_distributes_settings_and_preserves_offline_status(self):
        target = self.nodes[1]
        members = {node(1)['id']: self.member(1)}
        f.atomic(self.root / 'members.json', members)
        f.snapshot(self.root, self.config, members)
        service = {'id': 'printer', 'name': 'Printer', 'hostAddress': '192.168.1.20',
                   'protocol': 'https', 'port': 443, 'path': '/'}
        f.atomic(self.root / 'reports.json', {node(1)['id']: {
            'appliedRevision': 1,
            'hosts': [{'address': '192.168.1.20', 'name': 'printer.local'}],
            'hostsObservedAt': 100, 'services': [service], 'servicesObservedAt': 101}})
        lan = {'host': target['sshHost'], 'device': 'eth0', 'source': '192.168.2.10'}
        plan = {'id': 'deploy-second', 'expiresAt': time.time() + 600, 'configHash': f.digest(self.config),
                'hostKeyHash': f.digest('key'), 'membersHash': f.digest(members),
                'sshHash': f.digest({k: target[k] for k in ['sshHost', 'sshPort', 'sshUser']}),
                'lan': lan, 'availableModes': ['full'], 'installedArtifactHash': f.artifact_hash(),
                'artifactHash': f.artifact_hash(), 'artifactComponents': f.artifact_components(),
                'installedArtifactComponents': f.artifact_components(), 'routerHash': 'hash'}
        f.atomic(self.root / ('plan-' + target['id'] + '.json'), plan)
        req = {'action': 'deploy', 'nodes': self.nodes, 'networkId': self.config['networkId'],
               'nodeId': target['id'], 'planId': plan['id'], 'credentials': {'hostKey': 'key', 'password': 'test'}}
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f, 'ssh', return_value=b'hash') as ssh, \
                patch.object(f, 'installed_artifact_hash', return_value=f.artifact_hash()), \
                patch.object(f, 'installed_artifact_components', return_value=f.artifact_components()), \
                patch.object(f, 'remote', side_effect=[self.member(2), {'token': 'ok'},
                    {'state': 'waiting_peers', 'appliedRevision': 2}]) as remote, \
                patch.object(f, 'request_http', side_effect=ValueError('offline')) as http:
            result = f.controller(self.root, req)
        self.assertEqual(2, result['revision'])
        self.assertEqual(2, result['nodes'][target['id']]['appliedRevision'])
        self.assertFalse(result['nodes'][node(1)['id']]['reachable'])
        self.assertEqual(1, result['nodes'][node(1)['id']]['appliedRevision'])
        self.assertTrue(all(call.args[0]['id'] == target['id'] for call in ssh.call_args_list + remote.call_args_list))
        self.assertEqual(node(1)['zeroTierAddress'], http.call_args.args[0])
        self.assertEqual(('POST', '/bundle'), http.call_args.args[1:3])
        self.assertEqual(2, f.verify(self.public, http.call_args.args[3])['revision'])
        # Explicit retry reuses this signed revision; receipt is not application.
        with patch.object(f, 'request_http', return_value={}), \
                patch.object(f, 'peer_status', return_value={'receivedRevision': 2, 'appliedRevision': 1, 'state': 'pending'}):
            f.distribute_bundle(self.root, f.read(self.root / 'published.json'), exclude=target['id'])
        first = f.read(self.root / 'reports.json')[node(1)['id']]
        self.assertTrue(first['reachable'])
        self.assertNotIn('error', first)
        self.assertEqual(1, first['appliedRevision'])
        self.assertEqual(2, first['receivedRevision'])
        self.assertEqual('printer.local', first['hosts'][0]['name'])
        self.assertEqual(service, first['services'][0])

    def test_network_sync_refuses_software_and_commands(self):
        for key in ['software', 'command', 'artifact', 'update']:
            doc = self.document()
            doc[key] = 'unwanted'
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'pouze síťové'):
                f.accept(self.root, f.sign(self.root / 'root.pem', doc))
        self.assertFalse((self.root / 'accepted.json').exists())

    def test_web_renders_selected_status_and_escapes_router_names(self):
        doc = self.document(members={node(1)['id']: self.member(1), node(2)['id']: self.member(2)})
        doc['config']['nodes'][0]['name'] = '<script>alert(1)</script>'
        f.atomic(self.root / 'accepted.json', f.sign(self.root / 'root.pem', doc))
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'report.json', {'state': 'waiting_peers', 'appliedRevision': 1,
                 'checkedAt': 100, 'pendingPeers': [node(2)['id']], 'error': '<b>failure</b>', 'secret': 'REPORT-SECRET',
                 'hosts': [{'address': '192.168.1.20', 'name': 'printer.local'}], 'hostsObservedAt': 100,
                 'services': [{'id': 'printer', 'name': 'Printer web', 'hostAddress': '192.168.1.20',
                               'protocol': 'https', 'port': 8443, 'path': '/status'}], 'servicesObservedAt': 100})
        f.atomic(self.root / 'catalog.json', {node(2)['id']: {
                 'hosts': [{'address': '192.168.2.30', 'name': 'camera'}], 'hostsObservedAt': 100,
                 'services': [{'id': 'camera', 'name': 'Camera stream', 'hostAddress': '192.168.2.30',
                               'protocol': 'tcp', 'port': 8554, 'path': None}], 'servicesObservedAt': 100}})
        f.atomic(self.root / 'wireguard.key', b'PRIVATE-WG-SECRET')
        overview = f.web_page(self.root).decode()
        for wanted in ['&lt;script&gt;', '&lt;b&gt;failure&lt;/b&gt;', 'Stanoviště 2', 'Čeká na protějšky', '10.147.0.1', '192.168.1.0/24', 'printer.local', '192.168.2.30', 'camera']:
            self.assertIn(wanted, overview)
        directory = f.web_page(self.root, authenticated=False).decode()
        for wanted in ['&lt;script&gt;', 'Printer web', 'https://192.168.1.20:8443/status',
                       'Camera stream', '192.168.2.30:8554']:
            self.assertIn(wanted, directory)
        self.assertNotIn('Přes ZeroTier router', directory)
        self.assertIn('href="https://192.168.1.20:8443/status" target="_blank" rel="noopener noreferrer"', directory)
        self.assertNotIn('href="192.168.2.30:8554"', directory)
        for unwanted in ['<script>', '<b>failure</b>', 'PRIVATE-WG-SECRET', 'REPORT-SECRET', 'BEGIN PUBLIC KEY', 'BEGIN PRIVATE KEY']:
            self.assertNotIn(unwanted, overview)
            self.assertNotIn(unwanted, directory)
        self.assertIn('nepotvrzuje, že služba právě odpovídá', directory)
        filtered = f.web_page(self.root, service_filters={
            'service': 'Printer', 'protocol': 'https', 'host': 'printer.local', 'router': '<script>'},
            authenticated=False).decode()
        self.assertIn('Printer web', filtered)
        self.assertNotIn('Camera stream', filtered)

    def test_ping_badge_thresholds_and_stale_measurements(self):
        for replies, color in [(20, 'green'), (19, 'green'), (18, 'yellow'), (16, 'yellow'), (15, 'red'), (14, 'red'), (0, 'red')]:
            sample = {'samples': [True] * replies + [False] * (20 - replies), 'checkedAt': 100}
            with self.subTest(replies=replies):
                self.assertIn('signal ' + color, f.diagnostic_badge(sample, 110))
                self.assertIn('%s/20' % replies, f.diagnostic_badge(sample, 110))
                self.assertIn('unknown', f.diagnostic_badge(sample, 221))
                self.assertIn('unknown', f.diagnostic_badge(sample, 99))
        self.assertIn('unknown', f.diagnostic_badge({}, 100))

    def test_ping_sample_handles_loss_and_execution_errors(self):
        for code, expected in [(0, True), (1, False), (2, None)]:
            with patch.object(f.subprocess, 'run', return_value=subprocess.CompletedProcess([], code)) as run:
                self.assertIs(expected, f.ping_sample('10.147.0.2', '10.147.0.1'))
                self.assertEqual(['ping', '-c', '1', '-W', '1', '-I', '10.147.0.1', '10.147.0.2'], run.call_args.args[0])
        for error, expected in [(FileNotFoundError(), None), (subprocess.TimeoutExpired('ping', 4), False)]:
            with patch.object(f.subprocess, 'run', side_effect=error):
                self.assertIs(expected, f.ping_sample('10.147.0.2', 'tf_wg'))

    def test_notebook_diagnostics_only_ping_signed_enrolled_zerotier_targets(self):
        members = {node(1)['id']: self.member(1)}
        envelope = f.snapshot(self.root, self.config, members)
        with patch.object(f, 'ping_sample', return_value=True) as ping:
            result = f.notebook_diagnostics(self.root)
        self.assertEqual('complete', result['state'])
        self.assertEqual({node(1)['id']}, set(result['nodes']))
        self.assertEqual([True] * 5, result['nodes'][node(1)['id']]['zerotier']['samples'])
        self.assertEqual([('10.147.0.1', None)] * 5, [call.args for call in ping.call_args_list])
        self.assertEqual(1, f.verify(self.public, envelope)['revision'])

        with patch.object(f, 'ping_sample', return_value=True) as ping:
            f.controller(self.root, {'action': 'diagnostics', 'nodes': self.nodes,
                         'networkId': self.config['networkId'], 'target': '8.8.8.8'})
        self.assertEqual({('10.147.0.1', None)}, {call.args for call in ping.call_args_list})

        saved = f.read(self.root / 'notebook-diagnostics.json')
        saved['nodes'][node(2)['id']] = {'zerotier': {'address': '8.8.8.8', 'samples': [True]}}
        f.atomic(self.root / 'notebook-diagnostics.json', saved)
        self.assertEqual({node(1)['id']}, set(f.notebook_diagnostics_overview(self.root)['nodes']))

    def test_notebook_diagnostics_reject_missing_membership_and_stale_results(self):
        with self.assertRaisesRegex(ValueError, 'publikovanou'):
            f.notebook_diagnostics(self.root)
        f.snapshot(self.root, self.config, {})
        with self.assertRaisesRegex(ValueError, 'přijaté routery'):
            f.notebook_diagnostics(self.root)
        members = {node(1)['id']: self.member(1)}
        f.snapshot(self.root, self.config, members)
        f.atomic(self.root / 'notebook-diagnostics.json', {'revision': 0, 'state': 'complete', 'nodes': {node(1)['id']: {}}})
        self.assertEqual('idle', f.notebook_diagnostics_overview(self.root)['state'])

    def test_read_only_notebook_overview_uses_signed_revision_and_omits_admin_fields(self):
        members = {node(1)['id']: self.member(1)}
        config = f.normalize_with_notebooks(self.nodes, self.config['networkId'], [{
            'id': 'c' * 64, 'name': 'User notebook', 'role': 'user',
            'zeroTierAddress': None, 'wireguardAddress': None,
        }])
        f.snapshot(self.root, config, members)
        f.atomic(self.root / 'reports.json', {node(1)['id']: {
            'state': 'active', 'reachable': True, 'checkedAt': 100,
            'software': {'version': 'a' * 64, 'builtAt': 99},
            'components': {**f.artifact_components(), 'agent': 'b' * 64, 'init': 'c' * 64},
            'hosts': [{'address': '192.168.1.20', 'name': 'printer'}], 'hostsObservedAt': 100,
            'services': [{'id': 'printer-web', 'name': 'Printer', 'hostAddress': '192.168.1.20',
                          'protocol': 'https', 'port': 8443, 'path': '/status'}], 'servicesObservedAt': 100,
            'error': 'INTERNAL', 'privateKey': 'SECRET'},
            node(2)['id']: {'hosts': [{'address': '192.168.2.20', 'name': 'draft-host'}], 'hostsObservedAt': 100,
                            'services': [{'id': 'draft-service', 'name': 'Hidden', 'hostAddress': '192.168.2.20',
                                          'protocol': 'tcp', 'port': 1234, 'path': None}], 'servicesObservedAt': 100}})
        f.atomic(self.root / 'root.pub', self.public.encode())
        (self.root / 'root.pem').unlink()

        result = f.read_only_notebook_overview(self.root)
        self.assertEqual((1, 'abcdef0123456789'), (result['revision'], result['networkId']))
        self.assertEqual(2, len(result['nodes']))
        enrolled, draft = result['nodes']
        self.assertTrue(enrolled['enrolled'])
        self.assertEqual({'version': 'a' * 64, 'builtAt': 99}, enrolled['software'])
        self.assertEqual({**f.artifact_components(), 'agent': 'b' * 64, 'init': 'c' * 64},
                         enrolled['components'])
        self.assertIsNone(draft['software'])
        self.assertIsNone(draft['components'])
        self.assertEqual(f.artifact_hash(), result['availableRouterVersion'])
        self.assertEqual(f.artifact_components(), result['availableRouterComponents'])
        self.assertEqual([{'address': '192.168.1.20', 'name': 'printer'}], enrolled['hosts'])
        self.assertFalse(draft['enrolled'])
        self.assertEqual([], draft['hosts'])
        self.assertEqual(1, len(result['services']))
        self.assertEqual(('https://192.168.1.20:8443/status', 'printer', node(1)['id']),
                         (result['services'][0]['endpoint'], result['services'][0]['hostName'], result['services'][0]['routerId']))
        self.assertNotIn('draft-service', json.dumps(result['services']))
        self.assertEqual([{'id': 'c' * 64, 'name': 'User notebook', 'role': 'user',
                           'zeroTierAddress': None, 'wireguardAddress': None,
                           'software': None}], result['notebooks'])
        raw = json.dumps(result)
        for secret in ['sshHost', 'sshUser', 'sshPort', 'publicEndpoint', 'privateKey', 'SECRET', 'INTERNAL', 'fingerprint']:
            self.assertNotIn(secret, raw)

    def prepare_diagnostics(self):
        config = f.normalize(self.nodes + [node(3)], self.config['networkId'])
        doc = self.document(config=config, members={node(1)['id']: self.member(1), node(2)['id']: self.member(2)})
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'accepted.json', f.sign(self.root / 'root.pem', doc))
        f.atomic(self.root / 'report.json', {'appliedRevision': doc['revision'], 'state': 'active'})
        return doc

    def test_on_demand_ping_sends_five_packets_per_transport_without_history(self):
        self.prepare_diagnostics()
        with patch.object(f, 'ping_sample', side_effect=lambda address, interface: interface == 'tf_wg') as ping:
            worker = f.start_diagnostics(self.root)
            worker.join(5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(10, ping.call_count)
        self.assertEqual({('10.147.0.2', '10.147.0.1'), ('10.203.0.2', 'tf_wg')}, {c.args for c in ping.call_args_list})
        result = f.read(self.root / 'diagnostics.json')
        self.assertEqual('complete', result['state'])
        self.assertEqual([True] * 5, result['nodes'][node(2)['id']]['wireguard']['samples'])
        self.assertEqual(0, result['nodes'][node(2)['id']]['zerotier']['successPercent'])
        page = f.web_page(self.root).decode()
        for text in ['Ping ZeroTier', 'Ping WireGuard', 'signal green', 'signal red', '5/5', '0/5']:
            self.assertIn(text, page)
        with patch.object(f, 'ping_sample', return_value=False) as ping:
            worker = f.start_diagnostics(self.root)
            worker.join(5)
        self.assertEqual(10, ping.call_count)
        self.assertEqual([False] * 5, f.read(self.root / 'diagnostics.json')['nodes'][node(2)['id']]['wireguard']['samples'])
        self.assertNotIn('diagnostics', f.read(self.root / 'report.json'))

    def test_diagnostics_reject_concurrent_requests_and_discard_changed_revision(self):
        doc = self.prepare_diagnostics()
        entered, release = threading.Event(), threading.Event()
        def measure(*_):
            entered.set()
            release.wait(5)
            return {}
        with patch.object(f, 'ping_diagnostics', side_effect=measure):
            worker = f.start_diagnostics(self.root)
            try:
                self.assertTrue(entered.wait(2))
                self.assertIn('Probíhá měření', f.web_page(self.root).decode())
                with self.assertRaisesRegex(ValueError, 'už běží'):
                    f.start_diagnostics(self.root)
                doc['revision'] += 1
                f.atomic(self.root / 'accepted.json', f.sign(self.root / 'root.pem', doc))
            finally:
                release.set()
                worker.join(5)
        result = f.read(self.root / 'diagnostics.json')
        self.assertEqual('error', result['state'])
        self.assertEqual({}, result['nodes'])

    def test_diagnostics_require_applied_membership(self):
        with patch.object(f, 'ping_diagnostics') as ping:
            with self.assertRaises(ValueError):
                f.start_diagnostics(self.root)
            self.prepare_diagnostics()
            f.atomic(self.root / 'pending.json', {'phase': 'applying'})
            with self.assertRaises(ValueError):
                f.start_diagnostics(self.root)
            (self.root / 'pending.json').unlink()
            f.atomic(self.root / 'report.json', {'appliedRevision': 0})
            with self.assertRaises(ValueError):
                f.start_diagnostics(self.root)
            ping.assert_not_called()

    def test_periodic_health_uses_handshakes_without_sending_ping(self):
        doc = self.prepare_diagnostics()
        key = self.member(2)['wireguardKey']
        service = {'id': 'ollama', 'name': 'Ollama', 'hostAddress': '192.168.1.20',
                   'protocol': 'tcp', 'port': 11434, 'path': None}
        f.save_local_service(self.root, node(1), service)
        for handshake, state in [(1000, 'active'), (820, 'active'), (819, 'waiting_peers'), (0, 'waiting_peers')]:
            def run(args):
                if args[-1] == 'public-key':
                    return self.member(1)['wireguardKey'].encode()
                if args[-1] == 'peers':
                    return key.encode()
                if args[-1] == 'allowed-ips':
                    return (key + ' 10.203.0.2/32 192.168.2.0/24').encode()
                if args[-1] == 'latest-handshakes':
                    return (key + ' ' + str(handshake)).encode()
                return b'dev tf_wg'
            with self.subTest(handshake=handshake), patch.object(f, 'run', side_effect=run), \
                    patch.object(f.time, 'time', return_value=1000), patch.object(f, 'ping_sample') as ping:
                result = f.health(self.root, doc)
                self.assertEqual(state, result['state'])
                self.assertEqual(([service], 1000), (result['services'], result['servicesObservedAt']))
                ping.assert_not_called()
        self.assertFalse((self.root / 'diagnostics.json').exists())

    def test_router_validates_notebook_host_route_without_monitoring_its_handshake(self):
        doc = self.prepare_diagnostics()
        endpoint = {'id': 'f' * 64, 'name': 'User notebook', 'role': 'user',
                    'zeroTierAddress': '10.147.0.20', 'wireguardAddress': '10.203.0.20',
                    'wireguardKey': base64.b64encode(b'n' * 32).decode()}
        doc['schema'] = f.NOTEBOOK_WG_VERSION
        doc['config'] = f.normalize_with_notebook_endpoints(doc['config']['nodes'],
                                                            doc['config']['networkId'], [endpoint])
        router_key = self.member(2)['wireguardKey']
        def run(args):
            if args[-1] == 'public-key':
                return self.member(1)['wireguardKey'].encode()
            if args[-1] == 'peers':
                return (router_key + '\n' + endpoint['wireguardKey']).encode()
            if args[-1] == 'allowed-ips':
                return (router_key + ' 10.203.0.2/32 192.168.2.0/24\n' +
                        endpoint['wireguardKey'] + ' 10.203.0.20/32').encode()
            if args[-1] == 'latest-handshakes':
                return (router_key + ' 1000\n' + endpoint['wireguardKey'] + ' 0').encode()
            return b'dev tf_wg'
        with patch.object(f, 'run', side_effect=run), patch.object(f.time, 'time', return_value=1000):
            result = f.health(self.root, doc)
        self.assertEqual('active', result['state'])
        self.assertEqual([], result['pendingPeers'])

    def test_local_service_catalog_is_strict_atomic_and_router_owned(self):
        service = {'id': 'ollama-main', 'name': 'Ollama', 'hostAddress': '192.168.1.20',
                   'protocol': 'tcp', 'port': 11434, 'path': None}
        self.assertEqual([service], f.save_local_service(self.root, node(1), service))
        self.assertEqual([service], f.local_services(self.root, node(1)))
        self.assertEqual(0o600, (self.root / 'services.json').stat().st_mode & 0o777)
        published = f.read(self.root / 'report.json')
        self.assertEqual([service], published['services'])
        self.assertIsInstance(published['servicesObservedAt'], float)

        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'accepted.json', f.sign(self.root / 'root.pem', self.document()))
        f.atomic(self.root / 'report.json', {'state': 'rollback', 'appliedRevision': 0})
        hosts = [{'address': '192.168.1.20', 'name': 'printer.local'}]
        with patch.object(f, 'discover_hosts', return_value=hosts):
            recovered = f.status_report(self.root)
        self.assertEqual([service], recovered['services'])
        self.assertIsInstance(recovered['servicesObservedAt'], float)
        self.assertEqual(hosts, recovered['hosts'])
        self.assertIsInstance(recovered['hostsObservedAt'], float)

        invalid = [
            dict(service, hostAddress='192.168.2.20'),
            dict(service, port=0),
            dict(service, port=True),
            dict(service, protocol='udp'),
            dict(service, path='/not-for-tcp'),
            dict(service, id='Bad ID'),
            dict(service, name=''),
            {**service, 'unexpected': 'field'},
        ]
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(ValueError):
                f.validate_services(node(1), [item])
        for path in ['relative', '/search?q=secret', '/fragment#secret']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                f.validate_services(node(1), [dict(service, protocol='https', path=path)])
        self.assertEqual([service], f.local_services(self.root, node(1)))

    def test_duplicate_service_endpoint_requires_explicit_confirmation(self):
        first = {'id': 'ollama-main', 'name': 'Ollama', 'hostAddress': '192.168.1.20',
                 'protocol': 'tcp', 'port': 11434, 'path': None}
        second = dict(first, id='ollama-alias', name='Local model')
        f.save_local_service(self.root, node(1), first)
        with self.assertRaisesRegex(ValueError, 'potvrďte duplicitu'):
            f.save_local_service(self.root, node(1), second)
        self.assertEqual(2, len(f.save_local_service(self.root, node(1), second, allow_duplicate=True)))
        self.assertEqual([second], f.delete_local_service(self.root, node(1), first['id']))

    def test_service_dns_projects_only_exact_internal_names(self):
        services = [
            {'id': 'home-assistant', 'name': 'Home Assistant',
             'hostAddress': '192.168.1.20', 'protocol': 'https', 'port': 8123,
             'path': '/lovelace'},
            {'id': 'ollama', 'name': 'Ollama', 'hostAddress': '192.168.1.30',
             'protocol': 'tcp', 'port': 11434, 'path': None},
        ]
        self.assertEqual(
            b'192.168.1.20 home-assistant.cacke.internal\n'
            b'192.168.1.30 ollama.cacke.internal\n',
            f.render_service_dns_hosts(node(1), services, 'cacke.internal'))
        for zone in ['cacke.local', '*.cacke.internal', 'Cacke.internal',
                     'cacke.internal.', 'internal']:
            with self.subTest(zone=zone), self.assertRaises(ValueError):
                f.render_service_dns_hosts(node(1), services, zone)
        with self.assertRaisesRegex(ValueError, 'DNS jméno'):
            f.render_service_dns_hosts(node(1), [dict(services[0], id='nested.name')],
                                       'cacke.internal')

    def test_service_dns_reconcile_is_owned_retryable_and_disableable(self):
        service = {'id': 'ollama', 'name': 'Ollama', 'hostAddress': '192.168.1.20',
                   'protocol': 'tcp', 'port': 11434, 'path': None}
        f.save_local_service(self.root, node(1), service)
        f.configure_service_dns(self.root, node(1), 'cacke.internal')
        commands = []
        runtime_hosts = self.root / 'kresd' / 'turris-federation.hosts'
        runtime_hosts.parent.mkdir()
        def command(value):
            commands.append(value)
            return True
        result = f.reconcile_service_dns(self.root, node(1), command, runtime_hosts)
        self.assertEqual({'zone': 'cacke.internal', 'records': 1}, result)
        hosts_path = self.root / f.SERVICE_DNS_HOSTS
        self.assertEqual(b'192.168.1.20 ollama.cacke.internal\n', hosts_path.read_bytes())
        self.assertEqual(hosts_path.read_bytes(), runtime_hosts.read_bytes())
        self.assertEqual(0o644, runtime_hosts.stat().st_mode & 0o777)
        self.assertEqual(['hints.add_hosts(%s)' % json.dumps(str(runtime_hosts))], commands)

        # Reconciliation reloads memory-only hints after a resolver restart.
        commands.clear()
        f.reconcile_service_dns(self.root, node(1), command, runtime_hosts)
        self.assertEqual(['hints.add_hosts(%s)' % json.dumps(str(runtime_hosts))], commands)

        f.delete_local_service(self.root, node(1), 'ollama')
        f.save_local_service(self.root, node(1), dict(service, id='ollama-new'))
        commands.clear()
        f.reconcile_service_dns(self.root, node(1), command, runtime_hosts)
        self.assertEqual('hints.del("ollama.cacke.internal")', commands[0])
        self.assertEqual('hints.add_hosts(%s)' % json.dumps(str(runtime_hosts)), commands[1])
        self.assertIn(b'ollama-new.cacke.internal', hosts_path.read_bytes())

        f.disable_service_dns(self.root)
        commands.clear()
        result = f.reconcile_service_dns(self.root, node(1), command, runtime_hosts)
        self.assertEqual({'zone': None, 'records': 0}, result)
        self.assertEqual(['hints.del("ollama-new.cacke.internal")'], commands)
        self.assertEqual(b'', hosts_path.read_bytes())
        self.assertFalse(runtime_hosts.exists())

    def test_service_dns_reports_kresd_rejection_instead_of_false_success(self):
        service = {'id': 'ollama', 'name': 'Ollama', 'hostAddress': '192.168.1.20',
                   'protocol': 'tcp', 'port': 11434, 'path': None}
        f.save_local_service(self.root, node(1), service)
        f.configure_service_dns(self.root, node(1), 'cacke.internal')
        runtime_hosts = self.root / 'kresd' / 'turris-federation.hosts'
        runtime_hosts.parent.mkdir()
        with self.assertRaisesRegex(ValueError, 'nenačetl'):
            f.reconcile_service_dns(self.root, node(1), lambda _: False, runtime_hosts)
        self.assertFalse((self.root / f.SERVICE_DNS_LOADED).exists())

    def test_authenticated_web_manages_local_service_dns_with_csrf(self):
        self.prepare_diagnostics()
        handler = f.web_handler(self.root)
        page = self.web_request('GET', f.WEB_OVERVIEW_PATH, handler=handler)
        token = re.search(rb'name="token" value="([a-f0-9]+)"', page)[1].decode()
        self.assertIn('DNS lokality'.encode(), page)
        self.assertNotIn(b'name="zone"', self.web_request('GET', f.WEB_PATH, handler=handler))

        invalid = self.web_request('POST', f.WEB_OVERVIEW_PATH + 'dns/config',
                                   urlencode({'token': token, 'zone': 'example.com'}), handler)
        self.assertIn(b'409', invalid)
        self.assertFalse((self.root / f.SERVICE_DNS_CONFIG).exists())

        configured = self.web_request('POST', f.WEB_OVERVIEW_PATH + 'dns/config',
                                      urlencode({'token': token, 'zone': 'cacke.internal'}), handler)
        self.assertIn(b'303', configured)
        self.assertEqual({'zone': 'cacke.internal'}, f.service_dns_configuration(self.root))
        self.assertIn(b'value="cacke.internal"',
                      self.web_request('GET', f.WEB_OVERVIEW_PATH, handler=handler))

        disabled = self.web_request('POST', f.WEB_OVERVIEW_PATH + 'dns/disable',
                                    urlencode({'token': token}), handler)
        self.assertIn(b'303', disabled)
        self.assertIsNone(f.service_dns_configuration(self.root))

    def test_legacy_router_port_is_dropped_locally_and_rejected_in_reports(self):
        service = {'id': 'home-assistant', 'name': 'Home Assistant',
                   'hostAddress': '192.168.1.20', 'protocol': 'https', 'port': 8123,
                   'path': '/lovelace'}
        legacy = {**service, 'routerPort': 18123}
        f.atomic(self.root / 'services.json', [legacy])
        self.assertEqual([service], f.local_services(self.root, node(1)))
        with self.assertRaises(ValueError):
            f.validate_services(node(1), [legacy])
        f.save_local_service(self.root, node(1), service)
        self.assertEqual([service], f.read(self.root / 'services.json'))
        self.assertEqual([service], f.read(self.root / 'report.json')['services'])

    def test_service_editor_hosts_are_observed_or_already_configured(self):
        service = {'id': 'legacy', 'name': 'Legacy service', 'hostAddress': '192.168.1.20',
                   'protocol': 'tcp', 'port': 1234, 'path': None}
        report = {'hosts': [{'address': '192.168.1.30', 'name': 'current.local'}],
                  'hostsObservedAt': 100}
        hosts = f.editable_service_hosts(node(1), report, [service])
        self.assertEqual([
            {'address': '192.168.1.20', 'name': None, 'observed': False},
            {'address': '192.168.1.30', 'name': 'current.local', 'observed': True},
        ], hosts)

    def test_authenticated_web_editor_enforces_csrf_and_exact_service_fields(self):
        self.prepare_diagnostics()
        report = f.read(self.root / 'report.json')
        report.update(hosts=[{'address': '192.168.1.20', 'name': 'home.local'}], hostsObservedAt=time.time())
        f.atomic(self.root / 'report.json', report)
        handler = f.web_handler(self.root)
        page = self.web_request('GET', f.WEB_OVERVIEW_PATH, handler=handler)
        token = re.search(rb'name="token" value="([a-f0-9]+)"', page)[1].decode()
        self.assertIn(b'name="editorHost"', page)
        self.assertNotIn(b'name="hostAddress"', page)
        selected = self.web_request('GET', f.WEB_OVERVIEW_PATH + '?editorHost=192.168.1.20', handler=handler)
        self.assertIn(b'home.local', selected)
        self.assertIn(b'name="hostAddress" value="192.168.1.20"', selected)
        self.assertNotIn('Zlaté stránky služeb</h2>'.encode(), selected)
        service = {'token': token, 'id': 'home-assistant', 'name': 'Home Assistant',
                   'hostAddress': '192.168.1.20', 'protocol': 'https', 'port': '8123',
                   'path': '/lovelace', 'confirmDuplicate': '0'}
        for changed, status in [({'token': '0' * 64}, b'403'), ({'extra': 'field'}, b'400'),
                                ({'hostAddress': '192.168.1.21'}, b'409'),
                                ({'hostAddress': '192.168.2.20'}, b'409')]:
            response = self.web_request('POST', f.WEB_OVERVIEW_PATH + 'services/save',
                                        urlencode({**service, **changed}), handler)
            self.assertIn(status, response)
        self.assertFalse((self.root / 'services.json').exists())
        response = self.web_request('POST', f.WEB_OVERVIEW_PATH + 'services/save', urlencode(service), handler)
        self.assertIn(b'303', response)
        self.assertIn(b'Location: /turris-federation/overview/?editorHost=192.168.1.20', response)
        self.assertNotIn(b'home-assistant', self.web_request('GET', f.WEB_PATH, handler=handler))
        self.assertIn('Home Assistant'.encode(), self.web_request('GET', f.WEB_PATH, handler=handler))
        service_list = self.web_request('GET', f.WEB_OVERVIEW_PATH + '?editorHost=192.168.1.20', handler=handler)
        self.assertIn(b'home-assistant', service_list)
        self.assertIn(b'editorService=home-assistant', service_list)
        edit_page = self.web_request(
            'GET', f.WEB_OVERVIEW_PATH + '?editorHost=192.168.1.20&editorService=home-assistant', handler=handler)
        for expected in [b'Upravit slu', b'value="home-assistant" readonly', b'value="Home Assistant"',
                         b'value="8123"', b'value="/lovelace"', b'<option value="https" selected>']:
            self.assertIn(expected, edit_page)
        updated = {**service, 'name': 'Home Assistant upravený', 'protocol': 'http',
                   'port': '8124', 'path': '/dashboard'}
        response = self.web_request('POST', f.WEB_OVERVIEW_PATH + 'services/save',
                                    urlencode(updated), handler)
        self.assertIn(b'303', response)
        saved = f.local_services(self.root, node(1))
        self.assertEqual(1, len(saved))
        self.assertEqual(('Home Assistant upravený', 'http', 8124, '/dashboard'),
                         (saved[0]['name'], saved[0]['protocol'], saved[0]['port'],
                          saved[0]['path']))
        response = self.web_request('POST', f.WEB_OVERVIEW_PATH + 'services/delete',
                                    urlencode({'token': token, 'id': 'home-assistant'}), handler)
        self.assertIn(b'303', response)
        self.assertEqual([], f.local_services(self.root, node(1)))
        self.assertEqual([], f.read(self.root / 'report.json')['services'])

    def test_web_only_explicit_token_protected_post_starts_diagnostics(self):
        self.prepare_diagnostics()
        handler = f.web_handler(self.root)
        with patch.object(f, 'start_diagnostics') as start:
            page = self.web_request('GET', f.WEB_OVERVIEW_PATH, handler=handler)
            token = re.search(rb'name="token" value="([a-f0-9]+)"', page)[1].decode()
            self.web_request('GET', f.WEB_OVERVIEW_PATH, handler=handler)
            self.assertIn(b'404', self.web_request('GET', f.WEB_OVERVIEW_PATH + 'diagnostics', handler=handler))
            for body, status in [('token=wrong', b'403'), ('token=%FF', b'403'), ('token=' + token + '&target=8.8.8.8', b'403'), ('', b'400')]:
                response = self.web_request('POST', f.WEB_OVERVIEW_PATH + 'diagnostics', body, handler)
                self.assertIn(status, response)
            start.assert_not_called()
            response = self.web_request('POST', f.WEB_OVERVIEW_PATH + 'diagnostics', 'token=' + token, handler)
            self.assertIn(b'303', response)
            self.assertIn(b'Location: /turris-federation/overview/', response)
            start.assert_called_once_with(self.root)
        with patch.object(f, 'start_diagnostics', side_effect=ValueError('Diagnostika už běží.')):
            self.assertIn(b'409', self.web_request('POST', f.WEB_OVERVIEW_PATH + 'diagnostics', 'token=' + token, handler))

    def web_request(self, method, path, body='', handler=None):
        client, server = socket.socketpair()
        client.settimeout(5)
        server.settimeout(5)
        def handle():
            try:
                (handler or f.web_handler(self.root))(server, ('127.0.0.1', 1234), None)
            finally:
                server.close()
        thread = threading.Thread(target=handle)
        thread.start()
        try:
            client.sendall(('%s %s HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %s\r\n\r\n%s' % (method, path, len(body.encode()), body)).encode())
            parts = []
            while True:
                part = client.recv(65536)
                if not part:
                    break
                parts.append(part)
            return b''.join(parts)
        finally:
            client.close()
            thread.join(timeout=5)

    def test_public_web_directory_is_read_only_and_does_not_expose_overview_or_files(self):
        response = self.web_request('GET', '/turris-federation/')
        self.assertIn(b'200 OK', response)
        self.assertIn(b'Cache-Control: no-store', response)
        self.assertIn(b'frame-ancestors', response)
        self.assertIn('Zlaté stránky služeb'.encode(), response)
        self.assertIn(b'href="/turris-federation/overview/"', response)
        for private in ['Editor služeb', 'Uzly federace', 'ZeroTier Network ID', 'name="token"']:
            self.assertNotIn(private.encode(), response)
        self.assertIn(b'400', self.web_request('GET', '/turris-federation/?editorHost=192.168.1.20'))
        for path in ['/bundle', '/etc/turris-federation/root.pub', '/turris-federation/../root.pem']:
            self.assertIn(b'404', self.web_request('GET', path))
        script = self.web_request('GET', '/turris-federation/app.js')
        self.assertIn(b'200 OK', script)
        self.assertIn(b'navigator.clipboard.writeText', script)
        self.assertIn(b"script-src 'self'", response)
        self.assertIn(b'400', self.web_request('GET', '/turris-federation/?protocol=ssh'))
        self.assertIn(b'400', self.web_request('GET', '/turris-federation/?service=a&service=b'))
        for method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            self.assertIn(b'405', self.web_request(method, '/turris-federation/'))
        self.assertFalse((self.root / 'report.json').exists())

    def test_overview_route_contains_only_authenticated_management_content(self):
        response = self.web_request('GET', f.WEB_OVERVIEW_PATH)
        self.assertIn(b'200 OK', response)
        self.assertIn('Uzly federace'.encode(), response)
        self.assertIn('Editor služeb'.encode(), response)
        self.assertNotIn('Zlaté stránky služeb</h2>'.encode(), response)
        self.assertIn(b'href="/turris-federation/"', response)

    def test_web_corrupt_config_returns_error_without_raw_exception(self):
        f.atomic(self.root / 'accepted.json', b'PRIVATE-BROKEN-DATA')
        response = self.web_request('GET', '/turris-federation/')
        self.assertIn(b'503', response)
        self.assertNotIn(b'PRIVATE-BROKEN-DATA', response)

    def web_files_fixture(self):
        return {str(self.root / name.lstrip('/')): value for name, value in f.WEB_FILES.items()}

    def test_web_install_is_idempotent_and_publishes_readable_tile(self):
        files = self.web_files_fixture()
        old_umask = os.umask(0o077)
        try:
            with patch.object(f, 'WEB_FILES', files), \
                    patch.object(f, 'WEB_PROXY_PATH', self.root / str(f.WEB_PROXY_PATH).lstrip('/')), \
                    patch.object(f, 'run') as run:
                f.install_web()
                f.install_web()
                self.assertEqual(2, run.call_count)
        finally:
            os.umask(old_umask)
        for path, content in files.items():
            self.assertEqual(content, Path(path).read_bytes())
            self.assertEqual(0o644, Path(path).stat().st_mode & 0o777)
            self.assertEqual(0o755, Path(path).parent.stat().st_mode & 0o777)
        tile = json.loads(next(value for name, value in files.items() if name.endswith('.json')))
        self.assertEqual('/turris-federation/', tile['url'])
        self.assertEqual('/icons/turris-federation.svg', tile['icon'])
        proxy = next(value.decode() for name, value in files.items() if name.endswith('turris-federation.conf'))
        public_proxy, protected_proxy = proxy.split('$HTTP["url"] =~ "^/turris-federation/overview($|/)"', 1)
        self.assertNotIn('auth.require', public_proxy)
        self.assertIn('auth.backend = "pam"', protected_proxy)
        self.assertIn('auth.require', protected_proxy)

    def test_failed_web_update_restores_previous_files_and_permissions(self):
        files = self.web_files_fixture()
        first = Path(next(iter(files)))
        f.atomic(first, b'previous-tile')
        first.chmod(0o640)
        with patch.object(f, 'WEB_FILES', files), \
                patch.object(f, 'WEB_PROXY_PATH', self.root / str(f.WEB_PROXY_PATH).lstrip('/')), \
                patch.object(f, 'run', side_effect=[ValueError('invalid lighttpd config'), b'']):
            with self.assertRaisesRegex(ValueError, 'invalid lighttpd'):
                f.install_web()
        self.assertEqual(b'previous-tile', first.read_bytes())
        self.assertEqual(0o640, first.stat().st_mode & 0o777)
        self.assertTrue(all(not Path(name).exists() for name in files if Path(name) != first))

    def test_atomic_failure_retains_previous_revision(self):
        path = self.root / 'atomic.json'
        f.atomic(path, {'value': 1})
        with patch.object(f.os, 'replace', side_effect=OSError('disk')):
            with self.assertRaises(OSError):
                f.atomic(path, {'value': 2})
        self.assertEqual({'value': 1}, f.read(path))
        self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_drafts_never_render_as_wireguard_peers(self):
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'wireguard.key', b'private-test-only')
        calls = []
        with patch.object(f, 'run', side_effect=lambda args, data=None, **kw: calls.append((args, data)) or b''), \
             patch.object(f, 'owned_sections', return_value=[]), \
             patch.object(f, 'local_check', return_value={'zeroTierDevice': 'zt1234'}):
            f.render_apply(self.root, self.document())
        config = '\n'.join(raw.decode() for _, raw in calls if raw)
        self.assertNotIn('wireguard_tf_wg', config)
        self.assertNotIn('192.168.2.0/24', config)
        self.assertNotIn('tf_control', config)
        self.assertIn('tf_wg', config)
        self.assertFalse(any('private-test-only' in str(args) for args, _ in calls))

    def test_enrolled_peer_renders_scoped_routes_and_firewall(self):
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'wireguard.key', b'private-test-only')
        calls = []
        doc = self.document(members={node(1)['id']: self.member(1), node(2)['id']: self.member(2)})
        with patch.object(f, 'run', side_effect=lambda args, data=None, **kw: calls.append((args, data)) or b''), \
             patch.object(f, 'owned_sections', return_value=[]), \
             patch.object(f, 'local_check', return_value={'zeroTierDevice': 'zt1234'}):
            f.render_apply(self.root, doc)
        config = '\n'.join(raw.decode() for _, raw in calls if raw)
        self.assertIn('192.168.2.0/24', config)
        self.assertIn('10.203.0.2/32', config)
        self.assertIn('wireguard_tf_wg', config)
        self.assertIn("set network.tf_wg.nohostroute='1'", config)
        self.assertNotIn('0.0.0.0/0', config)
        self.assertNotIn('masq', config)

    def test_settings_apply_removes_legacy_service_redirect_without_recreating_it(self):
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'wireguard.key', b'private-test-only')
        legacy = {'id': 'home', 'name': 'Home', 'hostAddress': '192.168.1.20',
                  'protocol': 'https', 'port': 443, 'path': None, 'routerPort': 18443}
        f.atomic(self.root / 'services.json', [legacy])
        calls = []

        def owned(package):
            return ['firewall.tf_service_0'] if package == 'firewall' else []

        with patch.object(f, 'run', side_effect=lambda args, data=None, **kw: calls.append((args, data)) or b''), \
                patch.object(f, 'owned_sections', side_effect=owned), \
                patch.object(f, 'local_check', return_value={'zeroTierDevice': 'zt1234'}):
            f.render_apply(self.root, self.document(members={node(1)['id']: self.member(1)}))
        self.assertIn((['uci', 'delete', 'firewall.tf_service_0'], None), calls)
        self.assertFalse(any(args[:3] == ['uci', 'set', 'firewall.tf_service_0'] for args, _ in calls))

    def test_notebook_renders_only_host_route_and_role_scoped_underlay_rules(self):
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'wireguard.key', b'private-test-only')
        endpoints = [
            {'id': 'e' * 64, 'name': 'User notebook', 'role': 'user',
             'zeroTierAddress': '10.147.0.20', 'wireguardAddress': '10.203.0.20',
             'wireguardKey': base64.b64encode(b'n' * 32).decode()},
            {'id': 'a' * 64, 'name': 'Administrator notebook', 'role': 'administrator',
             'zeroTierAddress': '10.147.0.21', 'wireguardAddress': '10.203.0.21',
             'wireguardKey': base64.b64encode(b'a' * 32).decode()},
        ]
        config = f.normalize_with_notebook_endpoints(self.nodes, self.config['networkId'], endpoints)
        doc = self.document(config=config, members={node(1)['id']: self.member(1)})
        doc['schema'] = f.NOTEBOOK_WG_VERSION
        with patch.object(f, 'local_check', return_value={'zeroTierDevice': 'zt1234'}), \
                patch.object(f, 'run', return_value=b''), patch.object(f, 'owned_sections', return_value=[]), \
                patch.object(f, 'uci_section') as section:
            f.render_apply(self.root, doc)
        network = {call.args[1]: call.args[3] for call in section.call_args_list
                   if call.args[0] == 'network' and call.args[2] == 'wireguard_tf_wg'}
        notebook_peers = [value for name, value in network.items() if name.startswith('tf_n_')]
        self.assertCountEqual([['10.203.0.20/32'], ['10.203.0.21/32']],
                              [peer['allowed_ips'] for peer in notebook_peers])
        self.assertTrue(all('endpoint_host' not in peer for peer in notebook_peers))
        firewall = {call.args[1]: call.args[3] for call in section.call_args_list
                    if call.args[0] == 'firewall'}
        notebook_rules = {name: rule for name, rule in firewall.items() if '_notebook_' in name}
        self.assertEqual(5, len(notebook_rules))
        self.assertCountEqual(
            [('10.147.0.20', 'udp', '51830'), ('10.147.0.20', 'icmp', None),
             ('10.147.0.21', 'udp', '51830'), ('10.147.0.21', 'icmp', None),
             ('10.147.0.21', 'tcp', '8844')],
            [(rule['src_ip'], rule['proto'], rule.get('dest_port'))
             for rule in notebook_rules.values()])
        self.assertFalse(any(rule['src_ip'] == '10.147.0.20' and rule['proto'] == 'tcp'
                             for rule in notebook_rules.values()))
        for rule in notebook_rules.values():
            self.assertEqual('tf_zt', rule['src'])
            self.assertEqual('10.147.0.1', rule['dest_ip'])
            self.assertEqual('ACCEPT', rule['target'])
            self.assertEqual('ipv4', rule['family'])
        pings = [rule for rule in notebook_rules.values() if rule['proto'] == 'icmp']
        self.assertTrue(all(rule['icmp_type'] == ['echo-request'] for rule in pings))

    def test_zerotier_device_must_exist_and_have_expected_address(self):
        network = {'nwid': self.config['networkId'], 'status': 'OK',
                   'assignedAddresses': ['10.147.0.1/24'], 'portDeviceName': 'zt1234'}

        def run(args, **kwargs):
            if args[0] == 'zerotier-cli':
                return json.dumps([network]).encode()
            if args == ['ip', '-o', 'addr', 'show', 'dev', 'zt1234']:
                return b'7: zt1234 inet 10.147.0.1/24 scope global zt1234'
            if args == ['ip', '-o', 'addr', 'show']:
                return b'2: br-lan inet 192.168.1.1/24 scope global br-lan'
            if args == ['uci', '-q', 'get', 'network.lan']:
                return b'interface'
            if args == ['uci', 'export', 'firewall']:
                return b"config zone\n option name 'lan'\n"
            return b''

        with patch.object(f.os, 'geteuid', return_value=0), patch.object(f, 'run', side_effect=run):
            self.assertEqual('zt1234', f.local_check(node(1), self.config['networkId'])['zeroTierDevice'])
            for device in [None, '', '*', 'zt+', 'bad device', 'x' * 16]:
                network['portDeviceName'] = device
                with self.subTest(device=device), self.assertRaisesRegex(ValueError, 'rozhraní'):
                    f.local_check(node(1), self.config['networkId'])
            network['portDeviceName'] = 'zt1234'

        for result in [b'', b'7: zt1234 inet 10.147.0.99/24', ValueError('Device does not exist')]:
            def missing(args, **kwargs):
                if args == ['ip', '-o', 'addr', 'show', 'dev', 'zt1234']:
                    if isinstance(result, Exception):
                        raise result
                    return result
                return run(args, **kwargs)
            with self.subTest(result=result), patch.object(f.os, 'geteuid', return_value=0), \
                    patch.object(f, 'run', side_effect=missing), self.assertRaises(ValueError):
                f.local_check(node(1), self.config['networkId'])

    def test_firewall_zones_peer_allowlist_and_cleanup(self):
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'wireguard.key', b'private-test-only')
        doc = self.document(members={node(1)['id']: self.member(1), node(2)['id']: self.member(2)})
        # A draft must never acquire transport, control, or diagnostic access.
        doc['config']['nodes'].append(node(3))
        existing = "firewall.tf_control=rule\nfirewall.app_service=rule\n"
        with patch.object(f, 'local_check', return_value={'zeroTierDevice': 'zt1234'}), \
                patch.object(f, 'run', side_effect=lambda args, *a, **kw: existing.encode() if args == ['uci', 'show', 'firewall'] else b'') as run, \
                patch.object(f, 'uci_section') as section:
            f.render_apply(self.root, doc)
        run.assert_any_call(['uci', 'delete', 'firewall.tf_control'])
        self.assertNotIn((['uci', 'delete', 'firewall.app_service'],), [c.args for c in run.call_args_list])
        firewall = {c.args[1]: (c.args[2], c.args[3]) for c in section.call_args_list if c.args[0] == 'firewall'}
        for name, zone in [('tf_zt_zone', 'tf_zt'), ('tf_zone', 'tf_fed')]:
            self.assertEqual('zone', firewall[name][0])
            self.assertEqual(zone, firewall[name][1]['name'])
            for key, value in [('input', 'REJECT'), ('output', 'ACCEPT'), ('forward', 'REJECT')]:
                self.assertEqual(value, firewall[name][1][key])
        self.assertEqual(['zt1234'], firewall['tf_zt_zone'][1]['device'])
        self.assertEqual(['tf_wg'], firewall['tf_zone'][1]['network'])
        forwards = [v for kind, v in firewall.values() if kind == 'forwarding']
        self.assertCountEqual([{'src': 'lan', 'dest': 'tf_fed'}, {'src': 'tf_fed', 'dest': 'lan'}], forwards)
        rules = [v for kind, v in firewall.values() if kind == 'rule' and v['src'] != 'tf_fed']
        self.assertEqual(3, len(rules))
        self.assertCountEqual([('udp', '51830'), ('tcp', '8844'), ('icmp', None)],
                              [(v['proto'], v.get('dest_port')) for v in rules])
        ping = next(v for v in rules if v['proto'] == 'icmp')
        self.assertEqual(['echo-request'], ping['icmp_type'])
        self.assertNotIn('dest_port', ping)
        for rule in rules:
            self.assertEqual('tf_zt', rule['src'])
            self.assertEqual('10.147.0.2', rule['src_ip'])
            self.assertEqual('10.147.0.1', rule['dest_ip'])
            self.assertEqual('ACCEPT', rule['target'])
            self.assertEqual('ipv4', rule['family'])
            self.assertNotIn('dest', rule)

    def test_existing_safe_zerotier_zone_is_reused_without_duplicate_device_owner(self):
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'wireguard.key', b'private-test-only')
        doc = self.document(members={node(1)['id']: self.member(1), node(2)['id']: self.member(2)})
        existing = """firewall.vpn_zerotier=zone
firewall.vpn_zerotier.name='vpn_zerotier'
firewall.vpn_zerotier.network='zt0'
firewall.vpn_zerotier.input='REJECT'
firewall.vpn_zerotier.output='ACCEPT'
firewall.vpn_zerotier.forward='REJECT'
firewall.custom_include=include
firewall.custom_include.type='nftables'
firewall.custom_include.path='/etc/custom.nft'
"""
        network = """network.zt0=interface
network.zt0.proto='none'
network.zt0.device='zt1234'
"""

        def command(args, *unused, **kwargs):
            if args == ['uci', 'show', 'firewall']:
                return existing.encode()
            if args == ['uci', 'show', 'network']:
                return network.encode()
            return b''

        with patch.object(f, 'local_check', return_value={'zeroTierDevice': 'zt1234'}), \
                patch.object(f, 'run', side_effect=command), \
                patch.object(f, 'owned_sections', return_value=[]), \
                patch.object(f, 'uci_section') as section:
            f.render_apply(self.root, doc)
        firewall = {call.args[1]: (call.args[2], call.args[3]) for call in section.call_args_list
                    if call.args[0] == 'firewall'}
        self.assertNotIn('tf_zt_zone', firewall)
        underlay_rules = [values for kind, values in firewall.values()
                          if kind == 'rule' and values['src'] != 'tf_fed']
        self.assertTrue(underlay_rules)
        self.assertTrue(all(rule['src'] == 'vpn_zerotier' for rule in underlay_rules))

    def test_existing_zerotier_zone_must_have_restrictive_policies(self):
        existing = """firewall.vpn_zerotier=zone
firewall.vpn_zerotier.name='vpn_zerotier'
firewall.vpn_zerotier.device='zt1234'
firewall.vpn_zerotier.input='ACCEPT'
firewall.vpn_zerotier.output='ACCEPT'
firewall.vpn_zerotier.forward='REJECT'
"""
        with patch.object(f, 'run', return_value=existing.encode()), \
                self.assertRaisesRegex(ValueError, 'bezpečné zásady'):
            f.firewall_zone_for_device('zt1234')

    def test_wrong_confirmation_does_not_commit(self):
        f.atomic(self.root / 'accepted.json', f.sign(self.root / 'root.pem', self.document()))
        f.atomic(self.root / 'pending.json', {'token': 'correct', 'deadline': time.time() + 120})
        with patch.object(f, 'health') as health:
            with self.assertRaisesRegex(ValueError, 'Potvrzení'):
                f.confirm(self.root, 'wrong')
            health.assert_not_called()
        self.assertTrue((self.root / 'pending.json').exists())

    def test_waiting_peers_is_distinct_from_active_and_applied(self):
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'accepted.json', f.sign(self.root / 'root.pem', self.document()))
        f.atomic(self.root / 'pending.json', {'token': 'ok', 'revision': 1, 'deadline': time.time() + 120})
        service = {'id': 'printer', 'name': 'Printer', 'hostAddress': '192.168.1.20',
                   'protocol': 'https', 'port': 443, 'path': '/'}
        hosts = [{'address': '192.168.1.20', 'name': 'printer.local'}]
        f.atomic(self.root / 'report.json', {
            'hosts': hosts, 'hostsObservedAt': 100,
            'services': [service], 'servicesObservedAt': 101})
        with patch.object(f, 'health', return_value={'state': 'waiting_peers', 'pendingPeers': [node(2)['id']]}), patch.object(f, 'configuration_hash', return_value='hash'):
            report = f.confirm(self.root, 'ok')
        self.assertEqual('waiting_peers', report['state'])
        self.assertEqual(1, report['appliedRevision'])
        self.assertEqual(hosts, report['hosts'])
        self.assertEqual([service], report['services'])
        self.assertFalse((self.root / 'pending.json').exists())

    def test_partial_uci_failure_restores_both_files_and_keeps_old_applied_revision(self):
        config_dir = self.root / 'etc-config'
        config_dir.mkdir()
        for package in ['network', 'firewall']:
            f.atomic(config_dir / package, ('original-' + package).encode())
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'report.json', {'appliedRevision': 3})
        doc = self.document(4)
        def fail_apply(*_):
            f.atomic(config_dir / 'network', b'partial-network')
            raise ValueError('simulated failure')
        original_run = subprocess.run
        def fake_subprocess(args, **kwargs):
            if args[0] in ['ifup', 'ifdown']:
                return subprocess.CompletedProcess(args, 0)
            return original_run(args, **kwargs)
        with patch.object(f, 'CONFIG_DIR', config_dir), patch.object(f, 'local_check'), \
             patch.object(f, 'check_routes'), patch.object(f, 'render_apply', side_effect=fail_apply), \
             patch.object(f, 'run', return_value=b''), patch.object(f.subprocess, 'Popen'), \
             patch.object(f.subprocess, 'run', side_effect=fake_subprocess):
            with self.assertRaisesRegex(ValueError, 'simulated'):
                f.stage(self.root, doc)
        for package in ['network', 'firewall']:
            self.assertEqual(('original-' + package).encode(), (config_dir / package).read_bytes())
        self.assertFalse((self.root / 'pending.json').exists())
        report = f.read(self.root / 'report.json')
        self.assertEqual('rollback', report['state'])
        self.assertEqual(3, report['appliedRevision'])
        self.assertEqual(4, report['receivedRevision'])

    def test_expired_confirmation_never_marks_deploy_applied(self):
        f.atomic(self.root / 'accepted.json', f.sign(self.root / 'root.pem', self.document()))
        f.atomic(self.root / 'pending.json', {'token': 'old', 'deadline': time.time() - 1})
        with patch.object(f, 'health') as health:
            with self.assertRaisesRegex(ValueError, 'vypršelo'):
                f.confirm(self.root, 'old')
            health.assert_not_called()
        self.assertNotEqual('active', f.read(self.root / 'report.json', {}).get('state'))

    def test_enrolled_management_path_cannot_change_via_gossip(self):
        members = {node(1)['id']: self.member(1)}
        f.snapshot(self.root, self.config, members)
        changed = copy.deepcopy(self.config)
        changed['nodes'][0]['zeroTierAddress'] = '10.147.0.9'
        with self.assertRaisesRegex(ValueError, 'migraci'):
            f.snapshot(self.root, changed, members)
        self.assertEqual(1, f.verify(self.public, f.read(self.root / 'published.json'))['revision'])

    def test_existing_non_federation_routes_block_apply(self):
        f.atomic(self.root / 'node.json', self.member(1))
        doc = self.document(members={node(1)['id']: self.member(1), node(2)['id']: self.member(2)})
        with patch.object(f, 'run', return_value=b'192.168.2.0/24 dev br-guest proto kernel\n'):
            with self.assertRaisesRegex(ValueError, 'koliduje'):
                f.check_routes(self.root, doc)
        with patch.object(f, 'run', return_value=b'192.168.2.0/24 dev tf_wg proto static\n'):
            f.check_routes(self.root, doc)

    def test_watchdog_expiry_invokes_rollback_under_lock(self):
        f.atomic(self.root / 'pending.json', {'token': 'ok', 'deadline': time.time() - 1})
        with patch.object(f, 'rollback') as rollback:
            f.watchdog(self.root, 'ok')
            rollback.assert_called_once_with(self.root)
        with patch.object(f, 'rollback') as rollback:
            f.watchdog(self.root, 'wrong')
            rollback.assert_not_called()

    def prepare_operation(self):
        config_dir = self.root / 'config'
        config_dir.mkdir()
        for package in ['network', 'firewall']:
            f.atomic(config_dir / package, ('original-' + package).encode())
            f.atomic(self.root / 'backup' / package, ('original-' + package).encode())
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'accepted.json', f.sign(self.root / 'root.pem', self.document()))
        return config_dir

    def test_confirming_and_rollback_preserve_independent_catalog_sections(self):
        config_dir = self.prepare_operation()
        service = {'id': 'printer', 'name': 'Printer', 'hostAddress': '192.168.1.20',
                   'protocol': 'https', 'port': 443, 'path': '/'}
        hosts = [{'address': '192.168.1.20', 'name': 'printer.local'}]
        f.atomic(self.root / 'report.json', {
            'state': 'active', 'appliedRevision': 0,
            'hosts': hosts, 'hostsObservedAt': 100,
            'services': [service], 'servicesObservedAt': 101})
        with patch.object(f, 'CONFIG_DIR', config_dir), patch.object(f, 'local_check'), \
                patch.object(f, 'check_routes'), patch.object(f, 'render_apply'), \
                patch.object(f, 'verify', return_value=self.document()), \
                patch.object(f.subprocess, 'Popen'):
            f.stage(self.root, self.document())
        confirming = f.read(self.root / 'report.json')
        self.assertEqual('confirming', confirming['state'])
        self.assertEqual(hosts, confirming['hosts'])
        self.assertEqual([service], confirming['services'])
        with patch.object(f, 'CONFIG_DIR', config_dir), patch.object(f, 'run', return_value=b''), \
                patch.object(f.subprocess, 'run'):
            f.rollback(self.root)
        rolled_back = f.read(self.root / 'report.json')
        self.assertEqual('rollback', rolled_back['state'])
        self.assertEqual(hosts, rolled_back['hosts'])
        self.assertEqual([service], rolled_back['services'])

    def test_confirmation_health_does_not_block_watchdog_or_overwrite_rollback(self):
        config_dir = self.prepare_operation()
        pending = {'token': 'ok', 'revision': 1, 'previousApplied': None,
                   'deadline': time.time() + 120}
        f.atomic(self.root / 'pending.json', pending)
        started, release = threading.Event(), threading.Event()
        errors = []

        def slow_health(*_):
            started.set()
            if not release.wait(3):
                raise RuntimeError('health test timed out')
            return {'state': 'active'}

        def confirm():
            try:
                f.confirm(self.root, 'ok')
            except Exception as error:
                errors.append(error)

        with patch.object(f, 'CONFIG_DIR', config_dir), patch.object(f, 'health', side_effect=slow_health), \
                patch.object(f, 'run', return_value=b''), patch.object(f.subprocess, 'run'):
            worker = threading.Thread(target=confirm)
            worker.start()
            try:
                self.assertTrue(started.wait(2))
                with f.locked(self.root):
                    pending['deadline'] = time.time() - 1
                    f.atomic(self.root / 'pending.json', pending)
                f.watchdog(self.root, 'ok')
                self.assertEqual('rollback', f.read(self.root / 'report.json')['state'])
            finally:
                release.set()
                worker.join(4)
        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(errors))
        self.assertIsInstance(errors[0], ValueError)
        self.assertEqual('rollback', f.read(self.root / 'report.json')['state'])

    def test_stage_rechecks_revision_after_unlocked_preflight(self):
        config_dir = self.prepare_operation()
        next_envelope = f.sign(self.root / 'root.pem', self.document(2))

        def newer_revision(*_):
            with f.locked(self.root):
                f.accept(self.root, next_envelope)

        with patch.object(f, 'CONFIG_DIR', config_dir), \
                patch.object(f, 'local_check', side_effect=newer_revision), patch.object(f, 'check_routes'), \
                patch.object(f, 'render_apply') as apply:
            with self.assertRaisesRegex(ValueError, 'během kontroly'):
                f.stage(self.root, self.document())
            apply.assert_not_called()
        self.assertFalse((self.root / 'pending.json').exists())

    def test_rollback_between_apply_commands_fences_old_writer(self):
        config_dir = self.prepare_operation()

        def interrupted_apply(*_):
            with f.locked(self.root):
                pending = f.read(self.root / 'pending.json')
                pending['monotonicDeadline'] = time.monotonic() - 1
                f.atomic(self.root / 'pending.json', pending)
            # Watchdog is a separate execution context from the applying thread.
            with patch.object(f, 'run_command', return_value=b''), patch.object(f.subprocess, 'run'):
                watchdog = threading.Thread(target=f.watchdog, args=(self.root, pending['token']))
                watchdog.start()
                watchdog.join(2)
                self.assertFalse(watchdog.is_alive())
            with patch.object(f, 'run_apply_command') as command:
                with self.assertRaisesRegex(ValueError, 'vráceno'):
                    f.run(['uci', 'commit', 'network'])
                command.assert_not_called()

        original_popen = subprocess.Popen

        def start_process(args, **kwargs):
            if len(args) > 2 and args[2] == 'watchdog':
                return None
            return original_popen(args, **kwargs)

        with patch.object(f, 'CONFIG_DIR', config_dir), patch.object(f, 'local_check'), \
                patch.object(f, 'check_routes'), patch.object(f.subprocess, 'Popen', side_effect=start_process), \
                patch.object(f, 'render_apply', side_effect=interrupted_apply):
            with self.assertRaisesRegex(ValueError, 'vráceno'):
                f.stage(self.root, self.document())
        self.assertEqual('rollback', f.read(self.root / 'report.json')['state'])
        self.assertIsNone(f.APPLY_CONTEXT.operation)

    def test_confirm_rejects_changed_config_and_applying_phase(self):
        config_dir = self.prepare_operation()
        pending = {'token': 'ok', 'revision': 1, 'deadline': time.time() + 120, 'phase': 'applying'}
        f.atomic(self.root / 'pending.json', pending)
        with patch.object(f, 'CONFIG_DIR', config_dir), patch.object(f, 'health') as health:
            with self.assertRaisesRegex(ValueError, 'Potvrzení'):
                f.confirm(self.root, 'ok')
            health.assert_not_called()
            pending['phase'] = 'confirming'
            f.atomic(self.root / 'pending.json', pending)
            health.side_effect = lambda *_: f.atomic(config_dir / 'network', b'changed') or {'state': 'active'}
            with self.assertRaisesRegex(ValueError, 'během potvrzení'):
                f.confirm(self.root, 'ok')
        self.assertTrue((self.root / 'pending.json').exists())

    def test_apply_command_uses_remaining_deadline(self):
        f.atomic(self.root / 'pending.json', {'token': 'ok', 'monotonicDeadline': time.monotonic() + 0.5})
        f.APPLY_CONTEXT.operation = (self.root, 'ok')
        try:
            with patch.object(f, 'run_apply_command', return_value=b'ok') as command:
                self.assertEqual(b'ok', f.run(['uci', 'show'], timeout=30))
                self.assertGreater(command.call_args.args[2], 0)
                self.assertLessEqual(command.call_args.args[2], 0.5)
        finally:
            f.APPLY_CONTEXT.operation = None

    def test_timed_out_apply_kills_child_before_it_can_write(self):
        marker = self.root / 'late-write'
        child = "import time,pathlib; time.sleep(0.5); pathlib.Path(%r).write_text('late')" % str(marker)
        parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',%r]); time.sleep(10)" % child
        with self.assertRaises(subprocess.TimeoutExpired):
            f.run_apply_command([f.sys.executable, '-c', parent], None, 0.2)
        time.sleep(0.6)
        self.assertFalse(marker.exists())

    def test_http_serves_bundle_and_status_during_outgoing_sync(self):
        doc = self.document()
        envelope = f.sign(self.root / 'root.pem', doc)
        f.atomic(self.root / 'accepted.json', envelope)
        f.atomic(self.root / 'node.json', self.member(1))
        shutil.copy(self.root / 'root.pem', self.root / 'identity.pem')
        servers = []
        server_type = f.http.server.HTTPServer

        def local_server(address, handler):
            server = server_type(('127.0.0.1', 0), handler)
            servers.append(server)
            return server

        def blocked_sync(root):
            # A peer must receive replies before this outgoing sync can finish.
            for path in ['/bundle', '/status/' + 'a' * 64]:
                auth = base64.b64encode(f.encode(f.sign(root / 'root.pem', {'path': path}))).decode()
                conn = f.http.client.HTTPConnection(*servers[0].server_address, timeout=2)
                try:
                    conn.request('GET', path, headers={'X-TF-Notebook': auth})
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    result = json.loads(response.read())
                    if path == '/bundle':
                        self.assertEqual(result, envelope)
                    else:
                        self.assertEqual(f.verify(self.public, result)['nonce'], 'a' * 64)
                finally:
                    conn.close()
            raise RuntimeError('stop sync')

        with patch.object(f.http.server, 'HTTPServer', side_effect=local_server), \
                patch.object(f, 'local_check'), patch.object(f, 'rollback'), \
                patch.object(f, 'sync_loop', side_effect=blocked_sync):
            with self.assertRaisesRegex(RuntimeError, 'stop sync'):
                f.serve(self.root)
        self.assertEqual(servers[0].fileno(), -1)
        self.assertFalse(any(t.name == 'federation-http' for t in threading.enumerate()))


if __name__ == '__main__':
    unittest.main()
