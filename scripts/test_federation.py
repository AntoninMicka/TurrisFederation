#!/usr/bin/env python3
"""Protocol and deployment regressions; no real router/network is modified."""
import base64
import copy
import importlib.util
import json
import os
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

    def test_drafts_cannot_enroll_through_publish(self):
        f.atomic(self.root / 'members.json', {node(1)['id']: self.member(1)})
        with patch.object(f, 'request_http', side_effect=ValueError('offline')):
            result = f.controller(self.root, {'action': 'publish', 'nodes': self.nodes, 'networkId': 'abcdef0123456789'})
        self.assertFalse(result['nodes'][node(2)['id']]['enrolled'])
        self.assertNotIn('appliedRevision', result['nodes'][node(1)['id']])
        self.assertFalse(result['nodes'][node(1)['id']]['reachable'])
        self.assertEqual(1, result['revision'])

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
                'lan': lan, 'artifactHash': 'old-agent'}
        req = {'action': 'deploy', 'nodes': nodes, 'networkId': config['networkId'], 'nodeId': target['id'],
               'planId': 'update', 'credentials': {'hostKey': 'key', 'password': 'test'}}
        path = self.root / ('plan-' + target['id'] + '.json')
        f.atomic(path, plan)
        with patch.object(f, 'ssh') as ssh:
            with self.assertRaisesRegex(ValueError, 'verzi agenta'):
                f.controller(self.root, req)
            ssh.assert_not_called()
        plan['artifactHash'] = f.artifact_hash()
        f.atomic(path, plan)
        with patch.object(f, 'direct_lan', return_value=dict(lan, device='wlan0')), patch.object(f, 'ssh') as ssh:
            with self.assertRaisesRegex(ValueError, 'změnilo'):
                f.controller(self.root, req)
            ssh.assert_not_called()

    def test_validation_marks_existing_member_as_lan_update(self):
        target, _, _ = self.lan_fixture()
        f.atomic(self.root / 'members.json', {target['id']: self.member(1)})
        lan = {'host': target['sshHost'], 'device': 'eth0', 'source': '192.168.1.10'}
        probe = ('__BOARD__\n{}\n__ZT__\n' + json.dumps([{'nwid': 'abcdef0123456789', 'status': 'OK',
                 'assignedAddresses': ['10.147.0.1/24']}]) + '\n__ADDR__\ninet 192.168.1.1/24\n__END__\n').encode()
        req = {'action': 'validate', 'nodes': [target], 'networkId': 'abcdef0123456789',
               'nodeId': target['id'], 'credentials': {'hostKey': 'key', 'password': 'test'}}
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f, 'ssh', side_effect=[probe, b'hash']) as ssh:
            plan = f.controller(self.root, req)
        self.assertEqual('update', plan['operation'])
        self.assertEqual(lan, plan['lan'])
        self.assertEqual(f.artifact_hash(), plan['artifactHash'])
        self.assertTrue(all('opkg install' not in call.args[2] for call in ssh.call_args_list))

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
        f.atomic(self.root / 'reports.json', {node(1)['id']: {'appliedRevision': 1}})
        lan = {'host': target['sshHost'], 'device': 'eth0', 'source': '192.168.2.10'}
        plan = {'id': 'deploy-second', 'expiresAt': time.time() + 600, 'configHash': f.digest(self.config),
                'hostKeyHash': f.digest('key'), 'membersHash': f.digest(members),
                'sshHash': f.digest({k: target[k] for k in ['sshHost', 'sshPort', 'sshUser']}),
                'lan': lan, 'artifactHash': f.artifact_hash(), 'routerHash': 'hash'}
        f.atomic(self.root / ('plan-' + target['id'] + '.json'), plan)
        req = {'action': 'deploy', 'nodes': self.nodes, 'networkId': self.config['networkId'],
               'nodeId': target['id'], 'planId': plan['id'], 'credentials': {'hostKey': 'key', 'password': 'test'}}
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f, 'ssh', return_value=b'hash') as ssh, \
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

    def test_network_sync_refuses_software_and_commands(self):
        for key in ['software', 'command', 'artifact', 'update']:
            doc = self.document()
            doc[key] = 'unwanted'
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'pouze síťové'):
                f.accept(self.root, f.sign(self.root / 'root.pem', doc))
        self.assertFalse((self.root / 'accepted.json').exists())

    def test_web_renders_selected_status_and_escapes_router_names(self):
        doc = self.document()
        doc['config']['nodes'][0]['name'] = '<script>alert(1)</script>'
        f.atomic(self.root / 'accepted.json', f.sign(self.root / 'root.pem', doc))
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'report.json', {'state': 'waiting_peers', 'appliedRevision': 1,
                 'checkedAt': 100, 'pendingPeers': [node(2)['id']], 'error': '<b>failure</b>', 'secret': 'REPORT-SECRET'})
        f.atomic(self.root / 'wireguard.key', b'PRIVATE-WG-SECRET')
        page = f.web_page(self.root).decode()
        for wanted in ['&lt;script&gt;', '&lt;b&gt;failure&lt;/b&gt;', 'Stanoviště 2', 'Čeká na protějšky', '10.147.0.1', '192.168.1.0/24']:
            self.assertIn(wanted, page)
        for unwanted in ['<script>', '<b>failure</b>', 'PRIVATE-WG-SECRET', 'REPORT-SECRET', 'BEGIN PUBLIC KEY', 'BEGIN PRIVATE KEY']:
            self.assertNotIn(unwanted, page)
        self.assertIn('nikoli aktuální dostupnost', page)

    def web_request(self, method, path):
        client, server = socket.socketpair()
        client.settimeout(5)
        server.settimeout(5)
        def handle():
            try:
                f.web_handler(self.root)(server, ('127.0.0.1', 1234), None)
            finally:
                server.close()
        thread = threading.Thread(target=handle)
        thread.start()
        try:
            client.sendall(('%s %s HTTP/1.0\r\nHost: localhost\r\n\r\n' % (method, path)).encode())
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

    def test_web_http_is_read_only_and_does_not_expose_sync_or_files(self):
        response = self.web_request('GET', '/turris-federation/')
        self.assertIn(b'200 OK', response)
        self.assertIn(b'Cache-Control: no-store', response)
        self.assertIn(b'frame-ancestors', response)
        self.assertIn('Dokončete deploy'.encode(), response)
        for path in ['/bundle', '/etc/turris-federation/root.pub', '/turris-federation/../root.pem']:
            self.assertIn(b'404', self.web_request('GET', path))
        for method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            self.assertIn(b'405', self.web_request(method, '/turris-federation/'))
        self.assertFalse((self.root / 'report.json').exists())

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
             patch.object(f, 'local_check', return_value={'zeroTierNetworks': ['10.147.0.0/24']}):
            f.render_apply(self.root, self.document())
        config = '\n'.join(raw.decode() for _, raw in calls if raw)
        self.assertNotIn('wireguard_tf_wg', config)
        self.assertNotIn('192.168.2.0/24', config)
        self.assertIn('tf_control', config)
        self.assertIn('tf_wg', config)
        self.assertFalse(any('private-test-only' in str(args) for args, _ in calls))

    def test_enrolled_peer_renders_scoped_routes_and_firewall(self):
        f.atomic(self.root / 'node.json', self.member(1))
        f.atomic(self.root / 'wireguard.key', b'private-test-only')
        calls = []
        doc = self.document(members={node(1)['id']: self.member(1), node(2)['id']: self.member(2)})
        with patch.object(f, 'run', side_effect=lambda args, data=None, **kw: calls.append((args, data)) or b''), \
             patch.object(f, 'owned_sections', return_value=[]), \
             patch.object(f, 'local_check', return_value={'zeroTierNetworks': ['10.147.0.0/24']}):
            f.render_apply(self.root, doc)
        config = '\n'.join(raw.decode() for _, raw in calls if raw)
        self.assertIn('192.168.2.0/24', config)
        self.assertIn('10.203.0.2/32', config)
        self.assertIn('wireguard_tf_wg', config)
        self.assertNotIn('0.0.0.0/0', config)
        self.assertNotIn('masq', config)

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
        with patch.object(f, 'health', return_value={'state': 'waiting_peers', 'pendingPeers': [node(2)['id']]}), patch.object(f, 'configuration_hash', return_value='hash'):
            report = f.confirm(self.root, 'ok')
        self.assertEqual('waiting_peers', report['state'])
        self.assertEqual(1, report['appliedRevision'])
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
