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
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f, 'ssh', side_effect=[probe, (f.artifact_hash() + '  -').encode(), b'hash']) as ssh:
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
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f, 'ssh', side_effect=[probe, b'hash']), \
                patch.object(f, 'installed_artifact_hash', return_value=installed):
            plan = f.controller(self.root, req)
        return req, plan, lan

    def test_validation_recommends_full_update_for_different_or_missing_version(self):
        for installed, enrolled, recommended, modes in [
                (f.artifact_hash(), True, 'settings', ['full', 'settings']),
                ('a' * 64, True, 'full', ['full', 'settings']),
                (None, True, 'full', ['full']),
                (f.artifact_hash(), False, 'full', ['full'])]:
            with self.subTest(installed=installed, enrolled=enrolled):
                _, plan, _ = self.validation_fixture(installed, enrolled)
                self.assertEqual(recommended, plan['recommendedMode'])
                self.assertEqual(modes, plan['availableModes'])
                self.assertEqual(installed, plan['installedArtifactHash'])
                self.assertEqual(installed != f.artifact_hash(), plan['versionMismatch'])
                self.assertNotEqual(plan['stepsByMode']['full'], plan['stepsByMode']['settings'])

    def test_settings_update_preserves_software_and_uses_apply_confirm(self):
        # A version mismatch recommends full update but an explicit settings-only choice remains valid.
        req, plan, lan = self.validation_fixture('a' * 64)
        before = (self.root / 'members.json').read_bytes()
        req.update(action='deploy', mode='settings', planId=plan['id'])
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f, 'ssh', return_value=b'hash') as ssh, \
                patch.object(f, 'installed_artifact_hash', return_value='a' * 64), \
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
                patch.object(f, 'installed_artifact_hash', return_value='a' * 64), \
                patch.object(f, 'remote', side_effect=[self.member(1), {'token': None}, {'state': 'active'}]) as remote, \
                patch.object(f, 'distribute_bundle'):
            f.controller(self.root, req)
        self.assertEqual(['bootstrap', 'apply', 'status'], [c.args[2] for c in remote.call_args_list])
        commands = '\n'.join(c.args[2] for c in ssh.call_args_list)
        for expected in ['opkg', 'install-web', 'web-check', 'restart', 'base64 -d']:
            self.assertIn(expected, commands)

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
                'lan': lan, 'availableModes': ['full'], 'installedArtifactHash': f.artifact_hash(), 'artifactHash': f.artifact_hash(), 'routerHash': 'hash'}
        f.atomic(self.root / ('plan-' + target['id'] + '.json'), plan)
        req = {'action': 'deploy', 'nodes': self.nodes, 'networkId': self.config['networkId'],
               'nodeId': target['id'], 'planId': plan['id'], 'credentials': {'hostKey': 'key', 'password': 'test'}}
        with patch.object(f, 'direct_lan', return_value=lan), patch.object(f, 'ssh', return_value=b'hash') as ssh, \
                patch.object(f, 'installed_artifact_hash', return_value=f.artifact_hash()), \
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
                ping.assert_not_called()
        self.assertFalse((self.root / 'diagnostics.json').exists())

    def test_web_only_explicit_token_protected_post_starts_diagnostics(self):
        self.prepare_diagnostics()
        handler = f.web_handler(self.root)
        with patch.object(f, 'start_diagnostics') as start:
            page = self.web_request('GET', f.WEB_PATH, handler=handler)
            token = re.search(rb'name="token" value="([a-f0-9]+)"', page)[1].decode()
            self.web_request('GET', f.WEB_PATH, handler=handler)
            self.assertIn(b'404', self.web_request('GET', f.WEB_PATH + 'diagnostics', handler=handler))
            for body, status in [('token=wrong', b'403'), ('token=%FF', b'403'), ('token=' + token + '&target=8.8.8.8', b'403'), ('', b'400')]:
                response = self.web_request('POST', f.WEB_PATH + 'diagnostics', body, handler)
                self.assertIn(status, response)
            start.assert_not_called()
            response = self.web_request('POST', f.WEB_PATH + 'diagnostics', 'token=' + token, handler)
            self.assertIn(b'303', response)
            self.assertIn(b'Location: /turris-federation/', response)
            start.assert_called_once_with(self.root)
        with patch.object(f, 'start_diagnostics', side_effect=ValueError('Diagnostika už běží.')):
            self.assertIn(b'409', self.web_request('POST', f.WEB_PATH + 'diagnostics', 'token=' + token, handler))

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
        self.assertNotIn('0.0.0.0/0', config)
        self.assertNotIn('masq', config)

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
