#!/usr/bin/env python3
"""Protocol and deployment regressions; no real router/network is modified."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
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
        f.atomic(self.root / 'pending.json', {'token': 'ok', 'deadline': time.time() + 120})
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


if __name__ == '__main__':
    unittest.main()
