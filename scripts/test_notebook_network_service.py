import importlib.util
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'notebook_network_service', Path(__file__).with_name('notebook_network_service.py'))
s = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(s)
ROOT = Path(__file__).resolve().parent.parent


class Result:
    def __init__(self, returncode=0, value=b''):
        self.returncode = returncode
        self.stdout = value
        self.stderr = b''


class NotebookNetworkServiceTests(unittest.TestCase):
    def vpn_plan(self):
        return {'action': 'vpn_reconcile', 'schema': s.VPN_SCHEMA, 'revision': 3,
                'address': '10.203.0.2/32',
                'privateKey': base64.b64encode(b'k' * 32).decode(),
                'peers': [{'publicKey': base64.b64encode(b'p' * 32).decode(),
                           'endpoint': '10.43.192.54:51830',
                           'allowedIps': ['10.203.0.54/32', '192.168.100.0/24']}]}

    def test_command_failures_are_actionable(self):
        with patch.object(s.subprocess, 'run', side_effect=s.subprocess.TimeoutExpired(['ip'], 1)), \
                self.assertRaisesRegex(ValueError, 'neodpověděl včas'):
            s.run(['/usr/sbin/ip'])
        with patch.object(s.subprocess, 'run', side_effect=PermissionError(13, 'denied')), \
                self.assertRaisesRegex(ValueError, 'errno 13'):
            s.run(['/usr/sbin/ip'])

    def test_guard_is_scoped_to_forwarded_notebook_traffic(self):
        script = s.guard_script().decode()
        self.assertIn('hook forward', script)
        self.assertIn('iifname "tf_notebook"', script)
        self.assertIn('oifname "tf_notebook"', script)
        self.assertNotIn('policy drop', script)
        self.assertNotIn('hook input', script)
        self.assertNotIn('hook output', script)
        self.assertTrue(s.guard_script(replace=True).startswith(
            b'delete table inet turris_federation_notebook\n'))

    def test_zerotier_status_is_sanitized_and_selects_requested_network(self):
        info = {'address': 'abcdef1234', 'online': True, 'version': '1.14.2',
                'config': {'settings': {'interfacePrefixBlacklist': ['tf_notebook']}}}
        networks = [{'nwid': '154a350c865f967f', 'name': 'federation', 'status': 'OK',
                     'assignedAddresses': ['10.43.192.113/24'], 'portDeviceName': 'ztdhggvgxz',
                     'secret': 'must-not-escape'}]

        def command(args, **_kwargs):
            if args[-2:] == ['-j', 'info']:
                return Result(value=json.dumps(info).encode())
            if args[-2:] == ['-j', 'listnetworks']:
                return Result(value=json.dumps(networks).encode())
            return Result()

        with patch.object(s, 'zerotier_path', return_value='/usr/sbin/zerotier-cli'), \
                patch.object(s, 'service_enabled', return_value=True), \
                patch.object(s, 'run', side_effect=command):
            status = s.zerotier_status('154a350c865f967f')
        self.assertEqual(('ready', 'abcdef1234', 'ztdhggvgxz'),
                         (status['state'], status['deviceId'], status['device']))
        self.assertEqual(['10.43.192.113/24'], status['assignedAddresses'])
        self.assertTrue(status['wireguardInterfaceBlocked'])
        self.assertNotIn('secret', json.dumps(status))

    def test_dispatch_allows_only_bounded_actions_and_records_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / 'config.json'
            state = Path(temporary) / 'state.json'
            config.write_text('{"allowedUid":1000}')
            service = s.Service(config, Path(temporary) / 'service.sock', state)
            with patch.object(s, 'network_status', return_value={'guard': {'active': True}}), \
                    patch.object(s, 'guard_status', return_value={'active': True}):
                self.assertEqual({'guard': {'active': True}},
                                 service.dispatch({'action': 'status'}, 1000))
            receipt = json.loads(state.read_text())
            self.assertEqual(('status', 1000, True),
                             (receipt['action'], receipt['uid'], receipt['ok']))
            with self.assertRaisesRegex(ValueError, 'Neznámá'):
                service.dispatch({'action': 'shell', 'command': 'id'}, 1000)

    def test_network_id_is_strictly_validated(self):
        for value in ['', 'xyz', '154a350c865f967f;', '154A350C865F967F']:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'Network ID'):
                s.zerotier_membership('join', value)

    def test_vpn_plan_is_bounded_and_renders_without_commands(self):
        plan = s.normalize_vpn_plan(self.vpn_plan())
        config = s.render_wireguard(plan).decode()
        self.assertIn('Address = 10.203.0.2/32', config)
        self.assertIn('Endpoint = 10.43.192.54:51830', config)
        self.assertNotIn('PostUp', config)
        invalid = self.vpn_plan()
        invalid['peers'][0]['allowedIps'] = ['0.0.0.0/0']
        with self.assertRaisesRegex(ValueError, 'privátní'):
            s.normalize_vpn_plan(invalid)
        overlapping = self.vpn_plan()
        overlapping['peers'].append({
            'publicKey': base64.b64encode(b'q' * 32).decode(),
            'endpoint': '10.43.192.84:51830', 'allowedIps': ['192.168.100.1/32']})
        with self.assertRaisesRegex(ValueError, 'překrývají'):
            s.normalize_vpn_plan(overlapping)

    def test_vpn_runtime_requires_address_and_every_signed_route(self):
        responses = [
            Result(value=json.dumps([{'addr_info': [{'local': '10.203.0.2'}]}]).encode()),
            Result(value=json.dumps([{'dst': '10.203.0.54'},
                                     {'dst': '192.168.100.0/24'}]).encode()),
        ]
        with patch.object(s, 'command_path', return_value='/usr/sbin/ip'), \
                patch.object(s, 'run', side_effect=responses):
            runtime = s.verify_vpn_runtime(s.normalize_vpn_plan(self.vpn_plan()))
        self.assertEqual(['10.203.0.54/32', '192.168.100.0/24'], runtime['routes'])

        responses[-1] = Result(value=json.dumps([{'dst': '10.203.0.54/32'}]).encode())
        with patch.object(s, 'command_path', return_value='/usr/sbin/ip'), \
                patch.object(s, 'run', side_effect=responses), \
                self.assertRaisesRegex(ValueError, 'chybí očekávané VPN routy'):
            s.verify_vpn_runtime(s.normalize_vpn_plan(self.vpn_plan()))

    def test_dispatch_reconciles_only_validated_vpn_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / 'config.json'
            state = Path(temporary) / 'state.json'
            config.write_text('{"allowedUid":1000}')
            service = s.Service(config, Path(temporary) / 'service.sock', state)
            with patch.object(s, 'apply_vpn_plan', return_value={
                    'state': 'active', 'revision': 3, 'changed': True}) as reconcile, \
                    patch.object(s, 'guard_status', return_value={'active': True}):
                result = service.dispatch(self.vpn_plan(), 1000)
            self.assertEqual('active', result['vpn']['state'])
            reconcile.assert_called_once_with(self.vpn_plan())

    def test_vpn_reconcile_imports_once_then_reactivates_persisted_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / 'vpn.json'
            config = Path(temporary) / 'wireguard.conf'

            def temporary_config(**_kwargs):
                return os.open(config, os.O_CREAT | os.O_RDWR, 0o600), str(config)

            calls = []
            with patch.object(s, 'nmcli_connections', return_value={}), \
                    patch.object(s, 'all_connection_uuids', side_effect=[set(), {'new-uuid'}]), \
                    patch.object(s, 'active_uuids', return_value=set()), \
                    patch.object(s, 'nmcli_path', return_value='/usr/bin/nmcli'), \
                    patch.object(s, 'verify_vpn_runtime'), \
                    patch.object(s.tempfile, 'mkstemp', side_effect=temporary_config), \
                    patch.object(s, 'run', side_effect=lambda args, **kwargs: calls.append(args) or Result()):
                result = s.apply_vpn_plan(self.vpn_plan(), state)

            self.assertTrue(result['changed'])
            self.assertIn(['/usr/bin/nmcli', 'connection', 'up', 'uuid', 'new-uuid'], calls)
            persisted = json.loads(state.read_text())
            self.assertEqual(3, persisted['revision'])
            self.assertEqual(self.vpn_plan()['privateKey'], persisted['plan']['privateKey'])
            self.assertNotIn(self.vpn_plan()['privateKey'], json.dumps(result))

            calls = []
            with patch.object(s, 'nmcli_connections', return_value={s.VPN_CONNECTION: 'new-uuid'}), \
                    patch.object(s, 'active_uuids', return_value=set()), \
                    patch.object(s, 'nmcli_path', return_value='/usr/bin/nmcli'), \
                    patch.object(s, 'verify_vpn_runtime'), \
                    patch.object(s, 'run', side_effect=lambda args, **kwargs: calls.append(args) or Result()):
                repeated = s.apply_vpn_plan(self.vpn_plan(), state)
            self.assertFalse(repeated['changed'])
            self.assertIn(['/usr/bin/nmcli', 'connection', 'up', 'uuid', 'new-uuid'], calls)

    def test_unit_is_hardened_and_run_script_installs_versioned_service(self):
        unit = (ROOT / 'packaging/turris-federation-network.service').read_text()
        runner = (ROOT / 'run.sh').read_text()
        self.assertIn('ProtectSystem=strict', unit)
        self.assertIn('ProtectHome=true', unit)
        self.assertIn('NoNewPrivileges=true', unit)
        self.assertIn('CAP_NET_ADMIN', unit)
        self.assertIn('CAP_CHOWN', unit)
        self.assertNotIn('WorkingDirectory=', unit)
        self.assertIn('install_notebook_network_service.py --check --uid "$UID"', runner)
        self.assertIn('sudo python3 scripts/install_notebook_network_service.py --uid "$UID"', runner)


if __name__ == '__main__':
    unittest.main()
