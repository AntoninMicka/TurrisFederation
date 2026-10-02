import importlib.util
import json
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

    def test_unit_is_hardened_and_run_script_installs_versioned_service(self):
        unit = (ROOT / 'packaging/turris-federation-network.service').read_text()
        runner = (ROOT / 'run.sh').read_text()
        self.assertIn('ProtectSystem=strict', unit)
        self.assertIn('ProtectHome=true', unit)
        self.assertIn('NoNewPrivileges=true', unit)
        self.assertIn('CAP_NET_ADMIN', unit)
        self.assertNotIn('WorkingDirectory=', unit)
        self.assertIn('install_notebook_network_service.py --check --uid "$UID"', runner)
        self.assertIn('sudo python3 scripts/install_notebook_network_service.py --uid "$UID"', runner)


if __name__ == '__main__':
    unittest.main()
