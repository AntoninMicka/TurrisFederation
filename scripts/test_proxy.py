#!/usr/bin/env python3
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'proxy/tf_proxy.py'
ROOT = SOURCE.parents[1]
spec = importlib.util.spec_from_file_location('tf_proxy', SOURCE)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class ProxyTests(unittest.TestCase):
    def test_lxc_is_explicitly_not_a_router(self):
        sysctl = (ROOT / 'proxy/90-turris-federation-proxy.conf').read_text()
        self.assertIn('net.ipv4.ip_forward = 0', sysctl)
        self.assertIn('net.ipv6.conf.all.forwarding = 0', sysctl)

    def manifest(self):
        return {'schema': 1, 'nodeId': 'router-1', 'issuedAt': 1000, 'expiresAt': 1120,
                'services': [
                    {'id': 'diary', 'name': 'Diary', 'scheme': 'https',
                     'host': '192.168.1.20', 'port': 443, 'basePath': '/app',
                     'serverName': 'diary.cacke.internal',
                     'auth': {'username': 'alice', 'passwordHash': '{SSHA}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'}},
                    {'id': 'chat', 'name': 'Chat', 'scheme': 'http',
                     'host': '192.168.1.21', 'port': 8080, 'basePath': '/',
                     'serverName': '192.168.1.21',
                     'auth': {'username': None, 'passwordHash': None}},
                ]}

    def test_manifest_is_short_lived_router_bound_and_private(self):
        services = p.validate_manifest(self.manifest(), 'router-1', now=1050)
        self.assertEqual(['chat', 'diary'], [service['id'] for service in services])
        for change, message in [
                ({'nodeId': 'other'}, 'lokalni Turris'),
                ({'expiresAt': 999}, 'prosly'),
                ({'expiresAt': 1400}, 'platnost')]:
            manifest = self.manifest()
            manifest.update(change)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, message):
                p.validate_manifest(manifest, 'router-1', now=1050)
        public = self.manifest()
        public['services'][0]['host'] = '8.8.8.8'
        with self.assertRaisesRegex(ValueError, 'upstream'):
            p.validate_manifest(public, 'router-1', now=1050)

    def test_nginx_binds_only_explicit_vpn_and_lan_ips_and_verifies_upstream(self):
        services = p.validate_manifest(self.manifest(), 'router-1', now=1050)
        config = p.nginx_config(services, 'proxy.cacke.internal',
                                ['100.81.1.4', '192.168.1.10'],
                                '/cert.pem', '/key.pem', '/local-ca.pem')
        self.assertEqual(3, config.count('listen 100.81.1.4:443 ssl'))
        self.assertEqual(3, config.count('listen 192.168.1.10:443 ssl'))
        self.assertIn('server_name diary.proxy.cacke.internal;', config)
        self.assertIn('proxy_pass https://192.168.1.20:443/app/;', config)
        self.assertIn('proxy_ssl_verify on;', config)
        self.assertIn('proxy_ssl_name diary.cacke.internal;', config)
        self.assertIn('auth_basic "Turris Federation";', config)
        self.assertIn('/diary.htpasswd;', config)
        self.assertEqual(1, config.count('auth_basic_user_file'))
        self.assertIn('return 421;', config)
        self.assertNotIn('listen 0.0.0.0', config)
        self.assertIn('server_names_hash_bucket_size 256;', config)
        self.assertIn('server_names_hash_max_size 4096;', config)

    def test_manifest_rejects_header_and_nginx_injection(self):
        for field, value in [('id', 'bad.name'), ('serverName', 'ok.internal; include /tmp/x'),
                             ('basePath', '/ok\nproxy_pass http://evil'),
                             ('basePath', '/ok;include/tmp/x')]:
            manifest = self.manifest()
            manifest['services'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                p.validate_manifest(manifest, 'router-1', now=1050)

    def test_fetch_uses_configured_router_port(self):
        result = type('Result', (), {'returncode': 0, 'stdout': b'{}', 'stderr': b''})()
        config = {'routerUser': 'root', 'routerHost': '192.168.1.1', 'routerPort': 2222,
                  'knownHostsFile': '/known', 'identityFile': '/identity'}
        with patch.object(p.subprocess, 'run', return_value=result) as run:
            self.assertEqual({}, p.fetch(config))
        self.assertIn('2222', run.call_args.args[0])
        with self.assertRaises(ValueError):
            p.fetch({**config, 'routerPort': '2222'})
        denied = type('Result', (), {
            'returncode': 255, 'stdout': b'', 'stderr': b'root@router: Permission denied (publickey).\n'})()
        with patch.object(p.subprocess, 'run', return_value=denied), \
                self.assertRaisesRegex(ValueError, 'Permission denied'):
            p.fetch(config)

    def test_expired_cached_manifest_removes_all_upstreams(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = {
                'routerPublicKey': str(root / 'router.pub'), 'routerNodeId': 'router-1',
                'domain': 'proxy.cacke.internal', 'listenAddress': '100.81.1.4',
                'certificate': '/cert.pem', 'certificateKey': '/key.pem',
                'nginxConfig': str(root / 'proxy.conf'), 'stateFile': str(root / 'state.json'),
                'authDirectory': str(root / 'auth'),
            }
            (root / 'config.json').write_text(json.dumps(config))
            (root / 'state.json').write_text('{"expiresAt":1000}')
            result = type('Result', (), {'returncode': 0, 'stderr': b''})()
            with patch.object(p, 'fetch', side_effect=ValueError('offline')), \
                    patch.object(p.time, 'time', return_value=1100), \
                    patch.object(p.subprocess, 'run', return_value=result):
                p.reconcile(root / 'config.json')
            rendered = (root / 'proxy.conf').read_text()
            self.assertIn('return 421;', rendered)
            self.assertNotIn('proxy_pass', rendered)

    def test_invalid_candidate_restores_previous_nginx_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / 'proxy.conf'
            destination.write_text('previous valid configuration\n')
            config = {
                'routerPublicKey': str(root / 'router.pub'), 'routerNodeId': 'router-1',
                'domain': 'proxy.internal', 'listenAddress': '100.81.1.4',
                'certificate': '/cert.pem', 'certificateKey': '/key.pem',
                'nginxConfig': str(destination), 'stateFile': str(root / 'state.json'),
                'authDirectory': str(root / 'auth'),
            }
            (root / 'config.json').write_text(json.dumps(config))
            (root / 'state.json').write_text('{"expiresAt":1000}')
            rejected = type('Result', (), {'returncode': 1, 'stderr': b'invalid'})()
            with patch.object(p, 'fetch', side_effect=ValueError('offline')), \
                    patch.object(p.time, 'time', return_value=1100), \
                    patch.object(p.subprocess, 'run', return_value=rejected) as run, \
                    self.assertRaisesRegex(ValueError, 'posledni platna'):
                p.reconcile(root / 'config.json')
            self.assertEqual('previous valid configuration\n', destination.read_text())
            self.assertEqual([['nginx', '-t']], [call.args[0] for call in run.call_args_list])

    def test_basic_auth_files_are_group_readable_only_by_nginx(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            auth_root = root / 'auth'
            config = {
                'routerPublicKey': str(root / 'router.pub'), 'routerNodeId': 'router-1',
                'domain': 'proxy.internal', 'listenAddress': '100.81.1.4',
                'certificate': '/cert.pem', 'certificateKey': '/key.pem',
                'nginxConfig': str(root / 'proxy.conf'),
                'authDirectory': str(auth_root), 'nginxGroup': 'nginx-test',
                'stateFile': str(root / 'state.json'),
            }
            (root / 'config.json').write_text(json.dumps(config))
            success = type('Result', (), {'returncode': 0, 'stderr': b''})()
            group = type('Group', (), {'gr_gid': os.getgid()})()
            with patch.object(p, 'fetch', return_value={}), \
                    patch.object(p, 'verify', return_value=self.manifest()), \
                    patch.object(p.grp, 'getgrnam', return_value=group), \
                    patch.object(p.time, 'time', return_value=1050), \
                    patch.object(p.subprocess, 'run', return_value=success):
                p.reconcile(root / 'config.json')
            generation = next(auth_root.iterdir())
            auth_file = generation / 'diary.htpasswd'
            self.assertEqual(0o750, auth_root.stat().st_mode & 0o777)
            self.assertEqual(0o750, generation.stat().st_mode & 0o777)
            self.assertEqual(0o640, auth_file.stat().st_mode & 0o777)
            self.assertEqual(os.getgid(), auth_file.stat().st_gid)

    def test_failed_reload_restores_and_reloads_previous_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / 'proxy.conf'
            destination.write_text('previous valid configuration\n')
            config = {
                'routerPublicKey': str(root / 'router.pub'), 'routerNodeId': 'router-1',
                'domain': 'proxy.internal', 'listenAddress': '100.81.1.4',
                'certificate': '/cert.pem', 'certificateKey': '/key.pem',
                'nginxConfig': str(destination), 'stateFile': str(root / 'state.json'),
                'authDirectory': str(root / 'auth'),
            }
            (root / 'config.json').write_text(json.dumps(config))
            (root / 'state.json').write_text('{"expiresAt":1000}')
            success = type('Result', (), {'returncode': 0, 'stderr': b''})()
            reload_error = p.subprocess.CalledProcessError(1, ['nginx', '-s', 'reload'])
            with patch.object(p, 'fetch', side_effect=ValueError('offline')), \
                    patch.object(p.time, 'time', return_value=1100), \
                    patch.object(p.subprocess, 'run',
                                 side_effect=[success, reload_error, success, success]) as run, \
                    self.assertRaisesRegex(ValueError, 'obnovena'):
                p.reconcile(root / 'config.json')
            self.assertEqual('previous valid configuration\n', destination.read_text())
            self.assertEqual(
                [['nginx', '-t'], ['nginx', '-s', 'reload'],
                 ['nginx', '-t'], ['nginx', '-s', 'reload']],
                [call.args[0] for call in run.call_args_list])


if __name__ == '__main__':
    unittest.main()
