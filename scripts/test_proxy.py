#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'proxy/tf_proxy.py'
spec = importlib.util.spec_from_file_location('tf_proxy', SOURCE)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class ProxyTests(unittest.TestCase):
    def manifest(self):
        return {'schema': 1, 'nodeId': 'router-1', 'issuedAt': 1000, 'expiresAt': 1120,
                'services': [
                    {'id': 'diary', 'name': 'Diary', 'scheme': 'https',
                     'host': '192.168.1.20', 'port': 443, 'basePath': '/app',
                     'serverName': 'diary.cacke.internal'},
                    {'id': 'chat', 'name': 'Chat', 'scheme': 'http',
                     'host': '192.168.1.21', 'port': 8080, 'basePath': '/',
                     'serverName': '192.168.1.21'},
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

    def test_nginx_binds_only_vpn_ip_and_verifies_https_upstream(self):
        services = p.validate_manifest(self.manifest(), 'router-1', now=1050)
        config = p.nginx_config(services, 'proxy.cacke.internal', '100.81.1.4',
                                '/cert.pem', '/key.pem', '/local-ca.pem')
        self.assertEqual(3, config.count('listen 100.81.1.4:443 ssl'))
        self.assertIn('server_name diary.proxy.cacke.internal;', config)
        self.assertIn('proxy_pass https://192.168.1.20:443/app/;', config)
        self.assertIn('proxy_ssl_verify on;', config)
        self.assertIn('proxy_ssl_name diary.cacke.internal;', config)
        self.assertIn('return 421;', config)
        self.assertNotIn('listen 0.0.0.0', config)

    def test_manifest_rejects_header_and_nginx_injection(self):
        for field, value in [('id', 'bad.name'), ('serverName', 'ok.internal; include /tmp/x'),
                             ('basePath', '/ok\nproxy_pass http://evil'),
                             ('basePath', '/ok;include/tmp/x')]:
            manifest = self.manifest()
            manifest['services'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                p.validate_manifest(manifest, 'router-1', now=1050)

    def test_expired_cached_manifest_removes_all_upstreams(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = {
                'routerPublicKey': str(root / 'router.pub'), 'routerNodeId': 'router-1',
                'domain': 'proxy.cacke.internal', 'listenAddress': '100.81.1.4',
                'certificate': '/cert.pem', 'certificateKey': '/key.pem',
                'nginxConfig': str(root / 'proxy.conf'), 'stateFile': str(root / 'state.json'),
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


if __name__ == '__main__':
    unittest.main()
