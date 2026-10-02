#!/usr/bin/env python3
"""Privileged, narrowly scoped network service for a federation notebook."""

import argparse
import datetime
import json
import os
import pwd
import re
import socket
import socketserver
import struct
import subprocess
import threading
import time
from pathlib import Path

SOCKET_PATH = Path('/run/turris-federation/notebook-network.sock')
CONFIG_PATH = Path('/etc/turris-federation/notebook-network.json')
STATE_PATH = Path('/var/lib/turris-federation-notebook-network/state.json')
VPN_INTERFACE = 'tf_notebook'
NFT_TABLE = 'turris_federation_notebook'
LIMIT = 64 * 1024
NETWORK_ID = re.compile(r'^[0-9a-f]{16}$')


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + '.tmp')
    temporary.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def command_path(candidates):
    return next((path for path in candidates if Path(path).is_file() and os.access(path, os.X_OK)), None)


def run(args, data=None, check=True, timeout=15):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    if check and result.returncode:
        raise ValueError('Systémový síťový příkaz selhal.')
    return result


def guard_script(replace=False):
    prefix = b'delete table inet turris_federation_notebook\n' if replace else b''
    return prefix + b'''table inet turris_federation_notebook {
 chain forward {
  type filter hook forward priority 100; policy accept;
  iifname "tf_notebook" counter drop comment "turris-federation-notebook-input"
  oifname "tf_notebook" counter drop comment "turris-federation-notebook-output"
 }
}
'''


def nft_path():
    return command_path(['/usr/sbin/nft', '/usr/bin/nft'])


def guard_status():
    nft = nft_path()
    if not nft:
        return {'available': False, 'active': False, 'error': 'Nástroj nft není nainstalovaný.'}
    result = run([nft, 'list', 'table', 'inet', NFT_TABLE], check=False)
    output = result.stdout.decode(errors='replace')
    active = (result.returncode == 0
              and 'turris-federation-notebook-input' in output
              and 'turris-federation-notebook-output' in output
              and 'hook forward' in output)
    return {'available': True, 'active': active}


def apply_guard():
    nft = nft_path()
    if not nft:
        raise ValueError('Nástroj nft není nainstalovaný.')
    exists = run([nft, 'list', 'table', 'inet', NFT_TABLE], check=False).returncode == 0
    # Delete and recreate in one nft transaction so there is no unguarded gap.
    run([nft, '-f', '-'], guard_script(replace=exists))
    status = guard_status()
    if not status['active']:
        raise ValueError('Blokovací pravidla notebooku se nepodařilo ověřit.')
    return status


def zerotier_path():
    return command_path(['/usr/sbin/zerotier-cli', '/usr/bin/zerotier-cli',
                         '/usr/local/sbin/zerotier-cli', '/usr/local/bin/zerotier-cli'])


def service_enabled(name):
    systemctl = command_path(['/usr/bin/systemctl', '/bin/systemctl'])
    return bool(systemctl and run([systemctl, 'is-enabled', name], check=False).returncode == 0)


def zerotier_status(network_id=None):
    if network_id is not None and not NETWORK_ID.fullmatch(network_id):
        raise ValueError('Neplatné ZeroTier Network ID.')
    checked = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cli = zerotier_path()
    base = {'routerId': 'local-notebook', 'networkId': network_id,
            'installed': bool(cli), 'deviceId': None,
            'version': None, 'online': None, 'networkStatus': None,
            'networkName': None, 'assignedAddresses': [], 'device': None,
            'serviceEnabled': service_enabled('zerotier-one.service'),
            'persistent': False, 'wireguardInterfaceBlocked': None,
            'state': 'not_installed' if not cli else 'service_unavailable',
            'summary': 'ZeroTier není nainstalovaný.' if not cli else 'ZeroTier neodpovídá.',
            'details': '', 'checkedAt': checked}
    if not cli:
        return base
    info_result = run([cli, '-j', 'info'], check=False)
    networks_result = run([cli, '-j', 'listnetworks'], check=False)
    if info_result.returncode or networks_result.returncode:
        base['details'] = 'Privilegovaná služba nedokázala načíst stav ZeroTier.'
        return base
    try:
        info = json.loads(info_result.stdout)
        networks = json.loads(networks_result.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError):
        base.update(state='error', summary='ZeroTier vrátil neplatný stav.')
        return base
    base['deviceId'] = info.get('address') if isinstance(info.get('address'), str) else None
    base['version'] = info.get('version') if isinstance(info.get('version'), str) else None
    base['online'] = info.get('online') if isinstance(info.get('online'), bool) else None
    prefixes = (info.get('config', {}).get('settings', {}).get('interfacePrefixBlacklist', []))
    if isinstance(prefixes, list):
        base['wireguardInterfaceBlocked'] = any(
            isinstance(prefix, str) and prefix and VPN_INTERFACE.startswith(prefix)
            for prefix in prefixes)
    selected = None
    if isinstance(networks, list) and network_id:
        selected = next((item for item in networks if isinstance(item, dict)
                         and (item.get('nwid') or item.get('id')) == network_id), None)
    if selected:
        base['networkStatus'] = selected.get('status')
        base['networkName'] = selected.get('name')
        addresses = selected.get('assignedAddresses', [])
        base['assignedAddresses'] = [item for item in addresses if isinstance(item, str)]
        base['device'] = selected.get('portDeviceName') if isinstance(selected.get('portDeviceName'), str) else None
    base['persistent'] = bool(base['serviceEnabled'] and (selected if network_id else True))
    if base['online'] is False:
        base.update(state='offline', summary='ZeroTier je spuštěný, ale není online.')
    elif network_id and not selected:
        base.update(state='not_joined', summary='Notebook není připojený do uložené ZeroTier sítě.')
    elif selected and selected.get('status') != 'OK':
        base.update(state='pending', summary='ZeroTier síť čeká na autorizaci nebo konfiguraci.')
    else:
        base.update(state='ready', summary='ZeroTier je připravený.')
    base['details'] = 'Stav byl načten privilegovanou notebookovou síťovou službou.'
    return base


def zerotier_membership(action, network_id):
    if not isinstance(network_id, str) or not NETWORK_ID.fullmatch(network_id):
        raise ValueError('Neplatné ZeroTier Network ID.')
    cli = zerotier_path()
    if not cli:
        raise ValueError('ZeroTier není nainstalovaný.')
    run([cli, action, network_id])
    return zerotier_status(network_id)


def network_status(network_id=None):
    forwarding = {}
    for family, path in [('ipv4', '/proc/sys/net/ipv4/ip_forward'),
                         ('ipv6', '/proc/sys/net/ipv6/conf/all/forwarding')]:
        try:
            forwarding[family] = Path(path).read_text().strip() == '1'
        except OSError:
            forwarding[family] = None
    ip = command_path(['/usr/sbin/ip', '/usr/bin/ip'])
    interface = bool(ip and run([ip, 'link', 'show', 'dev', VPN_INTERFACE], check=False).returncode == 0)
    routes = []
    if ip and interface:
        result = run([ip, '-j', '-4', 'route', 'show', 'dev', VPN_INTERFACE], check=False)
        try:
            routes = [item.get('dst') for item in json.loads(result.stdout) if isinstance(item, dict)
                      and isinstance(item.get('dst'), str)]
        except (json.JSONDecodeError, UnicodeDecodeError):
            routes = []
    return {'guard': guard_status(), 'zerotier': zerotier_status(network_id),
            'wireguard': {'interface': VPN_INTERFACE, 'present': interface, 'routes': routes},
            'forwarding': forwarding}


class Service:
    def __init__(self, config_path=CONFIG_PATH, socket_path=SOCKET_PATH, state_path=STATE_PATH):
        config = json.loads(Path(config_path).read_text())
        uid = config.get('allowedUid')
        if not isinstance(uid, int) or uid < 1:
            raise ValueError('Konfigurace služby neobsahuje platné UID.')
        self.allowed_uid = uid
        self.socket_path = Path(socket_path)
        self.state_path = Path(state_path)
        self.stop = threading.Event()

    def authorize(self, connection):
        if not hasattr(socket, 'SO_PEERCRED'):
            raise ValueError('Systém nepodporuje ověření lokálního klienta.')
        _pid, uid, _gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid not in (0, self.allowed_uid):
            raise ValueError('Klient nemá oprávnění používat síťovou službu.')
        return uid

    def dispatch(self, request, uid):
        if not isinstance(request, dict) or not isinstance(request.get('action'), str):
            raise ValueError('Neplatný požadavek.')
        action = request['action']
        network_id = request.get('networkId')
        if action == 'status':
            result = network_status(network_id)
        elif action == 'reconcile':
            result = {'guard': apply_guard()}
        elif action == 'zerotier_join':
            result = {'zerotier': zerotier_membership('join', network_id)}
        elif action == 'zerotier_leave':
            result = {'zerotier': zerotier_membership('leave', network_id)}
        else:
            raise ValueError('Neznámá akce síťové služby.')
        atomic_json(self.state_path, {'checkedAt': time.time(), 'action': action, 'uid': uid,
                                      'ok': True, 'guard': guard_status()})
        return result

    def monitor(self):
        while not self.stop.wait(5):
            try:
                if not guard_status()['active']:
                    apply_guard()
            except Exception:
                atomic_json(self.state_path, {'checkedAt': time.time(), 'action': 'monitor',
                                              'ok': False, 'error': 'Blokovací pravidla nelze obnovit.'})

    def serve(self):
        apply_guard()
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists() or self.socket_path.is_socket():
            self.socket_path.unlink()
        service = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(3)
                try:
                    uid = service.authorize(self.connection)
                    raw = self.rfile.readline(LIMIT + 1)
                    if not raw or len(raw) > LIMIT:
                        raise ValueError('Neplatná délka požadavku.')
                    result = {'ok': True, **service.dispatch(json.loads(raw), uid)}
                except Exception as error:
                    result = {'ok': False, 'error': str(error) if type(error) is ValueError else 'Síťový požadavek selhal.'}
                self.wfile.write((json.dumps(result, separators=(',', ':')) + '\n').encode())

        class Server(socketserver.UnixStreamServer):
            pass

        server = Server(str(self.socket_path), Handler)
        os.chown(self.socket_path, 0, pwd.getpwuid(self.allowed_uid).pw_gid)
        os.chmod(self.socket_path, 0o660)
        monitor = threading.Thread(target=self.monitor, name='network-guard', daemon=True)
        monitor.start()
        try:
            server.serve_forever(poll_interval=0.5)
        finally:
            self.stop.set()
            server.server_close()
            monitor.join(timeout=2)
            self.socket_path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['serve'])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Systémová síťová služba musí běžet jako root.')
    if args.command == 'serve':
        Service().serve()


if __name__ == '__main__':
    main()
