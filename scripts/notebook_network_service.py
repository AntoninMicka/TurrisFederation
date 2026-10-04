#!/usr/bin/env python3
"""Privileged, narrowly scoped network service for a federation notebook."""

import argparse
import base64
import binascii
import datetime
import hashlib
import ipaddress
import json
import os
import pwd
import re
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

SOCKET_PATH = Path('/run/turris-federation/notebook-network.sock')
CONFIG_PATH = Path('/etc/turris-federation/notebook-network.json')
STATE_PATH = Path('/var/lib/turris-federation-notebook-network/state.json')
VPN_STATE_PATH = Path('/var/lib/turris-federation-notebook-network/vpn.json')
VPN_INTERFACE = 'tf_notebook'
VPN_CONNECTION = 'turris-federation'
VPN_BACKUP = 'turris-federation-rollback'
VPN_SCHEMA = 'tf-notebook-system-vpn-1'
WG_PORT = 51830
NFT_TABLE = 'turris_federation_notebook'
LIMIT = 64 * 1024
NETWORK_ID = re.compile(r'^[0-9a-f]{16}$')
WG_KEY = re.compile(r'^[A-Za-z0-9+/]{43}=$')
PRIVATE_V4 = tuple(ipaddress.ip_network(value) for value in [
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])


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


def wireguard_key(value):
    if not isinstance(value, str) or not WG_KEY.fullmatch(value):
        raise ValueError('Neplatný WireGuard klíč.')
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError('Neplatný WireGuard klíč.')
    except (ValueError, binascii.Error) as error:
        raise ValueError('Neplatný WireGuard klíč.') from error
    return value


def private_ipv4(value, prefix=None):
    if not isinstance(value, str):
        raise ValueError('VPN plán obsahuje neplatnou IPv4 adresu.')
    try:
        item = ipaddress.ip_interface(value) if '/' in value else ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError('VPN plán obsahuje neplatnou IPv4 adresu.') from error
    address = item.ip if isinstance(item, ipaddress.IPv4Interface) else item
    if address.version != 4 or not any(address in network for network in PRIVATE_V4):
        raise ValueError('VPN plán smí používat pouze privátní IPv4 adresy.')
    if prefix is not None and (not isinstance(item, ipaddress.IPv4Interface) or item.network.prefixlen != prefix):
        raise ValueError('VPN adresa notebooku musí být host route /32.')
    return str(item)


def normalize_vpn_plan(request):
    if not isinstance(request, dict) or set(request) != {
            'action', 'schema', 'revision', 'address', 'privateKey', 'peers'}:
        raise ValueError('Neplatný formát systémového VPN plánu.')
    if request['action'] != 'vpn_reconcile' or request['schema'] != VPN_SCHEMA:
        raise ValueError('Neplatné schéma systémového VPN plánu.')
    if not isinstance(request['revision'], int) or request['revision'] < 1:
        raise ValueError('Neplatná revize VPN plánu.')
    address = private_ipv4(request['address'], 32)
    private_key = wireguard_key(request['privateKey'])
    peers = request['peers']
    if not isinstance(peers, list) or not 1 <= len(peers) <= 128:
        raise ValueError('VPN plán musí obsahovat omezený seznam routerů.')
    normalized, networks = [], []
    for peer in peers:
        if not isinstance(peer, dict) or set(peer) != {'publicKey', 'endpoint', 'allowedIps'}:
            raise ValueError('Neplatný WireGuard peer.')
        public_key = wireguard_key(peer['publicKey'])
        try:
            host, port = peer['endpoint'].rsplit(':', 1)
        except (AttributeError, ValueError) as error:
            raise ValueError('Neplatný WireGuard endpoint.') from error
        private_ipv4(host)
        if port != str(WG_PORT):
            raise ValueError('WireGuard endpoint používá nepovolený port.')
        allowed = peer['allowedIps']
        if not isinstance(allowed, list) or not 1 <= len(allowed) <= 64:
            raise ValueError('WireGuard peer nemá platné routy.')
        clean = []
        for cidr in allowed:
            try:
                network = ipaddress.ip_network(cidr, strict=True)
            except (TypeError, ValueError) as error:
                raise ValueError('WireGuard peer obsahuje neplatnou routu.') from error
            if network.version != 4 or not any(network.subnet_of(private) for private in PRIVATE_V4):
                raise ValueError('WireGuard routy musí být privátní IPv4 prefixy.')
            if any(network.overlaps(existing) for existing in networks):
                raise ValueError('WireGuard routy peerů se překrývají.')
            networks.append(network)
            clean.append(str(network))
        normalized.append({'publicKey': public_key, 'endpoint': host + ':' + port,
                           'allowedIps': sorted(clean)})
    return {'schema': VPN_SCHEMA, 'revision': request['revision'], 'address': address,
            'privateKey': private_key, 'peers': sorted(normalized, key=lambda item: item['publicKey'])}


def render_wireguard(plan):
    lines = ['[Interface]', 'PrivateKey = ' + plan['privateKey'],
             'Address = ' + plan['address'], 'ListenPort = 0', '']
    for peer in plan['peers']:
        lines.extend(['[Peer]', 'PublicKey = ' + peer['publicKey'],
                      'Endpoint = ' + peer['endpoint'],
                      'AllowedIPs = ' + ', '.join(peer['allowedIps']),
                      'PersistentKeepalive = 25', ''])
    return ('\n'.join(lines)).encode()


def nmcli_path():
    path = command_path(['/usr/bin/nmcli', '/bin/nmcli'])
    if not path:
        raise ValueError('NetworkManager není nainstalovaný.')
    return path


def nmcli_connections():
    output = run([nmcli_path(), '-t', '-f', 'UUID,NAME,TYPE', 'connection', 'show']).stdout.decode()
    result = {}
    for line in output.splitlines():
        fields = line.split(':', 2)
        if len(fields) == 3 and fields[1] in [VPN_CONNECTION, VPN_BACKUP] and fields[2] == 'wireguard':
            if fields[1] in result:
                raise ValueError('NetworkManager obsahuje duplicitní spravované VPN profily.')
            result[fields[1]] = fields[0]
    return result


def active_uuids():
    output = run([nmcli_path(), '-t', '-f', 'UUID', 'connection', 'show', '--active']).stdout.decode()
    return set(output.splitlines())


def all_connection_uuids():
    output = run([nmcli_path(), '-t', '-f', 'UUID', 'connection', 'show']).stdout.decode()
    return set(output.splitlines())


def verify_vpn_runtime(plan):
    ip = command_path(['/usr/sbin/ip', '/usr/bin/ip'])
    if not ip:
        raise ValueError('Nástroj ip není nainstalovaný.')
    try:
        addresses = json.loads(run(
            [ip, '-j', '-4', 'address', 'show', 'dev', VPN_INTERFACE]).stdout)
        routes = json.loads(run(
            [ip, '-j', '-4', 'route', 'show', 'dev', VPN_INTERFACE]).stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError('Systém nevrátil ověřitelný stav VPN.') from error
    expected_address = plan['address'].split('/', 1)[0]
    present_addresses = {
        address.get('local')
        for link in addresses if isinstance(link, dict)
        for address in link.get('addr_info', []) if isinstance(address, dict)
    }
    if expected_address not in present_addresses:
        raise ValueError('Po aktivaci chybí přidělená VPN adresa.')
    present_routes = set()
    for route in routes:
        destination = route.get('dst') if isinstance(route, dict) else None
        if not isinstance(destination, str) or destination == 'default':
            continue
        if '/' not in destination:
            destination += '/32'
        try:
            present_routes.add(str(ipaddress.ip_network(destination, strict=True)))
        except ValueError:
            continue
    expected_routes = {
        cidr for peer in plan['peers'] for cidr in peer['allowedIps']
    }
    missing = sorted(expected_routes - present_routes)
    if missing:
        raise ValueError('Po aktivaci chybí očekávané VPN routy: ' + ', '.join(missing))
    return {'address': expected_address, 'routes': sorted(expected_routes)}


def apply_vpn_plan(raw_plan, state_path=VPN_STATE_PATH):
    plan = normalize_vpn_plan(raw_plan)
    config = render_wireguard(plan)
    desired_hash = hashlib.sha256(config).hexdigest()
    stored = {}
    try:
        stored = json.loads(Path(state_path).read_text())
    except (OSError, json.JSONDecodeError):
        pass
    managed = nmcli_connections()
    current = managed.get(VPN_CONNECTION)
    if current and stored.get('configHash') == desired_hash:
        run([nmcli_path(), 'connection', 'modify', 'uuid', current,
             'connection.autoconnect', 'yes', 'ipv4.never-default', 'yes',
             'ipv6.never-default', 'yes', 'wireguard.peer-routes', 'yes'])
        if current not in active_uuids():
            run([nmcli_path(), 'connection', 'up', 'uuid', current], timeout=30)
        verify_vpn_runtime(plan)
        return {'state': 'active', 'revision': plan['revision'], 'changed': False}
    backup = managed.get(VPN_BACKUP)
    new_uuid = None
    created_uuids = set()
    try:
        if backup:
            run([nmcli_path(), 'connection', 'delete', 'uuid', backup])
        if current:
            run([nmcli_path(), 'connection', 'modify', 'uuid', current,
                 'connection.id', VPN_BACKUP])
            run([nmcli_path(), 'connection', 'down', 'uuid', current], check=False)
        before = all_connection_uuids()
        descriptor, temporary = tempfile.mkstemp(prefix='tf-vpn-', suffix='.conf', dir='/run')
        try:
            os.write(descriptor, config)
            os.close(descriptor)
            descriptor = None
            os.chmod(temporary, 0o600)
            run([nmcli_path(), 'connection', 'import', 'type', 'wireguard', 'file', temporary])
        finally:
            if descriptor is not None:
                os.close(descriptor)
            Path(temporary).unlink(missing_ok=True)
        after = all_connection_uuids()
        created_uuids = after - before
        if len(created_uuids) != 1:
            raise ValueError('NetworkManager nepotvrdil právě jeden nový VPN profil.')
        new_uuid = next(iter(created_uuids))
        run([nmcli_path(), 'connection', 'modify', 'uuid', new_uuid,
             'connection.id', VPN_CONNECTION, 'connection.interface-name', VPN_INTERFACE,
             'connection.autoconnect', 'yes', 'ipv4.never-default', 'yes',
             'ipv6.never-default', 'yes', 'ipv4.route-metric', '2048',
             'ipv6.route-metric', '2048', 'wireguard.peer-routes', 'yes'])
        run([nmcli_path(), 'connection', 'up', 'uuid', new_uuid], timeout=30)
        verify_vpn_runtime(plan)
        atomic_json(state_path, {'schema': VPN_SCHEMA, 'revision': plan['revision'],
                                 'configHash': desired_hash, 'plan': plan})
        return {'state': 'active', 'revision': plan['revision'], 'changed': True}
    except Exception:
        for profile_uuid in created_uuids:
            run([nmcli_path(), 'connection', 'delete', 'uuid', profile_uuid], check=False)
        if current:
            run([nmcli_path(), 'connection', 'modify', 'uuid', current,
                 'connection.id', VPN_CONNECTION], check=False)
            run([nmcli_path(), 'connection', 'up', 'uuid', current], check=False, timeout=30)
        raise


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
        self.vpn_lock = threading.Lock()

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
        elif action == 'vpn_reconcile':
            with self.vpn_lock:
                result = {'vpn': apply_vpn_plan(request)}
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
            try:
                desired = json.loads(VPN_STATE_PATH.read_text()).get('plan')
                if desired:
                    with self.vpn_lock:
                        apply_vpn_plan({'action': 'vpn_reconcile', **desired})
            except FileNotFoundError:
                pass
            except Exception:
                atomic_json(self.state_path, {'checkedAt': time.time(), 'action': 'vpn-monitor',
                                              'ok': False, 'error': 'VPN profil nelze automaticky obnovit.'})

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
