#!/usr/bin/env python3
"""Notebook controller and Turris agent. No third-party Python dependencies."""
import base64
import contextlib
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import http.client
import http.server
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from urllib.parse import parse_qs, quote, urlsplit

VERSION = 1
NOTEBOOK_VERSION = 2
NOTEBOOK_WG_VERSION = 3
LIMIT = 1024 * 1024
PORT = 8844
WG_PORT = 51830
REMOTE = '/etc/turris-federation'
CONFIG_DIR = Path('/etc/config')
SYS_NET = Path('/sys/class/net')
PROGRAM = '/usr/lib/turris-federation/federation.py'
DHCP_LEASES = Path('/tmp/dhcp.leases')
HOST_LIMIT = 256
HOST_STATES = {'REACHABLE', 'STALE', 'DELAY', 'PROBE', 'PERMANENT'}
SERVICE_LIMIT = 128
SERVICE_PROTOCOLS = {'tcp', 'http', 'https'}


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def read(path, default=None):
    return json.loads(Path(path).read_text()) if Path(path).exists() else default


def atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data if isinstance(data, bytes) else encode(data))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def locked(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (root / 'lock').open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


APPLY_CONTEXT = threading.local()


def run(args, data=None, timeout=30):
    operation = getattr(APPLY_CONTEXT, 'operation', None)
    if operation:
        root, token = operation
        # Serialize each command with rollback, never the whole apply sequence.
        with locked(root):
            pending = read(Path(root) / 'pending.json')
            if not pending or pending['token'] != token or expired(pending):
                raise ValueError('Aplikování vypršelo nebo bylo vráceno.')
            remaining = pending['monotonicDeadline'] - time.monotonic()
            return run_apply_command(args, data, min(timeout, max(0.001, remaining)))
    return run_command(args, data, timeout)


def run_command(args, data=None, timeout=30):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        # Never expose input or command arguments: they can contain private keys.
        raise ValueError('Příkaz %s selhal (kód %s).' % (Path(args[0]).name, result.returncode))
    return result.stdout


def run_apply_command(args, data, timeout):
    # Service scripts may spawn children. Stop the entire process group before
    # releasing the lock, so a timed-out command cannot race the restore.
    with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True) as process:
        try:
            output, _ = process.communicate(data, timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        if process.returncode:
            raise ValueError('Příkaz %s selhal (kód %s).' % (Path(args[0]).name, process.returncode))
        return output


def public_key(path):
    return run(['openssl', 'pkey', '-in', str(path), '-pubout']).decode()


def identity(path):
    path = Path(path)
    if not path.exists():
        atomic(path, run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072']))
    return public_key(path)


def sign(path, payload):
    raw = encode(payload)
    signature = run(['openssl', 'dgst', '-sha256', '-sign', str(path)], raw)
    return {'payload': base64.b64encode(raw).decode(), 'signature': base64.b64encode(signature).decode()}


def verify(public, envelope):
    raw = base64.b64decode(envelope['payload'], validate=True)
    signature = base64.b64decode(envelope['signature'], validate=True)
    if len(raw) > LIMIT or len(signature) > 4096:
        raise ValueError('Podepsaná zpráva je příliš velká.')
    with tempfile.TemporaryDirectory() as directory:
        key, sig = Path(directory) / 'key', Path(directory) / 'sig'
        key.write_text(public)
        sig.write_bytes(signature)
        run(['openssl', 'dgst', '-sha256', '-verify', str(key), '-signature', str(sig)], raw)
    return json.loads(raw)


def address(value):
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local:
        raise ValueError('Pro první verzi použijte platnou IPv4 adresu ZeroTier / WireGuard.')
    return str(ip)


def normalize(nodes, network_id):
    if not re.fullmatch('[0-9a-f]{16}', network_id or ''):
        raise ValueError('Nejdřív uložte společné ZeroTier Network ID.')
    if len(nodes) > 32:
        raise ValueError('První verze podporuje nejvýše 32 stanovišť.')
    result, seen, prefixes, zt_ips, wg_ips = [], set(), [], set(), set()
    for item in sorted(nodes, key=lambda node: node['id']):
        node_id = str(uuid.UUID(item['id']))
        if not isinstance(item['name'], str) or not item['name'].strip() or len(item['name']) > 128:
            raise ValueError('Název stanoviště musí mít 1–128 znaků.')
        if node_id in seen:
            raise ValueError('Duplicitní ID uzlu.')
        seen.add(node_id)
        lans = sorted({str(ipaddress.ip_network(value, strict=True)) for value in item['lanCidrs']})
        for cidr in lans:
            net = ipaddress.ip_network(cidr)
            if net.prefixlen == 0 or net.is_multicast or net.is_loopback or net.is_link_local:
                raise ValueError('Nepodporovaná LAN síť: ' + cidr)
            for other, owner in prefixes:
                if net.version == other.version and net.overlaps(other):
                    raise ValueError('Překryv LAN sítí: %s a %s (%s).' % (cidr, other, owner))
            prefixes.append((net, item['name']))
        zt = address(item['zeroTierAddress']) if item.get('zeroTierAddress') else None
        wg = address(item['wireguardAddress']) if item.get('wireguardAddress') else None
        if zt and zt in zt_ips or wg and wg in wg_ips:
            raise ValueError('Duplicitní adresa ZeroTier nebo WireGuard.')
        if zt:
            zt_ips.add(zt)
        if wg:
            wg_ips.add(wg)
        result.append({'id': node_id, 'name': item['name'], 'lanCidrs': lans,
                       'zeroTierAddress': zt, 'wireguardAddress': wg})
    if zt_ips & wg_ips:
        raise ValueError('Adresy ZeroTier a WireGuard se nesmí shodovat.')
    for ip in zt_ips | wg_ips:
        if any(ipaddress.ip_address(ip).version == net.version and ipaddress.ip_address(ip) in net for net, _ in prefixes):
            raise ValueError('Tunelová nebo správcovská adresa koliduje s LAN sítí: ' + ip)
    return {'networkId': network_id, 'nodes': result}


def normalize_notebooks(notebooks, router_config, endpoints=False):
    if not isinstance(notebooks, list) or len(notebooks) > 128:
        raise ValueError('Federace podporuje nejvýše 128 notebooků.')
    result, seen, zt_ips, wg_ips, wg_keys = [], set(), set(), set(), set()
    router_zt = {node['zeroTierAddress'] for node in router_config['nodes'] if node['zeroTierAddress']}
    router_wg = {node['wireguardAddress'] for node in router_config['nodes'] if node['wireguardAddress']}
    router_lans = [ipaddress.ip_network(cidr) for node in router_config['nodes'] for cidr in node['lanCidrs']]
    for item in sorted(notebooks, key=lambda notebook: notebook['id']):
        fields = {'id', 'name', 'role', 'zeroTierAddress', 'wireguardAddress'}
        if endpoints:
            fields.add('wireguardKey')
        if set(item) != fields:
            raise ValueError('Notebook obsahuje nepodporovaná pole.')
        notebook_id = item['id']
        if not isinstance(notebook_id, str) or not re.fullmatch('[a-f0-9]{64}', notebook_id):
            raise ValueError('Neplatná identita notebooku.')
        if notebook_id in seen:
            raise ValueError('Duplicitní ID notebooku.')
        seen.add(notebook_id)
        name = item['name']
        if not isinstance(name, str) or not name.strip() or len(name) > 80:
            raise ValueError('Název notebooku musí mít 1–80 znaků.')
        if item['role'] not in ['administrator', 'user']:
            raise ValueError('Neplatná role notebooku.')
        zt = address(item['zeroTierAddress']) if item['zeroTierAddress'] else None
        wg = address(item['wireguardAddress']) if item['wireguardAddress'] else None
        wg_key = item['wireguardKey'] if endpoints else None
        if endpoints and wg_key is not None:
            if not isinstance(wg_key, str) or len(base64.b64decode(wg_key, validate=True)) != 32:
                raise ValueError('Neplatný veřejný WireGuard klíč notebooku.')
            if wg_key in wg_keys:
                raise ValueError('Dva notebooky používají stejný WireGuard klíč.')
            wg_keys.add(wg_key)
        if endpoints and any(value is not None for value in [zt, wg, wg_key]) and not all(
                value is not None for value in [zt, wg, wg_key]):
            raise ValueError('Síťový endpoint notebooku musí mít obě adresy a WireGuard klíč.')
        if zt and (zt in zt_ips or zt in router_zt) or wg and (wg in wg_ips or wg in router_wg):
            raise ValueError('Duplicitní adresa ZeroTier nebo WireGuard.')
        if zt:
            zt_ips.add(zt)
        if wg:
            wg_ips.add(wg)
        normalized = {'id': notebook_id, 'name': name, 'role': item['role'],
                      'zeroTierAddress': zt, 'wireguardAddress': wg}
        if endpoints:
            normalized['wireguardKey'] = wg_key
        result.append(normalized)
    if (zt_ips | router_zt) & (wg_ips | router_wg):
        raise ValueError('Adresy ZeroTier a WireGuard se nesmí shodovat.')
    for ip in zt_ips | wg_ips:
        if any(ipaddress.ip_address(ip) in network for network in router_lans):
            raise ValueError('Tunelová adresa notebooku koliduje s LAN sítí: ' + ip)
    return result


def normalize_with_notebooks(nodes, network_id, notebooks):
    config = normalize(nodes, network_id)
    config['notebooks'] = normalize_notebooks(notebooks, config)
    return config


def normalize_with_notebook_endpoints(nodes, network_id, notebooks):
    config = normalize(nodes, network_id)
    config['notebooks'] = normalize_notebooks(notebooks, config, endpoints=True)
    return config


def validate_document(doc):
    if set(doc) != {'schema', 'federationId', 'revision', 'previous', 'config', 'members'}:
        raise ValueError('Synchronizace přijímá pouze síťové nastavení, nikoli software nebo příkazy.')
    if doc.get('schema') not in [VERSION, NOTEBOOK_VERSION, NOTEBOOK_WG_VERSION] or type(doc.get('revision')) is not int or doc['revision'] < 1:
        raise ValueError('Nepodporované schéma nebo revize.')
    str(uuid.UUID(doc['federationId']))
    normalized = normalize(doc['config']['nodes'], doc['config']['networkId'])
    if doc['schema'] in [NOTEBOOK_VERSION, NOTEBOOK_WG_VERSION]:
        if set(doc['config']) != {'networkId', 'nodes', 'notebooks'}:
            raise ValueError('Konfigurace obsahuje nepodporovaná pole.')
        normalized['notebooks'] = normalize_notebooks(
            doc['config']['notebooks'], normalized, endpoints=doc['schema'] == NOTEBOOK_WG_VERSION)
    if normalized != doc['config']:
        raise ValueError('Konfigurace není normalizovaná.')
    keys = {notebook['wireguardKey'] for notebook in normalized.get('notebooks', [])
            if notebook.get('wireguardKey')}
    for node_id, member in doc['members'].items():
        if set(member) != {'nodeId', 'identity', 'wireguardKey'}:
            raise ValueError('Nepodporovaná pole člena síťové konfigurace.')
        node = next((node for node in normalized['nodes'] if node['id'] == node_id), None)
        if not node or not node['lanCidrs'] or not node['zeroTierAddress'] or not node['wireguardAddress']:
            raise ValueError('Přijatý uzel nemá kompletní konfiguraci.')
        if member['nodeId'] != node_id or not member['identity'].startswith('-----BEGIN PUBLIC KEY-----'):
            raise ValueError('Neplatná identita člena.')
        if len(base64.b64decode(member['wireguardKey'], validate=True)) != 32:
            raise ValueError('Neplatný WireGuard klíč.')
        if member['wireguardKey'] in keys:
            raise ValueError('Dva uzly používají stejný WireGuard klíč.')
        keys.add(member['wireguardKey'])
    return doc


def accept(root, envelope):
    root = Path(root)
    doc = validate_document(verify((root / 'root.pub').read_text(), envelope))
    old = read(root / 'accepted.json')
    if old:
        previous = verify((root / 'root.pub').read_text(), old)
        if doc['federationId'] != previous['federationId']:
            raise ValueError('Jiná federace.')
        if doc['revision'] < previous['revision']:
            raise ValueError('Zastaralá revize.')
        if doc['revision'] == previous['revision']:
            if envelope != old:
                raise ValueError('Konflikt stejné revize.')
            return doc
    pending = read(root / 'pending.json')
    if pending and pending['revision'] != doc['revision']:
        raise ValueError('Předchozí revize čeká na potvrzení nebo rollback.')
    # Full snapshots permit a site to catch up after missing several revisions.
    atomic(root / 'accepted.json', envelope)
    report = read(root / 'report.json', {})
    report.update(receivedRevision=doc['revision'], state='pending', checkedAt=time.time())
    atomic(root / 'report.json', report)
    return doc


def self_node(root, doc):
    node_id = read(Path(root) / 'node.json')['nodeId']
    return next((n for n in doc['config']['nodes'] if n['id'] == node_id), None)


def local_check(node, network_id):
    if os.geteuid() != 0:
        raise ValueError('Deploy vyžaduje root.')
    networks = json.loads(run(['zerotier-cli', '-j', 'listnetworks']))
    network = next((n for n in networks if n.get('nwid', n.get('id')) == network_id), None)
    if not network or network.get('status') != 'OK':
        raise ValueError('Router není autorizovaný ve společné ZeroTier síti.')
    assigned = [str(ipaddress.ip_interface(ip).ip) for ip in network.get('assignedAddresses', [])]
    if node['zeroTierAddress'] not in assigned:
        raise ValueError('ZeroTier adresa návrhu není přidělena tomuto routeru.')
    device = network.get('portDeviceName')
    if not isinstance(device, str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', device):
        raise ValueError('ZeroTier rozhraní nebylo nalezeno. Zkontrolujte připojení do sítě.')
    # Verify the kernel device and its address, not only ZeroTier's metadata.
    device_output = run(['ip', '-o', 'addr', 'show', 'dev', device]).decode()
    device_addresses = {str(ipaddress.ip_interface(ip).ip)
                        for ip in re.findall(r'inet6?\s+(\S+/\d+)', device_output)}
    if node['zeroTierAddress'] not in device_addresses:
        raise ValueError('ZeroTier zařízení nemá očekávanou IP adresu.')
    output = run(['ip', '-o', 'addr', 'show']).decode()
    actual = {str(ipaddress.ip_interface(ip).network) for ip in re.findall(r'inet6?\s+(\S+/\d+)', output)}
    if not set(node['lanCidrs']).issubset(actual):
        raise ValueError('LAN návrhu neodpovídá adresám rozhraní routeru. Opravte draft nebo LAN na routeru.')
    if run(['uci', '-q', 'changes', 'network']).strip() or run(['uci', '-q', 'changes', 'firewall']).strip():
        raise ValueError('Router má nepotvrzené UCI změny.')
    lan = run(['uci', '-q', 'get', 'network.lan']).decode().strip()
    if lan != 'interface':
        raise ValueError('První verze vyžaduje standardní UCI rozhraní network.lan.')
    firewall = run(['uci', 'export', 'firewall']).decode()
    if not re.search(r"option name ['\"]?lan['\"]?", firewall):
        raise ValueError('Chybí firewall zóna lan.')
    return {'zeroTierDevice': device, 'localNetworks': sorted(actual)}


def uci_section(package, name, kind, values):
    commands = ['set %s.%s=%s' % (package, name, kind)]
    for key, value in values.items():
        values_list = value if isinstance(value, list) else [value]
        for entry in values_list:
            commands.append('%s %s.%s.%s=%s' % ('add_list' if isinstance(value, list) else 'set', package, name, key, shell_quote(str(entry))))
    run(['uci', 'batch'], ('\n'.join(commands) + '\n').encode())


def owned_sections(package):
    output = run(['uci', 'show', package]).decode()
    return [line.split('=', 1)[0] for line in output.splitlines()
            if re.fullmatch(package + r'\.tf_[a-zA-Z0-9_]+=[a-zA-Z0-9_]+', line)]


def firewall_zone_for_device(device):
    """Return a safe pre-existing firewall zone which already owns device."""
    sections = {}
    for line in run(['uci', 'show', 'firewall']).decode().splitlines():
        if not line.startswith('firewall.') or '=' not in line:
            continue
        key, raw = line.split('=', 1)
        section, separator, option = key[len('firewall.'):].partition('.')
        if not section:
            continue
        try:
            values = shlex.split(raw)
        except ValueError as exc:
            raise ValueError('Firewall obsahuje nečitelnou UCI konfiguraci.') from exc
        entry = sections.setdefault(section, {})
        if separator:
            entry.setdefault(option, []).extend(values)
        elif len(values) == 1:
            entry['__section_type__'] = values[0]
    network_devices = {}
    for line in run(['uci', 'show', 'network']).decode().splitlines():
        if not line.startswith('network.') or '=' not in line:
            continue
        key, raw = line.split('=', 1)
        section, separator, option = key[len('network.'):].partition('.')
        if not separator or option not in {'device', 'ifname'}:
            continue
        try:
            network_devices.setdefault(section, []).extend(shlex.split(raw))
        except ValueError as exc:
            raise ValueError('Síť obsahuje nečitelnou UCI konfiguraci.') from exc

    def owns_device(zone):
        return (device in zone.get('device', [])
                or any(device in network_devices.get(network, [])
                       for network in zone.get('network', [])))

    matches = [entry for entry in sections.values()
               if entry.get('__section_type__') == 'zone' and owns_device(entry)]
    if len(matches) > 1:
        raise ValueError('ZeroTier zařízení je přiřazeno do více firewallových zón.')
    if not matches:
        return None
    zone = matches[0]
    names = zone.get('name', [])
    if (len(names) != 1 or not re.fullmatch(r'[A-Za-z0-9_]{1,32}', names[0])
            or zone.get('input') != ['REJECT'] or zone.get('output') != ['ACCEPT']
            or zone.get('forward') != ['REJECT']):
        raise ValueError('Existující firewallová zóna ZeroTier nemá bezpečné zásady REJECT/ACCEPT/REJECT.')
    return names[0]


def notebook_endpoints(doc):
    return [notebook for notebook in doc['config'].get('notebooks', [])
            if notebook.get('zeroTierAddress') and notebook.get('wireguardAddress')
            and notebook.get('wireguardKey')]


def render_apply(root, doc):
    node = self_node(root, doc)
    own_id = read(Path(root) / 'node.json')['nodeId']
    local = local_check(node, doc['config']['networkId']) if own_id in doc['members'] else None
    zero_tier_zone = firewall_zone_for_device(local['zeroTierDevice']) if local else None
    # tf_* is an explicitly reserved namespace, checked on first install.
    for package in ['network', 'firewall']:
        for section in owned_sections(package):
            run(['uci', 'delete', section])
    if own_id not in doc['members']:
        for package in ['network', 'firewall']:
            run(['uci', 'commit', package])
        run(['ifdown', 'tf_wg'])
        run(['/etc/init.d/firewall', 'reload'])
        return
    key = (Path(root) / 'wireguard.key').read_text().strip()
    uci_section('network', 'tf_wg', 'interface', {'proto': 'wireguard', 'private_key': key,
                'listen_port': str(WG_PORT), 'addresses': [node['wireguardAddress'] + '/32'],
                'nohostroute': '1'})
    peers = [n for n in doc['config']['nodes'] if n['id'] in doc['members'] and n['id'] != own_id]
    for peer in peers:
        uci_section('network', 'tf_p_' + peer['id'].replace('-', ''), 'wireguard_tf_wg', {
            'public_key': doc['members'][peer['id']]['wireguardKey'],
            'endpoint_host': peer['zeroTierAddress'], 'endpoint_port': str(WG_PORT),
            'persistent_keepalive': '25', 'route_allowed_ips': '1', 'nohostroute': '1',
            'allowed_ips': [peer['wireguardAddress'] + '/32'] + peer['lanCidrs']})
    notebooks = notebook_endpoints(doc)
    for peer in notebooks:
        uci_section('network', 'tf_n_' + peer['id'][:24], 'wireguard_tf_wg', {
            'public_key': peer['wireguardKey'], 'route_allowed_ips': '1', 'nohostroute': '1',
            'allowed_ips': [peer['wireguardAddress'] + '/32']})
    uci_section('firewall', 'tf_zone', 'zone', {'name': 'tf_fed', 'network': ['tf_wg'],
                'input': 'REJECT', 'output': 'ACCEPT', 'forward': 'REJECT'})
    zero_tier_zone = zero_tier_zone or 'tf_zt'
    if zero_tier_zone == 'tf_zt':
        uci_section('firewall', 'tf_zt_zone', 'zone', {'name': 'tf_zt', 'device': [local['zeroTierDevice']],
                    'input': 'REJECT', 'output': 'ACCEPT', 'forward': 'REJECT'})
    uci_section('firewall', 'tf_out', 'forwarding', {'src': 'lan', 'dest': 'tf_fed'})
    uci_section('firewall', 'tf_in', 'forwarding', {'src': 'tf_fed', 'dest': 'lan'})
    uci_section('firewall', 'tf_ping', 'rule', {'src': 'tf_fed', 'proto': 'icmp', 'icmp_type': ['echo-request'], 'target': 'ACCEPT', 'family': 'ipv4'})
    for index, peer in enumerate(peers):
        uci_section('firewall', 'tf_zt_ping_%s' % index, 'rule', {'src': zero_tier_zone, 'src_ip': peer['zeroTierAddress'],
                    'dest_ip': node['zeroTierAddress'], 'proto': 'icmp', 'icmp_type': ['echo-request'],
                    'target': 'ACCEPT', 'family': 'ipv4'})
        for suffix, protocol, port in [('wg', 'udp', WG_PORT), ('sync', 'tcp', PORT)]:
            uci_section('firewall', 'tf_%s_%s' % (suffix, index), 'rule', {'src': zero_tier_zone, 'src_ip': peer['zeroTierAddress'],
                        'dest_ip': node['zeroTierAddress'], 'proto': protocol, 'dest_port': str(port), 'target': 'ACCEPT', 'family': 'ipv4'})
    for index, peer in enumerate(notebooks):
        uci_section('firewall', 'tf_wg_notebook_%s' % index, 'rule', {
            'src': zero_tier_zone, 'src_ip': peer['zeroTierAddress'], 'dest_ip': node['zeroTierAddress'],
            'proto': 'udp', 'dest_port': str(WG_PORT), 'target': 'ACCEPT', 'family': 'ipv4'})
        uci_section('firewall', 'tf_ping_notebook_%s' % index, 'rule', {
            'src': zero_tier_zone, 'src_ip': peer['zeroTierAddress'], 'dest_ip': node['zeroTierAddress'],
            'proto': 'icmp', 'icmp_type': ['echo-request'], 'target': 'ACCEPT', 'family': 'ipv4'})
        if peer['role'] == 'administrator':
            uci_section('firewall', 'tf_sync_notebook_%s' % index, 'rule', {
                'src': zero_tier_zone, 'src_ip': peer['zeroTierAddress'], 'dest_ip': node['zeroTierAddress'],
                'proto': 'tcp', 'dest_port': str(PORT), 'target': 'ACCEPT', 'family': 'ipv4'})
    for package in ['network', 'firewall']:
        run(['uci', 'commit', package])
    run(['ifup', 'tf_wg'])
    run(['/etc/init.d/firewall', 'reload'])


def rollback(root):
    root = Path(root)
    pending = read(root / 'pending.json')
    if not pending:
        return
    for package in ['network', 'firewall']:
        run(['uci', '-q', 'revert', package])
        atomic(CONFIG_DIR / package, (root / 'backup' / package).read_bytes())
    subprocess.run(['ifdown', 'tf_wg'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    subprocess.run(['ifup', 'tf_wg'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    run(['/etc/init.d/firewall', 'reload'])
    atomic(root / 'report.json', {'state': 'rollback', 'receivedRevision': pending['revision'],
           'appliedRevision': pending['previousApplied'], 'error': 'Změna nebyla potvrzena; obnovena záloha.', 'checkedAt': time.time()})
    (root / 'pending.json').unlink()


def expired(pending):
    if 'monotonicDeadline' in pending:
        return time.monotonic() >= pending['monotonicDeadline']
    return time.time() >= pending['deadline']


def watchdog(root, token):
    while True:
        with locked(root):
            pending = read(Path(root) / 'pending.json')
            if not pending or pending['token'] != token:
                return
            if expired(pending):
                rollback(root)
                return
        time.sleep(2)


def check_routes(root, doc):
    own_id = read(Path(root) / 'node.json')['nodeId']
    remote_networks = [ipaddress.ip_network(cidr) for n in doc['config']['nodes']
                       if n['id'] != own_id and n['id'] in doc['members']
                       for cidr in n['lanCidrs'] + [n['wireguardAddress'] + '/32']]
    remote_networks.extend(ipaddress.ip_network(n['wireguardAddress'] + '/32')
                           for n in notebook_endpoints(doc))
    versions = {net.version for net in remote_networks}
    for version in versions:
        output = run(['ip', '-%s' % version, 'route', 'show']).decode()
        for line in output.splitlines():
            fields = line.split()
            if not fields or fields[0] == 'default' or re.search(r'\bdev tf_wg\b', line):
                continue
            try:
                actual = ipaddress.ip_network(fields[0], strict=False)
            except ValueError:
                continue
            if any(net.version == actual.version and net.overlaps(actual) for net in remote_networks):
                raise ValueError('Plán koliduje s existující trasou routeru: ' + str(actual))


def configuration_hash():
    return digest({package: hashlib.sha256((CONFIG_DIR / package).read_bytes()).hexdigest()
                   for package in ['network', 'firewall']})


def stage(root, doc, expected_hash=None):
    root = Path(root)
    with locked(root):
        accepted = read(root / 'accepted.json')
        report_before = read(root / 'report.json', {})
        pending = read(root / 'pending.json')
        if pending:
            if pending['revision'] == doc['revision'] and pending.get('phase') != 'applying':
                return pending
            raise ValueError('Předchozí deploy čeká na potvrzení nebo rollback.')
        if accepted and verify((root / 'root.pub').read_text(), accepted) != doc:
            raise ValueError('Přijatá revize se změnila.')
        before_hash = configuration_hash()
        if report_before.get('appliedRevision') == doc['revision'] and report_before.get('configurationHash') == before_hash:
            return {'token': None, 'revision': doc['revision']}
    node = self_node(root, doc)
    if node and node['id'] in doc['members']:
        local_check(node, doc['config']['networkId'])
        check_routes(root, doc)
        if doc['members'][node['id']] != read(root / 'node.json'):
            raise ValueError('Identita v konfiguraci neodpovídá lokálnímu routeru.')
    with locked(root):
        if (read(root / 'accepted.json') != accepted or read(root / 'pending.json') or
                read(root / 'report.json', {}) != report_before or configuration_hash() != before_hash):
            raise ValueError('Stav se během kontroly změnil; opakujte validaci.')
        if expected_hash and run(['sha256sum', '/etc/config/network', '/etc/config/firewall']).decode() != expected_hash:
            raise ValueError('Konfigurace routeru se od validace změnila. Spusťte novou validaci.')
        for package in ['network', 'firewall']:
            atomic(root / 'backup' / package, (CONFIG_DIR / package).read_bytes())
        pending = {'token': secrets.token_hex(24), 'revision': doc['revision'], 'phase': 'applying',
                   'deadline': time.time() + 120, 'monotonicDeadline': time.monotonic() + 120,
                   'previousApplied': report_before.get('appliedRevision')}
        atomic(root / 'pending.json', pending)
    try:
        subprocess.Popen([sys.executable, PROGRAM, 'watchdog', str(root), pending['token']],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        APPLY_CONTEXT.operation = (root, pending['token'])
        try:
            render_apply(root, doc)
        finally:
            APPLY_CONTEXT.operation = None
        with locked(root):
            if read(root / 'pending.json') != pending or expired(pending):
                raise ValueError('Aplikování vypršelo nebo bylo vráceno.')
            pending['phase'] = 'confirming'
            atomic(root / 'pending.json', pending)
            atomic(root / 'report.json', {'state': 'confirming', 'receivedRevision': doc['revision'],
                   'appliedRevision': pending['previousApplied'], 'checkedAt': time.time()})
        return pending
    except Exception:
        with locked(root):
            current = read(root / 'pending.json')
            if current and current['token'] == pending['token']:
                rollback(root)
        raise


PING_COUNT = 5
PING_MAX_AGE = 120


def ping_sample(address, interface):
    try:
        command = ['ping', '-c', '1', '-W', '1']
        if interface:
            command.extend(['-I', interface])
        command.append(address)
        result = subprocess.run(command,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        return result.returncode == 0 if result.returncode in (0, 1) else None
    except subprocess.TimeoutExpired:
        return False
    except OSError:
        return None


def ping_batch(address, interface):
    samples = [ping_sample(address, interface) for _ in range(PING_COUNT)]
    # Execution errors are not packet loss: do not publish a misleading percentage.
    valid = all(sample is not None for sample in samples)
    return {'address': address, 'samples': samples if valid else [], 'checkedAt': time.time(),
            'successPercent': 100 * sum(samples) / PING_COUNT if valid else None}


def ping_diagnostics(node, peers):
    jobs = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for peer in peers:
            for transport, field, interface in [('zerotier', 'zeroTierAddress', node['zeroTierAddress']),
                                                 ('wireguard', 'wireguardAddress', 'tf_wg')]:
                jobs.append((peer['id'], transport, pool.submit(ping_batch, peer[field], interface)))
        diagnostics = {}
        for peer_id, transport, future in jobs:
            diagnostics.setdefault(peer_id, {})[transport] = future.result()
    return diagnostics


def notebook_diagnostics(root):
    """Ping only ZeroTier addresses from the signed, accepted router set."""
    root = Path(root)
    published = read(root / 'published.json')
    if not published:
        raise ValueError('Federace zatím nemá publikovanou konfiguraci.')
    doc = validate_document(verify(notebook_public_key(root), published))
    peers = [node for node in doc['config']['nodes'] if node['id'] in doc['members']]
    if not peers:
        raise ValueError('Federace nemá přijaté routery k měření.')
    with ThreadPoolExecutor(max_workers=min(8, len(peers))) as pool:
        jobs = {node['id']: pool.submit(ping_batch, node['zeroTierAddress'], None) for node in peers}
        nodes = {node_id: {'zerotier': job.result()} for node_id, job in jobs.items()}
    result = {'revision': doc['revision'], 'state': 'complete', 'nodes': nodes}
    atomic(root / 'notebook-diagnostics.json', result)
    return result


def notebook_diagnostics_overview(root):
    root = Path(root)
    published = read(root / 'published.json')
    if not published:
        return {'revision': 0, 'state': 'idle', 'nodes': {}}
    doc = validate_document(verify(notebook_public_key(root), published))
    result = read(root / 'notebook-diagnostics.json', {})
    if result.get('revision') != doc['revision']:
        return {'revision': doc['revision'], 'state': 'idle', 'nodes': {}}
    allowed = set(doc['members'])
    return {**result, 'nodes': {node_id: value for node_id, value in result.get('nodes', {}).items() if node_id in allowed}}


def read_only_notebook_overview(root):
    """Return only reviewed fields from the signed revision and reports."""
    root = Path(root)
    published = read(root / 'published.json')
    if not published:
        raise ValueError('Federace zatím nemá publikovanou konfiguraci.')
    doc = validate_document(verify(notebook_public_key(root), published))
    reports = read(root / 'reports.json', {})
    nodes = []
    for node in doc['config']['nodes']:
        report = reports.get(node['id'], {}) if isinstance(reports, dict) else {}
        hosts, observed = [], None
        if node['id'] in doc['members']:
            try:
                catalog = validate_hosts(node, report)
                if catalog:
                    hosts, observed = catalog['hosts'], catalog['hostsObservedAt']
            except (TypeError, ValueError):
                pass
        state = report.get('state') if report.get('state') in WEB_LABELS else None
        checked = report.get('checkedAt') if isinstance(report.get('checkedAt'), (int, float)) else None
        reachable = report.get('reachable') if type(report.get('reachable')) is bool else None
        software, components = None, None
        if node['id'] in doc['members']:
            try:
                software = validate_software_info(report.get('software'))
                components = validate_components(report.get('components'))
            except (TypeError, ValueError):
                pass
        nodes.append({'id': node['id'], 'name': node['name'], 'lanCidrs': node['lanCidrs'],
                      'zeroTierAddress': node['zeroTierAddress'], 'wireguardAddress': node['wireguardAddress'],
                      'enrolled': node['id'] in doc['members'], 'state': state, 'reachable': reachable,
                      'checkedAt': checked, 'hosts': hosts, 'hostsObservedAt': observed,
                      'software': software, 'components': components})
    notebook_versions = read(root / 'notebook-software.json', {})
    notebook_versions = notebook_versions if isinstance(notebook_versions, dict) else {}
    notebooks = []
    for item in doc['config'].get('notebooks', []):
        software = None
        try:
            software = validate_software_info(notebook_versions.get(item['id']))
        except (TypeError, ValueError):
            pass
        notebooks.append({'id': item['id'], 'name': item['name'], 'role': item['role'],
                          'zeroTierAddress': item['zeroTierAddress'],
                          'wireguardAddress': item['wireguardAddress'], 'software': software})
    return {'revision': doc['revision'], 'networkId': doc['config']['networkId'],
            'availableRouterVersion': artifact_hash(),
            'availableRouterComponents': artifact_components(), 'nodes': nodes,
            'notebooks': notebooks, 'services': aggregate_services(doc, reports),
            'diagnostics': notebook_diagnostics_overview(root)}


def notebook_public_key(root):
    root = Path(root)
    if (root / 'root.pub').exists():
        return (root / 'root.pub').read_text()
    if (root / 'root.pem').exists():
        return public_key(root / 'root.pem')
    raise ValueError('Chybí veřejná kotva federace.')


def start_diagnostics(root):
    root = Path(root)
    guard = (root / 'diagnostics.lock').open('a')
    try:
        try:
            fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Diagnostika už běží. Obnovte stav za chvíli.')
        with locked(root):
            envelope = read(root / 'accepted.json')
            if not envelope:
                raise ValueError('Router ještě nemá konfiguraci federace.')
            doc = validate_document(verify((root / 'root.pub').read_text(), envelope))
            node = self_node(root, doc)
            report = read(root / 'report.json', {})
            if (not node or node['id'] not in doc['members'] or read(root / 'pending.json') or
                    report.get('appliedRevision') != doc['revision']):
                raise ValueError('Nejdřív dokončete aplikování konfigurace.')
            peers = [n for n in doc['config']['nodes'] if n['id'] in doc['members'] and n['id'] != node['id']]
            if not peers:
                raise ValueError('Federace nemá přijaté protějšky k měření.')
            job = {'revision': doc['revision'], 'startedAt': time.time(), 'state': 'running', 'nodes': {}}
            atomic(root / 'diagnostics.json', job)
        def measure():
            try:
                results = ping_diagnostics(node, peers)
                with locked(root):
                    if (read(root / 'accepted.json') != envelope or read(root / 'pending.json') or
                            read(root / 'report.json', {}).get('appliedRevision') != doc['revision']):
                        raise ValueError('Konfigurace se během měření změnila.')
                    atomic(root / 'diagnostics.json', dict(job, state='complete', nodes=results))
            except Exception:
                atomic(root / 'diagnostics.json', dict(job, state='error'))
            finally:
                guard.close()
        worker = threading.Thread(target=measure, daemon=True)
        worker.start()
        return worker
    except Exception:
        guard.close()
        raise


def diagnostic_badge(measurement, now):
    samples = measurement.get('samples', [])
    age = now - measurement.get('checkedAt', 0)
    if not samples or not 0 <= age <= PING_MAX_AGE:
        return '<span class="signal unknown">● Bez aktuálního měření</span>'
    percent = 100 * sum(samples) / len(samples)
    color, label = ('green', 'Dobré') if percent >= 95 else (('yellow', 'Zhoršené') if percent >= 80 else ('red', 'Výpadky'))
    return ('<span class="signal %s">● %s · %.1f %%</span><br>'
            '<small>%s/%s odpovědí · před %s s</small>') % (color, label, percent, sum(samples), len(samples), int(age))


def software_badge(value, expected):
    try:
        software = validate_software_info(value)
    except (TypeError, ValueError):
        software = None
    if not software:
        return '<span class="version version-unknown">● Verze neznámá</span><br><small>čas sestavení neznámý</small>'
    matching = software['version'] == expected
    built = (time.strftime('%d. %m. %Y %H:%M:%S UTC', time.gmtime(software['builtAt']))
             if software['builtAt'] is not None else 'čas sestavení neznámý')
    return ('<span class="version %s">● %s · %s</span><br><small>%s</small>' % (
            'green' if matching else 'red', software['version'][:12],
            'shodná' if matching else 'jiná verze', built))


def discover_hosts(node):
    """Best-effort passive LAN catalog. Never scans and never publishes MAC addresses."""
    try:
        result = subprocess.run(['ip', '-4', 'neigh', 'show'], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    names = {}
    try:
        lease_lines = DHCP_LEASES.read_text().splitlines()
    except OSError:
        lease_lines = []
    for line in lease_lines:
        fields = line.split()
        if len(fields) < 4 or fields[3] == '*' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,252}', fields[3]):
            continue
        try:
            names[address(fields[2])] = fields[3]
        except ValueError:
            continue
        pass
    networks = [ipaddress.ip_network(cidr) for cidr in node['lanCidrs']]
    hosts = {}
    for line in result.stdout.decode(errors='replace').splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[-1] not in HOST_STATES:
            continue
        try:
            ip = ipaddress.ip_address(fields[0])
        except ValueError:
            continue
        if ip.version != 4 or not any(ip in network for network in networks):
            continue
        hosts[str(ip)] = {'address': str(ip), 'name': names.get(str(ip))}
    return [hosts[ip] for ip in sorted(hosts, key=ipaddress.ip_address)[:HOST_LIMIT]]


def validate_hosts(node, report):
    hosts = report.get('hosts')
    observed = report.get('hostsObservedAt')
    if hosts is None and observed is None:
        return None
    if (not isinstance(hosts, list) or len(hosts) > HOST_LIMIT or
            not isinstance(observed, (int, float)) or isinstance(observed, bool) or
            not math.isfinite(observed) or observed < 0):
        raise ValueError('Neplatný katalog hostů uzlu.')
    networks = [ipaddress.ip_network(cidr) for cidr in node['lanCidrs']]
    normalized, seen = [], set()
    for host in hosts:
        if not isinstance(host, dict) or set(host) != {'address', 'name'}:
            raise ValueError('Neplatná položka katalogu hostů.')
        try:
            ip = ipaddress.ip_address(host['address'])
        except (TypeError, ValueError) as exc:
            raise ValueError('Neplatná adresa hostu v katalogu.') from exc
        name = host['name']
        if ip.version != 4 or not any(ip in network for network in networks) or str(ip) in seen:
            raise ValueError('Host neleží v LAN sítích oznamujícího uzlu.')
        if name is not None and (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,252}', name)):
            raise ValueError('Neplatný název hostu v katalogu.')
        seen.add(str(ip))
        normalized.append({'address': str(ip), 'name': name})
    normalized.sort(key=lambda host: ipaddress.ip_address(host['address']))
    return {'hosts': normalized, 'hostsObservedAt': observed}


def validate_services(node, services):
    """Validate administrator-authored services owned by this router's LAN."""
    if not isinstance(services, list) or len(services) > SERVICE_LIMIT:
        raise ValueError('Neplatný katalog služeb routeru.')
    networks = [ipaddress.ip_network(cidr) for cidr in node['lanCidrs']]
    normalized, seen = [], set()
    for service in services:
        if not isinstance(service, dict) or set(service) != {
                'id', 'name', 'hostAddress', 'protocol', 'port', 'path'}:
            raise ValueError('Neplatná položka katalogu služeb.')
        service_id, name = service['id'], service['name']
        protocol, port, path = service['protocol'], service['port'], service['path']
        if (not isinstance(service_id, str) or
                not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,63}', service_id) or service_id in seen):
            raise ValueError('Neplatné nebo duplicitní ID služby.')
        if (not isinstance(name, str) or not 1 <= len(name) <= 80 or name != name.strip()
                or any(ord(character) < 32 or ord(character) == 127 for character in name)):
            raise ValueError('Neplatný název služby.')
        try:
            host = ipaddress.ip_address(service['hostAddress'])
        except (TypeError, ValueError) as exc:
            raise ValueError('Neplatná adresa hosta služby.') from exc
        if host.version != 4 or not any(host in network for network in networks):
            raise ValueError('Služba neleží v LAN sítích tohoto routeru.')
        if protocol not in SERVICE_PROTOCOLS or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('Neplatný protokol nebo port služby.')
        if protocol == 'tcp':
            if path is not None:
                raise ValueError('TCP služba nesmí obsahovat cestu.')
        elif path is not None and (not isinstance(path, str) or not path.startswith('/')
                                   or '?' in path or '#' in path
                                   or any(ord(character) < 32 or ord(character) == 127 for character in path)):
            raise ValueError('Neplatná HTTP cesta služby.')
        seen.add(service_id)
        normalized.append({'id': service_id, 'name': name, 'hostAddress': str(host),
                           'protocol': protocol, 'port': port, 'path': path})
    normalized.sort(key=lambda service: service['id'])
    return normalized


def local_services(root, node):
    return validate_services(node, read(Path(root) / 'services.json', []))


def store_local_services(root, services):
    """Persist definitions and publish the same snapshot in the signed status source."""
    root = Path(root)
    atomic(root / 'services.json', services)
    report = read(root / 'report.json', {})
    report.update(services=services, servicesObservedAt=time.time())
    atomic(root / 'report.json', report)


def save_local_service(root, node, service, allow_duplicate=False):
    root = Path(root)
    with locked(root):
        services = local_services(root, node)
        validated = validate_services(node, [service])[0]
        duplicate = next((item for item in services if item['id'] != validated['id'] and
                          (item['hostAddress'], item['protocol'], item['port'], item['path']) ==
                          (validated['hostAddress'], validated['protocol'], validated['port'], validated['path'])), None)
        if duplicate and not allow_duplicate:
            raise ValueError('Stejný endpoint už má jinou službu; potvrďte duplicitu.')
        services = [item for item in services if item['id'] != validated['id']] + [validated]
        services = validate_services(node, services)
        store_local_services(root, services)
        return services


def delete_local_service(root, node, service_id):
    if not isinstance(service_id, str) or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,63}', service_id):
        raise ValueError('Neplatné ID služby.')
    root = Path(root)
    with locked(root):
        services = local_services(root, node)
        if not any(item['id'] == service_id for item in services):
            raise ValueError('Služba neexistuje.')
        services = [item for item in services if item['id'] != service_id]
        store_local_services(root, services)
        return services


def editable_service_hosts(node, report, services):
    """Offer observed hosts, while keeping hosts with existing definitions manageable."""
    hosts = {}
    try:
        catalog = validate_hosts(node, report)
    except (TypeError, ValueError):
        catalog = None
    for host in (catalog or {}).get('hosts', []):
        hosts[host['address']] = {**host, 'observed': True}
    for service in services:
        hosts.setdefault(service['hostAddress'], {
            'address': service['hostAddress'], 'name': None, 'observed': False})
    return sorted(hosts.values(), key=lambda host: ipaddress.ip_address(host['address']))


def validate_report_services(node, report):
    services = report.get('services')
    observed = report.get('servicesObservedAt')
    if services is None and observed is None:
        return None
    if (services is None or not isinstance(observed, (int, float)) or isinstance(observed, bool)
            or not math.isfinite(observed) or observed < 0):
        raise ValueError('Neplatný katalog služeb uzlu.')
    return {'services': validate_services(node, services), 'servicesObservedAt': observed}


def validate_catalog(node, report):
    result = {}
    hosts = validate_hosts(node, report)
    services = validate_report_services(node, report)
    software = validate_software_info(report.get('software'))
    components = validate_components(report.get('components'))
    if hosts is not None:
        result.update(hosts)
    if services is not None:
        result.update(services)
    if software is not None:
        result['software'] = software
    if components is not None:
        result['components'] = components
    return result or None


def service_endpoint(service):
    if service['protocol'] == 'tcp':
        return '%s:%s' % (service['hostAddress'], service['port'])
    path = quote(service['path'] or '', safe="/!$&'()*+,-.:;=@_~")
    return '%s://%s:%s%s' % (service['protocol'], service['hostAddress'], service['port'], path)


def aggregate_services(doc, reports, now=None):
    """Build a reviewed read-only projection from signed, enrolled-node reports."""
    now = time.time() if now is None else now
    if not isinstance(reports, dict):
        reports = {}
    result = []
    for node in doc['config']['nodes']:
        if node['id'] not in doc['members']:
            continue
        report = reports.get(node['id'], {})
        try:
            catalog = validate_report_services(node, report)
            hosts = validate_hosts(node, report)
        except (TypeError, ValueError):
            continue
        if catalog is None:
            continue
        host_names = {host['address']: host['name'] for host in (hosts or {}).get('hosts', [])}
        observed = catalog['servicesObservedAt']
        stale = report.get('reachable') is False or not 0 <= now - observed <= 120
        for service in catalog['services']:
            result.append({**service, 'routerId': node['id'], 'routerName': node['name'],
                           'hostName': host_names.get(service['hostAddress']),
                           'endpoint': service_endpoint(service), 'observedAt': observed,
                           'stale': stale, 'routeAdvertised': True})
    return sorted(result, key=lambda item: (item['routerName'].casefold(), item['name'].casefold(), item['id']))


def health(root, doc):
    own_id = read(Path(root) / 'node.json')['nodeId']
    if own_id not in doc['members']:
        return {'state': 'revoked', 'pendingPeers': []}
    expected_key = doc['members'][own_id]['wireguardKey']
    actual_key = run(['wg', 'show', 'tf_wg', 'public-key']).decode().strip()
    if expected_key != actual_key:
        raise ValueError('WireGuard nemá očekávanou identitu.')
    peers = [n for n in doc['config']['nodes'] if n['id'] in doc['members'] and n['id'] != own_id]
    notebooks = notebook_endpoints(doc)
    actual_peers = set(run(['wg', 'show', 'tf_wg', 'peers']).decode().split())
    expected_peers = {doc['members'][n['id']]['wireguardKey'] for n in peers}
    expected_peers.update(n['wireguardKey'] for n in notebooks)
    if actual_peers != expected_peers:
        raise ValueError('WireGuard nemá očekávaný seznam peerů.')
    allowed = {}
    for line in run(['wg', 'show', 'tf_wg', 'allowed-ips']).decode().splitlines():
        fields = line.replace(',', ' ').split()
        if fields:
            allowed[fields[0]] = set(fields[1:])
    for peer in peers:
        if allowed.get(doc['members'][peer['id']]['wireguardKey']) != set(peer['lanCidrs'] + [peer['wireguardAddress'] + '/32']):
            raise ValueError('WireGuard AllowedIPs neodpovídají plánu.')
    for peer in notebooks:
        if allowed.get(peer['wireguardKey']) != {peer['wireguardAddress'] + '/32'}:
            raise ValueError('Notebook má jiné WireGuard AllowedIPs než svou host route.')
    missing = []
    for peer in peers:
        for cidr in peer['lanCidrs'] + [peer['wireguardAddress'] + '/32']:
            net = ipaddress.ip_network(cidr)
            destination = net.network_address + (1 if net.num_addresses > 1 else 0)
            route = run(['ip', '-%s' % net.version, 'route', 'get', str(destination)]).decode()
            if not re.search(r'\bdev tf_wg\b', route):
                raise ValueError('Po deployi chybí WireGuard trasa: ' + cidr)
    for peer in notebooks:
        cidr = peer['wireguardAddress'] + '/32'
        route = run(['ip', '-4', 'route', 'get', peer['wireguardAddress']]).decode()
        if not re.search(r'\bdev tf_wg\b', route):
            raise ValueError('Po deployi chybí WireGuard trasa notebooku: ' + cidr)
    # Passive health check: only explicit web diagnostics may send ICMP probes.
    handshakes = {}
    for line in run(['wg', 'show', 'tf_wg', 'latest-handshakes']).decode().splitlines():
        fields = line.split()
        if len(fields) == 2:
            handshakes[fields[0]] = int(fields[1])
    now = time.time()
    for peer in peers:
        handshake = handshakes.get(doc['members'][peer['id']]['wireguardKey'], 0)
        if not handshake or not 0 <= now - handshake <= 180:
            missing.append(peer['id'])
    result = {'state': 'waiting_peers' if missing or not peers else 'active', 'pendingPeers': missing}
    hosts = discover_hosts(self_node(root, doc))
    if hosts is not None:
        result.update(hosts=hosts, hostsObservedAt=time.time())
    services = local_services(root, self_node(root, doc))
    result.update(services=services, servicesObservedAt=time.time())
    return result


def confirm(root, token):
    root = Path(root)
    with locked(root):
        pending = read(root / 'pending.json')
        envelope = read(root / 'accepted.json')
        doc = verify((root / 'root.pub').read_text(), envelope)
        if (not pending or pending['token'] != token or pending.get('revision') != doc['revision']
                or pending.get('phase') == 'applying' or expired(pending)):
            raise ValueError('Potvrzení deploye vypršelo nebo neodpovídá operaci.')
        before_hash = configuration_hash()
    result = health(root, doc)
    with locked(root):
        if (read(root / 'pending.json') != pending or read(root / 'accepted.json') != envelope
                or expired(pending) or configuration_hash() != before_hash):
            raise ValueError('Stav se během potvrzení změnil nebo potvrzení vypršelo.')
        result.update({'receivedRevision': doc['revision'], 'appliedRevision': doc['revision'],
                       'configurationHash': before_hash, 'checkedAt': time.time()})
        atomic(root / 'report.json', result)
        (root / 'pending.json').unlink()
        return {**result, 'software': software_info()}


def bootstrap(root, node_id, root_public):
    root = Path(root)
    str(uuid.UUID(node_id))
    if (root / 'root.pub').exists() and (root / 'root.pub').read_text() != root_public:
        raise ValueError('Router již patří jiné kotvě důvěry. Automatické přepárování je zakázáno.')
    old = read(root / 'node.json')
    if old and old['nodeId'] != node_id:
        raise ValueError('Router má jiné ID stanoviště.')
    if not old and any(owned_sections(package) for package in ['network', 'firewall']):
        raise ValueError('UCI prefix tf_ je obsazen. Nasazení zastaveno.')
    identity_public = identity(root / 'identity.pem')
    if not (root / 'wireguard.key').exists():
        atomic(root / 'wireguard.key', run(['wg', 'genkey']))
    wg_public = run(['wg', 'pubkey'], (root / 'wireguard.key').read_bytes()).decode().strip()
    member = {'nodeId': node_id, 'identity': identity_public, 'wireguardKey': wg_public}
    atomic(root / 'root.pub', root_public.encode())
    atomic(root / 'node.json', member)
    return member


def request_http(ip, method, path, payload=None, signer=None):
    route = run(['ip', 'route', 'get', address(ip)]).decode()
    if not re.search(r'\bdev zt[a-zA-Z0-9]+\b', route):
        raise ValueError('Zabezpečený přenos vyžaduje trasu přes ZeroTier na tomto zařízení.')
    conn = http.client.HTTPConnection(address(ip), PORT, timeout=8)
    try:
        headers = {'Content-Type': 'application/json'}
        if signer:
            headers['X-TF-Notebook'] = base64.b64encode(encode(sign(signer, {'path': path}))).decode()
        conn.request(method, path, body=encode(payload) if payload is not None else None, headers=headers)
        response = conn.getresponse()
        raw = response.read(LIMIT + 1)
        if response.status != 200 or len(raw) > LIMIT:
            raise ValueError('Synchronizační kanál odmítl požadavek.')
        return json.loads(raw)
    finally:
        conn.close()


def peer_status(peer, member, signer=None):
    nonce = secrets.token_hex(32)
    response = request_http(peer['zeroTierAddress'], 'GET', '/status/' + nonce, signer=signer)
    payload = verify(member['identity'], response)
    if payload.get('nonce') != nonce or payload.get('nodeId') != peer['id']:
        raise ValueError('Odpověď routeru neodpovídá požadavku.')
    report = payload.get('report')
    if not isinstance(report, dict):
        raise ValueError('Uzel vrátil neplatný provozní stav.')
    software = validate_software_info(report.get('software'))
    catalog = validate_catalog(peer, report)
    return {**report, **({'software': software} if software else {}), **(catalog or {})}


def refresh_catalog(root, current, own_id):
    root = Path(root)
    members = current['members']
    nodes = [node for node in current['config']['nodes'] if node['id'] in members]
    previous = read(root / 'catalog.json', {})
    if not isinstance(previous, dict):
        previous = {}
    catalog = {node['id']: previous[node['id']] for node in nodes if node['id'] in previous}
    own = next((node for node in nodes if node['id'] == own_id), None)
    own_report = status_report(root)
    if own:
        own_catalog = validate_catalog(own, own_report)
        if own_catalog is not None:
            catalog[own_id] = own_catalog
        else:
            catalog.pop(own_id, None)
    peers = [node for node in nodes if node['id'] != own_id]
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(peers)))) as pool:
        jobs = {pool.submit(peer_status, peer, members[peer['id']]): peer for peer in peers}
        for future, peer in jobs.items():
            try:
                report = future.result()
                peer_catalog = validate_catalog(peer, report)
                if peer_catalog is not None:
                    catalog[peer['id']] = peer_catalog
                else:
                    catalog.pop(peer['id'], None)
            except Exception:
                pass
    atomic(root / 'catalog.json', catalog)
    return catalog


def serve(root):
    root = Path(root)
    # Any incomplete apply is rolled back on service restart (including reboot).
    with locked(root):
        rollback(root)
    doc = verify((root / 'root.pub').read_text(), read(root / 'accepted.json'))
    node = self_node(root, doc)
    if not node or node['id'] not in doc['members']:
        raise ValueError('Router není členem federace.')
    local_check(node, doc['config']['networkId'])

    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(5)
            super().setup()

        def log_message(self, *_):
            pass

        def do_GET(self):
            try:
                self.connection.settimeout(5)
                with locked(root):
                    current = verify((root / 'root.pub').read_text(), read(root / 'accepted.json'))
                    ips = [n['zeroTierAddress'] for n in current['config']['nodes'] if n['id'] in current['members']]
                    notebook = self.headers.get('X-TF-Notebook')
                    if notebook:
                        if len(notebook) > 10000 or verify((root / 'root.pub').read_text(), json.loads(base64.b64decode(notebook, validate=True))) != {'path': self.path}:
                            raise ValueError('Neplatné ověření notebooku.')
                    elif self.client_address[0] not in ips:
                        raise ValueError('Neznámý zdroj.')
                    if self.path == '/bundle':
                        result = read(root / 'accepted.json')
                    elif re.fullmatch('/status/[0-9a-f]{64}', self.path):
                        result = sign(root / 'identity.pem', {'nonce': self.path.split('/')[-1],
                                      'nodeId': read(root / 'node.json')['nodeId'], 'report': status_report(root)})
                    else:
                        raise ValueError('Neznámá cesta.')
                raw = encode(result)
                self.send_response(200)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except Exception:
                self.send_error(403)

        def do_POST(self):
            try:
                self.connection.settimeout(5)
                size = int(self.headers.get('Content-Length', '0'))
                if self.path != '/bundle' or not 0 < size <= LIMIT:
                    raise ValueError('Neplatný požadavek.')
                envelope = json.loads(self.rfile.read(size))
                with locked(root):
                    accept(root, envelope)  # Only the notebook signature can authorize a change.
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{}')
            except Exception:
                self.send_error(403)

    # Serve incoming peer requests even while outgoing requests are waiting.
    # State mutations still use the same file lock as SSH commands/watchdog.
    with http.server.HTTPServer((node['zeroTierAddress'], PORT), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, name='federation-http', daemon=True)
        worker.start()
        try:
            sync_loop(root)
        finally:
            server.shutdown()
            worker.join()


def exchange_bundles(root, current, own_id):
    root = Path(root)
    with locked(root):
        envelope = read(root / 'accepted.json')
    for peer in current['config']['nodes']:
        if peer['id'] == own_id or peer['id'] not in current['members']:
            continue
        # Push first: a previously enrolled router does not yet know the new
        # member and cannot discover it by pulling from its old member list.
        try:
            request_http(peer['zeroTierAddress'], 'POST', '/bundle', envelope)
        except Exception:
            pass
        # A rejected/older push must not prevent us from fetching a newer one.
        try:
            received = request_http(peer['zeroTierAddress'], 'GET', '/bundle')
            with locked(root):
                accept(root, received)
        except Exception:
            pass


def sync_loop(root):
    next_sync = 0
    while True:
        delay = next_sync - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        next_sync = time.monotonic() + 30
        try:
            with locked(root):
                current = verify((root / 'root.pub').read_text(), read(root / 'accepted.json'))
            own_id = read(root / 'node.json')['nodeId']
            exchange_bundles(root, current, own_id)
            with locked(root):
                current = verify((root / 'root.pub').read_text(), read(root / 'accepted.json'))
                report = read(root / 'report.json', {})
                if report.get('state') == 'rollback' and report.get('receivedRevision') == current['revision']:
                    continue
            if report.get('appliedRevision') != current['revision']:
                pending = stage(root, current)
            else:
                pending = None
                before_hash = configuration_hash()
                if report.get('configurationHash') != before_hash:
                    raise ValueError('UCI konfigurace se po deployi změnila; ověřte a znovu validujte stanoviště.')
                result = health(root, current)
                with locked(root):
                    if (read(root / 'report.json', {}) != report or read(root / 'pending.json') or
                            verify((root / 'root.pub').read_text(), read(root / 'accepted.json')) != current or
                            configuration_hash() != before_hash):
                        continue
                    report.update(result, checkedAt=time.time())
                    report.pop('error', None)
                    atomic(root / 'report.json', report)
            if pending:
                # Confirm via the independent ZeroTier path from at least one enrolled peer.
                reachable = False
                for peer in current['config']['nodes']:
                    if peer['id'] != own_id and peer['id'] in current['members']:
                        try:
                            peer_status(peer, current['members'][peer['id']])
                            reachable = True
                            break
                        except Exception:
                            pass
                if reachable:
                    confirm(root, pending['token'])
            refresh_catalog(root, current, own_id)
        except Exception as error:
            with locked(root):
                report = read(root / 'report.json', {})
                if report.get('state') == 'rollback':
                    continue
                report.update(error=str(error), state='error', checkedAt=time.time())
                atomic(root / 'report.json', report)


WEB_PROXY_PATH = Path('/etc/lighttpd/conf.d/turris-federation.conf')
WEB_PORT = 8845
WEB_PATH = '/turris-federation/'
WEB_OVERVIEW_PATH = WEB_PATH + 'overview/'
WEB_FILES = {
    '/etc/turris-webapps/80-turris-federation.json': json.dumps({
        'id': 'turris-federation', 'title': 'Turris Federation', 'url': WEB_PATH,
        'icon': '/icons/turris-federation.svg',
        'description': {'en': 'Federation nodes and network status', 'cz': 'Uzly federace a stav sítě', 'cs': 'Uzly federace a stav sítě'}
    }, ensure_ascii=False).encode(),
    '/www/webapps-icons/turris-federation.svg': b'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96"><rect width="96" height="96" rx="20" fill="#123047"/><path d="M24 66 48 26 72 66Z" fill="none" stroke="#58d5c9" stroke-width="5"/><g fill="#fff"><circle cx="48" cy="26" r="10"/><circle cx="24" cy="66" r="10"/><circle cx="72" cy="66" r="10"/></g></svg>''',
    '/etc/lighttpd/conf.d/turris-federation.conf': b'''# Managed by Turris Federation LAN deployment.
server.modules += ( "mod_proxy", "mod_auth", "mod_authn_pam" )
$HTTP["url"] =~ "^/turris-federation($|/$|/app\\.js$)" {
  proxy.server = ( "" => ( ( "host" => "127.0.0.1", "port" => 8845 ) ) )
}
$HTTP["url"] =~ "^/turris-federation/overview($|/)" {
  auth.backend = "pam"
  auth.require = ( "" => ( "method" => "basic", "realm" => "Turris Federation", "require" => "valid-user" ) )
  proxy.server = ( "" => ( ( "host" => "127.0.0.1", "port" => 8845 ) ) )
}
''',
}
WEB_STYLE = '''
:root{color-scheme:light dark;font-family:system-ui,sans-serif;background:#0c1925;color:#e6eff6}
*{box-sizing:border-box}body{margin:0}main{max-width:1120px;margin:auto;padding:36px 22px}
a{color:#80e1d7}nav{display:flex;justify-content:space-between;gap:20px;margin-bottom:38px}
h1{font-size:clamp(28px,5vw,44px);margin:8px 0 14px}h2{font-size:21px;margin:0 0 20px}
p{line-height:1.6}.muted,dt{color:#a8bdcc}.kicker{color:#80e1d7;letter-spacing:.13em;font-size:12px;text-transform:uppercase}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;margin:28px 0}
.card,section{background:#13283a;border:1px solid #2a4355;border-radius:14px;padding:22px}
.card strong{display:block;font-size:28px;margin:12px 0}.card span{color:#a8bdcc}
section{margin:20px 0}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;text-align:left}
th,td{padding:14px 12px;border-bottom:1px solid #2a4355;vertical-align:top}th{color:#a8bdcc;font-weight:500}
td{overflow-wrap:anywhere}code{font-size:13px}.notice{border-left:3px solid #eeb76d;padding:10px 18px;background:#26303a}
.hosts{margin:0;padding-left:18px;min-width:170px}.hosts li{margin:0 0 6px}.hosts small{display:block}
.badge{display:inline-block;border-radius:20px;padding:5px 10px;background:#244653;font-size:13px}
.signal{white-space:nowrap;font-size:13px}.green{color:#7ee2a8}.yellow{color:#ffda75}.red{color:#ff9292}.unknown{color:#a8bdcc}
.version{display:inline-block;white-space:nowrap;padding:4px 8px;border-radius:999px;font-size:13px;font-weight:700;background:#123e35}.version.red{background:#4b232b}.version-unknown{color:#ffe096;background:#493b1e}
.button{padding:10px 16px;border:1px solid #517185;border-radius:8px;text-decoration:none;background:#13283a;color:#e6eff6;cursor:pointer}.web-tabs{display:flex;justify-content:flex-start;gap:8px}.web-tabs .active{background:#28556a;color:#fff}
.service-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;align-items:end;margin-top:18px}
label{display:grid;gap:6px;color:#a8bdcc;font-size:13px}input,select{min-width:0;padding:10px;border:1px solid #517185;border-radius:7px;background:#0c1925;color:#e6eff6}
.inline-form{display:inline}.danger{border-color:#a96060;color:#ffb4b4}
@media(max-width:600px){main{padding:24px 14px}section{padding:16px}.cards{grid-template-columns:1fr}}
'''
WEB_LABELS = {'pending': 'Čeká na aplikování', 'error': 'Chyba agenta', 'confirming': 'Čeká na potvrzení',
              'waiting_peers': 'Čeká na protějšky', 'active': 'Spojení ověřeno', 'rollback': 'Obnovena záloha', 'revoked': 'Členství odvoláno'}
WEB_SCRIPT = '''document.addEventListener("click",async event=>{const button=event.target.closest("[data-copy-endpoint]");if(!button)return;try{await navigator.clipboard.writeText(button.dataset.copyEndpoint);button.textContent="Zkopírováno"}catch(error){button.textContent="Kopírování selhalo"}});'''.encode()


def parse_service_filters(query, allow_editor=False):
    fields = parse_qs(query, keep_blank_values=True)
    allowed = {'service', 'protocol', 'host', 'router'} | ({'editorHost'} if allow_editor else set())
    if set(fields) - allowed or any(len(values) != 1 for values in fields.values()):
        raise ValueError('Neplatný filtr služeb.')
    result = {key: fields.get(key, [''])[0].strip() for key in allowed}
    if result['protocol'] not in SERVICE_PROTOCOLS | {''}:
        raise ValueError('Neplatný filtr protokolu.')
    result.setdefault('editorHost', '')
    if result['editorHost']:
        try:
            if ipaddress.ip_address(result['editorHost']).version != 4:
                raise ValueError
        except ValueError as exc:
            raise ValueError('Neplatný výběr hosta služeb.') from exc
    if any(len(value) > 120 or any(ord(character) < 32 for character in value)
           for value in result.values()):
        raise ValueError('Neplatný filtr služeb.')
    return result


def web_page(root, csrf_token='', service_filters=None, authenticated=True):
    """Render only selected public configuration/status fields, never raw files or keys."""
    import html
    def esc(value):
        return html.escape(str(value), quote=True)
    root = Path(root)
    report = status_report(root)
    envelope = read(root / 'accepted.json')
    doc = validate_document(verify((root / 'root.pub').read_text(), envelope)) if envelope else None
    own_id = read(root / 'node.json', {}).get('nodeId')
    own = next((node for node in doc['config']['nodes'] if node['id'] == own_id), None) if doc else None
    local_definitions = local_services(root, own) if own else []
    state = WEB_LABELS.get(report.get('state'), 'Zatím nenasazeno')
    checked = report.get('checkedAt')
    checked_text = time.strftime('%d. %m. %Y %H:%M:%S UTC', time.gmtime(checked)) if isinstance(checked, (int, float)) else 'Dosud neověřeno'
    diagnostics = read(root / 'diagnostics.json', {})
    shared_catalog = read(root / 'catalog.json', {})
    if not isinstance(shared_catalog, dict):
        shared_catalog = {}
    rows = []
    now = time.time()
    running = diagnostics.get('state') == 'running' and 0 <= now - diagnostics.get('startedAt', 0) <= 360
    if doc:
        for node in doc['config']['nodes']:
            member = node['id'] in doc['members']
            label = state if node['id'] == own_id else ('Přijatý uzel' if member else 'Draft')
            catalog_source = status_report(root) if node['id'] == own_id else shared_catalog.get(node['id'], {})
            try:
                host_catalog = validate_hosts(node, catalog_source) if member else None
            except (TypeError, ValueError):
                host_catalog = None
            hosts = ('<ul class="hosts">' + ''.join('<li><code>%s</code>%s</li>' % (
                     esc(host['address']), '<small>%s</small>' % esc(host['name']) if host['name'] else '')
                     for host in host_catalog['hosts']) + '</ul><small>Pozorováno %s UTC</small>' %
                     esc(time.strftime('%d. %m. %Y %H:%M:%S', time.gmtime(host_catalog['hostsObservedAt'])))) \
                    if host_catalog and host_catalog['hosts'] else '—'
            measurements = diagnostics.get('nodes', {}).get(node['id'], {}) if (member and own_id in doc['members'] and diagnostics.get('revision') == doc['revision'] and report.get('appliedRevision') == doc['revision']) else {}
            badges = ['—' if node['id'] == own_id else diagnostic_badge(measurements.get(transport, {}), now)
                      for transport in ['zerotier', 'wireguard']]
            version = software_badge(catalog_source.get('software'), software_info()['version'])
            rows.append('<tr><td><strong>%s</strong>%s</td><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td><td>%s</td><td><span class="badge">%s</span></td><td>%s</td><td>%s</td></tr>' % (
                esc(node['name']), '<br><small>Tento router</small>' if node['id'] == own_id else '',
                version,
                esc(node['zeroTierAddress'] or '—'), esc(node['wireguardAddress'] or '—'),
                '<br>'.join(esc(cidr) for cidr in node['lanCidrs']) or '—', hosts, esc(label), *badges))
    notices = '<p class="notice">Router ještě nepřijal konfiguraci federace. Dokončete deploy z notebooku přes LAN.</p>' if not doc else ''
    if report.get('error'):
        notices += '<p class="notice">%s</p>' % esc(report['error'])
    if report.get('pendingPeers'):
        names = {node['id']: node['name'] for node in doc['config']['nodes']} if doc else {}
        notices += '<p class="notice">Čekající protějšky: %s</p>' % esc(', '.join(names.get(peer, peer) for peer in report['pendingPeers']))
    diagnostic_form = ('<form method="post" action="%sdiagnostics"><input type="hidden" name="token" value="%s"><button class="button" %s>Spustit ping · 5 paketů</button></form>' % (WEB_OVERVIEW_PATH, esc(csrf_token), 'disabled' if running else '')) if doc and csrf_token else ''
    if running:
        diagnostic_form += '<p class="notice">Probíhá měření. Výsledky se zobrazí po dokončení.</p>'
    elif diagnostics.get('state') in ['running', 'error']:
        diagnostic_form += '<p class="notice">Měření nebylo dokončeno. Spusťte diagnostiku znovu.</p>'
    editable_hosts = editable_service_hosts(own, report, local_definitions) if own else []
    filters = {key: '' for key in ['service', 'protocol', 'host', 'router', 'editorHost']}
    filters.update(service_filters or {})
    editor_host = filters['editorHost'] if any(
        host['address'] == filters['editorHost'] for host in editable_hosts) else ''
    selected_definitions = [service for service in local_definitions if service['hostAddress'] == editor_host]
    local_service_rows = ''.join(
        '<tr><td><strong>%s</strong><br><code>%s</code></td><td><code>%s</code></td><td>%s</td><td><form class="inline-form" method="post" action="%sservices/delete"><input type="hidden" name="token" value="%s"><input type="hidden" name="id" value="%s"><button class="button danger">Odstranit</button></form></td></tr>' % (
            esc(service['name']), esc(service['id']), esc(service_endpoint(service)),
            esc('HTTP(S)' if service['protocol'] in {'http', 'https'} else 'TCP'), WEB_OVERVIEW_PATH,
            esc(csrf_token), esc(service['id'])) for service in selected_definitions)
    host_selector = '''<form class="service-form" method="get" action="''' + WEB_OVERVIEW_PATH + '''">
<label>Host (uzel v LAN)<select name="editorHost" required><option value="">Vyberte hosta</option>''' + ''.join(
        '<option value="%s"%s>%s%s</option>' % (
            esc(host['address']), ' selected' if host['address'] == editor_host else '',
            esc((host['name'] + ' · ') if host['name'] else ''), esc(host['address']) + ('' if host['observed'] else ' · nyní nepozorován'))
        for host in editable_hosts) + '''</select></label><button class="button">Vybrat hosta</button></form>''' if editable_hosts else \
        '<p class="notice">Router zatím nepropaguje žádného hosta, ke kterému lze přidat službu.</p>'
    service_editor = ''
    if own and csrf_token and editor_host:
        service_editor = '''<form class="service-form" method="post" action="''' + WEB_OVERVIEW_PATH + '''services/save">
<input type="hidden" name="token" value="''' + esc(csrf_token) + '''">
<input type="hidden" name="hostAddress" value="''' + esc(editor_host) + '''">
<label>ID služby<input name="id" required maxlength="64" pattern="[a-z0-9][a-z0-9._-]{0,63}" placeholder="ollama-main"></label>
<label>Název<input name="name" required maxlength="80" placeholder="Ollama"></label>
<label>Protokol<select name="protocol"><option value="tcp">tcp</option><option value="http">http</option><option value="https">https</option></select></label>
<label>Port<input name="port" required type="number" min="1" max="65535"></label>
<label>Cesta HTTP(S)<input name="path" placeholder="/lovelace"></label>
<label>Shodný endpoint<select name="confirmDuplicate"><option value="0">Odmítnout duplicitu</option><option value="1">Výslovně povolit</option></select></label>
<button class="button">Uložit službu</button></form>'''
    selected_host = next((host for host in editable_hosts if host['address'] == editor_host), None)
    selected_host_label = (selected_host['name'] + ' · ' if selected_host and selected_host['name'] else '') + editor_host
    selected_services = ('''<h3>Služby hosta ''' + esc(selected_host_label) + '''</h3>
<div class="table-wrap"><table><thead><tr><th>Služba</th><th>Endpoint</th><th>Typ</th><th>Akce</th></tr></thead><tbody>''' +
        (local_service_rows or '<tr><td colspan="4">Tento host zatím nemá definovanou žádnou službu.</td></tr>') +
        '''</tbody></table></div>''' + service_editor) if editor_host else '<p class="muted">Nejdřív vyberte hosta; potom se zobrazí pouze jeho služby a formulář pro přidání další.</p>'
    local_services_section = '''<section><h2>Editor služeb · tento router</h2>
<p class="muted">Služby se přiřazují ke konkrétním hostům propagovaným tímto routerem. Editor nemění firewall, DNS ani cílového hosta. Změna se místně publikuje ihned; ostatní routery ji převezmou v následujícím synchronizačním cyklu.</p>''' + host_selector + selected_services + '''</section>'''
    catalog_reports = {}
    if doc:
        for node in doc['config']['nodes']:
            source = report if node['id'] == own_id else shared_catalog.get(node['id'], {})
            if isinstance(source, dict):
                catalog_reports[node['id']] = source
    directory = aggregate_services(doc, catalog_reports, now) if doc else []
    directory = [service for service in directory
                 if filters['service'].casefold() in service['name'].casefold()
                 and (not filters['protocol'] or service['protocol'] == filters['protocol'])
                 and filters['host'].casefold() in ('%s %s' % (service['hostAddress'], service['hostName'] or '')).casefold()
                 and filters['router'].casefold() in service['routerName'].casefold()]
    directory_rows = ''.join(
        '<tr><td><strong>%s</strong><br><small>%s</small></td><td>%s<br><code>%s</code></td><td>%s<br><small>%s</small></td><td><span class="badge">%s</span></td><td><button type="button" class="button" data-copy-endpoint="%s">Kopírovat endpoint</button>%s</td></tr>' % (
            esc(service['name']), esc(service['protocol']), esc(service['hostName'] or service['hostAddress']),
            esc(service['endpoint']), esc(service['routerName']),
            esc(time.strftime('%d. %m. %Y %H:%M:%S UTC', time.gmtime(service['observedAt']))),
            'Zastaralé' if service['stale'] else 'Aktuální', esc(service['endpoint']),
            (' <a class="button" href="%s" target="_blank" rel="noopener noreferrer">Otevřít v prohlížeči</a>' % esc(service['endpoint']))
            if service['protocol'] in {'http', 'https'} else '') for service in directory)
    directory_section = '''<section><h2>Zlaté stránky služeb</h2>
<p class="muted">Ověřené definice přijatých routerů. Položka nepotvrzuje, že služba právě odpovídá.</p>
<form class="service-form" method="get" action="''' + WEB_PATH + '''">
<label>Služba<input name="service" value="''' + esc(filters['service']) + '''"></label>
<label>Protokol<select name="protocol"><option value="">všechny</option>''' + ''.join(
        '<option value="%s"%s>%s</option>' % (protocol, ' selected' if filters['protocol'] == protocol else '', protocol)
        for protocol in sorted(SERVICE_PROTOCOLS)) + '''</select></label>
<label>Host<input name="host" value="''' + esc(filters['host']) + '''"></label>
<label>Router<input name="router" value="''' + esc(filters['router']) + '''"></label>
<button class="button">Filtrovat</button></form>
<div class="table-wrap"><table><thead><tr><th>Služba</th><th>Endpoint</th><th>Router</th><th>Čerstvost</th><th>Akce</th></tr></thead><tbody>''' + (directory_rows or '<tr><td colspan="5">Filtru neodpovídá žádná ověřená služba.</td></tr>') + '''</tbody></table></div></section>'''
    refresh = '<meta http-equiv="refresh" content="2">' if running else ''
    head = '''<!doctype html><html lang="cs"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">''' + refresh + '''
<title>Turris Federation</title><style>''' + WEB_STYLE + '''</style><script src="/turris-federation/app.js" defer></script></head><body><main>'''
    tabs = '''<nav class="web-tabs" aria-label="Turris Federation"><a class="button%s" href="%s">Zlaté stránky</a><a class="button%s" href="%s">Přehled</a></nav>''' % (
        '' if authenticated else ' active', WEB_PATH, ' active' if authenticated else '', WEB_OVERVIEW_PATH)
    if not authenticated:
        return (head + tabs + '''
<div class="kicker">Turris Federation · veřejný katalog</div><h1>Zlaté stránky služeb</h1>
<p class="muted">Veřejný read-only seznam služeb oznámených přijatými routery. Přehled sítě a editor vyžadují přihlášení.</p>''' + directory_section + '''
</main></body></html>''').encode()
    return (head + tabs + '''
<div class="kicker">Turris Federation · přehled sítě</div><h1>''' + esc(own['name'] if own else 'Federace routerů') + '''</h1>
<p class="muted">Poslední zaznamenaný stav místního agenta. Načtení stránky neprovádí nový audit sítě.</p>''' + notices + '''
<div class="cards"><article class="card"><span>Stav tohoto routeru</span><strong>''' + esc(state) + '''</strong></article>
<article class="card"><span>Přijatá revize</span><strong>''' + esc(doc['revision'] if doc else '—') + '''</strong></article>
<article class="card"><span>Aplikovaná revize</span><strong>''' + esc(report.get('appliedRevision') or '—') + '''</strong></article></div>
<p class="muted">Poslední kontrola agenta: ''' + esc(checked_text) + '''</p>
<section><h2>Uzly federace</h2>''' + diagnostic_form + '''<div class="table-wrap"><table><thead><tr><th>Uzel</th><th>Verze agenta</th><th>ZeroTier</th><th>WireGuard</th><th>LAN sítě</th><th>Dostupní hosté</th><th>Stav / členství</th><th>Ping ZeroTier</th><th>Ping WireGuard</th></tr></thead><tbody>''' + ''.join(rows) + '''</tbody></table></div>
<p class="muted">Katalog obsahuje pasivně známé sousedy v LAN prefixech oznamujícího uzlu; neprovádí aktivní skenování a nesdílí MAC adresy. Členství vychází z konfigurace, nikoli aktuální dostupnosti. Ping se spouští pouze tlačítkem: 5 paketů z tohoto routeru ke každému přijatému protějšku přes ZeroTier i WireGuard. Zobrazen je výsledek posledního měření. Zelená ≥ 95 %, žlutá ≥ 80 %, červená &lt; 80 %. Výsledek starší než 120 s je šedý. Obnovit stav načte nové výsledky.</p></section>''' + local_services_section + '''
<section><h2>Síť a správa</h2><p>ZeroTier Network ID: <code>''' + esc(doc['config']['networkId'] if doc else '—') + '''</code></p>
<p>Notebook je řídicí uzel pouze v ZeroTier, bez WireGuard spojů. Jeho dostupnost tento router nekontroluje.</p>
<p>Nastavení sítě spravujte v desktopové aplikaci. Instalace a aktualizace softwaru vyžadují přímé LAN spojení z notebooku.</p></section>
</main></body></html>''').encode()


def web_handler(root):
    csrf_token = secrets.token_hex(32)
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            target = urlsplit(self.path)
            if target.path == WEB_PATH + 'app.js' and not target.query:
                body, status, content_type = WEB_SCRIPT, 200, 'application/javascript; charset=utf-8'
            elif target.path in [WEB_PATH, WEB_PATH.rstrip('/')]:
                try:
                    filters = parse_service_filters(target.query, allow_editor=False)
                except ValueError:
                    self.send_error(400)
                    return
                try:
                    body = web_page(root, service_filters=filters, authenticated=False)
                    status, content_type = 200, 'text/html; charset=utf-8'
                except Exception:
                    body = '<!doctype html><html lang="cs"><meta charset="utf-8"><title>Turris Federation</title><h1>Stav nelze načíst</h1><p>Zkontrolujte agenta z desktopové aplikace.</p></html>'.encode()
                    status, content_type = 503, 'text/html; charset=utf-8'
            elif target.path not in [WEB_OVERVIEW_PATH, WEB_OVERVIEW_PATH.rstrip('/')]:
                self.send_error(404)
                return
            else:
                try:
                    filters = parse_service_filters(target.query, allow_editor=True)
                except ValueError:
                    self.send_error(400)
                    return
                try:
                    body = web_page(root, csrf_token, filters, authenticated=True)
                    status, content_type = 200, 'text/html; charset=utf-8'
                except Exception:
                    body = '<!doctype html><html lang="cs"><meta charset="utf-8"><title>Turris Federation</title><h1>Stav nelze načíst</h1><p>Zkontrolujte agenta z desktopové aplikace.</p></html>'.encode()
                    status, content_type = 503, 'text/html; charset=utf-8'
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path not in [WEB_OVERVIEW_PATH + 'diagnostics', WEB_OVERVIEW_PATH + 'services/save', WEB_OVERVIEW_PATH + 'services/delete']:
                self.send_error(405)
                return
            try:
                size = int(self.headers.get('Content-Length', '0'))
            except ValueError:
                size = 0
            if not 0 < size <= 4096 or self.headers.get('Content-Type') != 'application/x-www-form-urlencoded':
                self.send_error(400)
                return
            fields = parse_qs(self.rfile.read(size).decode('utf-8', errors='replace'), keep_blank_values=True)
            token = fields.get('token', [''])[0]
            if not re.fullmatch('[0-9a-f]{64}', token) or not secrets.compare_digest(token, csrf_token):
                self.send_error(403)
                return
            redirect_location = WEB_OVERVIEW_PATH
            try:
                if self.path == WEB_OVERVIEW_PATH + 'diagnostics':
                    if set(fields) != {'token'} or fields['token'] != [token]:
                        self.send_error(403)
                        return
                    start_diagnostics(root)
                else:
                    envelope = read(Path(root) / 'accepted.json')
                    doc = validate_document(verify((Path(root) / 'root.pub').read_text(), envelope)) if envelope else None
                    own_id = read(Path(root) / 'node.json', {}).get('nodeId')
                    node = next((item for item in doc['config']['nodes'] if item['id'] == own_id), None) if doc else None
                    if not node or own_id not in doc['members']:
                        raise ValueError('Router nemá platné členství federace.')
                    if self.path == WEB_OVERVIEW_PATH + 'services/delete':
                        if set(fields) != {'token', 'id'} or any(len(value) != 1 for value in fields.values()):
                            self.send_error(400)
                            return
                        existing = next((service for service in local_services(root, node)
                                         if service['id'] == fields['id'][0]), None)
                        delete_local_service(root, node, fields['id'][0])
                        if existing:
                            redirect_location += '?editorHost=' + existing['hostAddress']
                    else:
                        expected = {'token', 'id', 'name', 'hostAddress', 'protocol', 'port', 'path', 'confirmDuplicate'}
                        if set(fields) != expected or any(len(value) != 1 for value in fields.values()):
                            self.send_error(400)
                            return
                        if fields['confirmDuplicate'][0] not in {'0', '1'}:
                            self.send_error(400)
                            return
                        try:
                            port = int(fields['port'][0])
                        except ValueError as exc:
                            raise ValueError('Neplatný port služby.') from exc
                        service = {'id': fields['id'][0], 'name': fields['name'][0],
                                   'hostAddress': fields['hostAddress'][0], 'protocol': fields['protocol'][0],
                                   'port': port, 'path': fields['path'][0] or None}
                        definitions = local_services(root, node)
                        allowed_hosts = {host['address'] for host in editable_service_hosts(
                            node, read(Path(root) / 'report.json', {}), definitions)}
                        if service['hostAddress'] not in allowed_hosts:
                            raise ValueError('Vyberte hosta propagovaného tímto routerem.')
                        save_local_service(root, node, service, fields['confirmDuplicate'][0] == '1')
                        redirect_location += '?editorHost=' + service['hostAddress']
            except ValueError as error:
                self.send_error(409, 'Operation unavailable', explain=str(error))
                return
            except Exception:
                self.send_error(503)
                return
            self.send_response(303)
            self.send_header('Location', redirect_location)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', '0')
            self.end_headers()

        def do_PUT(self):
            self.send_error(405)

        do_DELETE = do_PATCH = do_PUT
    return Handler


def serve_web(root):
    # Separate listener: the authenticated lighttpd proxy never exposes the sync API.
    class Server(http.server.ThreadingHTTPServer):
        def get_request(self):
            connection, client = super().get_request()
            connection.settimeout(5)
            return connection, client
    Server(('127.0.0.1', WEB_PORT), web_handler(root)).serve_forever()


def install_web():
    """Install changed web files only; reload lighttpd only when its config changed."""
    previous = {}
    proxy_path = WEB_PROXY_PATH
    proxy_changed = False
    try:
        for name, content in WEB_FILES.items():
            path = Path(name)
            old_content = path.read_bytes() if path.exists() else None
            if old_content == content:
                continue
            previous[path] = (old_content, path.stat().st_mode & 0o777) if old_content is not None else None
            # These shared directories must be traversable by lighttpd/WebApps.
            if not path.parent.exists():
                path.parent.mkdir(parents=True, mode=0o755)
                path.parent.chmod(0o755)
            atomic(path, content)
            path.chmod(0o644)
            proxy_changed = proxy_changed or path == proxy_path
        if proxy_changed:
            run(['lighttpd', '-tt', '-f', '/etc/lighttpd/lighttpd.conf'])
            run(['/etc/init.d/lighttpd', 'reload'])
    except Exception:
        for path, old in previous.items():
            if old is None:
                path.unlink(missing_ok=True)
            else:
                atomic(path, old[0])
                path.chmod(old[1])
        # Restore the old lighttpd configuration only when we touched it.
        if proxy_changed:
            try:
                run(['/etc/init.d/lighttpd', 'reload'])
            except Exception:
                pass
        raise


def check_web():
    tile_path = Path('/etc/turris-webapps/80-turris-federation.json')
    icon_path = Path('/www/webapps-icons/turris-federation.svg')
    proxy_path = WEB_PROXY_PATH

    try:
        tile = json.loads(tile_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError('Dlaždice Turris Federation chybí nebo není platný JSON.') from error
    expected_tile = {
        'id': 'turris-federation',
        'title': 'Turris Federation',
        'url': WEB_PATH,
        'icon': '/icons/turris-federation.svg',
    }
    if any(tile.get(key) != value for key, value in expected_tile.items()):
        raise ValueError('Registrace dlaždice Turris Federation neodpovídá instalované aplikaci.')

    try:
        icon = icon_path.read_bytes()
        proxy = proxy_path.read_bytes()
    except OSError as error:
        raise ValueError('Chybí ikona nebo konfigurace lighttpd pro Turris Federation.') from error
    if not icon.lstrip().startswith(b'<svg') or b'turris-federation' not in proxy or b'8845' not in proxy:
        raise ValueError('Ikona nebo konfigurace lighttpd pro Turris Federation je poškozená.')

    # First verify both backend pages independently of lighttpd/auth.
    connection = http.client.HTTPConnection('127.0.0.1', WEB_PORT, timeout=5)
    try:
        connection.request('GET', WEB_PATH)
        response = connection.getresponse()
        body = response.read(LIMIT)
        if response.status != 200 or 'Zlaté stránky služeb'.encode() not in body or 'Editor služeb'.encode() in body:
            raise ValueError('Interní veřejný katalog nepotvrdil funkční spuštění.')
    finally:
        connection.close()

    connection = http.client.HTTPConnection('127.0.0.1', WEB_PORT, timeout=5)
    try:
        connection.request('GET', WEB_OVERVIEW_PATH)
        response = connection.getresponse()
        body = response.read(LIMIT)
        if response.status != 200 or 'Přehled'.encode() not in body or 'Editor služeb'.encode() not in body:
            raise ValueError('Interní chráněný přehled nepotvrdil funkční spuštění.')
    finally:
        connection.close()

    # Then verify that lighttpd exposes the catalog without login.
    connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=5)
    try:
        connection.request('GET', WEB_PATH, headers={'Host': 'localhost'})
        response = connection.getresponse()
        body = response.read(LIMIT)
        if response.status != 200 or 'Zlaté stránky služeb'.encode() not in body:
            raise ValueError('Veřejné Zlaté stránky Turris Federation nejsou aktivní přes lighttpd.')
    finally:
        connection.close()

    # The network overview and editor must remain behind PAM authentication.
    connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=5)
    try:
        connection.request('GET', WEB_OVERVIEW_PATH, headers={'Host': 'localhost'})
        response = connection.getresponse()
        response.read(LIMIT)
        challenge = response.getheader('WWW-Authenticate', '')
        if response.status != 401 or 'Basic' not in challenge:
            raise ValueError('Přehled Turris Federation není chráněný PAM přihlášením.')
    finally:
        connection.close()


INIT = '''#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1
start_service() {
    procd_open_instance sync
    procd_set_param command /usr/bin/python3 /usr/lib/turris-federation/federation.py serve /etc/turris-federation
    procd_set_param respawn 3600 5 5
    procd_close_instance
    procd_open_instance web
    procd_set_param command /usr/bin/python3 /usr/lib/turris-federation/federation.py web /etc/turris-federation
    procd_set_param respawn 3600 5 5
    procd_close_instance
}
'''


def shell_quote(text):
    return "'" + text.replace("'", "'\"'\"'") + "'"


def direct_lan(node):
    """Fail closed: deploy/update uses a literal IPv4 on a physical local LAN."""
    error = 'Instalace i aktualizace vyžaduje přímé LAN spojení přes Ethernet/Wi-Fi a číselnou LAN IPv4 routeru.'
    try:
        host = address(node['sshHost'])
        ip = ipaddress.ip_address(host)
        if not any(ip in ipaddress.ip_network(cidr) for cidr in node['lanCidrs']
                   if ipaddress.ip_network(cidr).version == ip.version):
            raise ValueError(error)
        routes = json.loads(run(['ip', '-j', '-4', 'route', 'get', host]))
        if len(routes) != 1:
            raise ValueError(error)
        route = routes[0]
        dev, source = route.get('dev', ''), route.get('prefsrc', '')
        if (route.get('gateway') or route.get('via') or route.get('nexthops')
                or route.get('type', 'unicast') != 'unicast'
                or not re.fullmatch(r'[a-zA-Z0-9_.-]+', dev)):
            raise ValueError(error)
        # Do not trust interface names: a renamed VPN/TUN is still virtual.
        device = SYS_NET / dev
        if not (device / 'device').exists() or (device / 'type').read_text().strip() != '1':
            raise ValueError(error)
        links = json.loads(run(['ip', '-j', '-4', 'address', 'show', 'dev', dev]))
        addresses = [entry for link in links for entry in link.get('addr_info', [])
                     if entry.get('family') == 'inet' and entry.get('local') == source]
        if not any(ip in ipaddress.ip_interface('%s/%s' % (source, entry['prefixlen'])).network
                   and ip != ipaddress.ip_address(source) for entry in addresses):
            raise ValueError(error)
        return {'host': host, 'device': dev, 'source': source}
    except (ValueError, KeyError, TypeError, OSError) as exc:
        raise ValueError(error) from exc


def artifact_hash():
    return hashlib.sha256(Path(__file__).read_bytes() + INIT.encode()).hexdigest()


def artifact_components():
    return {'agent': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'init': hashlib.sha256(INIT.encode()).hexdigest(),
            'webTile': hashlib.sha256(WEB_FILES['/etc/turris-webapps/80-turris-federation.json']).hexdigest(),
            'webIcon': hashlib.sha256(WEB_FILES['/www/webapps-icons/turris-federation.svg']).hexdigest(),
            'webProxy': hashlib.sha256(WEB_FILES[str(WEB_PROXY_PATH)]).hexdigest()}


def installed_components():
    paths = {'agent': Path(__file__), 'init': Path('/etc/init.d/turris-federation'),
             'webTile': Path('/etc/turris-webapps/80-turris-federation.json'),
             'webIcon': Path('/www/webapps-icons/turris-federation.svg'),
             'webProxy': WEB_PROXY_PATH}
    return {name: hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
            for name, path in paths.items()}


def validate_components(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != set(artifact_components()):
        raise ValueError('Uzel vrátil neplatný manifest komponent.')
    for version in value.values():
        if version is not None and (not isinstance(version, str)
                                    or not re.fullmatch(r'[0-9a-f]{64}', version)):
            raise ValueError('Uzel vrátil neplatnou verzi komponenty.')
    return dict(value)


def software_info():
    try:
        built_at = Path(__file__).stat().st_mtime
    except OSError:
        built_at = None
    return {'version': artifact_hash(), 'builtAt': built_at}


def validate_software_info(value):
    if value is None:
        return None
    if (not isinstance(value, dict) or set(value) != {'version', 'builtAt'}
            or not isinstance(value.get('version'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', value['version'])):
        raise ValueError('Uzel vrátil neplatnou verzi softwaru.')
    built_at = value.get('builtAt')
    if (built_at is not None and (not isinstance(built_at, (int, float))
                                  or isinstance(built_at, bool) or not math.isfinite(built_at)
                                  or built_at < 0)):
        raise ValueError('Uzel vrátil neplatný čas sestavení softwaru.')
    return {'version': value['version'], 'builtAt': built_at}


def status_report(root):
    root = Path(root)
    report = read(root / 'report.json', {})
    # Service definitions are authoritative and survive a network rollback.
    # Reconstruct their published projection when rollback replaced report.json
    # without the catalog fields.
    if (root / 'services.json').exists():
        try:
            envelope = read(root / 'accepted.json')
            doc = validate_document(verify((root / 'root.pub').read_text(), envelope))
            node = self_node(root, doc)
            if node and node['id'] in doc['members']:
                report = {**report, 'services': local_services(root, node),
                          'servicesObservedAt': time.time()}
        except (OSError, TypeError, ValueError, KeyError):
            pass
    return {**report, 'software': software_info(), 'components': installed_components()}


def installed_artifact_hash(node, credentials):
    # Old agents need no version RPC: read the same bytes included in artifact_hash().
    command = ('set -eu; if test -f ' + PROGRAM + ' && test -f /etc/init.d/turris-federation; then '
               'cat ' + PROGRAM + ' /etc/init.d/turris-federation | sha256sum; else echo missing; fi')
    output = ssh(node, credentials, command).decode().strip()
    if output == 'missing':
        return None
    value = output.split()[0] if output else ''
    if not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('Nelze zjistit verzi nainstalovaného agenta. Opakujte validaci.')
    return value


def installed_artifact_components(node, credentials):
    paths = {'agent': PROGRAM, 'init': '/etc/init.d/turris-federation',
             'webTile': '/etc/turris-webapps/80-turris-federation.json',
             'webIcon': '/www/webapps-icons/turris-federation.svg',
             'webProxy': str(WEB_PROXY_PATH)}
    command = ('set -eu; for path in %s; do if test -f "$path"; then '
               'sha256sum "$path"; else echo missing "$path"; fi; done' %
               ' '.join(shell_quote(path) for path in paths.values()))
    lines = ssh(node, credentials, command).decode().splitlines()
    if len(lines) != len(paths):
        raise ValueError('Nelze zjistit verze komponent agenta.')
    result = {}
    for (name, path), line in zip(paths.items(), lines):
        fields = line.split()
        if fields == ['missing', path]:
            result[name] = None
        elif len(fields) >= 2 and fields[1] == path and re.fullmatch(r'[0-9a-f]{64}', fields[0]):
            result[name] = fields[0]
        else:
            raise ValueError('Nelze zjistit verzi komponenty %s.' % name)
    return result


def ssh(node, credentials, command, input_data=None):
    # Credentials are passed through stdin to this controller and an inherited pipe to sshpass.
    host, user, port = node['sshHost'], node['sshUser'], node['sshPort']
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.:%_-]*', host) or not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_.-]*', user) or not 0 < port < 65536:
        raise ValueError('Neplatná SSH adresa.')
    lan = direct_lan(node)  # Recheck before EVERY SSH session, including update and confirmation.
    if node.get('_deployLan') is not None and node['_deployLan'] != lan:
        raise ValueError('LAN připojení se od validace změnilo. Validujte znovu.')
    password = credentials['password']
    if not password or len(password.encode()) > 4096 or any(c in password for c in '\n\r\0'):
        raise ValueError('Neplatné SSH heslo.')
    with tempfile.TemporaryDirectory() as directory:
        key = Path(directory) / 'known_hosts'
        key.write_text(credentials['hostKey'])
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, (password + '\n').encode())
            os.close(write_fd)
            write_fd = None
            args = ['sshpass', '-d', str(read_fd), 'ssh', '-F', '/dev/null', '-T']
            if input_data is None:
                args.append('-n')
            args += [
                    '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                    '-o', 'UserKnownHostsFile=' + str(key), '-o', 'ConnectTimeout=10',
                    '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
                    '-o', 'PubkeyAuthentication=no', '-o', 'NumberOfPasswordPrompts=1',
                    '-B', lan['device'], '-b', lan['source'],
                    '-p', str(port), '-l', user, '--', lan['host'], command]
            result = subprocess.run(args, pass_fds=(read_fd,), input=input_data,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
            if result.returncode:
                # Remote errors only contain our sanitised exception, never shell command or input.
                detail = result.stderr.decode(errors='replace')[-1500:]
                raise ValueError('SSH/deploy selhal (kód %s). %s' % (result.returncode, detail))
            return result.stdout
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)


def remote(node, credentials, action, **kwargs):
    request = base64.b64encode(encode(dict(action=action, **kwargs))).decode()
    cmd = 'python3 %s rpc %s %s' % (PROGRAM, REMOTE, shell_quote(request))
    return json.loads(ssh(node, credentials, cmd))


def snapshot(root, config, members):
    root = Path(root)
    public = identity(root / 'root.pem')
    old_envelope = read(root / 'published.json')
    old = verify(public, old_envelope) if old_envelope else None
    if old and old['members']:
        if config['networkId'] != old['config']['networkId']:
            raise ValueError('Změna ZeroTier sítě přijaté federace vyžaduje samostatnou migraci; běžný sync ji nepovoluje.')
        old_nodes = {n['id']: n for n in old['config']['nodes']}
        for n in config['nodes']:
            if n['id'] in old['members'] and n['id'] in members and n['zeroTierAddress'] != old_nodes[n['id']]['zeroTierAddress']:
                raise ValueError('Změna správcovské adresy přijatého uzlu vyžaduje samostatnou migraci.')
    floor = read(root / 'revision-floor.json', 0)
    if old and old['revision'] >= floor and old['config'] == config and old['members'] == members:
        return old_envelope
    if 'notebooks' not in config:
        schema = VERSION
    elif any('wireguardKey' in notebook for notebook in config['notebooks']):
        schema = NOTEBOOK_WG_VERSION
    else:
        schema = NOTEBOOK_VERSION
    doc = {'schema': schema, 'federationId': old['federationId'] if old else str(uuid.uuid4()),
           'revision': max(old['revision'] + 1 if old else 1, floor), 'previous': digest(old) if old else None,
           'config': config, 'members': members}
    validate_document(doc)
    envelope = sign(root / 'root.pem', doc)
    atomic(root / 'published.json', envelope)
    return envelope


def overview(root, config):
    root = Path(root)
    published = read(root / 'published.json')
    doc = verify(public_key(root / 'root.pem'), published) if published else None
    reports = read(root / 'reports.json', {})
    members = read(root / 'members.json', {})
    return {'revision': doc['revision'] if doc else 0, 'unpublishedChanges': not doc or doc['config'] != config or doc['members'] != members or doc['revision'] < read(root / 'revision-floor.json', 0),
            'fingerprint': hashlib.sha256(public_key(root / 'root.pem').encode()).hexdigest() if (root / 'root.pem').exists() else None,
            'nodes': {n['id']: {'enrolled': n['id'] in members, **reports.get(n['id'], {})} for n in config['nodes']}}


def refresh_reports(root, doc):
    root = Path(root)
    peers = [node for node in doc['config']['nodes'] if node['id'] in doc['members']]
    previous = read(root / 'reports.json', {})
    reports = {node['id']: previous[node['id']] for node in peers
               if isinstance(previous, dict) and node['id'] in previous}
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(peers)))) as pool:
        jobs = {pool.submit(peer_status, peer, doc['members'][peer['id']], root / 'root.pem'): peer for peer in peers}
        for future, peer in jobs.items():
            try:
                fresh = dict(future.result(), reachable=True)
                previous_report = reports.get(peer['id'], {})
                previous_report = previous_report if isinstance(previous_report, dict) else {}
                # Missing means "not reported". An explicit empty list is the
                # authoritative way for a router to remove all catalog entries.
                for keys in [('hosts', 'hostsObservedAt'),
                             ('services', 'servicesObservedAt')]:
                    if not any(key in fresh for key in keys):
                        for key in keys:
                            if key in previous_report:
                                fresh[key] = previous_report[key]
                for key in ['software', 'components']:
                    if key not in fresh and key in previous_report:
                        fresh[key] = previous_report[key]
                reports[peer['id']] = fresh
            except Exception as error:
                reports[peer['id']] = dict(reports.get(peer['id'], {}), error=str(error), reachable=False)
    atomic(root / 'reports.json', reports)
    return reports


def distribute_bundle(root, envelope, exclude=None):
    root = Path(root)
    doc = verify(public_key(root / 'root.pem'), envelope)
    previous = read(root / 'reports.json', {})
    results = {node['id']: previous[node['id']] for node in doc['config']['nodes']
               if node['id'] in doc['members'] and isinstance(previous, dict) and node['id'] in previous}
    for peer in doc['config']['nodes']:
        if peer['id'] not in doc['members'] or peer['id'] == exclude:
            continue
        try:
            request_http(peer['zeroTierAddress'], 'POST', '/bundle', envelope)
            results[peer['id']] = dict(peer_status(peer, doc['members'][peer['id']], root / 'root.pem'), reachable=True)
        except Exception as error:
            results[peer['id']] = dict(results.get(peer['id'], {}), error=str(error), reachable=False)
    atomic(root / 'reports.json', results)


def preserve_notebooks(root, config):
    root = Path(root)
    published = read(root / 'published.json')
    if not published:
        return config
    document = validate_document(verify(public_key(root / 'root.pem'), published))
    notebooks = document['config'].get('notebooks')
    if notebooks is None:
        return config
    if document['schema'] == NOTEBOOK_WG_VERSION:
        return normalize_with_notebook_endpoints(config['nodes'], config['networkId'], notebooks)
    return normalize_with_notebooks(config['nodes'], config['networkId'], notebooks)


def controller(root, req):
    root = Path(root)
    if (root / 'notebook-sync-journal.json').exists():
        raise ValueError('Nejdřív dokončete obnovu synchronizace v záložce Notebooky.')
    action = req['action']
    if action == 'read_only_overview':
        return read_only_notebook_overview(root)
    if action == 'diagnostics_overview':
        return notebook_diagnostics_overview(root)
    if action == 'diagnostics':
        return notebook_diagnostics(root)
    nodes = req['nodes']
    config = preserve_notebooks(root, normalize(nodes, req['networkId']))
    if action == 'overview':
        return overview(root, config)
    if action == 'refresh':
        published = read(root / 'published.json')
        if published:
            refresh_reports(root, verify(public_key(root / 'root.pem'), published))
        return overview(root, config)
    if action == 'publish':
        envelope = snapshot(root, config, read(root / 'members.json', {}))
        distribute_bundle(root, envelope)
        return overview(root, config)
    node = next(n for n in nodes if n['id'] == req['nodeId'])
    target = next(n for n in config['nodes'] if n['id'] == node['id'])
    if not target['zeroTierAddress'] or not target['wireguardAddress'] or not target['lanCidrs']:
        raise ValueError('Pro deploy doplňte LAN, IPv4 adresu ZeroTier a unikátní IPv4 adresu WireGuard.')
    credentials = req['credentials']
    if action == 'validate':
        lan = direct_lan(node)
        node = dict(node, _deployLan=lan)
        probe = ssh(node, credentials, "set -eu; test \"$(id -u)\" = 0; test -f /etc/config/network; test -d /www; test -d /etc/lighttpd/conf.d; command -v lighttpd >/dev/null; command -v uci >/dev/null; command -v opkg >/dev/null; echo __BOARD__; ubus call system board; echo __ZT__; zerotier-cli -j listnetworks; echo __ADDR__; ip -o addr show; echo __END__")
        text = probe.decode()
        zt = json.loads(text.split('__ZT__\n', 1)[1].split('__ADDR__\n', 1)[0])
        net = next((n for n in zt if n.get('nwid', n.get('id')) == config['networkId']), None)
        if not net or net.get('status') != 'OK' or target['zeroTierAddress'] not in [str(ipaddress.ip_interface(v).ip) for v in net.get('assignedAddresses', [])]:
            raise ValueError('Nejdřív zprovozněte ZeroTier a opravte jeho adresu v draftu.')
        actual = {str(ipaddress.ip_interface(v).network) for v in re.findall(r'inet6?\s+(\S+/\d+)', text.split('__ADDR__\n')[1])}
        if not set(target['lanCidrs']).issubset(actual):
            raise ValueError('LAN sítě draftu neodpovídají routeru. Opravte draft a validujte znovu.')
        updating = node['id'] in read(root / 'members.json', {})
        installed = installed_artifact_hash(node, credentials)
        available = artifact_hash()
        installed_parts = installed_artifact_components(node, credentials)
        available_parts = artifact_components()
        component_mismatches = [name for name, version in available_parts.items()
                                if installed_parts.get(name) != version]
        requires_endpoint_agent = any(notebook.get('wireguardKey')
                                      for notebook in config.get('notebooks', []))
        versions_match = installed == available and not component_mismatches
        settings_supported = updating and installed and (versions_match or not requires_endpoint_agent)
        plan = {'operation': 'update' if updating else 'install', 'lan': lan, 'artifactHash': available,
                'installedArtifactHash': installed, 'artifactComponents': available_parts,
                'installedArtifactComponents': installed_parts,
                'componentMismatches': component_mismatches, 'versionMismatch': not versions_match,
                'availableModes': ['full', 'settings'] if settings_supported else ['full'],
                'recommendedMode': 'settings' if updating and versions_match else 'full',
                'id': secrets.token_hex(24), 'nodeId': node['id'], 'configHash': digest(config),
                'sshHash': digest({k: node[k] for k in ['sshHost', 'sshPort', 'sshUser']}),
                'hostKeyHash': digest(credentials['hostKey']), 'membersHash': digest(read(root / 'members.json', {})), 'routerHash': ssh(node, credentials, 'sha256sum /etc/config/network /etc/config/firewall').decode(), 'expiresAt': time.time() + 600,
                'steps': ['Doinstalovat pouze chybějící závislosti z repozitáře routeru.',
                          ('Aktualizovat agenta přes přímou LAN; zachovat identitu a předchozí soubor agenta.' if updating else 'Nainstalovat agenta přes přímou LAN a přijmout stanoviště pod kotvu důvěry notebooku.'),
                          'Nainstalovat webový přehled s přihlášením routeru a dlaždici na úvodní stránce Turrisu.',
                          'Podepsat a přenést konfiguraci včetně všech draftů.',
                          'Zálohovat UCI, zapnout 120s rollback a nastavit WireGuard, routy a firewall.',
                          'Ověřit další SSH spojení, potvrdit deploy a spustit synchronizaci.',
                          'Předat nové síťové nastavení ostatním přijatým routerům přes ZeroTier; nedostupné uzly je převezmou po obnovení spojení.'],
                'config': config, 'validatedAt': time.time()}
        plan['stepsByMode'] = {'full': plan['steps'], 'settings': [
            'Zachovat nainstalovaného agenta, web a závislosti.',
            'Podepsat a přenést konfiguraci včetně všech draftů.',
            'Zálohovat UCI, zapnout 120s rollback a nastavit WireGuard, routy a firewall.',
            'Ověřit další SSH spojení a potvrdit aplikování nastavení.',
            'Předat síťové nastavení ostatním přijatým routerům přes ZeroTier.']}
        atomic(root / ('plan-' + node['id'] + '.json'), plan)
        return plan
    if action != 'deploy':
        raise ValueError('Neznámá akce.')
    plan = read(root / ('plan-' + node['id'] + '.json'))
    if not plan or plan['id'] != req.get('planId') or plan['expiresAt'] < time.time() or plan['configHash'] != digest(config) or plan['hostKeyHash'] != digest(credentials['hostKey']) or plan.get('membersHash') != digest(read(root / 'members.json', {})) or plan['sshHash'] != digest({k: node[k] for k in ['sshHost', 'sshPort', 'sshUser']}):
        raise ValueError('Plán chybí, vypršel nebo se návrh změnil. Spusťte znovu validaci.')
    if (plan.get('artifactHash') != artifact_hash()
            or plan.get('artifactComponents') != artifact_components() or not plan.get('lan')):
        raise ValueError('Plán neodpovídá verzi agenta nebo chybí LAN kontrola. Validujte znovu.')
    mode = req.get('mode') or 'full'
    if mode not in plan.get('availableModes', []):
        raise ValueError('Tento režim aktualizace není ve validovaném plánu. Validujte znovu.')
    lan = direct_lan(node)
    if plan['lan'] != lan:
        raise ValueError('LAN připojení se od validace změnilo. Validujte znovu.')
    node = dict(node, _deployLan=lan)
    if ssh(node, credentials, 'sha256sum /etc/config/network /etc/config/firewall').decode() != plan['routerHash']:
        raise ValueError('Konfigurace routeru se od validace změnila. Validujte znovu.')
    if installed_artifact_hash(node, credentials) != plan.get('installedArtifactHash'):
        raise ValueError('Verze agenta na routeru se od validace změnila. Validujte znovu.')
    if installed_artifact_components(node, credentials) != plan.get('installedArtifactComponents'):
        raise ValueError('Verze komponent routeru se od validace změnily. Validujte znovu.')
    root_public = identity(root / 'root.pem')
    # Refuse to replace executable code on a router belonging to another notebook.
    check = "test ! -f %s/root.pub || test \"$(cat %s/root.pub)\" = %s" % (REMOTE, REMOTE, shell_quote(root_public.strip()))
    check_node = 'import json; assert json.load(open("/etc/turris-federation/node.json"))["nodeId"] == ' + repr(node['id'])
    members = read(root / 'members.json', {})
    if mode == 'settings':
        if node['id'] not in members:
            raise ValueError('Nejdřív proveďte kompletní instalaci a přijetí uzlu.')
        check_member = 'import json; assert json.load(open("/etc/turris-federation/node.json")) == ' + repr(members[node['id']])
        ssh(node, credentials, 'set -eu; test -f ' + REMOTE + '/root.pub; ' + check +
            '; test ! -f ' + REMOTE + '/pending.json; python3 -c ' + shell_quote(check_member))
    else:
        source = Path(__file__).read_bytes()
        payload = source + INIT.encode()
        unpack = ('import pathlib,sys;d=sys.stdin.buffer.read();n=%d;assert len(d)==%d;'
                  'pathlib.Path(%r).write_bytes(d[:n]);pathlib.Path(%r).write_bytes(d[n:])'
                  % (len(source), len(payload), PROGRAM + '.new', '/etc/init.d/turris-federation.new'))
        installer = 'set -eu; umask 077; ' + check + '; test ! -f /etc/turris-federation/pending.json; '
        check_node = 'import json; assert json.load(open(\"/etc/turris-federation/node.json\"))[\"nodeId\"] == ' + repr(node['id'])
        installer += 'if test -f /etc/turris-federation/node.json; then python3 -c ' + shell_quote(check_node) + '; fi; '
        packages = 'python3 openssl-util wireguard-tools kmod-wireguard lighttpd-mod-proxy lighttpd-mod-auth lighttpd-mod-authn_pam lighttpd-mod-authn_file'
        installer += "missing=''; for pkg in " + packages + "; do if ! opkg status \"$pkg\" 2>/dev/null | grep -q '^Status: .* installed'; then missing=\"$missing $pkg\"; fi; done; "
        installer += 'if test -n "$missing"; then opkg update >&2; opkg install $missing >&2; fi; '
        installer += 'mkdir -p /usr/lib/turris-federation /etc/turris-federation; '
        installer += 'trap ' + shell_quote('rm -f ' + PROGRAM + '.new /etc/init.d/turris-federation.new') + ' EXIT; '
        installer += 'python3 -c ' + shell_quote(unpack) + '; '
        installer += 'python3 -m py_compile ' + PROGRAM + '.new; if test -f ' + PROGRAM + '; then cp ' + PROGRAM + ' ' + PROGRAM + '.previous; fi; mv ' + PROGRAM + '.new ' + PROGRAM + '; '
        installer += 'chmod 755 /etc/init.d/turris-federation.new; mv /etc/init.d/turris-federation.new /etc/init.d/turris-federation'
        installer += '; python3 ' + PROGRAM + ' install-web ' + REMOTE
        ssh(node, credentials, installer, input_data=payload)
        if (installed_artifact_hash(node, credentials) != plan['artifactHash']
                or installed_artifact_components(node, credentials) != plan['artifactComponents']):
            raise ValueError('Po instalaci se neshodují všechny komponenty routerového agenta.')
        member = remote(node, credentials, 'bootstrap', nodeId=node['id'], rootPublic=root_public)
        members = read(root / 'members.json', {})
        if node['id'] in members and members[node['id']] != member:
            raise ValueError('Identita přijatého routeru se změnila. Automatické nahrazení je zakázáno.')
        members[node['id']] = member
        atomic(root / 'members.json', members)
    envelope = snapshot(root, config, members)
    pending = remote(node, credentials, 'apply', envelope=envelope, expectedRouterHash=plan['routerHash'])
    # Separate SSH session proves that management survived network changes.
    result = remote(node, credentials, 'confirm', token=pending['token']) if pending['token'] else remote(node, credentials, 'status')
    reports = read(root / 'reports.json', {})
    reports[node['id']] = result
    atomic(root / 'reports.json', reports)
    if mode == 'full':
        ssh(node, credentials, '/etc/init.d/turris-federation enable && /etc/init.d/turris-federation restart && sleep 2 && /etc/init.d/turris-federation running')
        ssh(node, credentials, 'python3 ' + PROGRAM + ' web-check ' + REMOTE)
    (root / ('plan-' + node['id'] + '.json')).unlink()
    distribute_bundle(root, envelope, exclude=node['id'])
    return overview(root, config)


def rpc(root, req):
    action = req['action']
    if action == 'bootstrap':
        with locked(root):
            return bootstrap(root, req['nodeId'], req['rootPublic'])
    if action == 'apply':
        with locked(root):
            expected = req.get('expectedRouterHash')
            if expected and run(['sha256sum', '/etc/config/network', '/etc/config/firewall']).decode() != expected:
                raise ValueError('Konfigurace routeru se od validace změnila. Spusťte novou validaci.')
            doc = accept(root, req['envelope'])
        return stage(root, doc, req.get('expectedRouterHash'))
    if action == 'confirm':
        return confirm(root, req['token'])
    if action == 'status':
        return status_report(root)
    raise ValueError('Neznámá akce agenta.')


def main():
    os.umask(0o077)
    mode, root = sys.argv[1:3]
    if mode == 'web':
        serve_web(root)
    elif mode == 'install-web':
        install_web()
    elif mode == 'web-check':
        check_web()
    elif mode == 'serve':
        serve(root)
    elif mode == 'watchdog':
        watchdog(root, sys.argv[3])
    else:
        request = json.loads(base64.b64decode(sys.argv[3], validate=True)) if mode == 'rpc' else json.loads(sys.stdin.buffer.read(LIMIT + 1))
        if mode == 'rpc':
            result = rpc(root, request)
        else:
            with locked(root):
                result = controller(root, request)
        print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
