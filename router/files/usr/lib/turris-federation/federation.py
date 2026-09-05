#!/usr/bin/env python3
"""Notebook controller and Turris agent. No third-party Python dependencies."""
import base64
import contextlib
import fcntl
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

VERSION = 1
LIMIT = 1024 * 1024
PORT = 8844
WG_PORT = 51830
REMOTE = '/etc/turris-federation'
CONFIG_DIR = Path('/etc/config')
SYS_NET = Path('/sys/class/net')
PROGRAM = '/usr/lib/turris-federation/federation.py'


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


def validate_document(doc):
    if set(doc) != {'schema', 'federationId', 'revision', 'previous', 'config', 'members'}:
        raise ValueError('Synchronizace přijímá pouze síťové nastavení, nikoli software nebo příkazy.')
    if doc.get('schema') != VERSION or type(doc.get('revision')) is not int or doc['revision'] < 1:
        raise ValueError('Nepodporované schéma nebo revize.')
    str(uuid.UUID(doc['federationId']))
    normalized = normalize(doc['config']['nodes'], doc['config']['networkId'])
    if normalized != doc['config']:
        raise ValueError('Konfigurace není normalizovaná.')
    keys = set()
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
    return {'zeroTierDevice': network.get('portDeviceName'), 'localNetworks': sorted(actual),
            'zeroTierNetworks': [str(ipaddress.ip_interface(value).network) for value in network.get('assignedAddresses', []) if ipaddress.ip_interface(value).version == 4]}


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


def render_apply(root, doc):
    node = self_node(root, doc)
    own_id = read(Path(root) / 'node.json')['nodeId']
    local = local_check(node, doc['config']['networkId']) if own_id in doc['members'] else None
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
                'listen_port': str(WG_PORT), 'addresses': [node['wireguardAddress'] + '/32']})
    peers = [n for n in doc['config']['nodes'] if n['id'] in doc['members'] and n['id'] != own_id]
    for peer in peers:
        uci_section('network', 'tf_p_' + peer['id'].replace('-', ''), 'wireguard_tf_wg', {
            'public_key': doc['members'][peer['id']]['wireguardKey'],
            'endpoint_host': peer['zeroTierAddress'], 'endpoint_port': str(WG_PORT),
            'persistent_keepalive': '25', 'route_allowed_ips': '1',
            'allowed_ips': [peer['wireguardAddress'] + '/32'] + peer['lanCidrs']})
    uci_section('firewall', 'tf_zone', 'zone', {'name': 'tf_fed', 'network': ['tf_wg'],
                'input': 'REJECT', 'output': 'ACCEPT', 'forward': 'REJECT'})
    uci_section('firewall', 'tf_out', 'forwarding', {'src': 'lan', 'dest': 'tf_fed'})
    uci_section('firewall', 'tf_in', 'forwarding', {'src': 'tf_fed', 'dest': 'lan'})
    uci_section('firewall', 'tf_ping', 'rule', {'src': 'tf_fed', 'proto': 'icmp', 'icmp_type': ['echo-request'], 'target': 'ACCEPT', 'family': 'ipv4'})
    uci_section('firewall', 'tf_control', 'rule', {'src': '*', 'src_ip': local['zeroTierNetworks'],
                'dest_ip': node['zeroTierAddress'], 'proto': 'tcp', 'dest_port': str(PORT), 'target': 'ACCEPT', 'family': 'ipv4'})
    for index, peer in enumerate(peers):
        for suffix, protocol, port in [('wg', 'udp', WG_PORT), ('sync', 'tcp', PORT)]:
            uci_section('firewall', 'tf_%s_%s' % (suffix, index), 'rule', {'src': '*', 'src_ip': peer['zeroTierAddress'],
                        'dest_ip': node['zeroTierAddress'], 'proto': protocol, 'dest_port': str(port), 'target': 'ACCEPT', 'family': 'ipv4'})
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


def health(root, doc):
    own_id = read(Path(root) / 'node.json')['nodeId']
    if own_id not in doc['members']:
        return {'state': 'revoked', 'pendingPeers': []}
    expected_key = doc['members'][own_id]['wireguardKey']
    actual_key = run(['wg', 'show', 'tf_wg', 'public-key']).decode().strip()
    if expected_key != actual_key:
        raise ValueError('WireGuard nemá očekávanou identitu.')
    peers = [n for n in doc['config']['nodes'] if n['id'] in doc['members'] and n['id'] != own_id]
    actual_peers = set(run(['wg', 'show', 'tf_wg', 'peers']).decode().split())
    if actual_peers != {doc['members'][n['id']]['wireguardKey'] for n in peers}:
        raise ValueError('WireGuard nemá očekávaný seznam peerů.')
    allowed = {}
    for line in run(['wg', 'show', 'tf_wg', 'allowed-ips']).decode().splitlines():
        fields = line.replace(',', ' ').split()
        if fields:
            allowed[fields[0]] = set(fields[1:])
    for peer in peers:
        if allowed.get(doc['members'][peer['id']]['wireguardKey']) != set(peer['lanCidrs'] + [peer['wireguardAddress'] + '/32']):
            raise ValueError('WireGuard AllowedIPs neodpovídají plánu.')
    missing = []
    for peer in peers:
        for cidr in peer['lanCidrs'] + [peer['wireguardAddress'] + '/32']:
            net = ipaddress.ip_network(cidr)
            destination = net.network_address + (1 if net.num_addresses > 1 else 0)
            route = run(['ip', '-%s' % net.version, 'route', 'get', str(destination)]).decode()
            if not re.search(r'\bdev tf_wg\b', route):
                raise ValueError('Po deployi chybí WireGuard trasa: ' + cidr)
        probe = subprocess.run(['ping', '-c', '1', '-W', '1', '-I', 'tf_wg', peer['wireguardAddress']],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        if probe.returncode:
            missing.append(peer['id'])
    return {'state': 'waiting_peers' if missing or not peers else 'active', 'pendingPeers': missing}


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
        return result


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
    return payload['report']


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
                                      'nodeId': read(root / 'node.json')['nodeId'], 'report': read(root / 'report.json', {})})
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
WEB_FILES = {
    '/etc/turris-webapps/80-turris-federation.json': json.dumps({
        'id': 'turris-federation', 'title': 'Turris Federation', 'url': WEB_PATH,
        'icon': '/icons/turris-federation.svg',
        'description': {'en': 'Federation nodes and network status', 'cz': 'Uzly federace a stav sítě', 'cs': 'Uzly federace a stav sítě'}
    }, ensure_ascii=False).encode(),
    '/www/webapps-icons/turris-federation.svg': b'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96"><rect width="96" height="96" rx="20" fill="#123047"/><path d="M24 66 48 26 72 66Z" fill="none" stroke="#58d5c9" stroke-width="5"/><g fill="#fff"><circle cx="48" cy="26" r="10"/><circle cx="24" cy="66" r="10"/><circle cx="72" cy="66" r="10"/></g></svg>''',
    '/etc/lighttpd/conf.d/turris-federation.conf': b'''# Managed by Turris Federation LAN deployment.
server.modules += ( "mod_proxy", "mod_auth", "mod_authn_pam" )
$HTTP["url"] =~ "^/turris-federation($|/)" {
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
.badge{display:inline-block;border-radius:20px;padding:5px 10px;background:#244653;font-size:13px}
.button{padding:10px 16px;border:1px solid #517185;border-radius:8px;text-decoration:none}
@media(max-width:600px){main{padding:24px 14px}section{padding:16px}.cards{grid-template-columns:1fr}}
'''
WEB_LABELS = {'pending': 'Čeká na aplikování', 'error': 'Chyba agenta', 'confirming': 'Čeká na potvrzení',
              'waiting_peers': 'Čeká na protějšky', 'active': 'Spojení ověřeno', 'rollback': 'Obnovena záloha', 'revoked': 'Členství odvoláno'}


def web_page(root):
    """Render only selected public configuration/status fields, never raw files or keys."""
    import html
    def esc(value):
        return html.escape(str(value), quote=True)
    root = Path(root)
    report = read(root / 'report.json', {})
    envelope = read(root / 'accepted.json')
    doc = validate_document(verify((root / 'root.pub').read_text(), envelope)) if envelope else None
    own_id = read(root / 'node.json', {}).get('nodeId')
    own = next((node for node in doc['config']['nodes'] if node['id'] == own_id), None) if doc else None
    state = WEB_LABELS.get(report.get('state'), 'Zatím nenasazeno')
    checked = report.get('checkedAt')
    checked_text = time.strftime('%d. %m. %Y %H:%M:%S UTC', time.gmtime(checked)) if isinstance(checked, (int, float)) else 'Dosud neověřeno'
    rows = []
    if doc:
        for node in doc['config']['nodes']:
            member = node['id'] in doc['members']
            label = state if node['id'] == own_id else ('Přijatý uzel' if member else 'Draft')
            rows.append('<tr><td><strong>%s</strong>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td><td><span class="badge">%s</span></td></tr>' % (
                esc(node['name']), '<br><small>Tento router</small>' if node['id'] == own_id else '',
                esc(node['zeroTierAddress'] or '—'), esc(node['wireguardAddress'] or '—'),
                '<br>'.join(esc(cidr) for cidr in node['lanCidrs']) or '—', esc(label)))
    notices = '<p class="notice">Router ještě nepřijal konfiguraci federace. Dokončete deploy z notebooku přes LAN.</p>' if not doc else ''
    if report.get('error'):
        notices += '<p class="notice">%s</p>' % esc(report['error'])
    if report.get('pendingPeers'):
        names = {node['id']: node['name'] for node in doc['config']['nodes']} if doc else {}
        notices += '<p class="notice">Čekající protějšky: %s</p>' % esc(', '.join(names.get(peer, peer) for peer in report['pendingPeers']))
    return ('''<!doctype html><html lang="cs"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Turris Federation</title><style>''' + WEB_STYLE + '''</style></head><body><main>
<nav><a href="/">← Úvodní stránka Turrisu</a><a class="button" href="/turris-federation/">Obnovit stav</a></nav>
<div class="kicker">Turris Federation · přehled sítě</div><h1>''' + esc(own['name'] if own else 'Federace routerů') + '''</h1>
<p class="muted">Poslední zaznamenaný stav místního agenta. Načtení stránky neprovádí nový audit sítě.</p>''' + notices + '''
<div class="cards"><article class="card"><span>Stav tohoto routeru</span><strong>''' + esc(state) + '''</strong></article>
<article class="card"><span>Přijatá revize</span><strong>''' + esc(doc['revision'] if doc else '—') + '''</strong></article>
<article class="card"><span>Aplikovaná revize</span><strong>''' + esc(report.get('appliedRevision') or '—') + '''</strong></article></div>
<p class="muted">Poslední kontrola agenta: ''' + esc(checked_text) + '''</p>
<section><h2>Uzly federace</h2><div class="table-wrap"><table><thead><tr><th>Uzel</th><th>ZeroTier</th><th>WireGuard</th><th>LAN sítě</th><th>Stav / členství</th></tr></thead><tbody>''' + ''.join(rows) + '''</tbody></table></div>
<p class="muted">U ostatních uzlů je uvedeno členství z přijaté konfigurace, nikoli aktuální dostupnost.</p></section>
<section><h2>Síť a správa</h2><p>ZeroTier Network ID: <code>''' + esc(doc['config']['networkId'] if doc else '—') + '''</code></p>
<p>Notebook je řídicí uzel pouze v ZeroTier, bez WireGuard spojů. Jeho dostupnost tento router nekontroluje.</p>
<p>Nastavení sítě spravujte v desktopové aplikaci. Instalace a aktualizace softwaru vyžadují přímé LAN spojení z notebooku.</p></section>
</main></body></html>''').encode()


def web_handler(root):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path not in [WEB_PATH, WEB_PATH.rstrip('/')]:
                self.send_error(404)
                return
            try:
                body = web_page(root)
                status = 200
            except Exception:
                body = '<!doctype html><html lang="cs"><meta charset="utf-8"><title>Turris Federation</title><h1>Stav nelze načíst</h1><p>Zkontrolujte agenta z desktopové aplikace.</p></html>'.encode()
                status = 503
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self.send_error(405)

        do_PUT = do_DELETE = do_PATCH = do_POST
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

    # First verify the private status backend independently of lighttpd/auth.
    connection = http.client.HTTPConnection('127.0.0.1', WEB_PORT, timeout=5)
    try:
        connection.request('GET', WEB_PATH)
        response = connection.getresponse()
        body = response.read(LIMIT)
        if response.status != 200 or b'Turris Federation' not in body:
            raise ValueError('Interní webový přehled nepotvrdil funkční spuštění.')
    finally:
        connection.close()

    # Then verify that lighttpd loaded the public route and protects it with auth.
    # Without credentials this route must be challenged, not return 404 or bypass auth.
    connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=5)
    try:
        connection.request('GET', WEB_PATH, headers={'Host': 'localhost'})
        response = connection.getresponse()
        response.read(LIMIT)
        challenge = response.getheader('WWW-Authenticate', '')
        if response.status != 401 or 'Basic' not in challenge:
            raise ValueError(
                'Veřejná cesta Turris Federation není aktivní přes lighttpd nebo není chráněná přihlášením.'
            )
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


def ssh(node, credentials, command):
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
            args = ['sshpass', '-d', str(read_fd), 'ssh', '-F', '/dev/null', '-T', '-n',
                    '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                    '-o', 'UserKnownHostsFile=' + str(key), '-o', 'ConnectTimeout=10',
                    '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
                    '-o', 'PubkeyAuthentication=no', '-o', 'NumberOfPasswordPrompts=1',
                    '-B', lan['device'], '-b', lan['source'],
                    '-p', str(port), '-l', user, '--', lan['host'], command]
            result = subprocess.run(args, pass_fds=(read_fd,), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
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
    if old and old['config'] == config and old['members'] == members:
        return old_envelope
    doc = {'schema': VERSION, 'federationId': old['federationId'] if old else str(uuid.uuid4()),
           'revision': old['revision'] + 1 if old else 1, 'previous': digest(old) if old else None,
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
    return {'revision': doc['revision'] if doc else 0, 'unpublishedChanges': not doc or doc['config'] != config or doc['members'] != members,
            'fingerprint': hashlib.sha256(public_key(root / 'root.pem').encode()).hexdigest() if (root / 'root.pem').exists() else None,
            'nodes': {n['id']: {'enrolled': n['id'] in members, **reports.get(n['id'], {})} for n in config['nodes']}}


def distribute_bundle(root, envelope, exclude=None):
    root = Path(root)
    doc = verify(public_key(root / 'root.pem'), envelope)
    results = read(root / 'reports.json', {})
    for peer in doc['config']['nodes']:
        if peer['id'] not in doc['members'] or peer['id'] == exclude:
            continue
        try:
            request_http(peer['zeroTierAddress'], 'POST', '/bundle', envelope)
            results[peer['id']] = dict(peer_status(peer, doc['members'][peer['id']], root / 'root.pem'), reachable=True)
        except Exception as error:
            results[peer['id']] = dict(results.get(peer['id'], {}), error=str(error), reachable=False)
    atomic(root / 'reports.json', results)


def controller(root, req):
    root = Path(root)
    nodes = req['nodes']
    config = normalize(nodes, req['networkId'])
    action = req['action']
    if action == 'overview':
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
        plan = {'operation': 'update' if updating else 'install', 'lan': lan, 'artifactHash': artifact_hash(),
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
        atomic(root / ('plan-' + node['id'] + '.json'), plan)
        return plan
    if action != 'deploy':
        raise ValueError('Neznámá akce.')
    plan = read(root / ('plan-' + node['id'] + '.json'))
    if not plan or plan['id'] != req.get('planId') or plan['expiresAt'] < time.time() or plan['configHash'] != digest(config) or plan['hostKeyHash'] != digest(credentials['hostKey']) or plan.get('membersHash') != digest(read(root / 'members.json', {})) or plan['sshHash'] != digest({k: node[k] for k in ['sshHost', 'sshPort', 'sshUser']}):
        raise ValueError('Plán chybí, vypršel nebo se návrh změnil. Spusťte znovu validaci.')
    if plan.get('artifactHash') != artifact_hash() or not plan.get('lan'):
        raise ValueError('Plán neodpovídá verzi agenta nebo chybí LAN kontrola. Validujte znovu.')
    lan = direct_lan(node)
    if plan['lan'] != lan:
        raise ValueError('LAN připojení se od validace změnilo. Validujte znovu.')
    node = dict(node, _deployLan=lan)
    if ssh(node, credentials, 'sha256sum /etc/config/network /etc/config/firewall').decode() != plan['routerHash']:
        raise ValueError('Konfigurace routeru se od validace změnila. Validujte znovu.')
    root_public = identity(root / 'root.pem')
    # Refuse to replace executable code on a router belonging to another notebook.
    check = "test ! -f %s/root.pub || test \"$(cat %s/root.pub)\" = %s" % (REMOTE, REMOTE, shell_quote(root_public.strip()))
    source = Path(__file__).read_bytes()
    installer = 'set -eu; umask 077; ' + check + '; test ! -f /etc/turris-federation/pending.json; '
    check_node = 'import json; assert json.load(open(\"/etc/turris-federation/node.json\"))[\"nodeId\"] == ' + repr(node['id'])
    installer += 'if test -f /etc/turris-federation/node.json; then python3 -c ' + shell_quote(check_node) + '; fi; '
    packages = 'python3 openssl-util wireguard-tools kmod-wireguard lighttpd-mod-proxy lighttpd-mod-auth lighttpd-mod-authn_pam lighttpd-mod-authn_file'
    installer += "missing=''; for pkg in " + packages + "; do if ! opkg status \"$pkg\" 2>/dev/null | grep -q '^Status: .* installed'; then missing=\"$missing $pkg\"; fi; done; "
    installer += 'if test -n "$missing"; then opkg update >&2; opkg install $missing >&2; fi; '
    installer += 'mkdir -p /usr/lib/turris-federation /etc/turris-federation; '
    installer += 'printf %s ' + shell_quote(base64.b64encode(source).decode()) + ' | base64 -d > ' + PROGRAM + '.new; '
    installer += 'python3 -m py_compile ' + PROGRAM + '.new; if test -f ' + PROGRAM + '; then cp ' + PROGRAM + ' ' + PROGRAM + '.previous; fi; mv ' + PROGRAM + '.new ' + PROGRAM + '; '
    installer += 'printf %s ' + shell_quote(base64.b64encode(INIT.encode()).decode()) + ' | base64 -d > /etc/init.d/turris-federation; chmod 755 /etc/init.d/turris-federation'
    installer += '; python3 ' + PROGRAM + ' install-web ' + REMOTE
    ssh(node, credentials, installer)
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
        return read(Path(root) / 'report.json', {})
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
