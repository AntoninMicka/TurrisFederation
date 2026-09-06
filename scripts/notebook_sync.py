#!/usr/bin/env python3
"""Opt-in notebook discovery and mutual-TLS configuration sync (stdlib only)."""
import contextlib
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

# Copied beside this script by the desktop launcher.
import federation as f

PORT = 8856
GROUP = '239.255.88.56'
INTERVAL = 30
MAX = 2 * 1024 * 1024
FIELDS = ['id', 'name', 'sshHost', 'sshPort', 'sshUser', 'lanCidrs',
          'zeroTierAddress', 'publicEndpoint', 'wireguardAddress']
COLUMNS = ['id', 'name', 'ssh_host', 'ssh_port', 'ssh_user', 'lan_cidrs',
           'zero_tier_address', 'public_endpoint', 'wireguard_address']
FLEET_FILES = ['root.pem', 'members.json', 'published.json', 'revision-floor.json']


def fingerprint(cert):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest()


def config_valid(data):
    if set(data) != {'nodes', 'zerotier', 'fleet'} or len(data['nodes']) > 128:
        raise ValueError('Neplatný synchronizační dokument.')
    seen = set()
    for node in data['nodes']:
        if set(node) != set(FIELDS) or str(uuid.UUID(node['id'])) != node['id'] or node['id'] in seen:
            raise ValueError('Neplatný nebo duplicitní router.')
        seen.add(node['id'])
        if not isinstance(node['name'], str) or not node['name'].strip() or len(node['name']) > 128:
            raise ValueError('Neplatný název routeru.')
        if type(node['sshPort']) is not int or not 0 < node['sshPort'] < 65536:
            raise ValueError('Neplatný SSH port.')
        for key, pattern in [('sshHost', r'[a-zA-Z0-9][a-zA-Z0-9.:%_-]*'), ('sshUser', r'[a-zA-Z0-9_][a-zA-Z0-9_.-]*')]:
            if not isinstance(node[key], str) or (node[key] and not re.fullmatch(pattern, node[key])):
                raise ValueError('Neplatné SSH nastavení.')
        if not isinstance(node['lanCidrs'], list) or len(node['lanCidrs']) > 128:
            raise ValueError('Neplatné LAN sítě.')
        for cidr in node['lanCidrs']:
            ipaddress.ip_network(cidr, strict=False)
        for key in ['zeroTierAddress', 'wireguardAddress', 'publicEndpoint']:
            if node[key] is not None and (not isinstance(node[key], str) or len(node[key]) > 512):
                raise ValueError('Neplatná adresa.')
    zt = data['zerotier']
    if set(zt) != {'networkId', 'central', 'zeroTierSubnet', 'wireguardSubnet'} or zt['central'] not in ['new', 'legacy']:
        raise ValueError('Neplatné nastavení sítě.')
    if zt['networkId'] is not None and not re.fullmatch('[0-9a-f]{16}', zt['networkId']):
        raise ValueError('Neplatné Network ID.')
    for key in ['zeroTierSubnet', 'wireguardSubnet']:
        if zt[key]:
            ipaddress.ip_network(zt[key])
    fleet = data['fleet']
    if not isinstance(fleet, dict) or set(fleet) - set(FLEET_FILES):
        raise ValueError('Nepovolené soubory identity.')
    for name, value in fleet.items():
        if not isinstance(value, str) or len(value) > MAX:
            raise ValueError('Neplatná identita federace.')
    if fleet:
        if 'root.pem' not in fleet:
            raise ValueError('Chybí kořenová identita.')
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'root.pem'
            f.atomic(key, fleet['root.pem'].encode())
            public = f.public_key(key)
        if 'published.json' in fleet:
            doc = f.validate_document(f.verify(public, json.loads(fleet['published.json'])))
            members = json.loads(fleet.get('members.json', '{}'))
            if members != doc['members']:
                raise ValueError('Členství neodpovídá podepsané revizi; dokončete deploy na zdroji.')
        elif json.loads(fleet.get('members.json', '{}')):
            raise ValueError('Chybí podepsaná revize členství.')
        floor = json.loads(fleet.get('revision-floor.json', '0'))
        if type(floor) is not int or not 0 <= floor < 2**53:
            raise ValueError('Neplatná revize.')
    return data


def version_valid(snapshot):
    if set(snapshot) != {'clock', 'data'} or not isinstance(snapshot['clock'], dict) or len(snapshot['clock']) > 128:
        raise ValueError('Neplatná verze konfigurace.')
    for peer, counter in snapshot['clock'].items():
        if not re.fullmatch('[a-f0-9]{64}', peer) or type(counter) is not int or not 0 < counter < 2**53:
            raise ValueError('Neplatná verze konfigurace.')
    config_valid(snapshot['data'])
    return snapshot


def dominates(left, right):
    return all(left.get(k, 0) >= v for k, v in right.items()) and left != right


def joined(left, right):
    return {k: max(left.get(k, 0), right.get(k, 0)) for k in left.keys() | right.keys()}


class Store:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.root = self.data_dir / 'notebooks'
        self.fleet = self.data_dir / 'deployment'
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.fleet.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.mutex = threading.RLock()

    def init_identity(self):
        with f.locked(self.root):
            if not (self.root / 'cert.pem').exists():
                # A interrupted generation never publishes half of an identity.
                with tempfile.TemporaryDirectory(dir=self.root) as directory:
                    key, cert = Path(directory) / 'key', Path(directory) / 'cert'
                    f.run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes',
                           '-days', '3650', '-subj', '/CN=Turris-Federation-Notebook',
                           '-keyout', str(key), '-out', str(cert)])
                    f.atomic(self.root / 'key.pem', key.read_bytes())
                    f.atomic(self.root / 'cert.pem', cert.read_bytes())
        self.cert = (self.root / 'cert.pem').read_text()
        self.id = fingerprint(self.cert)

    @contextlib.contextmanager
    def db(self):
        with self.mutex, f.locked(self.fleet):
            db = sqlite3.connect(self.data_dir / 'federation.db', timeout=10)
            try:
                db.execute('BEGIN IMMEDIATE')
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

    def data(self, db):
        nodes = []
        for row in db.execute('SELECT ' + ','.join(COLUMNS) + ' FROM nodes ORDER BY id'):
            node = dict(zip(FIELDS, row))
            node['lanCidrs'] = json.loads(node['lanCidrs'])
            nodes.append(node)
        row = db.execute("SELECT value FROM app_settings WHERE name='zerotier'").fetchone()
        zt = {'networkId': None, 'central': 'new', 'zeroTierSubnet': None, 'wireguardSubnet': None}
        if row:
            zt.update(json.loads(row[0]))
        fleet = {name: (self.fleet / name).read_text() for name in FLEET_FILES if (self.fleet / name).exists()}
        return {'nodes': nodes, 'zerotier': zt, 'fleet': fleet}

    def snapshot(self, db):
        data = self.data(db)
        row = db.execute("SELECT value FROM app_settings WHERE name='notebook-version'").fetchone()
        old = json.loads(row[0]) if row else {'clock': {}, 'dataHash': None}
        clock = dict(old['clock'])
        if f.digest(data) != old['dataHash']:
            if data['nodes'] or data['fleet'] or clock:
                clock[self.id] = clock.get(self.id, 0) + 1
        snapshot = {'clock': clock, 'data': data}
        if f.digest(data) != old['dataHash']:
            self.save_version(db, snapshot)
        return snapshot

    def save_version(self, db, snapshot):
        # The existing SQLite file and its WAL may have broader permissions.
        # Keep private keys exclusively in protected files, never in the database.
        metadata = {'clock': snapshot['clock'], 'dataHash': f.digest(snapshot['data'])}
        db.execute("INSERT INTO app_settings(name,value) VALUES('notebook-version',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                   (f.encode(metadata).decode(),))

    def apply(self, db, incoming):
        data = incoming['data']
        # Sync replaces the shared document, but never local SSH trust/audits.
        # Deletion is deliberately a conflict: deleting rows would destroy local history.
        existing = {row[0] for row in db.execute('SELECT id FROM nodes')}
        if existing - {node['id'] for node in data['nodes']}:
            raise ValueError('Synchronizace by odstranila místní routery. Sloučte návrhy před přenosem.')
        local_key = self.fleet / 'root.pem'
        if local_key.exists() and data['fleet'].get('root.pem') != local_key.read_text():
            raise ValueError('Notebook již má jinou kořenovou identitu. Automatické přepárování je zakázáno.')
        for node in data['nodes']:
            values = [json.dumps(node[k]) if k == 'lanCidrs' else node[k] for k in FIELDS]
            updates = ','.join(c + '=excluded.' + c for c in COLUMNS[1:])
            updates += ",status=CASE WHEN " + ' OR '.join(c + ' IS NOT excluded.' + c for c in COLUMNS[1:]) + " THEN 'draft' ELSE nodes.status END"
            db.execute('INSERT INTO nodes(' + ','.join(COLUMNS) + ",status,last_audit_at) VALUES(" + ','.join('?' * len(values)) + ",'draft',NULL) ON CONFLICT(id) DO UPDATE SET " + updates, values)
        db.execute("INSERT INTO app_settings(name,value) VALUES('zerotier',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", (f.encode(data['zerotier']).decode(),))
        for name in FLEET_FILES:
            if name in data['fleet']:
                f.atomic(self.fleet / name, data['fleet'][name].encode())
            elif (self.fleet / name).exists():
                raise ValueError('Synchronizace nesmí odstranit existující identitu federace.')
        self.save_version(db, incoming)

    def recover(self, db):
        journal = f.read(self.fleet / 'notebook-sync-journal.json')
        if journal:
            incoming = version_valid(journal['snapshot'])
            current = {k: self.data(db)[k] for k in ['nodes', 'zerotier']}
            expected = {k: incoming['data'][k] for k in ['nodes', 'zerotier']}
            if current not in [journal['beforeConfig'], expected]:
                raise ValueError('Obnova synchronizace zjistila další místní úpravy; automatický přepis byl zastaven.')
            self.apply(db, incoming)
            db.commit()
            (self.fleet / 'notebook-sync-journal.json').unlink()
            db.execute('BEGIN IMMEDIATE')

    def receive(self, peer, remote, choice=None, expected=None):
        version_valid(remote)
        with self.db() as db:
            if peer not in self.peers():
                raise ValueError('Notebook již není spárovaný.')
            self.recover(db)
            local = self.snapshot(db)
            if choice:
                if f.digest({'local': local, 'remote': remote}) != expected:
                    raise ValueError('Konfigurace se změnila. Obnovte náhled konfliktu.')
                selected = local if choice == 'local' else remote
                clock = joined(local['clock'], remote['clock'])
                clock[self.id] = clock.get(self.id, 0) + 1
                incoming = {'clock': clock, 'data': json.loads(f.encode(selected['data']))}
                # Resolve competing signed revisions by forcing the next publish
                # above both branches, rather than replaying either fork.
                revisions = []
                for item in [local, remote]:
                    fleet = item['data']['fleet']
                    if 'published.json' in fleet:
                        revisions.append(json.loads(__import__('base64').b64decode(json.loads(fleet['published.json'])['payload']))['revision'])
                if revisions and incoming['data']['fleet']:
                    incoming['data']['fleet']['revision-floor.json'] = str(max(revisions) + 1)
            elif remote['data'] == local['data']:
                self.save_version(db, {'clock': joined(local['clock'], remote['clock']), 'data': local['data']})
                (self.root / ('conflict-' + peer + '.json')).unlink(missing_ok=True)
                return 'synced'
            elif dominates(remote['clock'], local['clock']):
                incoming = remote
            elif dominates(local['clock'], remote['clock']):
                (self.root / ('conflict-' + peer + '.json')).unlink(missing_ok=True)
                return 'local_newer'
            else:
                f.atomic(self.root / ('conflict-' + peer + '.json'), remote)
                return 'conflict'
            # Validate every precondition before publishing the recovery journal.
            old = self.data(db)
            if {n['id'] for n in old['nodes']} - {n['id'] for n in incoming['data']['nodes']}:
                raise ValueError('Příchozí návrh postrádá místní routery; nejprve je sloučte.')
            if old['fleet'].get('root.pem') and old['fleet']['root.pem'] != incoming['data']['fleet'].get('root.pem'):
                raise ValueError('Notebook patří jiné kotvě důvěry; identita nebyla změněna.')
            if set(old['fleet']) - set(incoming['data']['fleet']):
                raise ValueError('Přenos nesmí odstranit soubory identity.')
            f.atomic(self.fleet / 'notebook-sync-journal.json', {'snapshot': incoming, 'beforeConfig': {k: old[k] for k in ['nodes', 'zerotier']}})
            self.apply(db, incoming)
            db.commit()
            (self.fleet / 'notebook-sync-journal.json').unlink()
            (self.root / ('conflict-' + peer + '.json')).unlink(missing_ok=True)
            db.execute('BEGIN IMMEDIATE')
            return 'synced'

    def peers(self):
        return f.read(self.root / 'peers.json', {})

    def status(self):
        with self.db() as db:
            self.recover(db)
            snapshot = self.snapshot(db)
        peers = self.peers()
        discovered = f.read(self.root / 'discovered.json', {})
        runtime = f.read(self.root / 'runtime.json', {})
        items = []
        for peer in peers.keys() | discovered.keys():
            item = {**discovered.get(peer, {}), **peers.get(peer, {}), **(runtime.get('peers', {}).get(peer, {}) if peer in peers else {}), 'id': peer, 'trusted': peer in peers}
            item.pop('cert', None)
            remote = f.read(self.root / ('conflict-' + peer + '.json'))
            if remote:
                item.update(state='conflict', conflictToken=f.digest({'local': snapshot, 'remote': remote}),
                            remoteNodes=[n['name'] for n in remote['data']['nodes']], localNodes=[n['name'] for n in snapshot['data']['nodes']],
                            localConfig={k: snapshot['data'][k] for k in ['nodes', 'zerotier']},
                            remoteConfig={k: remote['data'][k] for k in ['nodes', 'zerotier']})
            items.append(item)
        return {'id': self.id, 'name': f.read(self.root / 'config.json', {}).get('name', socket.gethostname()),
                'config': f.read(self.root / 'config.json', {}), 'peers': sorted(items, key=lambda p: p.get('name', p['id'])),
                'updatedAt': runtime.get('updatedAt'), 'error': runtime.get('error'),
                'configurationVersion': f.digest(snapshot['data']),
                'invitation': json.dumps({'name': f.read(self.root / 'config.json', {}).get('name', socket.gethostname()),
                                          'address': f.read(self.root / 'config.json', {}).get('address', ''), 'cert': self.cert})}


def server_context(store):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(store.root / 'cert.pem', store.root / 'key.pem')
    context.verify_mode = ssl.CERT_REQUIRED
    peers = store.peers()
    if peers:
        context.load_verify_locations(cadata='\n'.join(p['cert'] for p in peers.values()))
    return context


def fetch(store, peer):
    # Trust only the explicitly paired certificate. Both endpoints present one.
    context = ssl.create_default_context(cadata=peer['cert'])
    context.check_hostname = False
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(store.root / 'cert.pem', store.root / 'key.pem')
    connection = http.client.HTTPSConnection(peer['address'], PORT, timeout=5, context=context)
    try:
        connection.connect()
        if hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest() != fingerprint(peer['cert']):
            raise ValueError('Certifikát notebooku neodpovídá párování.')
        connection.request('GET', '/snapshot')
        response = connection.getresponse()
        raw = response.read(MAX + 1)
        if response.status != 200 or len(raw) > MAX:
            raise ValueError('Notebook odmítl synchronizaci.')
        return json.loads(raw)
    finally:
        connection.close()


def make_server(store, address):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            try:
                peer = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
                if self.path != '/snapshot' or peer not in store.peers():
                    self.send_error(403)
                    return
                with store.db() as db:
                    store.recover(db)
                    payload = f.encode(store.snapshot(db))
                if len(payload) > MAX:
                    raise ValueError('Konfigurace je příliš velká.')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception:
                self.send_error(503, 'Sync unavailable')

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
        def get_request(self):
            connection, source = self.socket.accept()
            connection.settimeout(5)
            try:
                return server_context(store).wrap_socket(connection, server_side=True), source
            except Exception:
                connection.close()
                raise OSError('TLS handshake rejected') from None
    return Server((address, PORT), Handler)


def interface(address):
    ipaddress.IPv4Address(address)
    for link in json.loads(f.run(['ip', '-j', '-4', 'address', 'show'])):
        for entry in link.get('addr_info', []):
            if entry.get('local') == address and entry.get('scope') != 'host':
                return ipaddress.ip_network('%s/%s' % (address, entry['prefixlen']), strict=False)
    raise ValueError('Vyberte IPv4 adresu aktivního LAN nebo ZeroTier rozhraní notebooku.')


def beacon(store, name, address):
    payload = {'schema': 'tf-notebook-1', 'name': name, 'address': address, 'time': int(time.time())}
    return f.encode({'cert': store.cert, 'signed': f.sign(store.root / 'key.pem', payload)})


def discover(store, raw, source, network):
    if len(raw) > 8192 or ipaddress.ip_address(source) not in network:
        return
    packet = json.loads(raw)
    cert = packet['cert']
    peer = fingerprint(cert)
    if peer == store.id:
        return
    public = f.run(['openssl', 'x509', '-pubkey', '-noout'], cert.encode()).decode()
    payload = f.verify(public, packet['signed'])
    if (set(payload) != {'schema', 'name', 'address', 'time'} or payload['schema'] != 'tf-notebook-1'
            or payload['address'] != source or abs(time.time() - payload['time']) > 90
            or not isinstance(payload['name'], str) or not 0 < len(payload['name']) <= 80):
        return
    with f.locked(store.root):
        peers = f.read(store.root / 'discovered.json', {})
        peers = {k: v for k, v in peers.items() if time.time() - v.get('seenAt', 0) < 3600}
        if len(peers) < 128 or peer in peers:
            peers[peer] = {'name': payload['name'], 'address': source, 'cert': cert, 'seenAt': time.time()}
            f.atomic(store.root / 'discovered.json', peers)


def serve(store):
    config = f.read(store.root / 'config.json')
    address = config['address']
    network = interface(address)
    parent = os.getppid()
    server = make_server(store, address)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    discovery_error = None
    try:
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind(('', PORT))
        udp.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(GROUP) + socket.inet_aton(address))
        udp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(address))
        udp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        udp.settimeout(0.5)
    except OSError:
        udp.close()
        udp = None
        discovery_error = 'Multicast není dostupný. Použijte ruční párování; TLS synchronizace zůstává dostupná.'
    stopped = threading.Event()

    def exchange():
        while not stopped.is_set() and os.getppid() == parent:
            runtime = {'updatedAt': time.time(), 'peers': f.read(store.root / 'runtime.json', {}).get('peers', {})}
            if discovery_error:
                runtime['error'] = discovery_error
            try:
                discovered = f.read(store.root / 'discovered.json', {})
                for peer, item in store.peers().items():
                    if stopped.is_set():
                        break
                    # Signed beacons allow paired notebooks to change their address.
                    if peer in discovered and time.time() - discovered[peer]['seenAt'] < 90:
                        item = dict(item, address=discovered[peer]['address'])
                    try:
                        remote = fetch(store, item)
                        if peer not in store.peers():
                            continue
                        state = store.receive(peer, remote)
                        runtime['peers'][peer] = {'state': state, 'lastSync': time.time(), 'address': item['address']}
                    except Exception:
                        runtime['peers'][peer] = {**runtime['peers'].get(peer, {}), 'state': 'error', 'error': 'Přenos se nezdařil. Ověřte vzájemné párování, dostupnost a shodu federace.'}
            except Exception:
                runtime['error'] = 'Discovery není dostupné na vybraném rozhraní.'
            f.atomic(store.root / 'runtime.json', runtime)
            stopped.wait(INTERVAL)
    worker = threading.Thread(target=exchange, daemon=True)
    worker.start()
    next_beacon = 0
    try:
        while os.getppid() == parent:
            if udp is None:
                stopped.wait(0.5)
                continue
            try:
                if time.monotonic() >= next_beacon:
                    udp.sendto(beacon(store, config['name'], address), (GROUP, PORT))
                    next_beacon = time.monotonic() + INTERVAL
                raw, source = udp.recvfrom(8193)
                discover(store, raw, source[0], network)
            except (socket.timeout, ValueError, KeyError, TypeError):
                pass
            except OSError:
                udp.close()
                udp = None
                discovery_error = 'Discovery je nedostupné; použijte ruční párování.'
    finally:
        stopped.set()
        if udp is not None:
            udp.close()
        server.shutdown()
        server.server_close()


def command(store, req):
    action = req['action']
    if action == 'status':
        return store.status()
    if action == 'configure':
        name, address = req['name'].strip(), req['address'].strip()
        if not 0 < len(name) <= 80:
            raise ValueError('Vyplňte název notebooku (nejvýše 80 znaků).')
        interface(address)
        f.atomic(store.root / 'config.json', {'enabled': True, 'name': name, 'address': address})
    elif action == 'stop':
        config = f.read(store.root / 'config.json', {})
        f.atomic(store.root / 'config.json', dict(config, enabled=False))
    elif action == 'manual':
        item = json.loads(req['invitation'])
        if set(item) != {'name', 'address', 'cert'} or not isinstance(item['name'], str) or not 0 < len(item['name']) <= 80:
            raise ValueError('Neplatné párovací údaje.')
        ip = ipaddress.IPv4Address(item['address'])
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
            raise ValueError('Neplatná adresa notebooku.')
        peer = fingerprint(item['cert'])
        if peer == store.id:
            raise ValueError('To jsou párovací údaje tohoto notebooku.')
        with f.locked(store.root):
            found = f.read(store.root / 'discovered.json', {})
            found[peer] = dict(item, seenAt=time.time())
            f.atomic(store.root / 'discovered.json', found)
    elif action == 'pair':
        peer = req['peer']
        if not re.fullmatch('[a-f0-9]{64}', peer):
            raise ValueError('Neplatný otisk notebooku.')
        with f.locked(store.root):
            found = f.read(store.root / 'discovered.json', {}).get(peer)
            if not found or fingerprint(found['cert']) != peer:
                raise ValueError('Notebook již není v přehledu discovery.')
            peers = store.peers()
            if len(peers) >= 32 and peer not in peers:
                raise ValueError('První verze podporuje nejvýše 32 spárovaných notebooků.')
            peers[peer] = found
            f.atomic(store.root / 'peers.json', peers)
    elif action == 'unpair':
        peer = req['peer']
        if not re.fullmatch('[a-f0-9]{64}', peer):
            raise ValueError('Neplatný otisk notebooku.')
        with f.locked(store.root):
            peers = store.peers()
            peers.pop(peer, None)
            f.atomic(store.root / 'peers.json', peers)
            (store.root / ('conflict-' + peer + '.json')).unlink(missing_ok=True)
    elif action == 'resolve':
        peer = req['peer']
        if peer not in store.peers() or req['choice'] not in ['local', 'remote']:
            raise ValueError('Neplatné řešení konfliktu.')
        remote = f.read(store.root / ('conflict-' + peer + '.json'))
        if not remote:
            raise ValueError('Konflikt již není dostupný.')
        store.receive(peer, remote, req['choice'], req['token'])
    else:
        raise ValueError('Neznámá operace synchronizace.')
    return store.status()


if __name__ == '__main__':
    os.umask(0o077)
    try:
        store = Store(sys.argv[2])
        store.init_identity()
        if sys.argv[1] == 'serve':
            serve(store)
        else:
            request = json.loads(sys.stdin.buffer.read(16384))
            print(json.dumps(command(store, request)))
    except Exception as error:
        if len(sys.argv) > 1 and sys.argv[1] == 'serve':
            f.atomic(Path(sys.argv[2]) / 'notebooks/runtime.json', {'updatedAt': time.time(), 'error': 'Službu nelze provozovat. Ověřte vybranou IPv4 adresu, dostupnost multicastu a volný port 8856.'})
        # Never print payloads, TLS data, or an exception containing private keys.
        print('Synchronizace notebooků selhala: ' + (str(error) if type(error) is ValueError else type(error).__name__), file=sys.stderr)
        sys.exit(1)
