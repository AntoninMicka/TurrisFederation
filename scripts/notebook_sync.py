#!/usr/bin/env python3
"""Opt-in notebook discovery and mutual-TLS configuration sync (stdlib only)."""
import contextlib
import base64
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

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
LOCAL_LIMIT = 16 * 1024
CREDENTIAL_SCHEMA = 'tf-notebook-credential-1'
USER_CREDENTIAL_SCHEMA = 'tf-notebook-credential-2'
ENROLLMENT_SCHEMA = 'tf-notebook-enrollment-2'
INVITATION_SCHEMA = 'tf-notebook-invitation-1'
TOPOLOGY_UPDATE_SCHEMA = 'tf-notebook-topology-update-1'
ENROLLMENT_TTL = 15 * 60
VPN_CONNECTION = 'turris-federation'
VPN_BACKUP = 'turris-federation-rollback'
VPN_REPLACED = 'turris-federation-replaced'
VPN_INTERFACE = 'tf_notebook'
VPN_PLAN_TTL = 10 * 60
VPN_HANDSHAKE_MAX_AGE = 180


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


def valid_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def local_command(args, allow_failure=False, timeout=120):
    environment = dict(os.environ, LC_ALL='C')
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, env=environment)
    if result.returncode and not allow_failure:
        raise ValueError('Systémový nástroj %s odmítl operaci.' % Path(args[0]).name)
    return result.stdout.decode(errors='replace')


def nmcli_uuids():
    output = local_command(['/usr/bin/nmcli', '-t', '-f', 'UUID', 'connection', 'show'])
    result = {line.strip() for line in output.splitlines() if line.strip()}
    if any(not valid_uuid(value) for value in result):
        raise ValueError('NetworkManager vrátil neplatný seznam profilů.')
    return result


def nmcli_active_uuids():
    output = local_command(['/usr/bin/nmcli', '-t', '-f', 'UUID', 'connection', 'show', '--active'])
    result = {line.strip() for line in output.splitlines() if line.strip()}
    if any(not valid_uuid(value) for value in result):
        raise ValueError('NetworkManager vrátil neplatný seznam aktivních profilů.')
    return result


def nmcli_connections():
    result = {}
    for name in [VPN_CONNECTION, VPN_BACKUP]:
        output = local_command(['/usr/bin/nmcli', '-t', '-f', 'UUID,TYPE', 'connection', 'show', 'id', name],
                               allow_failure=True).strip()
        if output:
            values = output.splitlines()
            fields = values[0].split(':') if len(values) == 1 else []
            if len(fields) != 2 or not valid_uuid(fields[0]) or fields[1] != 'wireguard':
                raise ValueError('NetworkManager obsahuje nejednoznačný spravovaný profil.')
            result[name] = {'uuid': fields[0], 'type': fields[1]}
    return result


def privileged_nmcli(args):
    if any(not isinstance(value, str) or '\x00' in value or '\n' in value for value in args):
        raise ValueError('Neplatný parametr NetworkManageru.')
    return local_command(['/usr/bin/pkexec', '/usr/bin/nmcli', *args])


def wireguard_handshakes():
    """Read only public peer keys and timestamps; retry through polkit when needed."""
    commands = [
        ['/usr/bin/wg', 'show', VPN_INTERFACE, 'latest-handshakes'],
        ['/usr/bin/pkexec', '/usr/bin/wg', 'show', VPN_INTERFACE, 'latest-handshakes'],
    ]
    for command in commands:
        try:
            output = local_command(command)
            result = {}
            for line in output.splitlines():
                fields = line.split('\t')
                if len(fields) != 2 or not fields[1].isdigit():
                    raise ValueError('Nástroj WireGuard vrátil neplatný stav handshake.')
                result[fields[0]] = int(fields[1])
            return result
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    return None


def verify_vpn(address, routes):
    links = json.loads(local_command(['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev', VPN_INTERFACE]))
    assigned = {item.get('local') for link in links for item in link.get('addr_info', [])
                if item.get('family') == 'inet'}
    if address not in assigned:
        raise ValueError('Aktivované rozhraní nemá podepsanou WireGuard adresu.')
    for cidr in routes:
        network = ipaddress.ip_network(cidr)
        destination = network.network_address + (1 if network.num_addresses > 1 else 0)
        found = json.loads(local_command(['/usr/sbin/ip', '-j', '-4', 'route', 'get', str(destination)]))
        if len(found) != 1 or found[0].get('dev') != VPN_INTERFACE:
            raise ValueError('Po aktivaci chybí očekávaná VPN route: ' + cidr)


def verify_underlay(address, document):
    links = json.loads(local_command(['/usr/sbin/ip', '-j', '-4', 'address', 'show']))
    devices = {link.get('ifname') for link in links for item in link.get('addr_info', [])
               if item.get('family') == 'inet' and item.get('local') == address}
    if len(devices) != 1:
        raise ValueError('Podepsaná ZeroTier adresa není jednoznačně přiřazená notebooku.')
    device = devices.pop()
    if not isinstance(device, str) or not re.fullmatch(r'zt[a-zA-Z0-9]+', device):
        raise ValueError('Podepsaná ZeroTier adresa není na rozhraní ZeroTier.')
    for router in document['config']['nodes']:
        if router['id'] not in document['members']:
            continue
        route = json.loads(local_command(['/usr/sbin/ip', '-j', '-4', 'route', 'get', router['zeroTierAddress']]))
        if len(route) != 1 or route[0].get('dev') != device:
            raise ValueError('Routerový WireGuard endpoint není dostupný přes ZeroTier.')
    return device


def public_vpn_plan(plan):
    return {key: (bool(value) if key == 'currentConnection' else value)
            for key, value in plan.items() if key not in ['configHash', 'currentTopologyHash',
                                                          'proposedTopologyHash', 'rollbackConnection', 'update']}


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

    def access_status(self):
        credential_path = self.root / 'credential.json'
        public_path = self.root / 'federation-root.pub'
        can_bootstrap = (self.fleet / 'root.pem').exists() and (self.fleet / 'published.json').exists()
        if not credential_path.exists() or not public_path.exists():
            return {'state': 'unconnected', 'role': None, 'canBootstrapAdmin': can_bootstrap}
        try:
            envelope = f.read(credential_path)
            credential = f.verify(public_path.read_text(), envelope)
            common = {'schema', 'federationId', 'subject', 'role', 'issuedAt', 'expiresAt', 'serial'}
            expected = common if credential.get('schema') == CREDENTIAL_SCHEMA else common | {'enrollmentNonce', 'acceptBy'}
            if set(credential) != expected:
                raise ValueError('Neplatná pole pověření.')
            if credential['schema'] not in [CREDENTIAL_SCHEMA, USER_CREDENTIAL_SCHEMA] or credential['role'] not in ['administrator', 'user']:
                raise ValueError('Neplatný typ pověření.')
            if credential['role'] == 'user' and (credential['schema'] != USER_CREDENTIAL_SCHEMA
                    or not re.fullmatch('[a-f0-9]{64}', credential['enrollmentNonce'])
                    or type(credential['acceptBy']) not in [int, float]):
                raise ValueError('Neplatné uživatelské pověření.')
            if credential['subject'] != self.id or str(uuid.UUID(credential['serial'])) != credential['serial']:
                raise ValueError('Pověření patří jinému notebooku.')
            if type(credential['issuedAt']) not in [int, float] or credential['issuedAt'] > time.time() + 300:
                raise ValueError('Neplatný čas vydání pověření.')
            expires = credential['expiresAt']
            if expires is not None and (type(expires) not in [int, float] or expires <= time.time()):
                raise ValueError('Pověření vypršelo.')
            published = f.read(self.fleet / 'published.json')
            if published:
                document = f.validate_document(f.verify(public_path.read_text(), published))
                if document['federationId'] != credential['federationId']:
                    raise ValueError('Pověření patří jiné federaci.')
                notebook = next((item for item in document['config'].get('notebooks', [])
                                 if item['id'] == credential['subject']), None)
                if not notebook or notebook['role'] != credential['role']:
                    raise ValueError('Notebook není členem podepsané topologie se svou vydanou rolí.')
            return {'state': 'valid', 'role': credential['role'], 'canBootstrapAdmin': False,
                    'federationId': credential['federationId'], 'subject': credential['subject'],
                    'issuedAt': credential['issuedAt'], 'expiresAt': expires}
        except Exception:
            return {'state': 'invalid', 'role': None, 'canBootstrapAdmin': False,
                    'error': 'Podepsané pověření notebooku není platné.'}

    def bootstrap_admin_credential(self):
        if (self.root / 'credential.json').exists():
            raise ValueError('Pověření notebooku již existuje.')
        private = self.fleet / 'root.pem'
        published = f.read(self.fleet / 'published.json')
        if not private.exists() or not published:
            raise ValueError('Chybí stávající řídicí identita a publikovaná federace.')
        public_path = self.root / 'federation-root.pub'
        public = f.public_key(private)
        if public_path.exists() and public_path.read_text() != public:
            raise ValueError('Existující kotva notebooku patří jiné federaci.')
        wg_public = self.wireguard_identity()
        subnets = self.network_subnets()
        configured_address = self.configured_zerotier_address(subnets)
        with f.locked(self.fleet):
            document = f.validate_document(f.verify(public, f.read(self.fleet / 'published.json')))
            administrator = self.endpoint_notebook(
                document, self.id, self.local_name(), 'administrator', wg_public, subnets,
                zero_tier_address=configured_address)
            published, document = self.publish_notebooks(private, document, [administrator])
            self.write_wireguard_config(document)
        now = int(time.time())
        credential = {'schema': CREDENTIAL_SCHEMA, 'federationId': document['federationId'],
                      'subject': self.id, 'role': 'administrator', 'issuedAt': now,
                      'expiresAt': None, 'serial': str(uuid.uuid4())}
        envelope = f.sign(private, credential)
        # Publish the pinned verifier before the credential. If interrupted,
        # the same verified migration can safely finish on the next attempt.
        if not public_path.exists():
            f.atomic(public_path, public.encode())
        f.atomic(self.root / 'credential.json', envelope)
        status = self.access_status()
        if status['state'] != 'valid' or status['role'] != 'administrator':
            raise ValueError('Vydané pověření nelze ověřit.')
        return status

    def local_name(self):
        name = f.read(self.root / 'config.json', {}).get('name', socket.gethostname())
        name = name.strip() if isinstance(name, str) else ''
        return name[:80] if name else 'Notebook ' + self.id[:8]

    def wireguard_identity(self):
        path = self.root / 'wireguard.key'
        if not path.exists():
            private = bytearray(secrets.token_bytes(32))
            private[0] &= 248
            private[31] = (private[31] & 127) | 64
            f.atomic(path, (base64.b64encode(private).decode() + '\n').encode())
        try:
            private = base64.b64decode(path.read_text().strip(), validate=True)
        except (ValueError, OSError) as exc:
            raise ValueError('Privátní WireGuard klíč notebooku je poškozený.') from exc
        if len(private) != 32:
            raise ValueError('Privátní WireGuard klíč notebooku je poškozený.')
        der = bytes.fromhex('302e020100300506032b656e04220420') + private
        public_der = f.run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'], der)
        prefix = bytes.fromhex('302a300506032b656e032100')
        if len(public_der) != len(prefix) + 32 or not public_der.startswith(prefix):
            raise ValueError('Nelze odvodit veřejný WireGuard klíč notebooku.')
        return base64.b64encode(public_der[len(prefix):]).decode()

    def network_subnets(self):
        db = sqlite3.connect(self.data_dir / 'federation.db', timeout=10)
        try:
            row = db.execute("SELECT value FROM app_settings WHERE name='zerotier'").fetchone()
        finally:
            db.close()
        settings = json.loads(row[0]) if row else {}
        try:
            zero_tier = ipaddress.ip_network(settings['zeroTierSubnet'], strict=True)
            wireguard = ipaddress.ip_network(settings['wireguardSubnet'], strict=True)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError('Před přijetím notebooku nastavte IPv4 subnet ZeroTier i WireGuard.') from exc
        if (zero_tier.version != 4 or wireguard.version != 4
                or not 16 <= zero_tier.prefixlen <= 30 or not 16 <= wireguard.prefixlen <= 30
                or zero_tier.overlaps(wireguard)):
            raise ValueError('Notebooky vyžadují IPv4 subnet ZeroTier a WireGuard o velikosti /16 až /30.')
        return zero_tier, wireguard

    def configured_zerotier_address(self, subnets=None):
        address = f.read(self.root / 'config.json', {}).get('address')
        if not address:
            return None
        try:
            value = ipaddress.IPv4Address(address)
        except (TypeError, ValueError) as exc:
            raise ValueError('Nastavená synchronizační adresa notebooku není platná IPv4.') from exc
        zero_tier = (subnets or self.network_subnets())[0]
        if value not in zero_tier:
            raise ValueError('Synchronizační adresa notebooku neleží v nastaveném ZeroTier subnetu.')
        return str(value)

    @staticmethod
    def free_address(network, used):
        for candidate in network.hosts():
            if str(candidate) not in used:
                return str(candidate)
        raise ValueError('V adresním plánu už není volná adresa pro notebook.')

    def endpoint_notebook(self, document, notebook_id, name, role, wireguard_key, subnets,
                          zero_tier_address=None):
        existing = next((item for item in document['config'].get('notebooks', [])
                         if item['id'] == notebook_id), None)
        if existing and (existing['name'] != name or existing['role'] != role):
            raise ValueError('Notebook je již evidovaný s jiným názvem nebo rolí.')
        if existing and existing.get('wireguardKey') not in [None, wireguard_key]:
            raise ValueError('Notebook je již evidovaný s jiným WireGuard klíčem.')
        used_zt = {node['zeroTierAddress'] for node in document['config']['nodes'] if node['zeroTierAddress']}
        used_wg = {node['wireguardAddress'] for node in document['config']['nodes'] if node['wireguardAddress']}
        for item in document['config'].get('notebooks', []):
            if item['id'] != notebook_id:
                if item['zeroTierAddress']:
                    used_zt.add(item['zeroTierAddress'])
                if item['wireguardAddress']:
                    used_wg.add(item['wireguardAddress'])
        zero_tier = zero_tier_address or (existing.get('zeroTierAddress') if existing else None)
        if zero_tier:
            try:
                zero_tier = str(ipaddress.IPv4Address(zero_tier))
            except ValueError as exc:
                raise ValueError('ZeroTier adresa notebooku není platná IPv4.') from exc
            if ipaddress.IPv4Address(zero_tier) not in subnets[0]:
                raise ValueError('ZeroTier adresa notebooku neleží v nastaveném subnetu.')
            if zero_tier in used_zt:
                raise ValueError('ZeroTier adresa notebooku je už použitá jiným členem federace.')
        wireguard = existing.get('wireguardAddress') if existing else None
        return {'id': notebook_id, 'name': name, 'role': role,
                'zeroTierAddress': zero_tier or self.free_address(subnets[0], used_zt),
                'wireguardAddress': wireguard or self.free_address(subnets[1], used_wg),
                'wireguardKey': wireguard_key}

    def reconcile_administrator_endpoint(self, address):
        if self.access_status().get('role') != 'administrator':
            return False
        private = self.fleet / 'root.pem'
        published = f.read(self.fleet / 'published.json')
        if not private.exists() or not published:
            raise ValueError('Chybí řídicí identita nebo publikovaná revize.')
        subnets = self.network_subnets()
        if str(ipaddress.IPv4Address(address)) != self.configured_zerotier_address(subnets):
            raise ValueError('Synchronizační adresa notebooku se během aktualizace změnila.')
        public = f.public_key(private)
        with f.locked(self.fleet):
            document = f.validate_document(f.verify(public, f.read(self.fleet / 'published.json')))
            existing = next((item for item in document['config'].get('notebooks', [])
                             if item['id'] == self.id and item['role'] == 'administrator'), None)
            if not existing:
                raise ValueError('Administrátorský notebook chybí v podepsané topologii.')
            administrator = self.endpoint_notebook(
                document, self.id, existing['name'], 'administrator', self.wireguard_identity(), subnets,
                zero_tier_address=address)
            if administrator == existing:
                return False
            _, updated = self.publish_notebooks(private, document, [administrator])
            self.write_wireguard_config(updated)
            return True

    def publish_notebooks(self, private, document, requested):
        notebooks = [dict(item, wireguardKey=item.get('wireguardKey'))
                     for item in document['config'].get('notebooks', [])]
        for item in requested:
            existing = next((current for current in notebooks if current['id'] == item['id']), None)
            if existing:
                notebooks[notebooks.index(existing)] = item
            else:
                notebooks.append(item)
        config = f.normalize_with_notebook_endpoints(document['config']['nodes'],
                                                     document['config']['networkId'], notebooks)
        published = f.snapshot(self.fleet, config, document['members'])
        public = f.public_key(private)
        return published, f.validate_document(f.verify(public, published))

    def revoke_user_notebook(self, notebook_id):
        if self.access_status().get('role') != 'administrator':
            raise ValueError('Odvolání notebooku vyžaduje administrátorské pověření.')
        if not isinstance(notebook_id, str) or not re.fullmatch('[a-f0-9]{64}', notebook_id):
            raise ValueError('Neplatné ID notebooku.')
        private = self.fleet / 'root.pem'
        if not private.exists():
            raise ValueError('Chybí řídicí identita nebo publikovaná revize.')
        with f.locked(self.fleet):
            public = f.public_key(private)
            document = f.validate_document(f.verify(public, f.read(self.fleet / 'published.json')))
            target = next((item for item in document['config'].get('notebooks', [])
                           if item['id'] == notebook_id), None)
            if not target:
                raise ValueError('Notebook už není členem podepsané topologie.')
            if target['role'] != 'user':
                raise ValueError('Administrátorský notebook nelze bezpečně odvolat touto operací.')
            notebooks = [item for item in document['config']['notebooks'] if item['id'] != notebook_id]
            config = f.normalize_with_notebook_endpoints(
                document['config']['nodes'], document['config']['networkId'], notebooks)
            published = f.snapshot(self.fleet, config, document['members'])
            updated = f.validate_document(f.verify(public, published))
            # The administrator remains an endpoint; regenerate its local source
            # configuration so it is bound to the same signed revision.
            self.write_wireguard_config(updated)
            return {'id': notebook_id, 'name': target['name'], 'revision': updated['revision']}

    def topology_update_export(self):
        if self.access_status().get('role') != 'administrator':
            raise ValueError('Export aktualizace vyžaduje administrátorské pověření.')
        published = f.read(self.fleet / 'published.json')
        public_path = self.root / 'federation-root.pub'
        if not published or not public_path.exists():
            raise ValueError('Chybí podepsaná topologie nebo veřejná kotva federace.')
        f.validate_document(f.verify(public_path.read_text(), published))
        return json.dumps({'schema': TOPOLOGY_UPDATE_SCHEMA,
                           'rootPublic': public_path.read_text(), 'published': published})

    def validate_topology_update(self, raw):
        if self.access_status().get('role') != 'user':
            raise ValueError('Aktualizace topologie je určena uživatelskému notebooku s platným členstvím.')
        try:
            update = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError('Aktualizační balíček není platný JSON.') from exc
        if (not isinstance(update, dict) or set(update) != {'schema', 'rootPublic', 'published'}
                or update.get('schema') != TOPOLOGY_UPDATE_SCHEMA):
            raise ValueError('Neplatný aktualizační balíček topologie.')
        public_path = self.root / 'federation-root.pub'
        if not public_path.exists() or update['rootPublic'] != public_path.read_text():
            raise ValueError('Aktualizace používá jinou kotvu federace.')
        current_envelope = f.read(self.fleet / 'published.json')
        if not current_envelope:
            raise ValueError('Chybí současná podepsaná topologie.')
        current = f.validate_document(f.verify(update['rootPublic'], current_envelope))
        proposed = f.validate_document(f.verify(update['rootPublic'], update['published']))
        if proposed['federationId'] != current['federationId']:
            raise ValueError('Aktualizace patří jiné federaci.')
        if proposed['revision'] <= current['revision']:
            raise ValueError('Aktualizace musí obsahovat novější revizi.')
        if proposed['revision'] == current['revision'] + 1 and proposed['previous'] != f.digest(current):
            raise ValueError('Nová revize nenavazuje na současnou topologii.')
        credential = f.verify(update['rootPublic'], f.read(self.root / 'credential.json'))
        if credential.get('subject') != self.id or credential.get('role') != 'user':
            raise ValueError('Pověření nepatří tomuto uživatelskému notebooku.')
        notebook = next((item for item in f.notebook_endpoints(proposed) if item['id'] == self.id), None)
        if notebook and (notebook['role'] != 'user' or notebook['wireguardKey'] != self.wireguard_identity()):
            raise ValueError('Aktualizace mění roli nebo WireGuard identitu tohoto notebooku.')
        return update, current_envelope, current, proposed, notebook

    @staticmethod
    def routes_for(document):
        routes = []
        for router in document['config']['nodes']:
            if router['id'] in document['members']:
                routes.extend([router['wireguardAddress'] + '/32'] + router['lanCidrs'])
        return sorted(set(routes), key=lambda value: (ipaddress.ip_network(value).network_address,
                                                       ipaddress.ip_network(value).prefixlen))

    def wireguard_config(self, document, notebook):
        lines = ['[Interface]', 'PrivateKey = ' + (self.root / 'wireguard.key').read_text().strip(),
                 'Address = ' + notebook['wireguardAddress'] + '/32']
        for router in document['config']['nodes']:
            member = document['members'].get(router['id'])
            if not member:
                continue
            allowed = [router['wireguardAddress'] + '/32'] + router['lanCidrs']
            lines.extend(['', '[Peer]', 'PublicKey = ' + member['wireguardKey'],
                          'Endpoint = ' + router['zeroTierAddress'] + ':' + str(f.WG_PORT),
                          'AllowedIPs = ' + ', '.join(allowed), 'PersistentKeepalive = 25'])
        return ('\n'.join(lines) + '\n').encode()

    def topology_refresh_plan(self, raw):
        update, current_envelope, current, proposed, notebook = self.validate_topology_update(raw)
        required = ['/usr/bin/nmcli', '/usr/bin/pkexec'] + (['/usr/sbin/ip'] if notebook else [])
        if not all(Path(path).exists() for path in required):
            raise ValueError('Aktualizace topologie vyžaduje NetworkManager a polkit.')
        managed = nmcli_connections()
        current_routes = self.routes_for(current)
        proposed_routes = self.routes_for(proposed) if notebook else []
        kind = 'update' if notebook else 'revoked'
        plan = {'id': secrets.token_hex(24), 'expiresAt': time.time() + VPN_PLAN_TTL,
                'kind': kind, 'currentRevision': current['revision'], 'revision': proposed['revision'],
                'currentTopologyHash': f.digest(current_envelope),
                'proposedTopologyHash': f.digest(update['published']), 'update': update,
                'routes': proposed_routes, 'addedRoutes': sorted(set(proposed_routes) - set(current_routes)),
                'removedRoutes': sorted(set(current_routes) - set(proposed_routes)),
                'currentConnection': managed.get(VPN_CONNECTION),
                'rollbackConnection': managed.get(VPN_BACKUP)}
        if notebook:
            forwarding = self.forwarding_state()
            underlay = verify_underlay(notebook['zeroTierAddress'], proposed)
            config = self.wireguard_config(proposed, notebook)
            f.atomic(self.root / 'wireguard-refresh.conf', config)
            plan.update({'configHash': hashlib.sha256(config).hexdigest(),
                         'connectionName': VPN_CONNECTION, 'interfaceName': VPN_INTERFACE,
                         'address': notebook['wireguardAddress'] + '/32',
                         'zeroTierAddress': notebook['zeroTierAddress'], 'underlayDevice': underlay,
                         'forwarding': forwarding,
                         'steps': [
                             'Znovu ověřit podpis, federaci, návaznost a místní WireGuard identitu.',
                             'Přes polkit vytvořit nový NetworkManager profil z nové revize.',
                             'Předchozí profil zachovat jako obnovovací kopii.',
                             'Ověřit adresu a routy; aktivní systémový forwarding zobrazit jako varování.',
                             'Při selhání obnovit předchozí profil i podepsanou revizi.',
                         ]})
        else:
            (self.root / 'wireguard-refresh.conf').unlink(missing_ok=True)
            plan['steps'] = [
                'Znovu ověřit podpis, federaci a návaznost odvolávající revize.',
                'Odstranit aktivní spravovaný VPN profil i jeho federovanou rollback kopii.',
                'Přijmout odvolání bez smazání místní TLS nebo WireGuard identity.',
            ]
        f.atomic(self.root / 'topology-refresh-plan.json', plan)
        return public_vpn_plan(plan)

    def write_wireguard_config(self, document):
        notebook = next((item for item in f.notebook_endpoints(document) if item['id'] == self.id), None)
        if not notebook or notebook['wireguardKey'] != self.wireguard_identity():
            raise ValueError('Podepsaná topologie neobsahuje síťový endpoint tohoto notebooku.')
        f.atomic(self.root / 'wireguard.conf', self.wireguard_config(document, notebook))

    def wireguard_endpoint(self):
        status = self.access_status()
        if status.get('state') != 'valid' or status.get('role') not in ['administrator', 'user']:
            raise ValueError('Instalace VPN vyžaduje platné pověření člena federace.')
        published = f.read(self.fleet / 'published.json')
        public_path = self.root / 'federation-root.pub'
        if not published or not public_path.exists():
            raise ValueError('Chybí podepsaná topologie nebo veřejná kotva federace.')
        document = f.validate_document(f.verify(public_path.read_text(), published))
        notebook = next((item for item in f.notebook_endpoints(document) if item['id'] == self.id), None)
        if not notebook or notebook['wireguardKey'] != self.wireguard_identity():
            raise ValueError('Podepsaná topologie neobsahuje síťový endpoint tohoto notebooku.')
        config = self.root / 'wireguard.conf'
        if not config.exists():
            self.write_wireguard_config(document)
        return document, notebook, config, self.routes_for(document)

    @staticmethod
    def forwarding_state():
        values = {}
        for name, path in [('ipv4', Path('/proc/sys/net/ipv4/ip_forward')),
                           ('ipv6', Path('/proc/sys/net/ipv6/conf/all/forwarding'))]:
            try:
                values[name] = path.read_text().strip() == '1'
            except OSError:
                values[name] = None
        return values

    def vpn_plan(self):
        if not all(Path(path).exists() for path in ['/usr/bin/nmcli', '/usr/bin/pkexec', '/usr/sbin/ip']):
            raise ValueError('Instalace VPN vyžaduje NetworkManager, polkit a nástroj ip.')
        document, notebook, config, routes = self.wireguard_endpoint()
        forwarding = self.forwarding_state()
        underlay = verify_underlay(notebook['zeroTierAddress'], document)
        current = nmcli_connections().get(VPN_CONNECTION)
        plan = {'id': secrets.token_hex(24), 'expiresAt': time.time() + VPN_PLAN_TTL,
                'revision': document['revision'], 'configHash': hashlib.sha256(config.read_bytes()).hexdigest(),
                'connectionName': VPN_CONNECTION, 'interfaceName': VPN_INTERFACE,
                'address': notebook['wireguardAddress'] + '/32',
                'zeroTierAddress': notebook['zeroTierAddress'], 'underlayDevice': underlay, 'routes': routes,
                'currentConnection': current, 'forwarding': forwarding,
                'steps': [
                    'Ověřit podepsanou revizi a lokální WireGuard klíč; stav IP forwardingu zaznamenat.',
                    'Přes polkit vytvořit nový NetworkManager profil bez výchozí trasy.',
                    'Předchozí profil zachovat jako obnovovací kopii.',
                    'Aktivovat rozhraní tf_notebook a ověřit adresu i host routy.',
                    'Při selhání odstranit nový profil a automaticky obnovit předchozí.',
                ]}
        f.atomic(self.root / 'vpn-plan.json', plan)
        return public_vpn_plan(plan)

    def vpn_install(self, plan_id):
        plan = f.read(self.root / 'vpn-plan.json')
        document, notebook, config, routes = self.wireguard_endpoint()
        if (not plan or plan.get('id') != plan_id or plan.get('expiresAt', 0) < time.time()
                or plan.get('revision') != document['revision']
                or plan.get('configHash') != hashlib.sha256(config.read_bytes()).hexdigest()
                or plan.get('address') != notebook['wireguardAddress'] + '/32' or plan.get('routes') != routes):
            raise ValueError('Plán instalace VPN chybí, vypršel nebo se konfigurace změnila.')
        return self.activate_vpn(plan, document, notebook, config, routes,
                                 self.root / 'vpn-plan.json')

    def activate_vpn(self, plan, document, notebook, config, routes, plan_path,
                     commit=None, restore=None):
        if plan.get('underlayDevice') != verify_underlay(notebook['zeroTierAddress'], document):
            raise ValueError('ZeroTier podklad se od vytvoření plánu změnil.')
        before = nmcli_connections()
        if (plan.get('currentConnection') != before.get(VPN_CONNECTION)
                or ('rollbackConnection' in plan
                    and plan.get('rollbackConnection') != before.get(VPN_BACKUP))):
            raise ValueError('Spravované VPN profily se od vytvoření plánu změnily.')
        current = before.get(VPN_CONNECTION, {}).get('uuid')
        new_uuid = None
        backup_uuid = None
        committed = False
        try:
            stale_backup = before.get(VPN_BACKUP, {}).get('uuid')
            if stale_backup:
                privileged_nmcli(['connection', 'delete', 'uuid', stale_backup])
            if current:
                backup_uuid = current
                privileged_nmcli(['connection', 'modify', 'uuid', current, 'connection.id', VPN_BACKUP])
            before_import = nmcli_uuids()
            privileged_nmcli(['connection', 'import', 'type', 'wireguard', 'file', str(config)])
            after_import = nmcli_uuids()
            created = after_import - before_import
            if len(created) != 1:
                raise ValueError('NetworkManager nepotvrdil právě jeden nový profil.')
            new_uuid = created.pop()
            privileged_nmcli(['connection', 'modify', 'uuid', new_uuid,
                              'connection.id', VPN_CONNECTION, 'connection.interface-name', VPN_INTERFACE,
                              'connection.autoconnect', 'yes', 'ipv4.never-default', 'yes',
                              'ipv6.never-default', 'yes', 'wireguard.peer-routes', 'yes'])
            privileged_nmcli(['connection', 'up', 'uuid', new_uuid])
            verify_vpn(notebook['wireguardAddress'], routes)
            if commit:
                commit()
                committed = True
            receipt = {'state': 'installed', 'revision': document['revision'], 'installedAt': time.time(),
                       'activeUuid': new_uuid, 'backupUuid': backup_uuid, 'address': plan['address'],
                       'routes': routes, 'forwarding': self.forwarding_state()}
            f.atomic(self.root / 'vpn-state.json', receipt)
            plan_path.unlink(missing_ok=True)
            return self.vpn_status()
        except Exception as error:
            rollback_errors = []
            if committed and restore:
                try:
                    restore()
                except Exception as rollback_error:
                    rollback_errors.append(str(rollback_error))
            if new_uuid:
                try:
                    privileged_nmcli(['connection', 'delete', 'uuid', new_uuid])
                except Exception as rollback_error:
                    rollback_errors.append(str(rollback_error))
            if backup_uuid:
                try:
                    privileged_nmcli(['connection', 'modify', 'uuid', backup_uuid,
                                      'connection.id', VPN_CONNECTION])
                    privileged_nmcli(['connection', 'up', 'uuid', backup_uuid])
                except Exception as rollback_error:
                    rollback_errors.append(str(rollback_error))
            f.atomic(self.root / 'vpn-state.json', {'state': 'error', 'failedAt': time.time(),
                     'error': 'Instalace VPN selhala.' + (' Automatická obnova také selhala.' if rollback_errors else ''),
                     'rollbackComplete': not rollback_errors})
            raise ValueError('Instalace VPN selhala; ' + ('předchozí profil byl obnoven.' if not rollback_errors
                             else 'automatickou obnovu se nepodařilo dokončit.')) from error

    def topology_refresh_apply(self, plan_id):
        plan_path = self.root / 'topology-refresh-plan.json'
        plan = f.read(plan_path)
        if not plan or plan.get('id') != plan_id or plan.get('expiresAt', 0) < time.time():
            raise ValueError('Plán aktualizace topologie chybí nebo vypršel.')
        update, current_envelope, current, proposed, notebook = self.validate_topology_update(
            json.dumps(plan.get('update')))
        if (plan.get('currentRevision') != current['revision'] or plan.get('revision') != proposed['revision']
                or plan.get('currentTopologyHash') != f.digest(current_envelope)
                or plan.get('proposedTopologyHash') != f.digest(update['published'])
                or plan.get('kind') != ('update' if notebook else 'revoked')):
            raise ValueError('Topologie se od vytvoření plánu změnila.')
        if not notebook:
            managed = nmcli_connections()
            if (plan.get('currentConnection') != managed.get(VPN_CONNECTION)
                    or plan.get('rollbackConnection') != managed.get(VPN_BACKUP)):
                raise ValueError('Spravované VPN profily se od vytvoření plánu změnily.')
            removed = []
            # Delete the rollback copy first: if removing the active profile
            # then fails, connectivity remains on the current known profile.
            for name in [VPN_BACKUP, VPN_CONNECTION]:
                profile = managed.get(name)
                if profile:
                    privileged_nmcli(['connection', 'delete', 'uuid', profile['uuid']])
                    removed.append(profile['uuid'])
            f.atomic(self.fleet / 'published.json', update['published'])
            f.atomic(self.root / 'vpn-state.json', {
                'state': 'revoked', 'revision': proposed['revision'], 'revokedAt': time.time(),
                'managedProfilesRemoved': len(removed),
            })
            (self.root / 'vpn-plan.json').unlink(missing_ok=True)
            (self.root / 'vpn-diagnostics.json').unlink(missing_ok=True)
            (self.root / 'wireguard-refresh.conf').unlink(missing_ok=True)
            plan_path.unlink(missing_ok=True)
            return {'access': self.access_status(), 'vpn': self.vpn_status(),
                    'revision': proposed['revision'], 'kind': 'revoked'}

        config = self.root / 'wireguard-refresh.conf'
        routes = self.routes_for(proposed)
        if (not config.exists() or plan.get('configHash') != hashlib.sha256(config.read_bytes()).hexdigest()
                or plan.get('address') != notebook['wireguardAddress'] + '/32'
                or plan.get('routes') != routes):
            raise ValueError('Připravená VPN konfigurace se změnila.')
        old_config = (self.root / 'wireguard.conf').read_bytes() if (self.root / 'wireguard.conf').exists() else None

        def commit():
            try:
                f.atomic(self.root / 'wireguard.conf', config.read_bytes())
                f.atomic(self.fleet / 'published.json', update['published'])
            except Exception:
                if old_config is None:
                    (self.root / 'wireguard.conf').unlink(missing_ok=True)
                else:
                    f.atomic(self.root / 'wireguard.conf', old_config)
                f.atomic(self.fleet / 'published.json', current_envelope)
                raise

        def restore():
            if old_config is None:
                (self.root / 'wireguard.conf').unlink(missing_ok=True)
            else:
                f.atomic(self.root / 'wireguard.conf', old_config)
            f.atomic(self.fleet / 'published.json', current_envelope)

        vpn = self.activate_vpn(plan, proposed, notebook, config, routes, plan_path,
                                commit=commit, restore=restore)
        config.unlink(missing_ok=True)
        (self.root / 'vpn-diagnostics.json').unlink(missing_ok=True)
        return {'access': self.access_status(), 'vpn': vpn,
                'revision': proposed['revision'], 'kind': 'update'}

    def vpn_rollback(self):
        if self.access_status().get('state') != 'valid':
            raise ValueError('Návrat VPN vyžaduje platné pověření člena federace.')
        state = f.read(self.root / 'vpn-state.json', {})
        active = state.get('activeUuid')
        backup = state.get('backupUuid')
        if state.get('state') != 'installed' or not valid_uuid(active) or (backup and not valid_uuid(backup)):
            raise ValueError('Není k dispozici ověřený stav pro návrat VPN.')
        if backup:
            try:
                privileged_nmcli(['connection', 'modify', 'uuid', active, 'connection.id', VPN_REPLACED])
                privileged_nmcli(['connection', 'modify', 'uuid', backup, 'connection.id', VPN_CONNECTION])
                privileged_nmcli(['connection', 'up', 'uuid', backup])
                privileged_nmcli(['connection', 'delete', 'uuid', active])
            except Exception as error:
                try:
                    privileged_nmcli(['connection', 'modify', 'uuid', backup, 'connection.id', VPN_BACKUP])
                    privileged_nmcli(['connection', 'modify', 'uuid', active, 'connection.id', VPN_CONNECTION])
                    privileged_nmcli(['connection', 'up', 'uuid', active])
                except Exception:
                    f.atomic(self.root / 'vpn-state.json', {**state, 'state': 'error',
                             'error': 'Návrat VPN i obnova aktivního profilu selhaly.',
                             'rollbackComplete': False, 'failedAt': time.time()})
                    raise ValueError('Návrat VPN selhal a aktivní profil se nepodařilo obnovit.') from error
                raise ValueError('Návrat VPN selhal; aktivní profil byl zachován.') from error
        else:
            privileged_nmcli(['connection', 'delete', 'uuid', active])
        result = {**state, 'state': 'rolled_back', 'rolledBackAt': time.time(), 'activeUuid': backup,
                  'backupUuid': None}
        f.atomic(self.root / 'vpn-state.json', result)
        return self.vpn_status()

    def vpn_status(self):
        state = f.read(self.root / 'vpn-state.json', {'state': 'ready' if (self.root / 'wireguard.conf').exists() else 'unconfigured'})
        result = {key: value for key, value in state.items() if key not in ['activeUuid', 'backupUuid']}
        diagnostics = f.read(self.root / 'vpn-diagnostics.json')
        if diagnostics:
            result['diagnostics'] = diagnostics
        return result

    def vpn_diagnostics(self):
        document, notebook, _config, routes = self.wireguard_endpoint()
        checked_at = time.time()
        try:
            managed = nmcli_connections().get(VPN_CONNECTION)
            active = nmcli_active_uuids()
            profile = 'active' if managed and managed['uuid'] in active else ('inactive' if managed else 'missing')
        except (OSError, ValueError, subprocess.SubprocessError):
            profile = 'unknown'

        try:
            links = json.loads(local_command(['/usr/sbin/ip', '-j', 'link', 'show', 'dev', VPN_INTERFACE]))
            interface_present = len(links) == 1 and links[0].get('ifname') == VPN_INTERFACE
        except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError):
            interface_present = None
        try:
            addresses = json.loads(local_command(['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev', VPN_INTERFACE]))
            assigned = {item.get('local') for link in addresses for item in link.get('addr_info', [])
                        if item.get('family') == 'inet'}
            address_assigned = notebook['wireguardAddress'] in assigned
        except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError):
            address_assigned = None

        missing_routes = []
        unknown_routes = []
        for cidr in routes:
            network = ipaddress.ip_network(cidr)
            destination = network.network_address + (1 if network.num_addresses > 1 else 0)
            try:
                found = json.loads(local_command(['/usr/sbin/ip', '-j', '-4', 'route', 'get', str(destination)]))
                if len(found) != 1 or found[0].get('dev') != VPN_INTERFACE:
                    missing_routes.append(cidr)
            except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError):
                unknown_routes.append(cidr)

        handshakes = wireguard_handshakes()
        handshake_available = handshakes is not None
        handshakes = handshakes or {}

        peers = [router for router in document['config']['nodes'] if router['id'] in document['members']]
        with ThreadPoolExecutor(max_workers=max(1, min(8, len(peers)))) as pool:
            jobs = {router['id']: pool.submit(f.ping_batch, router['wireguardAddress'], VPN_INTERFACE)
                    for router in peers}
            nodes = {}
            for router in peers:
                timestamp = handshakes.get(document['members'][router['id']]['wireguardKey'], 0)
                if not handshake_available:
                    handshake_state = 'unknown'
                elif timestamp <= 0:
                    handshake_state = 'never'
                elif checked_at - timestamp <= VPN_HANDSHAKE_MAX_AGE:
                    handshake_state = 'recent'
                else:
                    handshake_state = 'stale'
                nodes[router['id']] = {
                    'name': router['name'], 'address': router['wireguardAddress'],
                    'handshakeState': handshake_state,
                    'handshakeAt': timestamp if timestamp > 0 else None,
                    'wireguard': jobs[router['id']].result(),
                }
        result = {
            'revision': document['revision'], 'state': 'complete', 'checkedAt': checked_at,
            'profile': profile, 'interfacePresent': interface_present,
            'addressAssigned': address_assigned,
            'routesExpected': len(routes),
            'routesActive': len(routes) - len(missing_routes) - len(unknown_routes),
            'missingRoutes': missing_routes, 'unknownRoutes': unknown_routes,
            'forwarding': self.forwarding_state(), 'nodes': nodes,
        }
        f.atomic(self.root / 'vpn-diagnostics.json', result)
        return result

    def enrollment_request(self, name):
        if self.access_status()['state'] == 'valid':
            raise ValueError('Notebook již má platné pověření.')
        name = name.strip()
        if not 0 < len(name) <= 80:
            raise ValueError('Vyplňte název notebooku (nejvýše 80 znaků).')
        pending = {'nonce': secrets.token_hex(32), 'createdAt': int(time.time())}
        f.atomic(self.root / 'pending-enrollment.json', pending)
        payload = {'schema': ENROLLMENT_SCHEMA, 'subject': self.id, 'name': name,
                   'nonce': pending['nonce'], 'createdAt': pending['createdAt'],
                   'wireguardKey': self.wireguard_identity()}
        return {'cert': self.cert, 'signed': f.sign(self.root / 'key.pem', payload)}

    def issue_user_invitation(self, raw):
        if self.access_status().get('role') != 'administrator':
            raise ValueError('Vydání pozvánky vyžaduje administrátorské pověření.')
        request = json.loads(raw)
        if set(request) != {'cert', 'signed'} or fingerprint(request['cert']) == self.id:
            raise ValueError('Neplatná žádost notebooku.')
        public = f.run(['openssl', 'x509', '-pubkey', '-noout'], request['cert'].encode()).decode()
        payload = f.verify(public, request['signed'])
        if (set(payload) != {'schema', 'subject', 'name', 'nonce', 'createdAt', 'wireguardKey'} or payload['schema'] != ENROLLMENT_SCHEMA
                or payload['subject'] != fingerprint(request['cert']) or not re.fullmatch('[a-f0-9]{64}', payload['nonce'])
                or not isinstance(payload['name'], str) or not 0 < len(payload['name']) <= 80
                or not isinstance(payload['wireguardKey'], str)
                or len(base64.b64decode(payload['wireguardKey'], validate=True)) != 32
                or type(payload['createdAt']) not in [int, float] or not 0 <= time.time() - payload['createdAt'] <= ENROLLMENT_TTL):
            raise ValueError('Žádost notebooku je neplatná nebo vypršela.')
        private = self.fleet / 'root.pem'
        if not private.exists():
            raise ValueError('Chybí řídicí identita nebo publikovaná revize.')
        subnets = self.network_subnets()
        administrator_key = self.wireguard_identity()
        with f.locked(self.fleet):
            published = f.read(self.fleet / 'published.json')
            if not published:
                raise ValueError('Chybí řídicí identita nebo publikovaná revize.')
            root_public = f.public_key(private)
            document = f.validate_document(f.verify(root_public, published))
            administrator = self.endpoint_notebook(document, self.id, self.local_name(), 'administrator',
                                                   administrator_key, subnets,
                                                   zero_tier_address=self.configured_zerotier_address(subnets))
            allocation_document = json.loads(f.encode(document))
            allocation_notebooks = [item for item in allocation_document['config'].get('notebooks', [])
                                    if item['id'] != self.id]
            allocation_notebooks.append(administrator)
            allocation_document['config']['notebooks'] = allocation_notebooks
            requested = self.endpoint_notebook(allocation_document, payload['subject'], payload['name'], 'user',
                                               payload['wireguardKey'], subnets)
            published, document = self.publish_notebooks(private, document, [administrator, requested])
            self.write_wireguard_config(document)
            now = int(time.time())
            credential = {'schema': USER_CREDENTIAL_SCHEMA, 'federationId': document['federationId'],
                          'subject': payload['subject'], 'role': 'user', 'issuedAt': now,
                          'expiresAt': now + 365 * 24 * 3600, 'serial': str(uuid.uuid4()),
                          'enrollmentNonce': payload['nonce'], 'acceptBy': now + ENROLLMENT_TTL}
            return {'schema': INVITATION_SCHEMA, 'rootPublic': root_public, 'published': published,
                    'credential': f.sign(private, credential)}

    def accept_user_invitation(self, raw):
        if self.access_status()['state'] == 'valid' or (self.fleet / 'root.pem').exists():
            raise ValueError('Notebook již má pověření nebo řídicí identitu.')
        invitation = json.loads(raw)
        if set(invitation) != {'schema', 'rootPublic', 'published', 'credential'} or invitation['schema'] != INVITATION_SCHEMA:
            raise ValueError('Neplatná pozvánka notebooku.')
        credential = f.verify(invitation['rootPublic'], invitation['credential'])
        document = f.validate_document(f.verify(invitation['rootPublic'], invitation['published']))
        pending = f.read(self.root / 'pending-enrollment.json')
        notebook = next((item for item in document['config'].get('notebooks', [])
                         if item['id'] == self.id), None)
        if (not pending or credential.get('schema') != USER_CREDENTIAL_SCHEMA or credential.get('role') != 'user'
                or credential.get('subject') != self.id or credential.get('federationId') != document['federationId']
                or credential.get('enrollmentNonce') != pending.get('nonce') or time.time() > credential.get('acceptBy', 0)
                or not notebook or notebook['role'] != 'user'):
            raise ValueError('Pozvánka neodpovídá této platné žádosti notebooku.')
        if notebook.get('wireguardKey') != self.wireguard_identity():
            raise ValueError('Pozvánka obsahuje jiný WireGuard klíč notebooku.')
        self.write_wireguard_config(document)
        # All signatures and bindings are checked before publishing any file.
        for path, value in [(self.root / 'federation-root.pub', invitation['rootPublic'].encode()),
                            (self.fleet / 'root.pub', invitation['rootPublic'].encode())]:
            if path.exists() and path.read_bytes() != value:
                raise ValueError('Notebook již používá jinou kotvu federace.')
        f.atomic(self.root / 'federation-root.pub', invitation['rootPublic'].encode())
        f.atomic(self.fleet / 'root.pub', invitation['rootPublic'].encode())
        f.atomic(self.fleet / 'published.json', invitation['published'])
        f.atomic(self.root / 'credential.json', invitation['credential'])
        status = self.access_status()
        if status.get('role') != 'user':
            raise ValueError('Přijaté uživatelské pověření nelze ověřit.')
        (self.root / 'pending-enrollment.json').unlink(missing_ok=True)
        return status

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
                'access': self.access_status(),
                'config': f.read(self.root / 'config.json', {}), 'peers': sorted(items, key=lambda p: p.get('name', p['id'])),
                'updatedAt': runtime.get('updatedAt'), 'error': runtime.get('error'),
                'configurationVersion': f.digest(snapshot['data']),
                'invitation': json.dumps({'name': f.read(self.root / 'config.json', {}).get('name', socket.gethostname()),
                                          'address': f.read(self.root / 'config.json', {}).get('address', ''), 'cert': self.cert})}

    def public_status(self):
        result = self.status()
        result['vpn'] = self.vpn_status()
        if result['access'].get('role') != 'administrator':
            result['peers'] = []
            result['invitation'] = ''
            result['configurationVersion'] = ''
            result['config'] = {'enabled': bool(result['config'].get('enabled'))}
        return result


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


def zerotier_interface(address):
    ipaddress.IPv4Address(address)
    for link in json.loads(f.run(['ip', '-j', '-4', 'address', 'show'])):
        for entry in link.get('addr_info', []):
            if entry.get('local') == address and entry.get('scope') != 'host':
                if not isinstance(link.get('ifname'), str) or not re.fullmatch(r'zt[a-zA-Z0-9]+', link['ifname']):
                    raise ValueError('Synchronizace notebooků vyžaduje stabilní IPv4 adresu rozhraní ZeroTier, nikoli adresu místní LAN.')
                return ipaddress.ip_network('%s/%s' % (address, entry['prefixlen']), strict=False)
    raise ValueError('Vyberte IPv4 adresu aktivního rozhraní ZeroTier notebooku.')


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


def local_socket_path():
    override = os.environ.get('TF_BACKEND_SOCKET')
    if override:
        return Path(override)
    runtime = os.environ.get('XDG_RUNTIME_DIR')
    if not runtime:
        raise ValueError('Chybí XDG_RUNTIME_DIR pro lokální rozhraní backendu.')
    return Path(runtime) / 'turris-federation' / 'backend.sock'


def make_local_server(store, path=None):
    path = Path(path or local_socket_path())
    if path.parent.is_symlink():
        raise ValueError('Adresář lokálního socketu nesmí být symbolický odkaz.')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.stat().st_uid != os.getuid():
        raise ValueError('Adresář lokálního socketu patří jinému uživateli.')
    os.chmod(path.parent, 0o700)
    if path.exists() or path.is_socket():
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.2)
            probe.connect(str(path))
        except OSError:
            path.unlink(missing_ok=True)
        else:
            raise ValueError('Lokální backend již běží.')
        finally:
            probe.close()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                if hasattr(socket, 'SO_PEERCRED'):
                    pid, uid, _ = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid != os.getuid() or pid <= 0:
                        raise ValueError('Nepovolený místní klient.')
                raw = self.rfile.readline(LOCAL_LIMIT + 1)
                if not raw.endswith(b'\n') or len(raw) > LOCAL_LIMIT:
                    raise ValueError('Neplatný místní požadavek.')
                request = json.loads(raw)
                if request != {'action': 'status'}:
                    raise ValueError('Lokální rozhraní je pouze pro čtení stavu.')
                response = {'ok': True, 'status': store.public_status(), 'backend': {'running': True, 'pid': os.getpid()}}
            except Exception as error:
                response = {'ok': False, 'error': str(error) if type(error) is ValueError else 'Neplatný místní požadavek.'}
            self.wfile.write(f.encode(response) + b'\n')

    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True

    server = Server(str(path), Handler)
    os.chmod(path, 0o600)
    server.socket_path = path
    return server


def serve_sync(store, stopped):
    config = f.read(store.root / 'config.json')
    address = config['address']
    network = zerotier_interface(address)
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


def serve(store):
    local = make_local_server(store)
    local_worker = threading.Thread(target=local.serve_forever, daemon=True)
    local_worker.start()
    stopped = threading.Event()
    try:
        config = f.read(store.root / 'config.json', {})
        if config.get('enabled'):
            serve_sync(store, stopped)
        else:
            f.atomic(store.root / 'runtime.json', {'updatedAt': time.time(), 'state': 'idle'})
            while True:
                time.sleep(3600)
    finally:
        stopped.set()
        local.shutdown()
        local.server_close()
        local.socket_path.unlink(missing_ok=True)


def command(store, req):
    action = req['action']
    if action in ['pair', 'unpair', 'resolve', 'manual', 'revoke_user_notebook', 'topology_update_export'] and store.access_status().get('role') != 'administrator':
        raise ValueError('Operace vyžaduje platné administrátorské pověření notebooku.')
    if action == 'status':
        return store.public_status()
    if action == 'access_status':
        return store.access_status()
    if action == 'bootstrap_admin':
        store.bootstrap_admin_credential()
        return store.status()
    if action == 'enrollment_request':
        return {'request': json.dumps(store.enrollment_request(req['name']))}
    if action == 'issue_user_invitation':
        return {'invitation': json.dumps(store.issue_user_invitation(req['request']))}
    if action == 'accept_user_invitation':
        store.accept_user_invitation(req['invitation'])
        return store.public_status()
    if action == 'revoke_user_notebook':
        if req.get('confirm') is not True:
            raise ValueError('Odvolání notebooku vyžaduje výslovné potvrzení.')
        revoked = store.revoke_user_notebook(req.get('notebookId'))
        result = store.public_status()
        result['revoked'] = revoked
        return result
    if action == 'topology_update_export':
        return {'update': store.topology_update_export()}
    if action == 'topology_refresh_plan':
        return {'plan': store.topology_refresh_plan(req.get('update')),
                'vpn': store.vpn_status()}
    if action == 'topology_refresh_apply':
        if req.get('confirm') is not True:
            raise ValueError('Aktualizace topologie vyžaduje výslovné potvrzení.')
        return store.topology_refresh_apply(req.get('planId'))
    if action == 'vpn_plan':
        return {'plan': store.vpn_plan(), 'vpn': store.vpn_status()}
    if action == 'vpn_install':
        return {'vpn': store.vpn_install(req.get('planId'))}
    if action == 'vpn_rollback':
        if req.get('confirm') is not True:
            raise ValueError('Návrat VPN vyžaduje výslovné potvrzení.')
        return {'vpn': store.vpn_rollback()}
    if action == 'vpn_status':
        return {'vpn': store.vpn_status()}
    if action == 'vpn_diagnostics':
        return {'diagnostics': store.vpn_diagnostics(), 'vpn': store.vpn_status()}
    if action == 'disconnect':
        if req.get('confirm') is not True:
            raise ValueError('Odpojení notebooku vyžaduje výslovné potvrzení.')
        state = store.vpn_status()
        if state.get('state') == 'installed':
            store.vpn_rollback()
        config = f.read(store.root / 'config.json', {})
        f.atomic(store.root / 'config.json', dict(config, enabled=False))
        return store.public_status()
    if action == 'configure':
        name, address = req['name'].strip(), req['address'].strip()
        if not 0 < len(name) <= 80:
            raise ValueError('Vyplňte název notebooku (nejvýše 80 znaků).')
        zerotier_interface(address)
        f.atomic(store.root / 'config.json', {'enabled': True, 'name': name, 'address': address})
        store.reconcile_administrator_endpoint(address)
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
            raw = sys.stdin.buffer.read(MAX + 1)
            if len(raw) > MAX:
                raise ValueError('Požadavek je příliš velký.')
            request = json.loads(raw)
            print(json.dumps(command(store, request)))
    except Exception as error:
        if len(sys.argv) > 1 and sys.argv[1] == 'serve':
            f.atomic(Path(sys.argv[2]) / 'notebooks/runtime.json', {'updatedAt': time.time(), 'error': 'Službu nelze provozovat. Ověřte vybranou IPv4 adresu, dostupnost multicastu a volný port 8856.'})
        # Never print payloads, TLS data, or an exception containing private keys.
        print('Synchronizace notebooků selhala: ' + (str(error) if type(error) is ValueError else type(error).__name__), file=sys.stderr)
        sys.exit(1)
