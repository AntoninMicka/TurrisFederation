#!/usr/bin/env python3
"""Fail-closed reconciler for a Turris Federation application gateway."""
import base64
import grp
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

LIMIT = 256 * 1024
ID = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
DOMAIN = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
PASSWORD_HASH = re.compile(r'\{SSHA\}[A-Za-z0-9+/=]{32,128}\Z')
CA_LIMIT = 16 * 1024
CA_TOTAL_LIMIT = 128 * 1024
PEM_CERTIFICATE = re.compile(
    r'-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END CERTIFICATE-----\n\Z')


def verify(public_key, envelope):
    if not isinstance(envelope, dict) or set(envelope) != {'payload', 'signature'}:
        raise ValueError('Router vratil neplatnou podepsanou obalku.')
    try:
        raw = base64.b64decode(envelope['payload'], validate=True)
        signature = base64.b64decode(envelope['signature'], validate=True)
    except (TypeError, ValueError) as error:
        raise ValueError('Router vratil neplatnou podepsanou obalku.') from error
    if len(raw) > LIMIT or len(signature) > 4096:
        raise ValueError('Manifest proxy je prilis velky.')
    with tempfile.TemporaryDirectory() as directory:
        payload, sig = Path(directory) / 'payload', Path(directory) / 'signature'
        payload.write_bytes(raw)
        sig.write_bytes(signature)
        result = subprocess.run(
            ['openssl', 'dgst', '-sha256', '-verify', str(public_key),
             '-signature', str(sig), str(payload)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    if result.returncode:
        raise ValueError('Podpis manifestu neodpovida identite lokalniho Turrisu.')
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('Podepsany manifest neni platny JSON.') from error


def validate_upstream_ca(value):
    """Validate one public trust certificate before nginx is allowed to trust it."""
    if value is None:
        return None
    if not isinstance(value, str) or len(value.encode()) > CA_LIMIT or '\0' in value:
        raise ValueError('Manifest obsahuje neplatny CA certifikat upstreamu.')
    value = value.replace('\r\n', '\n').strip() + '\n'
    if not PEM_CERTIFICATE.fullmatch(value):
        raise ValueError('Manifest obsahuje neplatny CA certifikat upstreamu.')
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'ca.pem'
        path.write_text(value)
        result = subprocess.run(
            ['openssl', 'x509', '-in', str(path), '-noout', '-checkend', '0', '-text'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
    if result.returncode:
        raise ValueError('Manifest obsahuje neplatny CA certifikat upstreamu.')
    return value


def validate_manifest(payload, node_id, now=None):
    now = time.time() if now is None else now
    required = {'schema', 'nodeId', 'issuedAt', 'expiresAt', 'services'}
    if (not isinstance(payload, dict) or set(payload) != required
            or payload['schema'] not in {1, 2}):
        raise ValueError('Nepodporovane schema manifestu proxy.')
    if payload['nodeId'] != node_id:
        raise ValueError('Manifest nevydal ocekavany lokalni Turris.')
    issued, expires = payload['issuedAt'], payload['expiresAt']
    if (type(issued) not in {int, float} or type(expires) not in {int, float}
            or issued > now + 30 or expires < now or expires > issued + 300):
        raise ValueError('Manifest proxy je prosly nebo ma neplatnou platnost.')
    if not isinstance(payload['services'], list) or len(payload['services']) > 128:
        raise ValueError('Manifest obsahuje neplatny seznam sluzeb.')
    result, seen = [], set()
    legacy_fields = {'id', 'name', 'scheme', 'host', 'port', 'basePath', 'serverName', 'auth'}
    fields = legacy_fields | {'upstreamCa'}
    total_ca_bytes = 0
    for service in payload['services']:
        expected_fields = legacy_fields if payload['schema'] == 1 else fields
        if not isinstance(service, dict) or set(service) != expected_fields:
            raise ValueError('Manifest obsahuje neplatnou sluzbu.')
        service_id = service['id']
        if not isinstance(service_id, str) or not ID.fullmatch(service_id) or service_id in seen:
            raise ValueError('Manifest obsahuje neplatne nebo duplicitni ID sluzby.')
        try:
            host = ipaddress.ip_address(service['host'])
        except (TypeError, ValueError) as error:
            raise ValueError('Manifest obsahuje neplatnou adresu upstreamu.') from error
        if (host.version != 4 or not host.is_private or service['scheme'] not in {'http', 'https'}
                or type(service['port']) is not int or not 1 <= service['port'] <= 65535):
            raise ValueError('Manifest obsahuje nepovoleny upstream.')
        path = service['basePath']
        if (not isinstance(path, str)
                or not re.fullmatch(r'/[A-Za-z0-9._~%/@+-]*', path)):
            raise ValueError('Manifest obsahuje neplatnou cestu upstreamu.')
        server_name = service['serverName']
        if not isinstance(server_name, str) or not (DOMAIN.fullmatch(server_name) or server_name == str(host)):
            raise ValueError('Manifest obsahuje neplatne TLS jmeno upstreamu.')
        if not isinstance(service['name'], str) or not service['name']:
            raise ValueError('Manifest obsahuje neplatny nazev sluzby.')
        auth = service['auth']
        if not isinstance(auth, dict) or set(auth) != {'username', 'passwordHash'}:
            raise ValueError('Manifest obsahuje neplatne nastaveni autentizace.')
        username, password_hash = auth['username'], auth['passwordHash']
        if ((username is None) != (password_hash is None)
                or username is not None and (not isinstance(username, str)
                    or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', username))
                or password_hash is not None and (not isinstance(password_hash, str)
                    or not PASSWORD_HASH.fullmatch(password_hash))):
            raise ValueError('Manifest obsahuje neplatne prihlasovaci udaje.')
        upstream_ca = validate_upstream_ca(service.get('upstreamCa'))
        if service['scheme'] != 'https' and upstream_ca is not None:
            raise ValueError('Vlastni certifikat lze pouzit jen pro HTTPS upstream.')
        total_ca_bytes += len(upstream_ca.encode()) if upstream_ca else 0
        if total_ca_bytes > CA_TOTAL_LIMIT:
            raise ValueError('Manifest obsahuje prilis mnoho certifikatu upstreamu.')
        seen.add(service_id)
        result.append({**service, 'host': str(host), 'upstreamCa': upstream_ca})
    return sorted(result, key=lambda item: item['id'])


def nginx_config(services, domain, listen, certificate, certificate_key, upstream_ca,
                 auth_directory='/etc/nginx/turris-federation-auth/current'):
    listens = listen if isinstance(listen, list) else [listen]
    if not 1 <= len(listens) <= 2 or len(set(listens)) != len(listens):
        raise ValueError('Proxy domena nebo VPN adresa neni platna.')
    try:
        addresses = [ipaddress.ip_address(value) for value in listens]
    except (TypeError, ValueError) as error:
        raise ValueError('Proxy domena nebo VPN adresa neni platna.') from error
    if (not DOMAIN.fullmatch(domain) or any(address.version != 4 or address.is_unspecified
            or address.is_multicast or address.is_loopback for address in addresses)):
        raise ValueError('Proxy domena nebo VPN adresa neni platna.')
    default_listens = ''.join('    listen %s:443 ssl default_server;\n' % address
                              for address in addresses).rstrip()
    service_listens = ''.join('    listen %s:443 ssl;\n' % address
                              for address in addresses).rstrip()
    header = '''server_names_hash_bucket_size 256;
server_names_hash_max_size 4096;
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}
server {
%s
    server_name _;
    ssl_certificate %s;
    ssl_certificate_key %s;
    return 421;
}
''' % (default_listens, certificate, certificate_key)
    blocks = []
    for service in services:
        upstream = '%s://%s:%d%s' % (service['scheme'], service['host'], service['port'],
                                     service['basePath'].rstrip('/') + '/')
        default_port = 443 if service['scheme'] == 'https' else 80
        upstream_authority = service['serverName'] + (
            '' if service['port'] == default_port else ':' + str(service['port']))
        tls = ''
        if service['scheme'] == 'https':
            trusted_ca = service.get('upstreamCaFile') or upstream_ca
            tls = ('        proxy_ssl_server_name on;\n'
                   '        proxy_ssl_name %s;\n'
                   '        proxy_ssl_verify on;\n'
                   '        proxy_ssl_trusted_certificate %s;\n' %
                   (service['serverName'], trusted_ca))
        auth = ''
        if service['auth']['username'] is not None:
            auth = ('        auth_basic "Turris Federation";\n'
                    '        auth_basic_user_file %s/%s.htpasswd;\n' %
                    (auth_directory, service['id']))
        blocks.append('''server {
%s
    server_name %s.%s;
    ssl_certificate %s;
    ssl_certificate_key %s;
    location / {
%s%s        proxy_pass %s;
        proxy_http_version 1.1;
        proxy_set_header Host %s;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_cookie_domain %s %s.%s;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
''' % (service_listens, service['id'], domain, certificate, certificate_key, tls, auth, upstream,
       upstream_authority, service['serverName'], service['id'], domain))
    return header + ''.join(blocks)


def fetch(config):
    port = config.get('routerPort', 22)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Konfigurace obsahuje neplatny SSH port Turrisu.')
    target = '%s@%s' % (config.get('routerUser', 'root'), config['routerHost'])
    command = ['ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes',
               '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'UserKnownHostsFile=' + config['knownHostsFile'],
               '-i', config['identityFile'], '-p', str(port), target]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=15, check=False)
    if result.returncode or len(result.stdout) > LIMIT:
        detail = result.stderr.decode(errors='replace')[-600:].strip()
        detail = re.sub(r'[^\x20-\x7e]+', ' ', detail)
        suffix = ' SSH: ' + detail if detail else ''
        raise ValueError('Manifest nelze nacist z lokalniho Turrisu omezenym SSH prikazem.' + suffix)
    return json.loads(result.stdout)


def atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def reconcile(config_path):
    config = json.loads(Path(config_path).read_text())
    state_path = Path(config.get('stateFile', '/var/lib/turris-federation-proxy/state.json'))
    try:
        payload = verify(config['routerPublicKey'], fetch(config))
        services = validate_manifest(payload, config['routerNodeId'])
        next_state = {'expiresAt': payload['expiresAt']}
    except Exception:
        try:
            state = json.loads(state_path.read_text())
        except (OSError, ValueError):
            state = {}
        if type(state.get('expiresAt')) not in {int, float} or state['expiresAt'] >= time.time():
            raise
        # Revocation is fail-closed: after the last signed manifest expires,
        # a disconnected proxy retains TLS but publishes no upstream servers.
        services, next_state = [], state
    auth_root = Path(config.get('authDirectory', '/etc/nginx/turris-federation-auth'))
    auth_generation = auth_root / str(int(time.time() * 1000000))
    auth_generation.mkdir(parents=True, exist_ok=False)
    nginx_readable_files = any(service['auth']['username'] is not None
                               or service.get('upstreamCa') is not None
                               for service in services)
    nginx_gid = None
    if nginx_readable_files:
        nginx_group = config.get('nginxGroup', 'www-data')
        if not isinstance(nginx_group, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', nginx_group):
            raise ValueError('Konfigurace obsahuje neplatnou skupinu nginx.')
        try:
            nginx_gid = grp.getgrnam(nginx_group).gr_gid
        except KeyError as error:
            raise ValueError('Skupina nginx pro cteni autentizace neexistuje.') from error
        for directory in [auth_root, auth_generation]:
            os.chown(directory, -1, nginx_gid)
            directory.chmod(0o750)
    runtime_services = []
    for service in services:
        runtime_service = dict(service)
        if service['auth']['username'] is not None:
            auth_file = auth_generation / (service['id'] + '.htpasswd')
            atomic(auth_file, '%s:%s\n' % (service['auth']['username'], service['auth']['passwordHash']))
            os.chown(auth_file, -1, nginx_gid)
            auth_file.chmod(0o640)
        if service.get('upstreamCa') is not None:
            ca_file = auth_generation / (service['id'] + '.ca.pem')
            atomic(ca_file, service['upstreamCa'])
            os.chown(ca_file, -1, nginx_gid)
            ca_file.chmod(0o640)
            runtime_service['upstreamCaFile'] = str(ca_file)
        runtime_services.append(runtime_service)
    rendered = nginx_config(runtime_services, config['domain'],
                            config.get('listenAddresses', config['listenAddress']),
                            config['certificate'], config['certificateKey'],
                            config.get('upstreamCa', '/etc/ssl/certs/ca-certificates.crt'),
                            str(auth_generation))
    destination = Path(config.get('nginxConfig', '/etc/nginx/conf.d/turris-federation.conf'))
    staged = destination.with_suffix('.candidate')
    atomic(staged, rendered)
    previous = destination.read_text() if destination.exists() else None
    os.replace(staged, destination)

    def restore_previous():
        if previous is None:
            destination.unlink(missing_ok=True)
        else:
            atomic(destination, previous)

    result = subprocess.run(['nginx', '-t'], stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, timeout=10)
    if result.returncode:
        restore_previous()
        shutil.rmtree(auth_generation, ignore_errors=True)
        raise ValueError('Nova konfigurace nginx neprosla kontrolou; posledni platna zustava aktivni.')
    try:
        subprocess.run(['nginx', '-s', 'reload'], check=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as error:
        restore_previous()
        subprocess.run(['nginx', '-t'], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=10, check=False)
        subprocess.run(['nginx', '-s', 'reload'], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=10, check=False)
        shutil.rmtree(auth_generation, ignore_errors=True)
        raise ValueError(
            'Nginx novou konfiguraci nenacetl; posledni platna byla obnovena.') from error
    atomic(state_path, json.dumps(next_state, sort_keys=True) + '\n')
    for previous in auth_root.iterdir():
        if previous != auth_generation and previous.is_dir():
            shutil.rmtree(previous)


if __name__ == '__main__':
    try:
        reconcile(sys.argv[1] if len(sys.argv) > 1 else '/etc/turris-federation-proxy/config.json')
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
