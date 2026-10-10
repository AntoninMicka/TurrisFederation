#!/usr/bin/env python3
"""Install or check the development notebook network system service."""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = {
    ROOT / 'scripts/notebook_network_service.py': Path('/usr/lib/turris-federation/notebook_network_service.py'),
    ROOT / 'packaging/turris-federation-network.service': Path('/etc/systemd/system/turris-federation-network.service'),
}
CONFIG = Path('/etc/turris-federation/notebook-network.json')
STATE_DIRECTORY = Path('/var/lib/turris-federation-notebook-network')
UNIT = 'turris-federation-network.service'
VPN_CONNECTIONS = ('turris-federation-rollback', 'turris-federation')
NFT_TABLE = 'turris_federation_notebook'


def same_file(source, target):
    try:
        return source.read_bytes() == target.read_bytes()
    except OSError:
        return False


def check(uid):
    try:
        config = json.loads(CONFIG.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    active = subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet',
                             'turris-federation-network.service'], check=False).returncode == 0
    return config == {'allowedUid': uid} and active and all(same_file(source, target)
                                                            for source, target in SOURCES.items())


def atomic_install(source, target, mode):
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + target.name + '.', dir=target.parent)
    os.close(descriptor)
    try:
        shutil.copyfile(source, temporary)
        os.chmod(temporary, mode)
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def install(uid):
    if os.geteuid() != 0:
        raise SystemExit('Instalace systémové služby vyžaduje sudo.')
    atomic_install(ROOT / 'scripts/notebook_network_service.py', SOURCES[ROOT / 'scripts/notebook_network_service.py'], 0o755)
    atomic_install(ROOT / 'packaging/turris-federation-network.service', SOURCES[ROOT / 'packaging/turris-federation-network.service'], 0o644)
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.notebook-network.', dir=CONFIG.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump({'allowedUid': uid}, stream, separators=(',', ':'))
            stream.write('\n')
        os.chmod(temporary, 0o644)
        os.replace(temporary, CONFIG)
    finally:
        Path(temporary).unlink(missing_ok=True)
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True)
    subprocess.run(['/usr/bin/systemctl', 'enable', '--now', UNIT], check=True)
    subprocess.run(['/usr/bin/systemctl', 'restart', UNIT], check=True)


def executable(candidates):
    return next((path for path in candidates if Path(path).is_file() and os.access(path, os.X_OK)), None)


def remove_managed_vpn_profiles():
    nmcli = executable(['/usr/bin/nmcli', '/bin/nmcli'])
    if not nmcli:
        return
    result = subprocess.run(
        [nmcli, '-t', '-f', 'UUID,NAME,TYPE', 'connection', 'show'],
        check=True, stdout=subprocess.PIPE, text=True)
    managed = []
    for line in result.stdout.splitlines():
        fields = line.split(':', 2)
        if len(fields) == 3 and fields[1] in VPN_CONNECTIONS and fields[2] == 'wireguard':
            managed.append((VPN_CONNECTIONS.index(fields[1]), fields[0]))
    for _order, profile_uuid in sorted(managed):
        subprocess.run([nmcli, 'connection', 'delete', 'uuid', profile_uuid], check=True)


def remove_managed_nft_table():
    nft = executable(['/usr/sbin/nft', '/usr/bin/nft'])
    if not nft:
        return
    present = subprocess.run(
        [nft, 'list', 'table', 'inet', NFT_TABLE],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if present:
        subprocess.run([nft, 'delete', 'table', 'inet', NFT_TABLE], check=True)


def uninstall():
    if os.geteuid() != 0:
        raise SystemExit('Odinstalace systémové služby vyžaduje sudo.')
    subprocess.run(['/usr/bin/systemctl', 'disable', '--now', UNIT], check=False)
    if subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', UNIT], check=False).returncode == 0:
        raise SystemExit('Systémovou síťovou službu se nepodařilo zastavit.')
    # Keep the service artifacts and its root-only desired state until both
    # network cleanup operations succeed. A failed cleanup can then be retried
    # without losing the exact managed-state boundary.
    remove_managed_vpn_profiles()
    remove_managed_nft_table()
    for target in [*SOURCES.values(), CONFIG]:
        target.unlink(missing_ok=True)
    if STATE_DIRECTORY.exists():
        shutil.rmtree(STATE_DIRECTORY)
    for directory in [Path('/usr/lib/turris-federation'), CONFIG.parent]:
        try:
            directory.rmdir()
        except OSError:
            pass
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True)
    subprocess.run(['/usr/bin/systemctl', 'reset-failed', UNIT], check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--uid', type=int)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--uninstall', action='store_true')
    args = parser.parse_args()
    if args.check and args.uninstall:
        parser.error('--check a --uninstall nelze použít současně')
    if args.uninstall:
        uninstall()
        return
    if args.uid is None or args.uid < 1:
        raise SystemExit('Neplatné UID uživatele.')
    if args.check:
        raise SystemExit(0 if check(args.uid) else 1)
    install(args.uid)


if __name__ == '__main__':
    main()
