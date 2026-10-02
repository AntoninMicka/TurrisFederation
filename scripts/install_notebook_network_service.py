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
    subprocess.run(['/usr/bin/systemctl', 'enable', '--now', 'turris-federation-network.service'], check=True)
    subprocess.run(['/usr/bin/systemctl', 'restart', 'turris-federation-network.service'], check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.uid < 1:
        raise SystemExit('Neplatné UID uživatele.')
    if args.check:
        raise SystemExit(0 if check(args.uid) else 1)
    install(args.uid)


if __name__ == '__main__':
    main()
