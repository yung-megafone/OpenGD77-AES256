#!/usr/bin/env python3
"""Generate portable AES-256 keysets and provision OpenGD77-AES256 radios.

Uses the firmware repository's aes_key_store.py for radio writes. It does not
modify that tool's flash layout or preserve unrelated custom-data blocks.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

FORMAT = 'OpenGD77-AES256-Keyset-v1'
HEX = set('0123456789abcdefABCDEF')


def load(path):
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('format') != FORMAT or not isinstance(data.get('keys'), list):
        raise ValueError('Unrecognized keyset format')
    ids = set()
    for entry in data['keys']:
        if not isinstance(entry, dict):
            raise ValueError('Invalid key entry')
        kid, key = entry.get('id'), entry.get('key')
        if type(kid) is not int or not 1 <= kid <= 15 or kid in ids:
            raise ValueError(f'Invalid or repeated key ID: {kid!r}')
        if not isinstance(key, str) or len(key) != 64 or any(c not in HEX for c in key):
            raise ValueError(f'Invalid 256-bit key for ID {kid}')
        ids.add(kid)
    if not ids:
        raise ValueError('Empty keyset')
    return sorted(data['keys'], key=lambda x: x['id'])


def generate(args):
    path = Path(args.file).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {'format': FORMAT, 'keys': [
        {'id': i, 'key': secrets.token_hex(32).upper()} for i in range(1, 16)
    ]}
    # Atomic exclusive creation; never overwrite existing secrets.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
            f.write('\n')
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    print(f'Generated 15 independent AES-256 keys (IDs 1–15): {path}')
    print('Keep this file private. Reuse it on other radios; do not regenerate.')


def show(args):
    keys = load(Path(args.file).expanduser())
    print(f'{len(keys)} keys: IDs ' + ', '.join(str(k['id']) for k in keys))
    print('Key values hidden.')


def provision(args):
    keys = load(Path(args.file).expanduser())
    tool = Path(args.tool).expanduser().resolve()
    if not tool.is_file():
        raise FileNotFoundError(f'Radio writer not found: {tool}')
    print(f'Will write {len(keys)} keys to radio on {args.port}.')
    print('WARNING: The repository writer can replace other OpenGD77 custom data.')
    print('Back up custom data first; a normal codeplug backup may not include it.')
    if not args.yes:
        if input('Type WRITE to proceed: ').strip() != 'WRITE':
            print('Cancelled; no writes attempted.')
            return
    for entry in keys:
        kid = entry['id']
        print(f'Writing key ID {kid}...', flush=True)
        # The upstream tool prints "read-back verify: MISMATCH" but exits 0.
        proc = subprocess.run(
            [sys.executable, str(tool), '--key', entry['key'], '--keyid', str(kid), '--port', args.port],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        # Avoid printing the upstream output in full if it contains key bytes.
        if proc.returncode or 'read-back verify: OK' not in proc.stdout:
            print(f'Write failed at key ID {kid}. Stop and inspect the radio.', file=sys.stderr)
            print('Writer output (redacted):', file=sys.stderr)
            for line in proc.stdout.splitlines():
                if 'key=' not in line.lower() and 'wrote:' not in line.lower() and 'read :' not in line.lower():
                    print(line, file=sys.stderr)
            raise SystemExit(1)
    print('All keys written and individually read-back verified.')
    print('Encrypted TX selection unchanged; use the firmware tool --tx-key if needed.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    g = sub.add_parser('generate', help='Create a new portable keyset; never overwrite')
    g.add_argument('file', help='Destination JSON file')
    g.set_defaults(func=generate)
    s = sub.add_parser('show', help='Show saved key IDs only')
    s.add_argument('file')
    s.set_defaults(func=show)
    i = sub.add_parser('import', help='Write keys to an OpenGD77-AES256 radio')
    i.add_argument('file')
    i.add_argument('--port', required=True, help='Serial port, e.g. /dev/ttyACM0 or COM4')
    i.add_argument('--tool', default='MDUV380_firmware/tools/aes_key_store.py', help='Path to upstream key writer')
    i.add_argument('--yes', action='store_true', help='Skip confirmation')
    i.set_defaults(func=provision)
    a = p.parse_args()
    try:
        a.func(a)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        p.exit(1, f'Error: {e}\n')


if __name__ == '__main__':
    main()
