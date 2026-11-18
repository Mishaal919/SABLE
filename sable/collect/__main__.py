"""``python -m sable.collect`` : run read-only collection and write a snapshot.

This is the collector's standalone entry point (EC-01/EC-13/EC-15). The product's
``sable scan`` / ``sable analyze`` subcommands — which also analyse, plan and report —
live in ``sable/cli.py`` (Thomas's module); they call :func:`collect_snapshot` here
plus the analyzer and reporter. Keeping this entry separate avoids editing cli.py
while a producer/consumer handoff is agreed.

Exit codes: 0 on success, 2 on any handled connection/authorisation/I-O error.
"""
import argparse
import getpass
import os
import sys
from pathlib import Path

from sable.collect import collect_snapshot
from sable.collect.errors import CollectorError
from sable.contracts.validation import ContractError, dumps


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m sable.collect',
                                     description='SABLE read-only evidence collector')
    parser.add_argument('target', help='user@host to scan')
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--key', dest='key_path', help='SSH private key file')
    parser.add_argument('--password-env', metavar='NAME',
                        help='environment variable holding the SSH password')
    parser.add_argument('--accept-new-host-key', action='store_true',
                        help='trust an unknown host key on first use')
    parser.add_argument('--elevated', action='store_true',
                        help='add allow-listed sudo -n commands (reads full sudoers)')
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument('--audit-log', default='audit.log')
    parser.add_argument('--output', type=Path, default=Path('snapshot.json'))
    parser.add_argument('--yes', action='store_true', help='skip the authorisation prompt (CI)')
    args = parser.parse_args(argv)

    if '@' not in args.target:
        parser.error('target must be user@host')
    user, host = args.target.split('@', 1)

    password = None
    secrets = []
    if args.password_env:
        password = os.environ.get(args.password_env)
        if password is None:
            parser.error(f'environment variable {args.password_env} is not set')
        secrets.append(password)
    elif not args.key_path:
        password = getpass.getpass('SSH password: ')
        if password:
            secrets.append(password)

    try:
        snapshot = collect_snapshot(
            host, user, port=args.port, key_path=args.key_path, password=password,
            accept_new_host_key=args.accept_new_host_key, timeout=args.timeout,
            config={'elevated': args.elevated}, audit_path=args.audit_log,
            assume_yes=args.yes, secrets=tuple(secrets),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(dumps(snapshot), encoding='utf-8')
    except (CollectorError, ContractError) as error:
        sys.stderr.write(f'{error}\n')
        return 2
    except (OSError, UnicodeError) as error:
        sys.stderr.write(f'Cannot write the snapshot file: {error}\n')
        return 2
    sys.stderr.write(f'Wrote redacted snapshot to {args.output}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
