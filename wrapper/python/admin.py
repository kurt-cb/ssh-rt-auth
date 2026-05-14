"""ssh-rt-wrapper-admin — operator CLI for the Python wrapper.

Phase 1A commands:
  lint              Validate wrapper.yaml and on-disk file permissions.
  status            Print mode and the listen / fallback config.

Phase 1B will add:
  init              Generate local user-CA keypair + initial state dirs.
  rotate-ca         Generate a new local user-CA keypair; SIGHUP wrapper.
  verify            Health-check (CA reachability, inner sshd config hash, …).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import WrapperConfig


def cmd_lint(args: argparse.Namespace) -> int:
    path = args.config
    try:
        cfg = WrapperConfig.load(path)
    except FileNotFoundError:
        print(f'config not found: {path}', file=sys.stderr)
        return 2
    except Exception as e:
        print(f'config load error: {e}', file=sys.stderr)
        return 2
    try:
        cfg.validate()
        cfg.check_permissions()
    except ValueError as e:
        print(f'config validation failed: {e}', file=sys.stderr)
        return 1
    print(f'OK — {path} valid for mode={cfg.mode}')
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    try:
        cfg = WrapperConfig.load(args.config)
    except FileNotFoundError:
        print(f'config not found: {args.config}', file=sys.stderr)
        return 2
    print(f'mode:             {cfg.mode}')
    print(f'listen:           {cfg.listen.external_address}:'
          f'{cfg.listen.external_port}')
    if cfg.mode == 'fallback':
        print(f'fallback target:  {cfg.fallback.host}:{cfg.fallback.port}')
    else:
        print(f'ca endpoints:     {", ".join(cfg.ca.endpoints) or "(none)"}')
        print(f'inner sshd:       {cfg.inner.sshd_binary}')
        print(f'allowed users:    {", ".join(cfg.users.allowed) or "(none)"}')
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    print('init: not implemented in Phase 1A '
          '(generates local user-CA key + state dirs in Phase 1B)',
          file=sys.stderr)
    return 2


def cmd_rotate_ca(args: argparse.Namespace) -> int:
    print('rotate-ca: not implemented in Phase 1A (see Phase 1B)',
          file=sys.stderr)
    return 2


def cmd_verify(args: argparse.Namespace) -> int:
    print('verify: not implemented in Phase 1A (see Phase 1B)',
          file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog='ssh-rt-wrapper-admin')
    ap.add_argument('--config', default='/etc/ssh-rt-auth/wrapper.yaml',
                    help='path to wrapper.yaml')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('lint',      help='validate wrapper.yaml').set_defaults(fn=cmd_lint)
    sub.add_parser('status',    help='print wrapper state').set_defaults(fn=cmd_status)
    sub.add_parser('init',      help='generate state dirs + local user-CA').set_defaults(fn=cmd_init)
    sub.add_parser('rotate-ca', help='rotate the local user-CA key').set_defaults(fn=cmd_rotate_ca)
    sub.add_parser('verify',    help='health-check').set_defaults(fn=cmd_verify)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == '__main__':
    sys.exit(main())
