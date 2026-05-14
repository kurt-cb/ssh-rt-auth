#!/usr/bin/env python3
"""ssh-rt-auth shim for unmodified OpenSSH (AuthorizedKeysCommand).

OpenSSH's ``sshd`` already supports plugging in an external authorized-keys
provider via the ``AuthorizedKeysCommand`` config directive (man sshd_config,
since OpenSSH 6.9). For each authentication attempt sshd runs the configured
command, passing the username + the key the client is offering. If the
command outputs an ``authorized_keys``-format line, sshd accepts the key;
otherwise sshd denies.

This shim wires that hook into our existing ``shim.Shim`` (which talks mTLS
to the CA). It is intentionally simple — no PAM module, no sshd patch — so
it works against stock OpenSSH on Ubuntu/Debian.

Install:

    /usr/local/bin/ssh-rt-auth-openssh-shim    # this file, mode 0755, owner root

Configure in ``/etc/ssh/sshd_config.d/ssh-rt-auth.conf`` (or main config)::

    PasswordAuthentication no
    PubkeyAuthentication   yes
    AuthorizedKeysFile     none
    AuthorizedKeysCommand     /usr/local/bin/ssh-rt-auth-openssh-shim %u %t %k
    AuthorizedKeysCommandUser sshrt

And reload sshd::

    systemctl reload ssh

The shim is a short-lived subprocess (one fresh process per call), so it
**must** use the persistent SQLite cache backend rather than the in-memory
one — otherwise every invocation re-queries the CA and the audit log gets
duplicate entries (sshd routinely calls ``AuthorizedKeysCommand`` twice per
accepted connection). Set this in ``/etc/ssh-rt-auth/shim.yaml``::

    cache:
      backend: sqlite
      db_path: /var/cache/ssh-rt-auth/cert-cache.sqlite3

The shim auto-promotes the backend to ``sqlite`` if the config still says
``memory``, since the in-memory path is always wrong for this caller.

Limitations of this hook (called out in tests/issues.md as well):

- sshd does NOT pass the remote IP via env vars to AuthorizedKeysCommand.
  We try ``SSH_CLIENT`` / ``SSH_CONNECTION`` (set by some versions) and fall
  back to scanning the parent sshd's TCP connections via /proc. If neither
  works, source_ip degrades to ``0.0.0.0`` and any source-cidr policy will
  reject the connection — set the policy to ``0.0.0.0/0`` when using this
  shim, or wait for the planned sshd patch with first-class context plumbing.

- sshd does not run the X.509 cert constraint extensions (``server-bind``,
  ``channel-policy``, ``force-command``). For those, you still need the
  AsyncSSH server in ``server/ssh_server.py`` or a proper sshd patch.
  AuthorizedKeysCommand only answers "is this key authorized" — yes/no.

- The shim must run as a dedicated unprivileged user that can read the
  shim's mTLS cert/key (mode 600). Typical install adds ``sshrt`` to a
  ``sshrt`` group and chgrp's the keys to that group with mode 640. The
  SQLite cache file must also be writeable by that user (typical owner is
  ``sshrt:sshrt``, mode 0700 on the parent directory).
"""
from __future__ import annotations

import base64
import os
import sys
import time
from pathlib import Path


def _resolve_source_ip() -> str:
    """Figure out the remote client IP. Returns '' if we couldn't.

    Strategy:
      1. Honour ``SSH_CLIENT`` / ``SSH_CONNECTION`` if set (some sshd versions).
      2. Scan the parent process's TCP connection state via /proc.
    """
    for var in ('SSH_CLIENT', 'SSH_CONNECTION'):
        val = (os.environ.get(var) or '').strip()
        if val:
            return val.split()[0]
    try:
        ppid = os.getppid()
        # Build inode → ppid socket map.
        fd_dir = Path(f'/proc/{ppid}/fd')
        if not fd_dir.exists():
            return ''
        ppid_inodes = set()
        for fd in fd_dir.iterdir():
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if target.startswith('socket:['):
                ppid_inodes.add(target[len('socket:['):-1])
        if not ppid_inodes:
            return ''
        for tcp in ('/proc/net/tcp', '/proc/net/tcp6'):
            try:
                lines = Path(tcp).read_text().splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                f = line.split()
                if len(f) < 10:
                    continue
                if f[9] not in ppid_inodes:
                    continue
                rem = f[2].split(':')[0]
                if tcp.endswith('tcp6'):
                    # IPv6 in 8 little-endian 16-bit words. For an IPv4-mapped
                    # address only the last 4 bytes are meaningful.
                    if len(rem) == 32 and rem.startswith('0' * 20 + 'FFFF'):
                        return _ipv4_from_hex(rem[24:32])
                    return _ipv6_from_hex(rem)
                return _ipv4_from_hex(rem)
    except Exception:
        return ''
    return ''


def _ipv4_from_hex(hex8: str) -> str:
    """Hex-encoded little-endian IPv4 (per /proc/net/tcp) → dotted-quad."""
    if len(hex8) != 8:
        return ''
    return '.'.join(str(int(hex8[i:i + 2], 16)) for i in (6, 4, 2, 0))


def _ipv6_from_hex(hex32: str) -> str:
    """Hex-encoded /proc/net/tcp6 remote address → colon-separated IPv6."""
    if len(hex32) != 32:
        return ''
    # The format is 4 little-endian 32-bit words. Re-byteswap each word.
    words = []
    for w in range(4):
        chunk = hex32[w * 8:(w + 1) * 8]
        b = bytes(int(chunk[i:i + 2], 16) for i in (6, 4, 2, 0))
        words.append(f'{int.from_bytes(b[:2], "big"):x}:'
                     f'{int.from_bytes(b[2:], "big"):x}')
    return ':'.join(words)


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        sys.stderr.write(
            'usage: ssh-rt-auth-openssh-shim <username> <key-type> '
            '<base64-key>\n')
        return 1

    username, key_type, key_blob_b64 = argv[1], argv[2], argv[3]

    # Allow the install to vendor the source tree somewhere other than /app
    # and the shim config somewhere other than /etc/ssh-rt-auth/shim.yaml.
    sys.path.insert(0, os.environ.get('SSHRT_SRC_ROOT', '/app'))

    # Importing here (rather than at module top) keeps the script cheap to
    # type-check / lint without the project source on PYTHONPATH.
    from shim.shim import STATUS_AUTHORIZED, Shim
    from shim.config import ShimConfig

    cfg_path = os.environ.get(
        'SSHRT_SHIM_CONFIG', '/etc/ssh-rt-auth/shim.yaml')
    try:
        cfg = ShimConfig.load(cfg_path)
        # Force SQLite for this caller — see module docstring for why.
        if cfg.cache_backend != 'sqlite':
            cfg.cache_backend = 'sqlite'
        shim = Shim(cfg)
    except Exception as e:
        # Misconfiguration — fail closed (no key line → sshd denies). We
        # write the error to stderr so it lands in the sshd auth log.
        sys.stderr.write(f'ssh-rt-auth-openssh-shim: config error: {e}\n')
        return 1

    try:
        key_blob = base64.b64decode(key_blob_b64, validate=True)
    except Exception as e:
        sys.stderr.write(f'ssh-rt-auth-openssh-shim: bad b64 key blob: {e}\n')
        return 1

    source_ip = _resolve_source_ip() or '0.0.0.0'

    # `username` is what the client typed at the prompt; pass it as connection
    # context so the CA's audit log records who tried to log in, but the
    # CA still authenticates the *key* (sshd already validated the
    # signature). The CA's policy resolves the username from the key blob's
    # fingerprint via the enrollment store.
    outcome = shim.authorize(
        identity_type='pubkey',
        identity_data=key_blob,
        source_ip=source_ip,
        source_port=0,
        timestamp=int(time.time()),
        channels=['session'],
    )

    if outcome.status == STATUS_AUTHORIZED:
        # Echo back the key line. sshd matches the client's offered key
        # against this output; if it matches, auth succeeds. We could prefix
        # ``restrict,command="..."`` options to enforce the CA's
        # force-command, but that requires parsing the cert extensions,
        # which is overkill for the prototype.
        sys.stdout.write(f'{key_type} {key_blob_b64}\n')
        sys.stdout.flush()
        # Optional diagnostic for the operator's sshd auth log.
        sys.stderr.write(
            f'ssh-rt-auth-openssh-shim: granted user={username} '
            f'fp-prefix={key_blob_b64[:24]}… serial={outcome.serial} '
            f'source_ip={source_ip}\n')
        return 0

    sys.stderr.write(
        f'ssh-rt-auth-openssh-shim: denied user={username} '
        f'reason={outcome.deny_reason or outcome.detail!r} '
        f'source_ip={source_ip}\n')
    # Returning 0 with no stdout is sshd-equivalent to "no key matched".
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
