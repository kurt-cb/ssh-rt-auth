"""AsyncSSH server with ssh-rt-auth shim integration.

The SSH server enforces no authorization on its own; after public-key auth
succeeds, it asks the shim. The shim returns the X.509 authorization cert (or
denial). The server parses the X.509 critical extensions and enforces them on
the session (source-bind, server-bind, channel-policy).
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import logging
import os
import pty
import shutil
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import asyncssh
from cryptography import x509

from shim.config import ShimConfig
from shim.shim import (STATUS_AUTHORIZED, STATUS_DENIED, STATUS_ERROR,
                       AuthorizeOutcome, Shim)


log = logging.getLogger('ssh-rt-auth-server')


# X.509 OIDs for the policy extensions. Must match ca/cert_minter.py.
_OID_SOURCE_BIND = '1.3.6.1.4.1.55555.1.1'
_OID_SERVER_BIND = '1.3.6.1.4.1.55555.1.2'
_OID_CHANNEL_POLICY = '1.3.6.1.4.1.55555.1.3'


@dataclass
class CertPolicy:
    source_bind: str
    server_bind: str
    channels: list[str]


def parse_policy_from_cert(cert_der: bytes) -> CertPolicy:
    cert = x509.load_der_x509_certificate(cert_der)
    source_bind = ''
    server_bind = ''
    channels: list[str] = []
    for ext in cert.extensions:
        oid_s = ext.oid.dotted_string
        if oid_s == _OID_SOURCE_BIND:
            source_bind = _decode_der_utf8(ext.value.value)
        elif oid_s == _OID_SERVER_BIND:
            server_bind = _decode_der_utf8(ext.value.value)
        elif oid_s == _OID_CHANNEL_POLICY:
            channels = _decode_der_seq_utf8(ext.value.value)
    return CertPolicy(source_bind=source_bind, server_bind=server_bind,
                      channels=channels)


# ---------------------------------------------------------------------------
# Minimal DER reader (parses what cert_minter writes).
# ---------------------------------------------------------------------------

def _read_len(buf: bytes, pos: int) -> tuple[int, int]:
    first = buf[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7f
    length = int.from_bytes(buf[pos:pos + n], 'big')
    return length, pos + n


def _decode_der_utf8(buf: bytes) -> str:
    if not buf or buf[0] != 0x0c:
        return ''
    length, pos = _read_len(buf, 1)
    return buf[pos:pos + length].decode('utf-8', errors='replace')


def _decode_der_seq_utf8(buf: bytes) -> list[str]:
    if not buf or buf[0] != 0x30:
        return []
    length, pos = _read_len(buf, 1)
    end = pos + length
    out: list[str] = []
    while pos < end:
        if buf[pos] != 0x0c:
            break
        elen, p2 = _read_len(buf, pos + 1)
        out.append(buf[p2:p2 + elen].decode('utf-8', errors='replace'))
        pos = p2 + elen
    return out


# ---------------------------------------------------------------------------
# AsyncSSH integration
# ---------------------------------------------------------------------------

class AuthorizationDenied(Exception):
    """Raised to reject a connection after the shim denies authorization."""


class _SshrtAuthServer(asyncssh.SSHServer):
    """One instance per SSH connection.

    Public-key auth: AsyncSSH calls ``begin_auth`` then ``public_key_auth_supported``
    + ``validate_public_key``. We accept any client key, then after the password/
    key-auth completes we consult the shim. AsyncSSH doesn't have a clean
    post-auth hook, so we do the shim call inside ``validate_public_key`` and
    record the outcome. Once auth succeeds we enforce the session policy via
    channel-open hooks.
    """

    # Class-level state — set by the factory before each connection.
    _shim: Shim | None = None
    _allowed_users: set[str] | None = None
    _per_user_keys: dict[str, list[bytes]] | None = None

    def __init__(self):
        super().__init__()
        self._conn: asyncssh.SSHServerConnection | None = None
        self._authorized = False
        self._auth_outcome: AuthorizeOutcome | None = None
        self._policy: CertPolicy | None = None
        self._username: str | None = None
        self._source_ip: str | None = None
        self._auth_cert_der: bytes | None = None

    # --- AsyncSSH callbacks ---

    def connection_made(self, conn):
        self._conn = conn
        peer = conn.get_extra_info('peername')
        self._source_ip = peer[0] if peer else ''
        log.debug('connection from %s', self._source_ip)

    def begin_auth(self, username):
        self._username = username
        # We do public-key auth only, no password.
        return True

    def password_auth_supported(self):
        return False

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key) -> bool:
        # Outermost guard: AsyncSSH swallows exceptions raised from this
        # callback and treats them as auth failures (silent). We've been
        # bitten by that — wrap the whole body, log, and reject explicitly.
        try:
            return self._validate_public_key_inner(username, key)
        except Exception:
            log.exception('validate_public_key raised — rejecting connection')
            return False

    def _validate_public_key_inner(self, username, key) -> bool:
        """Accept the key if (a) it matches an enrolled key for ``username`` and
        (b) the shim authorizes the connection.

        The first check is local: AsyncSSH gives us a key object; we compare
        its raw blob against ``_per_user_keys[username]``. The second check is
        the shim call to the CA. We record outcome and cert for use in
        ``session_requested``.
        """
        if self._per_user_keys is None or self._shim is None:
            log.error('SSH server misconfigured: no shim or per_user_keys')
            return False
        if username not in (self._per_user_keys or {}):
            log.info('rejecting auth: unknown unix user %s', username)
            return False
        try:
            client_blob = key.public_data
        except Exception:
            log.warning('public_key_auth: cannot get raw blob')
            return False
        log.info('validate_public_key: user=%s key_type=%s blob_len=%d '
                 'blob_head=%s', username,
                 type(key).__name__, len(client_blob),
                 client_blob[:16].hex())
        if not any(client_blob == enrolled for enrolled in self._per_user_keys[username]):
            log.info('rejecting auth: key not enrolled for %s; '
                     'enrolled_count=%d enrolled_heads=%s', username,
                     len(self._per_user_keys[username]),
                     [e[:16].hex() for e in self._per_user_keys[username]])
            return False

        identity_type = 'pubkey'
        # If asyncssh handed us an OpenSSH cert, switch type.
        cert_obj = getattr(key, 'cert', None)
        identity_data = client_blob
        if cert_obj is not None:
            try:
                identity_data = cert_obj.public_data
                identity_type = 'openssh-cert'
            except Exception:
                pass

        # Call the shim.
        ts = int(_dt.datetime.now(tz=_dt.timezone.utc).timestamp())
        peer_port = 0
        if self._conn is not None:
            pi = self._conn.get_extra_info('peername')
            if pi and len(pi) >= 2:
                peer_port = pi[1]
        outcome = self._shim.authorize(
            identity_type=identity_type,
            identity_data=identity_data,
            source_ip=self._source_ip or '0.0.0.0',
            source_port=peer_port,
            timestamp=ts,
            channels=['session'],
        )
        self._auth_outcome = outcome
        if outcome.status != STATUS_AUTHORIZED:
            log.info('shim denied: user=%s status=%s reason=%s detail=%s',
                     username, outcome.status, outcome.deny_reason, outcome.detail)
            return False
        # Parse policy from the cert.
        try:
            self._policy = parse_policy_from_cert(outcome.cert_der or b'')
        except Exception as e:
            log.warning('cannot parse cert policy: %s', e)
            return False
        # Defense-in-depth checks the shim doesn't perform.
        if (self._policy.server_bind
                and self._policy.server_bind != (self._shim.server_name or '')):
            log.info('cert server_bind=%s does not match our name=%s',
                     self._policy.server_bind, self._shim.server_name)
            return False
        if (self._policy.source_bind
                and self._policy.source_bind != (self._source_ip or '')):
            log.info('cert source_bind=%s does not match source_ip=%s',
                     self._policy.source_bind, self._source_ip)
            return False
        self._authorized = True
        self._auth_cert_der = outcome.cert_der
        log.info('authorized: user=%s serial=%s channels=%s',
                 username, outcome.serial, self._policy.channels)
        # Stash auth state on the connection so process_factory can pull it.
        if self._conn is not None:
            try:
                self._conn.set_extra_info(
                    sshrt_auth_serial=outcome.serial,
                    sshrt_auth_username=username,
                )
            except Exception:
                pass
        return True

    def session_requested(self):
        if not self._authorized:
            return False
        if self._policy and 'session' not in self._policy.channels:
            log.info('session channel not allowed by policy: %s',
                     self._policy.channels)
            return False
        # Returning True lets AsyncSSH delegate the session to process_factory
        # (registered in run_server) which spawns a real shell.
        return True


# ---------------------------------------------------------------------------
# process_factory: spawn a real shell (or run the requested exec command)
# ---------------------------------------------------------------------------

def _detect_shell() -> str:
    for cand in ('/bin/bash', '/bin/sh'):
        if os.path.exists(cand):
            return cand
    return '/bin/sh'


async def _handle_session(process: asyncssh.SSHServerProcess) -> None:
    try:
        await _handle_session_inner(process)
    except Exception:
        log.exception('process handler crashed')
        try:
            process.exit(1)
        except Exception:
            pass


async def _handle_session_inner(process: asyncssh.SSHServerProcess) -> None:
    """Handle one authorized session: emit banner, then exec command or shell."""
    conn = process.channel.get_connection()
    username = conn.get_extra_info('sshrt_auth_username') or process.get_extra_info('username') or '?'
    serial = conn.get_extra_info('sshrt_auth_serial') or '?'
    banner = (
        f'ssh-rt-auth: authorized session\r\n'
        f'user={username} serial={serial}\r\n'
    )

    if process.command:
        # ----- exec mode: `ssh user@host some_command` --------------------
        # Drop to the target unix user via `su` so the command runs as them
        # (the AsyncSSH server itself runs as root inside the container).
        # Fall back to /bin/sh -c if we aren't root or the user doesn't exist
        # locally — handy for loopback tests where the server runs unprivileged.
        process.stdout.write(banner)
        if os.geteuid() == 0 and Path(f'/home/{username}').is_dir():
            argv = ['su', '-', str(username), '-c', process.command]
        else:
            argv = ['/bin/sh', '-c', process.command]
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await proc.communicate()
        if stdout_b:
            process.stdout.write(stdout_b.decode('utf-8', errors='replace'))
        if stderr_b:
            process.stderr.write(stderr_b.decode('utf-8', errors='replace'))
        process.exit(proc.returncode or 0)
        return

    # ----- interactive shell with PTY -------------------------------------
    # Use `su - <user>` to spawn a login shell as the right unix user.
    master_fd, slave_fd = pty.openpty()
    try:
        env = {
            'TERM': process.term_type or 'xterm-256color',
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'SSHRT_AUTH_SERIAL': str(serial),
        }
        if os.geteuid() == 0 and Path(f'/home/{username}').is_dir():
            argv = ['su', '-', str(username)]
        else:
            argv = [_detect_shell(), '-i']
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            preexec_fn=os.setsid,
            env=env, cwd='/',
        )
    finally:
        os.close(slave_fd)

    # Write banner directly to the master so the shell sees it via the PTY.
    try:
        os.write(master_fd, banner.encode('utf-8'))
    except OSError:
        pass

    # Bridge SSH I/O <-> PTY master FD.
    process.redirect(stdin=master_fd, stdout=master_fd, stderr=master_fd,
                     send_eof=False, recv_eof=False)
    try:
        rc = await proc.wait()
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass
    process.exit(rc or 0)


# ---------------------------------------------------------------------------
# Server factory and main entry point.
# ---------------------------------------------------------------------------

@dataclass
class ServerConfig:
    listen_host: str
    listen_port: int
    host_key_path: str
    shim_config_path: str
    per_user_keys: dict[str, list[bytes]]  # username -> list of raw SSH pubkey blobs


def make_server_factory(shim: Shim,
                        per_user_keys: dict[str, list[bytes]]):
    """Return a callable usable as ``asyncssh.listen``'s ``server_factory``."""
    def _factory():
        srv = _SshrtAuthServer()
        srv._shim = shim
        srv._per_user_keys = per_user_keys
        return srv
    return _factory


async def run_server(cfg: ServerConfig) -> asyncssh.SSHAcceptor:
    shim_cfg = ShimConfig.load(cfg.shim_config_path)
    shim = Shim(shim_cfg)
    server_keys = [asyncssh.read_private_key(cfg.host_key_path)]
    acceptor = await asyncssh.create_server(
        server_factory=make_server_factory(shim, cfg.per_user_keys),
        host=cfg.listen_host, port=cfg.listen_port,
        server_host_keys=server_keys,
        process_factory=_handle_session,
        allow_pty=True,
        line_editor=False,
    )
    return acceptor


def _parse_user_keys_file(path: str) -> dict[str, list[bytes]]:
    """Read a per-user-keys file: ``username ssh-ed25519 AAAA... [comment]`` lines."""
    import base64 as _b64
    out: dict[str, list[bytes]] = {}
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        user = parts[0]
        try:
            blob = _b64.b64decode(parts[2])
        except Exception:
            continue
        out.setdefault(user, []).append(blob)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog='ssh-rt-auth-server')
    p.add_argument('--shim-config', required=True)
    p.add_argument('--host-key', required=True)
    p.add_argument('--users-file', required=True,
                   help='File with lines: "<username> <ssh-key-type> <b64-blob> [comment]"')
    p.add_argument('--listen-host', default='127.0.0.1')
    p.add_argument('--listen-port', default=2222, type=int)
    p.add_argument('--debug', action='store_true')
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s')
    cfg = ServerConfig(
        listen_host=args.listen_host, listen_port=args.listen_port,
        host_key_path=args.host_key, shim_config_path=args.shim_config,
        per_user_keys=_parse_user_keys_file(args.users_file),
    )

    async def _runner():
        acceptor = await run_server(cfg)
        log.info('SSH server on %s:%d', cfg.listen_host, cfg.listen_port)
        await acceptor.wait_closed()

    try:
        asyncio.run(_runner())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
