"""mssh — client CLI for ssh-rt-auth wrapper hosts.

Speaks the outer-protocol-v1 (JSON header + raw byte stream) over a
TLS 1.3 + mTLS tunnel directly to the wrapper. No openssh-client
dependency, no openssl subprocess. Pure Python (uses ``ssl.SSLContext``
which underlies OpenSSL).

Protocol (matches design/ssh-rt-auth-detailed-wrapper.md §3):

  1. TCP + TLS 1.3 + mTLS handshake.
  2. Client → server (1 line of JSON):
       {"v":1,"command":...,"interactive":...,"term":...,
        "rows":...,"cols":...,"env":...}
  3. Server → client ack: {"v":1,"ok":true} or {"v":1,"ok":false,"reason":...}
  4. After ack: raw bytes both ways (stdin ↔ stdout+stderr merged).
  5. TCP close = session end.

Usage:
    mssh alice@server-01                  # interactive shell, port 2200
    mssh alice@server-01 -- uname -a      # exec
    mssh -p 2222 alice@server-01
    mssh --identity ~/.mssh/alt-cert alice@server-01

Configuration (~/.mssh/config, key=value):
    default_port = 2200
    cert         = ~/.mssh/cert.pem
    key          = ~/.mssh/key.pem
    ca           = ~/.mssh/ca.pem
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import select
import shutil
import socket
import ssl
import sys
import termios
import tty
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


log = logging.getLogger('mssh')


DEFAULT_WRAPPER_PORT = 2200
DEFAULT_CONFIG_PATH = '~/.mssh/config'
DEFAULT_CERT = '~/.mssh/cert.pem'
DEFAULT_KEY = '~/.mssh/key.pem'
DEFAULT_CA = '~/.mssh/ca.pem'

PROTOCOL_VERSION = 1
MAX_HEADER_BYTES = 4096


@dataclass
class Target:
    user: str
    host: str
    port: int


@dataclass
class Identity:
    cert: Path
    key: Path
    ca: Path


# ---------------------------------------------------------------------------
# Pure-data helpers (unit-tested in tests/test_wrapper_mssh.py)
# ---------------------------------------------------------------------------

def _expand(p: str | Path) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(str(p))))


def parse_target(s: str, *, default_port: int,
                 default_user: str | None = None) -> Target:
    """'user@host[:port]' (user optional) → Target."""
    if '@' in s:
        user_part, rest = s.split('@', 1)
        user = user_part
    else:
        user = default_user or ''
        rest = s
    if ':' in rest:
        if rest.startswith('['):
            raise ValueError(
                'IPv6 bracket notation not supported in mssh v1; '
                'use -p <port> instead.')
        host, port_str = rest.split(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f'invalid port {port_str!r}') from None
    else:
        host = rest
        port = default_port
    if not host:
        raise ValueError('host required')
    return Target(user=user, host=host, port=port)


def load_config(path: str | Path) -> dict[str, str]:
    """Load a flat key=value config file."""
    p = _expand(path)
    if not p.exists():
        return {}
    out: dict[str, str] = {}
    for line_no, raw in enumerate(p.read_text().splitlines(), 1):
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if '=' not in line:
            raise ValueError(
                f'{p}:{line_no}: expected key=value, got {raw!r}')
        k, v = line.split('=', 1)
        out[k.strip()] = v.strip()
    return out


def resolve_identity(config: dict[str, str], *,
                     cert_override: str | None = None,
                     key_override: str | None = None,
                     ca_override: str | None = None) -> Identity:
    """Resolve cert/key/ca paths from CLI / env / config / defaults."""
    cert = _expand(cert_override
                   or os.environ.get('MSSH_CERT')
                   or config.get('cert', DEFAULT_CERT))
    key = _expand(key_override
                  or os.environ.get('MSSH_KEY')
                  or config.get('key', DEFAULT_KEY))
    ca = _expand(ca_override
                 or os.environ.get('MSSH_CA')
                 or config.get('ca', DEFAULT_CA))
    return Identity(cert=cert, key=key, ca=ca)


def validate_identity(ident: Identity) -> None:
    for label, p in (('cert', ident.cert), ('key', ident.key),
                     ('ca', ident.ca)):
        if not p.exists():
            raise ValueError(
                f'{label} not found at {p}. Set MSSH_{label.upper()}=... '
                f'or write {p}.')
    mode = ident.key.stat().st_mode & 0o777
    if mode & 0o077:
        raise ValueError(
            f'private key {ident.key} has insecure permissions '
            f'(mode={mode:o}). Run: chmod 0600 {ident.key}')


def build_header(target: Target, *,
                 command: Optional[str] = None,
                 interactive: bool = False,
                 term: Optional[str] = None,
                 rows: Optional[int] = None,
                 cols: Optional[int] = None,
                 env: Optional[dict[str, str]] = None) -> bytes:
    """Construct the v1 outer-protocol header line (newline-terminated)."""
    body = {
        'v': PROTOCOL_VERSION,
        'command': command,
        'interactive': interactive,
        'term': term,
        'rows': rows,
        'cols': cols,
        'env': env,
        # Principal echo for audit visibility on the server side.
        # The wrapper doesn't trust this — it derives the principal
        # from the mTLS cert — but it's useful in audit logs.
        'principal_hint': target.user,
    }
    encoded = json.dumps(body, separators=(',', ':')).encode('utf-8') + b'\n'
    if len(encoded) > MAX_HEADER_BYTES:
        raise ValueError(
            f'header too large ({len(encoded)} > {MAX_HEADER_BYTES})')
    return encoded


def parse_ack(line: bytes) -> tuple[bool, str]:
    """Parse a server ack line into (ok, reason). Reason is empty if ok."""
    try:
        body = json.loads(line.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f'malformed ack: {e}') from e
    if not isinstance(body, dict):
        raise ValueError(f'malformed ack: not an object: {body!r}')
    if int(body.get('v', 0)) != PROTOCOL_VERSION:
        raise ValueError(f'unsupported ack version: {body.get("v")}')
    if body.get('ok'):
        return True, ''
    return False, str(body.get('reason', '(no reason given)'))


# ---------------------------------------------------------------------------
# Connect + run
# ---------------------------------------------------------------------------

def _build_ssl_context(ident: Identity) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=str(ident.cert), keyfile=str(ident.key))
    ctx.load_verify_locations(cafile=str(ident.ca))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False  # ssh-rt-auth hosts are addressed by IP/short name;
                                # SAN-based hostname verification isn't worth
                                # the operator-side complexity for v1.
    return ctx


def _read_line(sock: ssl.SSLSocket, max_bytes: int) -> bytes:
    """Read one newline-terminated line of at most max_bytes."""
    buf = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError('server closed before sending ack')
        buf.append(chunk[0])
        if chunk == b'\n':
            return bytes(buf)
        if len(buf) >= max_bytes:
            raise ConnectionError(f'ack exceeded {max_bytes} bytes')


def run_session(target: Target, ident: Identity, *,
                command: Optional[str], interactive: bool,
                env: Optional[dict[str, str]] = None) -> int:
    """Open the mTLS session, do the v1 handshake, pump stdin/stdout
    until either side closes. Returns 0 on clean close; non-zero on
    handshake / network error."""
    ctx = _build_ssl_context(ident)
    try:
        raw_sock = socket.create_connection((target.host, target.port),
                                            timeout=10.0)
    except OSError as e:
        print(f'mssh: connect {target.host}:{target.port}: {e}',
              file=sys.stderr)
        return 4

    try:
        sock = ctx.wrap_socket(raw_sock, server_hostname=target.host)
    except (ssl.SSLError, ConnectionError) as e:
        raw_sock.close()
        print(f'mssh: TLS handshake failed: {e}', file=sys.stderr)
        return 5

    try:
        # Pull terminal size if interactive (and stdin/stdout are TTYs).
        rows = cols = None
        if interactive and sys.stdin.isatty() and sys.stdout.isatty():
            try:
                size = os.get_terminal_size(sys.stdout.fileno())
                rows, cols = size.lines, size.columns
            except OSError:
                pass

        term = os.environ.get('TERM') if interactive else None
        try:
            header = build_header(
                target, command=command, interactive=interactive,
                term=term, rows=rows, cols=cols, env=env,
            )
        except ValueError as e:
            print(f'mssh: {e}', file=sys.stderr)
            return 2
        sock.sendall(header)

        try:
            ack_line = _read_line(sock, MAX_HEADER_BYTES)
        except ConnectionError as e:
            print(f'mssh: {e}', file=sys.stderr)
            return 6
        try:
            ok, reason = parse_ack(ack_line)
        except ValueError as e:
            print(f'mssh: {e}', file=sys.stderr)
            return 6
        if not ok:
            print(f'mssh: wrapper rejected request: {reason}',
                  file=sys.stderr)
            return 7

        # Set the underlying TCP socket to non-blocking for the pump.
        # We do select() across the local stdin fd and the TLS socket
        # for portability across Python versions.
        return _pump(sock, interactive=interactive)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _pump(sock: ssl.SSLSocket, *, interactive: bool) -> int:
    """Bidirectional stdin/stdout byte pump.

    Returns 0 on clean close (server EOF), non-zero on local I/O
    errors.
    """
    stdin_fd = sys.stdin.fileno() if sys.stdin.isatty() or interactive else 0
    stdout_fd = sys.stdout.fileno()

    # Put stdin into raw mode for interactive sessions so we don't
    # eat the Ctrl-C / arrow keys locally — they go to the remote.
    saved_tty: Optional[list] = None
    if interactive and sys.stdin.isatty():
        try:
            saved_tty = termios.tcgetattr(stdin_fd)
            tty.setraw(stdin_fd)
        except (termios.error, OSError):
            saved_tty = None

    server_closed = False
    try:
        while True:
            r, _, _ = select.select([stdin_fd, sock.fileno()], [], [], 0.5)
            if stdin_fd in r:
                try:
                    chunk = os.read(stdin_fd, 65536)
                except OSError:
                    chunk = b''
                if not chunk:
                    # Local EOF: half-close write side via TLS shutdown
                    # is messy; just rely on close at exit.
                    pass
                else:
                    try:
                        sock.sendall(chunk)
                    except (ssl.SSLError, OSError):
                        break
            if sock.fileno() in r:
                try:
                    data = sock.recv(65536)
                except (ssl.SSLZeroReturnError, ssl.SSLWantReadError):
                    data = b''
                except (ssl.SSLError, OSError):
                    return 8
                if not data:
                    server_closed = True
                    break
                try:
                    os.write(stdout_fd, data)
                except OSError:
                    return 8
    finally:
        if saved_tty is not None:
            try:
                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, saved_tty)
            except (termios.error, OSError):
                pass

    return 0 if server_closed else 8


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog='mssh',
        description='ssh-rt-auth client (mTLS + JSON-framed session-RPC).',
        usage='mssh [options] user@host[:port] [-- command [args ...]]',
    )
    parser.add_argument('target',
                        help='user@host[:port] or host[:port]')
    parser.add_argument('-p', '--port', type=int, default=None,
                        help=f'wrapper port (default {DEFAULT_WRAPPER_PORT} '
                             f'or config.default_port)')
    parser.add_argument('-l', '--login-name',
                        help='login user (alternative to user@host syntax)')
    parser.add_argument('--identity', '-i',
                        help='path to mTLS client cert (default ~/.mssh/cert.pem)')
    parser.add_argument('--key',
                        help='path to mTLS client key (default ~/.mssh/key.pem)')
    parser.add_argument('--ca',
                        help='path to CA trust root (default ~/.mssh/ca.pem)')
    parser.add_argument('--config', default=DEFAULT_CONFIG_PATH,
                        help='path to mssh config (default ~/.mssh/config)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='log what mssh is doing to stderr')
    parser.add_argument('-t', '--force-tty', action='store_true',
                        help='request an interactive PTY even when stdin '
                             'is not a tty')
    parser.add_argument('-T', '--no-tty', action='store_true',
                        help='do not request a PTY')
    parser.add_argument('command', nargs=argparse.REMAINDER,
                        help='optional remote command (after --)')

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format='mssh: %(message)s',
        stream=sys.stderr,
    )

    try:
        cfg = load_config(args.config)
    except ValueError as e:
        print(f'mssh: config error: {e}', file=sys.stderr)
        return 2

    default_port = args.port or int(cfg.get('default_port',
                                            DEFAULT_WRAPPER_PORT))

    try:
        target = parse_target(args.target,
                              default_port=default_port,
                              default_user=args.login_name or os.environ.get('USER'))
    except ValueError as e:
        print(f'mssh: {e}', file=sys.stderr)
        return 2

    if not target.user:
        print('mssh: no login user (use user@host or -l user)', file=sys.stderr)
        return 2

    try:
        ident = resolve_identity(cfg,
                                 cert_override=args.identity,
                                 key_override=args.key,
                                 ca_override=args.ca)
        validate_identity(ident)
    except ValueError as e:
        print(f'mssh: {e}', file=sys.stderr)
        return 2

    # argparse REMAINDER preserves the leading '--' if present.
    remote_command_parts = list(args.command)
    if remote_command_parts and remote_command_parts[0] == '--':
        remote_command_parts = remote_command_parts[1:]
    remote_command = ' '.join(remote_command_parts) if remote_command_parts else None

    if args.force_tty and args.no_tty:
        print('mssh: -t and -T are mutually exclusive', file=sys.stderr)
        return 2

    # Default: interactive when no command + stdin is a TTY.
    if args.force_tty:
        interactive = True
    elif args.no_tty:
        interactive = False
    else:
        interactive = remote_command is None and sys.stdin.isatty()

    log.debug('target=%s interactive=%s command=%r',
              target, interactive, remote_command)

    return run_session(target, ident,
                       command=remote_command,
                       interactive=interactive)


if __name__ == '__main__':
    sys.exit(main())
