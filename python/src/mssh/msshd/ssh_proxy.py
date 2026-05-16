"""Inner SSH proxy — speaks outer-protocol-v1 to the mssh client and
asyncssh to the hermetic inner sshd.

After enforce_listener.py has done mTLS + CA call + cert mint, this
module:

  1. Reads one JSON header line from the outer stream.
  2. Acks (or denies) based on policy / sanity checks.
  3. Dispatches:
       - exec mode  → conn.run(command)
       - interactive → conn.create_session(..., term_type=...)
  4. Pumps bytes between the outer stream and the inner SSH session.

Protocol: see design/ssh-rt-auth-detailed-wrapper.md §3.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import asyncssh


log = logging.getLogger('msshd.ssh_proxy')


PROTOCOL_VERSION = 1
MAX_HEADER_BYTES = 4096


async def _read_header_line(reader: asyncio.StreamReader) -> dict:
    """Read one newline-terminated JSON object, ≤ MAX_HEADER_BYTES."""
    line = await asyncio.wait_for(
        reader.readuntil(b'\n'), timeout=10.0)
    if len(line) > MAX_HEADER_BYTES:
        raise ValueError(
            f'header exceeds {MAX_HEADER_BYTES} bytes ({len(line)})')
    body = json.loads(line.decode('utf-8'))
    if not isinstance(body, dict):
        raise ValueError('header not a JSON object')
    if int(body.get('v', 0)) != PROTOCOL_VERSION:
        raise ValueError(
            f'unsupported protocol version {body.get("v")!r}')
    return body


def _write_ack(writer: asyncio.StreamWriter, *,
               ok: bool, reason: str = '') -> None:
    body = {'v': PROTOCOL_VERSION, 'ok': ok}
    if not ok:
        body['reason'] = reason
    writer.write(json.dumps(body, separators=(',', ':')).encode('utf-8')
                  + b'\n')


class _OuterRelay(asyncssh.SSHClientSession):
    """Relays inner session stdout/stderr to the outer writer."""

    def __init__(self, outer_writer: asyncio.StreamWriter):
        self._outer = outer_writer

    def data_received(self, data, datatype):
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            self._outer.write(data)
        except (ConnectionResetError, BrokenPipeError):
            pass

    def eof_received(self):
        try:
            self._outer.write_eof()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        return False


async def proxy_to_inner_ssh(
    *,
    outer_reader: asyncio.StreamReader,
    outer_writer: asyncio.StreamWriter,
    inner_host: str,
    inner_port: int,
    principal: str,
    user_private_key: asyncssh.SSHKey,
    user_cert: asyncssh.SSHCertificate,
    inner_host_key_path: str,
    conn_id: str = '?',
    max_session_seconds: Optional[int] = None,
    forced_command: Optional[str] = None,
    forced_env: Optional[dict[str, str]] = None,
) -> None:
    """Read the v1 header from the outer stream, ack, then drive
    asyncssh against the inner sshd.

    Cert-mandated overrides:
      - ``forced_command`` (from mssh-force-command) overrides
        the client's ``command`` field if set.
      - ``forced_env`` (from mssh-environment) overrides /
        augments the client's ``env`` map.
    """
    # ---- 1. read header ----
    try:
        header = await _read_header_line(outer_reader)
    except asyncio.TimeoutError:
        log.warning('[%s] outer client did not send header in time', conn_id)
        _write_ack(outer_writer, ok=False, reason='header_timeout')
        await _drain_and_close(outer_writer)
        return
    except (json.JSONDecodeError, ValueError, asyncio.IncompleteReadError) as e:
        log.warning('[%s] outer header invalid: %s', conn_id, e)
        try:
            _write_ack(outer_writer, ok=False, reason=f'bad_header: {e}')
        except Exception:
            pass
        await _drain_and_close(outer_writer)
        return

    raw_command = header.get('command')
    interactive = bool(header.get('interactive'))
    term = header.get('term')
    rows = header.get('rows')
    cols = header.get('cols')
    env = header.get('env') or {}

    # Apply cert-mandated overrides.
    command: Optional[str]
    if forced_command:
        command = forced_command
    elif isinstance(raw_command, str):
        command = raw_command
    else:
        command = None  # interactive shell
    if forced_env:
        # Force-env wins — operator policy overrides client preference.
        env = {**env, **forced_env}

    log.info('[%s] outer header: command=%r interactive=%s term=%s '
             'rows=%s cols=%s',
             conn_id, command, interactive, term, rows, cols)

    # ---- 2. connect to inner sshd ----
    # asyncssh's `known_hosts` parameter expects a file in
    # ``ssh_config(5) known_hosts`` format (host + key per line) or a
    # 3-tuple. The wrapper has just generated the inner sshd's host
    # key itself, so trust it explicitly via the tuple form.
    try:
        host_pubkey_bytes = open(inner_host_key_path, 'rb').read()
        trusted_host_key = asyncssh.import_public_key(host_pubkey_bytes)
    except Exception as e:
        log.error('[%s] cannot read inner host key %s: %s',
                  conn_id, inner_host_key_path, e)
        _write_ack(outer_writer, ok=False, reason='inner_host_key_unreadable')
        await _drain_and_close(outer_writer)
        return
    known_hosts_tuple = ([trusted_host_key], [], [])

    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                host=inner_host, port=inner_port,
                username=principal,
                client_keys=[(user_private_key, user_cert)],
                known_hosts=known_hosts_tuple,
                keepalive_interval=0,
            ),
            timeout=10.0,
        )
    except (asyncssh.Error, asyncio.TimeoutError, OSError) as e:
        log.error('[%s] inner SSH connect failed: %s', conn_id, e)
        _write_ack(outer_writer, ok=False, reason=f'inner_connect_failed')
        await _drain_and_close(outer_writer)
        return

    # ---- 3. ack the client ----
    _write_ack(outer_writer, ok=True)
    try:
        await outer_writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        conn.close()
        return

    # ---- 4. dispatch ----
    async with conn:
        try:
            await asyncio.wait_for(
                _run_session(conn, outer_reader, outer_writer,
                             command=command,
                             interactive=interactive,
                             term=term, rows=rows, cols=cols, env=env,
                             conn_id=conn_id),
                timeout=max_session_seconds
                       if max_session_seconds and max_session_seconds > 0
                       else None,
            )
        except asyncio.TimeoutError:
            log.info('[%s] max_session_seconds elapsed; closing', conn_id)

    log.info('[%s] inner SSH session closed', conn_id)


async def _run_session(conn: asyncssh.SSHClientConnection,
                       outer_reader: asyncio.StreamReader,
                       outer_writer: asyncio.StreamWriter,
                       *,
                       command: Optional[str],
                       interactive: bool,
                       term: Optional[str],
                       rows: Optional[int],
                       cols: Optional[int],
                       env: dict[str, str],
                       conn_id: str) -> None:
    # asyncssh's create_session signature:
    #   create_session(session_factory, command=None, *, request_pty='auto',
    #                  term_type=None, term_size=(cols, rows), env=...)
    # Choose request_pty explicitly to make behavior predictable.
    request_pty: bool | str
    if interactive:
        request_pty = True
    else:
        request_pty = False

    create_kwargs: dict = {
        'command': command,                # None ⇒ interactive shell
        'request_pty': request_pty,
        'env': env or None,
    }
    if interactive:
        if term:
            create_kwargs['term_type'] = term
        if rows and cols:
            create_kwargs['term_size'] = (int(cols), int(rows))

    chan, _session = await conn.create_session(
        lambda: _OuterRelay(outer_writer), **create_kwargs)

    async def pump_outer_to_inner():
        try:
            while True:
                data = await outer_reader.read(65536)
                if not data:
                    chan.write_eof()
                    break
                chan.write(data)
        except (ConnectionResetError, BrokenPipeError,
                 asyncio.IncompleteReadError):
            pass
        finally:
            try:
                chan.close()
            except Exception:
                pass

    pump = asyncio.create_task(pump_outer_to_inner())
    try:
        await chan.wait_closed()
    finally:
        pump.cancel()
        try:
            await pump
        except (asyncio.CancelledError, Exception):
            pass

    # Drain any remaining buffered output.
    try:
        await outer_writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass


async def _drain_and_close(writer: asyncio.StreamWriter) -> None:
    try:
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
