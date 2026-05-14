"""Inner SSH proxy — opens an asyncssh client connection to the inner
sshd, presents the just-minted user cert, and shuffles bytes between
the outer (TLS-terminated) stream and the inner SSH session.

Phase 1B uses asyncssh as the inner SSH client (no protocol parsing).
A future Variant B will sit between this layer and the outer
TLS stream to inspect channel-open / channel-request frames.

The current outer protocol over TLS is **raw SSH** — the wrapper
expects the client to speak ordinary SSH wire format inside the TLS
tunnel. That means we are effectively a single-session SSH relay
right now, not a generic byte proxy.

Phase 1B simplification: we don't multiplex SSH channels through
asyncssh's high-level API; instead we let asyncssh terminate the
inner SSH transport and we shuffle stdin/stdout/stderr of a single
``conn.create_session()`` call. Multi-channel support comes later.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import asyncssh


log = logging.getLogger('ssh-rt-wrapperd.ssh_proxy')


class _OuterRelay(asyncssh.SSHClientSession):
    """Relays inner-SSH session output to the outer TLS stream and
    vice-versa.

    This is the asyncssh-side endpoint. We pair it with an asyncio task
    that reads from the outer stream and feeds it into the inner
    channel.
    """

    def __init__(self, outer_writer: asyncio.StreamWriter):
        self._outer_writer = outer_writer
        self._inner_channel: Optional[asyncssh.SSHClientChannel] = None

    def connection_made(self, chan):
        self._inner_channel = chan

    def data_received(self, data, datatype):
        # datatype: None for stdout, EXTENDED_DATA_STDERR for stderr.
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            self._outer_writer.write(data)
        except (ConnectionResetError, BrokenPipeError):
            if self._inner_channel is not None:
                self._inner_channel.close()

    def eof_received(self):
        try:
            self._outer_writer.write_eof()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        return False

    def connection_lost(self, exc):
        if exc:
            log.debug('inner SSH channel lost: %s', exc)
        try:
            self._outer_writer.close()
        except Exception:
            pass


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
) -> None:
    """Connect to ``(inner_host, inner_port)`` as ``principal`` using
    ``user_private_key + user_cert``, open an interactive shell, and
    proxy bytes between it and the outer stream.

    Returns when either side EOFs or ``max_session_seconds`` fires.
    """
    log.info('[%s] connecting to inner sshd at %s:%d as %s',
             conn_id, inner_host, inner_port, principal)

    # Build a tuple asyncssh accepts as a client identity. The cert is
    # presented; the private key is used to sign the userauth request.
    client_keys = [(user_private_key, user_cert)]

    # Pin the inner sshd's host key (we just generated it).
    known_hosts = inner_host_key_path

    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                host=inner_host,
                port=inner_port,
                username=principal,
                client_keys=client_keys,
                known_hosts=known_hosts,
                keepalive_interval=0,
            ),
            timeout=10.0,
        )
    except (asyncssh.Error, asyncio.TimeoutError, OSError) as e:
        log.error('[%s] inner SSH connect failed: %s', conn_id, e)
        return

    async with conn:
        # Open a single interactive session. The hermetic inner sshd
        # only allows session channels (forwarding is disabled), so this
        # is the only channel type we need to expose.
        chan, session = await conn.create_session(
            lambda: _OuterRelay(outer_writer),
            term_type='xterm',
        )

        # Feed outer-stream bytes into the inner channel.
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

        pump_task = asyncio.create_task(pump_outer_to_inner())

        try:
            if max_session_seconds and max_session_seconds > 0:
                try:
                    await asyncio.wait_for(chan.wait_closed(),
                                            timeout=max_session_seconds)
                except asyncio.TimeoutError:
                    log.info('[%s] max_session_seconds (%d) elapsed; '
                             'closing channel', conn_id, max_session_seconds)
                    chan.close()
            else:
                await chan.wait_closed()
        finally:
            pump_task.cancel()
            try:
                await pump_task
            except (asyncio.CancelledError, Exception):
                pass

    log.info('[%s] inner SSH session closed', conn_id)
