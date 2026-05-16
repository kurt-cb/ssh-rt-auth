"""Bytes proxy — moves bytes between an outer (client) connection and
an inner (sshd) connection in both directions.

In fallback mode the outer connection is a plain TCP socket and the
inner is also plain TCP to localhost:22.

In enforce mode (Phase 1B) the outer is TLS-terminated and the inner
is an asyncssh client session to the hermetic inner sshd. The proxy's
shape is the same; only how each side is established differs.

This module is intentionally protocol-agnostic — Variant B channel-aware
proxying (parse SSH_MSG_CHANNEL_OPEN frames) will live in a separate
``channel_filter.py`` and slot in between the two streams.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable


log = logging.getLogger('msshd.proxy')


# Buffer size for byte-shuffling. 64K is the practical maximum for most
# kernels' socket buffers; smaller chunks waste syscalls, larger ones
# may not be delivered in a single read.
_BUFSIZE = 65536


async def shuffle(
    src_reader: asyncio.StreamReader,
    dst_writer: asyncio.StreamWriter,
    *,
    label: str = 'proxy',
    on_close: Callable[[], Awaitable[None]] | None = None,
) -> int:
    """Read from ``src_reader`` and write to ``dst_writer`` until EOF or
    error. Returns total bytes shuffled. Always closes ``dst_writer``
    when done; the caller is responsible for the reader side.

    If ``on_close`` is supplied it is awaited after the shuffle ends
    (regardless of success/failure) — useful for tearing down the
    other half of a bidirectional proxy.
    """
    total = 0
    try:
        while True:
            chunk = await src_reader.read(_BUFSIZE)
            if not chunk:
                # EOF from src.
                break
            dst_writer.write(chunk)
            await dst_writer.drain()
            total += len(chunk)
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError) as e:
        log.debug('[%s] connection closed mid-shuffle: %s', label, e)
    except Exception:
        log.exception('[%s] unexpected error during shuffle', label)
        raise
    finally:
        try:
            dst_writer.close()
            try:
                await dst_writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass
        except Exception:
            log.debug('[%s] dst close raised', label, exc_info=True)
        if on_close is not None:
            try:
                await on_close()
            except Exception:
                log.debug('[%s] on_close raised', label, exc_info=True)
    return total


async def bidirectional_proxy(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    server_reader: asyncio.StreamReader,
    server_writer: asyncio.StreamWriter,
    *,
    conn_id: str = '?',
) -> tuple[int, int]:
    """Shuffle bytes both ways between (client_reader/writer) and
    (server_reader/writer) until one side EOFs. Returns
    (client_to_server_bytes, server_to_client_bytes).

    When either direction finishes, the other side is closed so both
    shuffler tasks unwind promptly.
    """
    log.debug('[%s] proxy started', conn_id)

    # Coroutines that close the *other* side when their direction ends.
    async def close_server():
        try:
            server_writer.close()
            await server_writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    async def close_client():
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    c2s_task = asyncio.create_task(
        shuffle(client_reader, server_writer,
                label=f'{conn_id} c→s', on_close=close_server))
    s2c_task = asyncio.create_task(
        shuffle(server_reader, client_writer,
                label=f'{conn_id} s→c', on_close=close_client))

    done, pending = await asyncio.wait(
        {c2s_task, s2c_task}, return_when=asyncio.FIRST_COMPLETED)
    # Whichever finished first has triggered its on_close; the other
    # task should unwind quickly once its peer is closed.
    for t in pending:
        try:
            await asyncio.wait_for(t, timeout=5.0)
        except asyncio.TimeoutError:
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass

    c2s = c2s_task.result() if c2s_task.done() and not c2s_task.cancelled() else 0
    s2c = s2c_task.result() if s2c_task.done() and not s2c_task.cancelled() else 0
    log.info('[%s] proxy finished: c→s=%d s→c=%d', conn_id, c2s, s2c)
    return c2s, s2c
