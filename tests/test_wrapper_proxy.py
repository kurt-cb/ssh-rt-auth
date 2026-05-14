"""Tests for wrapper.python.proxy — bidirectional byte shuffler."""
from __future__ import annotations

import asyncio
import os

import pytest

from wrapper.python.proxy import bidirectional_proxy, shuffle


pytestmark = pytest.mark.asyncio


async def _spawn_echo_server(host='127.0.0.1', port=0) -> tuple[asyncio.base_events.Server, int]:
    """Tiny echo server: reads bytes, writes them back, closes on EOF."""
    async def handle(reader, writer):
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle, host=host, port=port,
                                        reuse_address=True)
    real_port = server.sockets[0].getsockname()[1]
    return server, real_port


@pytest.fixture
def event_loop():
    """Per-test event loop (some pytest-asyncio versions need this)."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


async def test_shuffle_basic():
    """Simple read-from-stream-write-to-stream check."""
    payload = b'hello\nworld\n'

    # In-memory pipes via os.pipe.
    r_fd, w_fd = os.pipe()
    os.write(w_fd, payload)
    os.close(w_fd)

    src_reader = asyncio.StreamReader()
    loop = asyncio.get_running_loop()
    src_transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(src_reader),
        os.fdopen(r_fd, 'rb', buffering=0))

    # Destination: another pipe.
    dst_r, dst_w = os.pipe()
    dst_writer_transport, dst_writer_protocol = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin,
        os.fdopen(dst_w, 'wb', buffering=0))
    dst_writer = asyncio.StreamWriter(
        dst_writer_transport, dst_writer_protocol, None, loop)

    total = await shuffle(src_reader, dst_writer, label='test')
    assert total == len(payload)

    # Read what arrived on the destination pipe.
    out = os.read(dst_r, 64)
    os.close(dst_r)
    assert out == payload


async def test_bidirectional_proxy_against_echo():
    """End-to-end: client → proxy → echo server. Bytes round-trip."""
    server, server_port = await _spawn_echo_server()
    try:
        # Stand up the proxy as a server too.
        async def proxy_handler(client_reader, client_writer):
            srv_reader, srv_writer = await asyncio.open_connection(
                '127.0.0.1', server_port)
            await bidirectional_proxy(
                client_reader, client_writer,
                srv_reader, srv_writer,
                conn_id='test')

        proxy_server = await asyncio.start_server(
            proxy_handler, host='127.0.0.1', port=0,
            reuse_address=True)
        proxy_port = proxy_server.sockets[0].getsockname()[1]

        try:
            client_reader, client_writer = await asyncio.open_connection(
                '127.0.0.1', proxy_port)
            client_writer.write(b'ping\n')
            await client_writer.drain()
            data = await asyncio.wait_for(
                client_reader.readline(), timeout=2.0)
            assert data == b'ping\n'
            client_writer.write(b'pong\n')
            await client_writer.drain()
            data = await asyncio.wait_for(
                client_reader.readline(), timeout=2.0)
            assert data == b'pong\n'
            client_writer.close()
            try:
                await client_writer.wait_closed()
            except Exception:
                pass
        finally:
            proxy_server.close()
            await proxy_server.wait_closed()
    finally:
        server.close()
        await server.wait_closed()
