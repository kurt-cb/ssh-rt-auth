"""Outer connection listener.

In fallback mode this is a plain TCP listener that proxies each
connection to ``fallback.host:fallback.port`` (typically the system
sshd on localhost:22). No TLS, no auth — just bytes.

In enforce mode (Phase 1B) the listener will terminate mTLS, validate
the client cert, call the CA, mint an OpenSSH cert, and SSH to the
hermetic inner sshd. That path lives in ``enforce_listener`` (to be
added in Phase 1B); for now this module only handles fallback.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Awaitable, Callable

from .config import WrapperConfig
from .proxy import bidirectional_proxy


log = logging.getLogger('msshd.listener')


class FallbackListener:
    """A plain TCP listener that proxies to (fallback.host, fallback.port).

    Connections are independent; one bad connection doesn't tear down
    others. The server runs until ``stop()`` is called.
    """

    def __init__(self, cfg: WrapperConfig):
        self.cfg = cfg
        self._server: asyncio.base_events.Server | None = None
        self._active: set[asyncio.Task] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._on_client,
            host=self.cfg.listen.external_address,
            port=self.cfg.listen.external_port,
            reuse_address=True,
        )
        sockets = self._server.sockets or []
        for s in sockets:
            log.info('listening on %s (fallback to %s:%d)',
                     s.getsockname(),
                     self.cfg.fallback.host,
                     self.cfg.fallback.port)

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError('start() not called')
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        try:
            await self._server.wait_closed()
        except Exception:
            log.debug('server wait_closed raised', exc_info=True)
        # Cancel any in-flight connection handlers.
        for t in list(self._active):
            t.cancel()
        if self._active:
            await asyncio.gather(*self._active, return_exceptions=True)

    async def _on_client(self,
                         client_reader: asyncio.StreamReader,
                         client_writer: asyncio.StreamWriter) -> None:
        peer = client_writer.get_extra_info('peername') or ('?', 0)
        conn_id = uuid.uuid4().hex[:8]
        log.info('[%s] accept from %s:%d (fallback)', conn_id, peer[0], peer[1])

        task = asyncio.current_task()
        if task is not None:
            self._active.add(task)
        try:
            try:
                server_reader, server_writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host=self.cfg.fallback.host,
                        port=self.cfg.fallback.port),
                    timeout=10.0)
            except (OSError, asyncio.TimeoutError) as e:
                log.error('[%s] connect to fallback %s:%d failed: %s',
                          conn_id, self.cfg.fallback.host,
                          self.cfg.fallback.port, e)
                try:
                    client_writer.close()
                    await client_writer.wait_closed()
                except Exception:
                    pass
                return

            await bidirectional_proxy(
                client_reader, client_writer,
                server_reader, server_writer,
                conn_id=conn_id)
        finally:
            if task is not None:
                self._active.discard(task)
            log.info('[%s] closed', conn_id)
