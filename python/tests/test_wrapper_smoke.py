"""Smoke test: spawn msshd in fallback mode, drive bytes
through it to an in-process echo server, verify round-trip."""
from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f'port {host}:{port} did not open in {timeout}s')


async def _run_echo(port: int):
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

    server = await asyncio.start_server(handle, host='127.0.0.1', port=port,
                                        reuse_address=True)
    return server


def test_fallback_daemon_proxies_bytes(tmp_path):
    """Spawn the wrapper in fallback mode and confirm bytes shuffle
    end-to-end through it."""
    wrapper_port = _free_port()
    fallback_port = _free_port()

    cfg = tmp_path / 'wrapper.yaml'
    cfg.write_text(
        f'mode: fallback\n'
        f'fallback: {{host: 127.0.0.1, port: {fallback_port}}}\n'
        f'listen: '
        f'{{external_address: 127.0.0.1, external_port: {wrapper_port}}}\n'
        f'logging: {{level: warn, destination: stderr}}\n'
    )

    # Echo server on a thread-local asyncio loop. The shutdown_event is
    # awaited inside the loop and set from the main thread via
    # call_soon_threadsafe — keeps teardown clean (no
    # "Event loop stopped before Future completed").
    import threading

    loop = asyncio.new_event_loop()
    echo_started = threading.Event()
    shutdown_event: asyncio.Event | None = None

    def run_echo_loop():
        nonlocal shutdown_event

        async def _go():
            nonlocal shutdown_event
            server = await _run_echo(fallback_port)
            shutdown_event = asyncio.Event()
            echo_started.set()
            try:
                await shutdown_event.wait()
            finally:
                server.close()
                try:
                    await server.wait_closed()
                except Exception:
                    pass

        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_go())
        finally:
            try:
                loop.close()
            except Exception:
                pass

    echo_thread = threading.Thread(target=run_echo_loop, daemon=True)
    echo_thread.start()
    assert echo_started.wait(timeout=2.0), 'echo server failed to start'
    assert shutdown_event is not None

    # Spawn the wrapper daemon as a subprocess. The subprocess doesn't
    # inherit conftest's sys.path tweak, so pass PYTHONPATH explicitly.
    src_dir = Path(__file__).resolve().parent.parent / 'src'
    env = {**os.environ, 'PYTHONPATH': str(src_dir)}
    proc = subprocess.Popen(
        [sys.executable, '-m', 'sshrt.msshd', '--config', str(cfg)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=str(Path(__file__).resolve().parent.parent),
        env=env,
    )
    try:
        _wait_for_port('127.0.0.1', wrapper_port, timeout=5.0)

        # Send bytes through the wrapper, expect them echoed back.
        with socket.create_connection(('127.0.0.1', wrapper_port),
                                       timeout=3.0) as s:
            s.sendall(b'ping-through-the-wrapper\n')
            data = s.recv(64)
            assert data == b'ping-through-the-wrapper\n'

            s.sendall(b'pong-back\n')
            data = s.recv(64)
            assert data == b'pong-back\n'
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        # Stop the echo server cleanly via its asyncio.Event.
        if shutdown_event is not None:
            loop.call_soon_threadsafe(shutdown_event.set)
        echo_thread.join(timeout=2.0)


def test_fallback_daemon_rejects_no_fallback_target(tmp_path):
    """If the fallback target isn't reachable, the wrapper should
    accept the client connection then close it cleanly — not crash."""
    wrapper_port = _free_port()
    # Pick a port that's almost certainly not listening.
    fallback_port = 1   # privileged, almost always closed for non-root.

    cfg = tmp_path / 'wrapper.yaml'
    cfg.write_text(
        f'mode: fallback\n'
        f'fallback: {{host: 127.0.0.1, port: {fallback_port}}}\n'
        f'listen: '
        f'{{external_address: 127.0.0.1, external_port: {wrapper_port}}}\n'
        f'logging: {{level: warn, destination: stderr}}\n'
    )

    src_dir = Path(__file__).resolve().parent.parent / 'src'
    env = {**os.environ, 'PYTHONPATH': str(src_dir)}
    proc = subprocess.Popen(
        [sys.executable, '-m', 'sshrt.msshd', '--config', str(cfg)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=str(Path(__file__).resolve().parent.parent),
        env=env,
    )
    try:
        _wait_for_port('127.0.0.1', wrapper_port, timeout=5.0)
        # Connect; wrapper should accept then close.
        with socket.create_connection(('127.0.0.1', wrapper_port),
                                       timeout=3.0) as s:
            # Read should return empty (EOF) within timeout.
            s.settimeout(3.0)
            data = s.recv(64)
            assert data == b''   # EOF
        # And the wrapper is still alive.
        assert proc.poll() is None
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
