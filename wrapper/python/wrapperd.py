"""ssh-rt-wrapperd — daemon entry point.

Phase 1A: fallback mode only. Listens, proxies bytes to a downstream
sshd. No mTLS, no CA, no cert minting.

Phase 1B (next): enforce mode. The same daemon, with a TLS-terminating
listener + CA call + cert mint + inner-sshd-managed handoff.

Invocation:
    python -m wrapper.python --config /etc/ssh-rt-auth/wrapper.yaml
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from .config import MODE_ENFORCE, MODE_FALLBACK, WrapperConfig
from .listener import FallbackListener


log = logging.getLogger('ssh-rt-wrapperd')


_LEVELS = {
    'debug': logging.DEBUG, 'info': logging.INFO,
    'warn': logging.WARNING, 'warning': logging.WARNING,
    'error': logging.ERROR,
}


def _setup_logging(cfg: WrapperConfig) -> None:
    level = _LEVELS.get(cfg.logging_.level.lower(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(name)s [%(levelname)s] %(message)s',
        stream=sys.stderr,
    )


async def _run(cfg: WrapperConfig) -> int:
    if cfg.mode == MODE_FALLBACK:
        listener = FallbackListener(cfg)
        await listener.start()

        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop_event.set)

        serve_task = asyncio.create_task(listener.serve_forever())
        try:
            await stop_event.wait()
            log.info('shutdown signal received')
        finally:
            await listener.stop()
            serve_task.cancel()
            try:
                await serve_task
            except (asyncio.CancelledError, Exception):
                pass
        return 0

    if cfg.mode == MODE_ENFORCE:
        log.error(
            'enforce mode is not implemented in Phase 1A. '
            'Set mode: fallback in wrapper.yaml, or wait for Phase 1B.')
        return 2

    log.error('unknown mode: %r', cfg.mode)
    return 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog='ssh-rt-wrapperd')
    ap.add_argument('--config', default='/etc/ssh-rt-auth/wrapper.yaml',
                    help='path to wrapper.yaml')
    args = ap.parse_args(argv)

    try:
        cfg = WrapperConfig.load(args.config)
        cfg.validate()
        cfg.check_permissions()
    except (FileNotFoundError, ValueError) as e:
        print(f'config error: {e}', file=sys.stderr)
        return 2
    except Exception as e:
        print(f'config load failed: {e}', file=sys.stderr)
        return 2

    _setup_logging(cfg)
    log.info('ssh-rt-wrapperd starting (mode=%s)', cfg.mode)

    try:
        return asyncio.run(_run(cfg))
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    sys.exit(main())
