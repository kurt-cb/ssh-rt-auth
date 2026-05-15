"""ssh-rt-wrapperd — daemon entry point.

Phase 1A: fallback mode. Listens, proxies bytes to a downstream sshd.
No mTLS, no CA, no cert minting.

Phase 1B: enforce mode. TLS-terminating listener + CA call + cert mint
+ inner-sshd-managed handoff via asyncssh.

Invocation:
    python -m sshrt.msshd --config /etc/ssh-rt-auth/wrapper.yaml
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
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
        return await _run_enforce(cfg)

    log.error('unknown mode: %r', cfg.mode)
    return 2


async def _run_enforce(cfg: WrapperConfig) -> int:
    # Lazy imports — enforce mode pulls in asyncssh + cryptography
    # heavy paths only when needed.
    from .ca import WrapperCAClient
    from .enforce_listener import EnforceListener
    from .inner import InnerSshd
    from .userca import UserCA

    state_dir = os.environ.get(
        'SSH_RT_AUTH_WRAPPER_STATE_DIR',
        '/var/lib/ssh-rt-auth')

    # 1. Load the user-CA private key (in memory only after this).
    user_ca_priv_path = os.path.join(state_dir, 'wrapper-user-ca')
    try:
        user_ca = UserCA.load(user_ca_priv_path)
    except (FileNotFoundError, ValueError) as e:
        log.error('cannot load wrapper-user-ca from %s: %s. '
                  'Run: ssh-rt-wrapper-admin init',
                  user_ca_priv_path, e)
        return 2

    # 2. Inner sshd lifecycle.
    inner = InnerSshd(
        cfg, state_dir=os.path.join(state_dir, 'inner-sshd'),
        user_ca_pubkey_path=os.path.join(
            state_dir, 'inner-sshd', 'wrapper-user-ca.pub'),
    )
    try:
        await inner.start()
    except Exception as e:
        log.error('inner sshd failed to start: %s', e)
        return 3

    try:
        # 3. CA client.
        try:
            ca_client = WrapperCAClient(cfg)
        except Exception as e:
            log.error('CA client init failed: %s', e)
            await inner.stop()
            return 4

        # 4. The actual outer mTLS listener.
        listener = EnforceListener(cfg, user_ca=user_ca,
                                   ca_client=ca_client, inner_sshd=inner)
        try:
            await listener.start()
        except Exception as e:
            log.error('enforce listener failed to start: %s', e)
            return 5

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
    finally:
        await inner.stop()


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
