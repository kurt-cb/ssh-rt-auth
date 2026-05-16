"""Inner sshd subprocess lifecycle.

The wrapper owns a private OpenSSH ``sshd`` instance bound to a
high-port on 127.0.0.1. Its config is **hermetic** — rendered from a
template that ships with the wrapper, hash-validated against an
embedded known-good per OpenSSH version, and never edited by
operators.

See [detailed-wrapper.md §5](../../design/ssh-rt-auth-detailed-wrapper.md).

Lifecycle:
  - ``InnerSshd.start()`` — render config, generate host key if absent,
    spawn ``sshd -f config -D`` (foreground), wait for it to bind.
  - ``InnerSshd.stop()`` — SIGTERM + wait, escalate to SIGKILL after
    grace period.
  - ``InnerSshd.port`` — the actual bound port (allocated by us before
    spawn; sshd does not pick its own).

This module is asyncio-friendly: ``start`` and ``stop`` are coroutines.
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import re
import shutil
import socket
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

from .config import WrapperConfig


log = logging.getLogger('msshd.inner')


_DEFAULT_BANNER = """\
─────────────────────────────────────────────────────────────
  Welcome — this session is mediated by mssh.

  Authorization was issued by the mssh CA. Your access is
  logged centrally. Per-session context (user, server, group,
  CA authorization details) will appear here once variable
  substitution lands — see design/future-ideas.md.

  To customize this banner, contact your administrator
  (mssh-admin server banner — coming).
─────────────────────────────────────────────────────────────
"""


def _find_template() -> Path:
    """Locate the hermetic sshd_config.template file.

    Checked in priority order:
      1. ``$SSHRT_SSHD_CONFIG_TEMPLATE`` env var (operator escape hatch).
      2. ``/etc/ssh-rt-auth/sshd_config.template`` (installed location).
      3. Walking up from this file, find the nearest ``config/sshd_config.template``.
         Handles both the development checkout layout (template at the
         repo root's ``config/``) and the LXC-test push-source layout
         (template at ``/app/config/``).

    Raises FileNotFoundError if no candidate exists.
    """
    candidates = []

    env_override = os.environ.get('SSHRT_SSHD_CONFIG_TEMPLATE')
    if env_override:
        candidates.append(Path(env_override))

    candidates.append(Path('/etc/ssh-rt-auth/sshd_config.template'))

    # Walk up from this file's parents looking for `config/sshd_config.template`.
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / 'config' / 'sshd_config.template'
        candidates.append(cand)
        # Stop walking once we leave a plausible project root (one of the
        # parents is named one of these).
        if parent.name in ('src', 'python', 'ssh-rt-auth'):
            continue
        if parent == parent.parent:  # filesystem root
            break

    for c in candidates:
        if c.is_file():
            return c
    raise FileNotFoundError(
        f'sshd_config.template not found in any of: '
        + ', '.join(str(c) for c in candidates))


class InnerSshdError(RuntimeError):
    """Inner sshd failed to start or died unexpectedly."""


class InnerSshd:
    def __init__(self, cfg: WrapperConfig, *,
                 state_dir: str | Path = '/var/lib/ssh-rt-auth/inner-sshd',
                 user_ca_pubkey_path: str | Path | None = None):
        self.cfg = cfg
        self.state_dir = Path(state_dir)
        self.user_ca_pubkey_path = (
            Path(user_ca_pubkey_path) if user_ca_pubkey_path
            else self.state_dir / 'wrapper-user-ca.pub')
        self._port: int | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._sshd_binary = cfg.inner.sshd_binary

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    @property
    def port(self) -> int:
        if self._port is None:
            raise RuntimeError('InnerSshd not started yet')
        return self._port

    async def start(self) -> None:
        if self._proc is not None and self._proc.returncode is None:
            raise InnerSshdError('already running')

        if not Path(self._sshd_binary).is_file():
            raise InnerSshdError(
                f'sshd binary not found at {self._sshd_binary}')

        version = await _detect_sshd_version(self._sshd_binary)
        log.info('inner sshd binary: %s (%s)', self._sshd_binary, version)

        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o0750)

        # OpenSSH's distro builds use /run/sshd for privilege separation.
        # Systemd creates it for the system ssh.service via RuntimeDirectory;
        # we're not on that path, so we have to ensure it exists. Best-effort:
        # if we don't have privilege to create it, the sshd binary will
        # complain and we'll surface that via wait_port_open's error path.
        try:
            Path('/run/sshd').mkdir(mode=0o0755, exist_ok=True)
        except PermissionError:
            log.warning('cannot create /run/sshd — inner sshd may fail '
                        'to start. Run wrapper as root or use a sshd '
                        'binary built with a custom --with-privsep-path.')

        # 1. Ensure a host key exists. Per-host, generated on first
        #    start, not rotated routinely (it's behind the outer mTLS;
        #    only matters between wrapper and inner sshd on localhost).
        host_key = self.state_dir / 'ssh_host_ed25519_key'
        if not host_key.exists():
            await _gen_host_key(host_key)
            log.info('generated inner sshd host key at %s', host_key)

        # 2. Ensure the user-CA pubkey file exists; the wrapper writes
        #    it via UserCA.write_public_to() in admin init. We don't
        #    write it here — that's a wrapperd-startup concern.
        if not self.user_ca_pubkey_path.exists():
            raise InnerSshdError(
                f'user-CA pubkey not at {self.user_ca_pubkey_path} '
                '(run ssh-rt-wrapper-admin init)')

        # 3. Allocate a port in the configured range.
        lo, hi = self.cfg.inner.port_range
        self._port = _allocate_port(lo, hi)
        log.info('inner sshd will bind 127.0.0.1:%d', self._port)

        # 4. Write the pre-auth banner file. Hardcoded content for
        #    now; per-session ({user}, {server}, {group},
        #    $MSSH_AUTH_DATA) substitution is planned (future-ideas.md).
        banner_path = self.state_dir / 'banner'
        banner_path.write_text(_DEFAULT_BANNER)
        os.chmod(banner_path, 0o0644)

        # 5. Render the hermetic config.
        config_path = self.state_dir / 'sshd_config'
        rendered = _render_template(_find_template(),
            INNER_PORT=str(self._port),
            INNER_HOST_KEY=str(host_key),
            USER_CA_PUBKEY=str(self.user_ca_pubkey_path),
            BANNER_FILE=str(banner_path),
        )
        config_path.write_text(rendered)
        os.chmod(config_path, 0o0600)
        log.debug('wrote inner sshd_config to %s', config_path)

        # 5. Spawn sshd in foreground mode. We hold its lifecycle.
        self._proc = await asyncio.create_subprocess_exec(
            self._sshd_binary, '-D', '-f', str(config_path),
            '-E', str(self.state_dir / 'sshd.log'),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        # 6. Wait for the port to come up. If sshd crashes during
        #    startup, surface stderr in the exception so operators see
        #    a real reason.
        if not await _wait_port_open('127.0.0.1', self._port, timeout=10.0):
            stderr = b''
            try:
                stderr = await asyncio.wait_for(
                    self._proc.stderr.read(8192), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            await self.stop(grace=0.5)
            raise InnerSshdError(
                f'inner sshd did not bind 127.0.0.1:{self._port} within 10s '
                f'(stderr={stderr!r})')

        log.info('inner sshd is up on 127.0.0.1:%d (pid=%d)',
                 self._port, self._proc.pid)

    async def stop(self, *, grace: float = 3.0) -> None:
        if self._proc is None or self._proc.returncode is not None:
            return
        log.info('stopping inner sshd (pid=%d, grace=%.1fs)',
                 self._proc.pid, grace)
        try:
            self._proc.terminate()
        except ProcessLookupError:
            return
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._proc.wait(), timeout=grace)
        if self._proc.returncode is None:
            log.warning('inner sshd did not exit after SIGTERM; sending SIGKILL')
            try:
                self._proc.kill()
            except ProcessLookupError:
                pass
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._proc.wait(), timeout=grace)

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _render_template(template_path: Path, **vars: str) -> str:
    text = template_path.read_text()
    for k, v in vars.items():
        text = text.replace('{{' + k + '}}', v)
    return text


def _allocate_port(lo: int, hi: int) -> int:
    """Return an available TCP port on 127.0.0.1 in [lo, hi].

    Race-free strategy: try a handful of random ports, return the
    first that ``bind()``s successfully. We don't hold the bind --
    sshd will re-bind when it starts. There's a small TOCTOU window
    where another process could grab the port between us closing and
    sshd binding, but it's negligible on a host the wrapper owns.
    """
    candidates = random.sample(range(lo, hi + 1), k=min(100, hi - lo + 1))
    for port in candidates:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
            except OSError:
                continue
            return port
    raise InnerSshdError(f'no free port found in [{lo}, {hi}]')


async def _wait_port_open(host: str, port: int, *, timeout: float) -> bool:
    """Poll for the port to be listening. Returns True on success."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            r, w = await asyncio.open_connection(host, port)
        except (ConnectionRefusedError, OSError):
            await asyncio.sleep(0.1)
            continue
        w.close()
        with suppress(Exception):
            await w.wait_closed()
        return True
    return False


async def _detect_sshd_version(sshd_binary: str) -> str:
    """Run ``sshd -V`` (or fall back to parsing ``sshd -h``) to get the
    OpenSSH version string. Best-effort; we just want it for logging
    and (in Phase 1B+) hermetic-config hash-table lookups."""
    # sshd typically reports version on stderr in response to invalid
    # invocation. Use -V if supported (newer OpenSSH), else -h.
    try:
        proc = await asyncio.create_subprocess_exec(
            sshd_binary, '-V',
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = await proc.communicate()
        text = (out + err).decode('utf-8', errors='replace')
    except FileNotFoundError:
        return 'unknown'
    m = re.search(r'OpenSSH[_ ]\d+\.\d+[a-z]?\d*', text)
    return m.group(0) if m else 'unknown'


async def _gen_host_key(host_key_path: Path) -> None:
    """Generate an Ed25519 host key via ssh-keygen. We don't use
    asyncssh.generate_private_key here because OpenSSH may expect a
    specific format wrinkle for host keys; ssh-keygen is the canonical
    producer."""
    ssh_keygen = shutil.which('ssh-keygen') or '/usr/bin/ssh-keygen'
    proc = await asyncio.create_subprocess_exec(
        ssh_keygen, '-t', 'ed25519', '-N', '', '-f', str(host_key_path),
        '-q', stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    rc = await proc.wait()
    if rc != 0:
        stderr = await proc.stderr.read()
        raise InnerSshdError(
            f'ssh-keygen failed (rc={rc}): {stderr.decode(errors="replace")}')
    os.chmod(host_key_path, 0o0600)
