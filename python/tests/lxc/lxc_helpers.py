"""LXC container helpers for ssh-rt-auth integration tests.

Topology (4 SSH machines + 1 CA, modeled on the user-confirmed plan):

  CA_HOST       Ubuntu 22.04 — Flask CA + ssh-rt-admin
  SSHRT_U1      Ubuntu 22.04 — sshd + Python shim
  SSHRT_U2      Ubuntu 22.04 — sshd + Python shim
  SSHRT_U3      Ubuntu 22.04 — sshd + Python shim
  SSHRT_ALPINE  Alpine 3     — sshd + Python shim   (cross-distro coverage)

All SSH hosts have Unix accounts for the full user matrix so the auth result
is governed by ssh-rt-auth's policy, not by a missing-account error. The user
matrix is built by ``tests/lxc/randomized.py`` from a deterministic seed.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


# Container names.
CA_HOST       = 'sshrt-lxc-ca'
SSHRT_U1      = 'sshrt-lxc-u1'
SSHRT_U2      = 'sshrt-lxc-u2'
SSHRT_U3      = 'sshrt-lxc-u3'
SSHRT_ALPINE  = 'sshrt-lxc-alpine'

ALL_SSH_HOSTS = [SSHRT_U1, SSHRT_U2, SSHRT_U3, SSHRT_ALPINE]
ALL_CONTAINERS = [CA_HOST] + ALL_SSH_HOSTS

UBUNTU_IMAGE = 'images:ubuntu/22.04'
ALPINE_IMAGE = 'images:alpine/3.21'

CA_PORT = 8443


# ---------------------------------------------------------------------------
# Subprocess wrappers
# ---------------------------------------------------------------------------

def lxc(*args: str, timeout: int = 180,
        check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ['lxc', *args], check=check, capture_output=True,
        text=True, timeout=timeout,
    )


def lxc_exec(container: str, *cmd: str, check: bool = True,
             timeout: int = 120,
             input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ['lxc', 'exec', container, '--', *cmd],
        check=check, capture_output=True, text=True,
        timeout=timeout, input=input_text,
    )


def push_text(container: str, content: str, remote_path: str,
              mode: str | None = None, owner: str | None = None) -> None:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False) as f:
        f.write(content)
        local = f.name
    try:
        subprocess.run(['lxc', 'file', 'push', local,
                        f'{container}{remote_path}'],
                       check=True, capture_output=True)
    finally:
        os.unlink(local)
    if mode:
        lxc_exec(container, 'chmod', mode, remote_path)
    if owner:
        lxc_exec(container, 'chown', owner, remote_path)


def push_file(container: str, local_path: str | Path, remote_path: str,
              mode: str | None = None, owner: str | None = None) -> None:
    subprocess.run(['lxc', 'file', 'push', str(local_path),
                    f'{container}{remote_path}'],
                   check=True, capture_output=True)
    if mode:
        lxc_exec(container, 'chmod', mode, remote_path)
    if owner:
        lxc_exec(container, 'chown', owner, remote_path)


def pull_file(container: str, remote_path: str,
              local_path: str | Path) -> None:
    subprocess.run(['lxc', 'file', 'pull',
                    f'{container}{remote_path}', str(local_path)],
                   check=True, capture_output=True)


def get_ip(container: str, max_wait: int = 120) -> str:
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = subprocess.run(['lxc', 'list', container, '--format', 'json'],
                           capture_output=True, text=True)
        data = json.loads(r.stdout or '[]')
        if data:
            net = (data[0].get('state') or {}).get('network') or {}
            for iface in net.values():
                for addr in iface.get('addresses') or []:
                    if (addr.get('family') == 'inet'
                            and not addr['address'].startswith('127.')):
                        return addr['address']
        time.sleep(2)
    raise RuntimeError(f'{container}: no IPv4 within {max_wait}s')


def wait_for_apt_quiescent(container: str, max_wait: int = 120) -> None:
    """Disable Ubuntu's background apt automation so our installs are
    deterministic, then wait for any in-flight apt-daily or
    unattended-upgrades to finish (so we can take the dpkg lock cleanly).

    Fresh Ubuntu containers run `apt-daily.timer`, `apt-daily-upgrade.timer`,
    `unattended-upgrades`, `apport`, and `ubuntu-report` on first boot.
    Racing them produces exit 100 ('Could not get lock
    /var/lib/dpkg/lock-frontend'). For a throwaway test container we
    don't need any of these services; the safest fix is to disable them
    proactively. Subsequent calls on an already-prepared container are
    a fast no-op.

    Idempotent: re-running on a prepared container is harmless.
    """
    # 1. Disable the timers so they won't kick off NEW apt jobs after we
    #    finish waiting. Best-effort: ignore failures from services that
    #    don't exist on minimal images.
    lxc_exec(container, 'sh', '-c', """
        systemctl stop  apt-daily.timer         apt-daily-upgrade.timer \
                       apport.service           2>/dev/null || true
        systemctl disable apt-daily.timer       apt-daily-upgrade.timer \
                       apport.service           2>/dev/null || true
        systemctl mask apt-daily.service        apt-daily-upgrade.service \
                       2>/dev/null || true
        ubuntu-report -f send no                2>/dev/null || true
    """, check=False, timeout=30)

    # 2. Wait for any in-flight apt/dpkg job to finish so we get the lock.
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = lxc_exec(
            container, 'sh', '-c',
            'pgrep -fa "apt-get|unattended-upgr|dpkg|aptd" 2>/dev/null '
            '| grep -v pgrep || echo CLEAR',
            check=False,
        )
        if 'CLEAR' in (r.stdout or ''):
            break
        time.sleep(2)
    else:
        raise RuntimeError(
            f'{container}: apt did not become quiescent in {max_wait}s')

    # 3. Purge unattended-upgrades so it can't be re-triggered. Done
    #    AFTER the wait, when we know we hold the lock.
    lxc_exec(container, 'sh', '-c',
             'DEBIAN_FRONTEND=noninteractive apt-get purge -y -q '
             'unattended-upgrades 2>/dev/null || true',
             check=False, timeout=60)


def wait_for_port(container: str, port: int, max_wait: int = 60) -> None:
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = lxc_exec(
            container, 'python3', '-c',
            f'import socket; s=socket.socket(); s.settimeout(2); '
            f's.connect(("127.0.0.1",{port})); s.close(); print("ok")',
            check=False,
        )
        if 'ok' in r.stdout:
            return
        time.sleep(2)
    raise RuntimeError(f'{container}: port {port} not ready')


def push_source(container: str, app_root: Path) -> None:
    """Bundle the ssh-rt-auth source tree and push to /app inside the container.

    ``app_root`` is the repo root; the tar bundles the Python source
    (python/src/ → /app/src/) plus the language-neutral configs
    (config/, scripts/, systemd/) used by the wrapper at runtime.
    Tests inside the container reference ``/app/src/sshrt/...``.
    """
    with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as f:
        tar = f.name
    try:
        subprocess.run(
            ['tar', '-C', str(app_root / 'python'), '-czf', tar,
             '--exclude=.git', '--exclude=__pycache__', '--exclude=.venv',
             '--exclude=tests/lxc',
             'src', 'requirements.txt'],
            check=True, capture_output=True,
        )
        lxc_exec(container, 'mkdir', '-p', '/app')
        push_file(container, tar, '/tmp/ssh-rt-auth.tar.gz')
        lxc_exec(container, 'tar', '-xzf', '/tmp/ssh-rt-auth.tar.gz', '-C', '/app')
        # Push language-neutral configs/scripts that live at the repo root.
        for top in ('config', 'scripts', 'systemd'):
            top_path = app_root / top
            if top_path.exists():
                with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as f2:
                    extra_tar = f2.name
                subprocess.run(
                    ['tar', '-C', str(app_root), '-czf', extra_tar, top],
                    check=True, capture_output=True,
                )
                try:
                    push_file(container, extra_tar, f'/tmp/{top}.tar.gz')
                    lxc_exec(container, 'tar', '-xzf',
                             f'/tmp/{top}.tar.gz', '-C', '/app')
                finally:
                    os.unlink(extra_tar)
    finally:
        os.unlink(tar)


def lxc_available() -> bool:
    try:
        r = subprocess.run(['lxc', 'version'], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Snoopy: opt-in command-execution logger for test diagnostics
# ---------------------------------------------------------------------------
#
# Snoopy is a small library that hooks `execve()` via /etc/ld.so.preload and
# writes every command (with uid, tty, cwd, full argv) to a log. When testing
# the full deployment, having a per-container log of every exec call is
# invaluable for diagnosing "why didn't this connection work" or "what did the
# shim actually try to run".
#
# Only installs on Ubuntu (apt package `snoopy` 2.4.15 in universe). Alpine
# uses musl libc; the upstream snoopy requires a custom musl build that is
# out of scope for the PoC.


SNOOPY_LOG_DIR  = '/root/systemlogs'
SNOOPY_LOG_FILE = f'{SNOOPY_LOG_DIR}/snoopy.log'


def install_snoopy(container: str) -> bool:
    """Install + configure snoopy on ``container``. Returns True on success.

    Side effects:
      - On Ubuntu: ``apt install snoopy`` + writes ``/etc/snoopy.ini`` + adds
        the library path to ``/etc/ld.so.preload`` so every future process
        is hooked (existing processes inside the container are NOT
        retroactively hooked — restart them if you want their commands too).
      - On Alpine: prints a notice and returns False (musl build out of scope).
    """
    if container.endswith('alpine'):
        print(f'  snoopy: Alpine container {container} skipped '
              '(needs musl source build — not packaged in apk)',
              file=sys.stderr, flush=True)
        return False
    r = lxc_exec(
        container, 'sh', '-c',
        'DEBIAN_FRONTEND=noninteractive apt-get install -y -q snoopy 2>&1',
        check=False, timeout=180,
    )
    if r.returncode != 0:
        print(f'  snoopy: apt install failed on {container}; tail:\n'
              f'{(r.stdout or r.stderr)[-300:]}',
              file=sys.stderr, flush=True)
        return False
    # Create log directory.
    lxc_exec(container, 'mkdir', '-p', SNOOPY_LOG_DIR)
    lxc_exec(container, 'sh', '-c',
             f': > {SNOOPY_LOG_FILE} && chmod 644 {SNOOPY_LOG_FILE}')
    # Configure snoopy output destination.
    ini = (
        '# Generated by tests/lxc/lxc_helpers.py:install_snoopy()\n'
        '[snoopy]\n'
        f'output = file:{SNOOPY_LOG_FILE}\n'
        'message_format = '
        '"%{datetime}|uid=%{uid}|pid=%{pid}|tty=%{tty}|cwd=%{cwd}|'
        'cmd=%{cmdline}"\n'
    )
    push_text(container, ini, '/etc/snoopy.ini', mode='644')
    # Locate libsnoopy.so (on Ubuntu it lives under /lib/<triplet>/ not /usr).
    r = lxc_exec(container, 'sh', '-c',
                 'for d in /lib /usr/lib /usr/lib64 /lib64; do '
                 '  find "$d" -name "libsnoopy.so" 2>/dev/null; '
                 'done | head -1',
                 check=False)
    so_path = (r.stdout or '').strip().splitlines()[0] if r.stdout else ''
    if not so_path:
        print(f'  snoopy: libsnoopy.so not found on {container}',
              file=sys.stderr, flush=True)
        return False
    # Idempotent preload registration.
    lxc_exec(container, 'sh', '-c',
             f'grep -q "{so_path}" /etc/ld.so.preload 2>/dev/null || '
             f'echo "{so_path}" >> /etc/ld.so.preload')
    print(f'  snoopy: installed on {container} → {SNOOPY_LOG_FILE} '
          f'(preload {so_path})', file=sys.stderr, flush=True)
    return True


def install_snoopy_on_all(containers: list[str]) -> dict[str, bool]:
    """Apply install_snoopy to a list of containers; return per-container result."""
    return {c: install_snoopy(c) for c in containers}
