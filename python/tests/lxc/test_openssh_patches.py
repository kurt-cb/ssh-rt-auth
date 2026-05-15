"""OpenSSH patches (0002 + 0003) — end-to-end test.

Verifies the two upstream-targeted patches in
``openssh-patches/patches/`` (at the repo root):

  - **0001** (NOTES.md's 0003): `SSH_AKC_PHASE` env var set on every
    `AuthorizedKeysCommand` invocation, with value `query` on the
    pubkey-auth `have_sig=0` (querying) phase and `verify` on
    `have_sig=1`.
  - **0002**: New `%R`, `%r`, `%L`, `%l` tokens expand to the remote
    IP, remote port, local IP, and local port that the connection
    arrived on.

The test builds patched OpenSSH from source inside an LXC container
(AKC strict-mode requires root-owned scripts on a root-owned path,
which we can satisfy in the container but not on the dev host), wires
in a trivial AKC shim that logs its env and argv, then drives one SSH
connection and inspects the log.

Architecture:

```
  client (ssh from inside the same container)
    |
    | ssh -i ed25519_key kgodwin@127.0.0.1
    v
  patched sshd (port 12222, inside container)
    | AuthorizedKeysCommand=/usr/local/bin/akc-shim.sh %u %R %r %L %l
    v
  akc-shim.sh
    | logs env (SSH_AKC_PHASE, etc.) + argv to /tmp/akc.log
    | returns the user's pubkey (auth succeeds)
```

Opt-in marker: ``-m openssh_patches``.

Container name: ``sshrt-patches-test``.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


# Re-use the lxc helpers loader trick.
import importlib.util as _ilu
_HERE = Path(__file__).resolve().parent
for _name in ('lxc_helpers', 'log_helpers'):
    _spec = _ilu.spec_from_file_location(_name, _HERE / f'{_name}.py')
    _mod = _ilu.module_from_spec(_spec)
    sys.modules[_name] = _mod
    _spec.loader.exec_module(_mod)

from lxc_helpers import (
    UBUNTU_IMAGE, get_ip, lxc, lxc_exec, push_file, push_text,
    wait_for_apt_quiescent, wait_for_port,
)
from log_helpers import banner, section


pytestmark = [pytest.mark.lxc, pytest.mark.openssh_patches]


CONTAINER = 'sshrt-patches-test'
SSHD_PORT = 12222


# The patches live at <repo-root>/openssh-patches/patches/. The
# openssh-portable submodule itself is *not* absorbed — operators
# clone it themselves (or use the sibling ssh-rt-auth-openssh repo
# if they already have one). The env var SSHRT_OPENSSH_PORTABLE
# can override the source path.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_OPENSSH_REPO = _REPO_ROOT / 'openssh-patches'
_OPENSSH_PORTABLE = Path(os.environ.get(
    'SSHRT_OPENSSH_PORTABLE',
    str(_REPO_ROOT.parent / 'ssh-rt-auth-openssh' / 'openssh-portable')))


# Apt packages needed for build + run.
_BUILD_DEPS = [
    'build-essential',
    'autoconf',
    'automake',     # provides aclocal — recommended by autoconf but
                    # we strip recommends; depend on it explicitly.
    'libssl-dev',
    'zlib1g-dev',
    'libcrypt-dev',
    'pkg-config',
    'openssh-client',  # for the test client; we use our own sshd binary
]


def _push_dir_tar(container: str, host_dir: Path, container_dir: str):
    """Tar a host directory into a container — works around 'lxc file
    push --recursive' being unavailable in some lxd versions."""
    tar_p = subprocess.Popen(
        ['tar', '-C', str(host_dir.parent), '-cf', '-', host_dir.name],
        stdout=subprocess.PIPE)
    extract_p = subprocess.Popen(
        ['lxc', 'exec', container, '--',
         'sh', '-c', f'mkdir -p {container_dir} && '
                     f'tar -C {container_dir} -xf -'],
        stdin=tar_p.stdout)
    tar_p.stdout.close()
    rc = extract_p.wait()
    tar_p.wait()
    if rc != 0:
        raise RuntimeError(f'tar→lxc-exec extract failed for {host_dir}')


def _push_git_archive(container: str, repo: Path, tag: str,
                      container_dir: str):
    """`git archive TAG` on the host, pipe into `tar -xf -` in the
    container. Produces a pristine source tree of TAG with no git
    metadata."""
    subprocess.run(['lxc', 'exec', container, '--',
                    'mkdir', '-p', container_dir], check=True)
    archive_p = subprocess.Popen(
        ['git', '-C', str(repo), 'archive', '--format=tar', tag],
        stdout=subprocess.PIPE)
    extract_p = subprocess.Popen(
        ['lxc', 'exec', container, '--',
         'tar', '-C', container_dir, '-xf', '-'],
        stdin=archive_p.stdout)
    archive_p.stdout.close()
    rc = extract_p.wait()
    archive_p.wait()
    if rc != 0:
        raise RuntimeError(
            f'git archive {tag} → tar -xf failed in {container}')


def test_openssh_patches_end_to_end(request):
    """Build patched sshd, drive one SSH connection, verify env + tokens."""

    keep = request.config.getoption('--keep-containers', default=False)

    if not _OPENSSH_REPO.exists():
        pytest.skip(f'{_OPENSSH_REPO} not present — '
                    'openssh-patches/ should be a top-level dir of the repo.')

    patches_dir = _OPENSSH_REPO / 'patches'
    if not (patches_dir / 'series').exists():
        pytest.skip(f'No patches/series in {patches_dir}')

    banner('OpenSSH patches 0002 + 0003 — end-to-end')

    section('Tearing down any pre-existing container')
    subprocess.run(['lxc', 'delete', '--force', CONTAINER],
                   capture_output=True)

    section('Launching container')
    lxc('launch', UBUNTU_IMAGE, CONTAINER,
        '--config', 'security.privileged=true', timeout=300)

    section('Installing build deps')
    wait_for_apt_quiescent(CONTAINER, max_wait=120)
    lxc_exec(CONTAINER, 'apt-get', 'update', '-q', timeout=180)
    lxc_exec(CONTAINER, 'apt-get', 'install', '-y', '-q',
             '--no-install-recommends', *_BUILD_DEPS, timeout=600)
    lxc_exec(CONTAINER, 'apt-get', 'clean')

    section('Pushing pristine V_9_9_P1 source via git archive')
    src = _OPENSSH_PORTABLE
    if not src.exists():
        pytest.skip(f'No openssh-portable submodule at {src} — '
                    'run `git submodule update --init` in '
                    f'{_OPENSSH_REPO}.')
    _push_git_archive(CONTAINER, src, 'V_9_9_P1',
                      '/build/openssh-portable')

    section('Pushing patches')
    _push_dir_tar(CONTAINER, patches_dir, '/build')
    series = (patches_dir / 'series').read_text()
    patch_files = [ln.strip() for ln in series.splitlines()
                   if ln.strip() and not ln.startswith('#')]

    section('Applying patches via `patch -p1`')
    for p in patch_files:
        section(f'  apply {p}')
        lxc_exec(CONTAINER, 'sh', '-c',
                 f'cd /build/openssh-portable && '
                 f'patch -p1 < /build/patches/{p}', timeout=30)
    # Confirm both patches landed in the source.
    r = lxc_exec(CONTAINER, 'sh', '-c',
                 'grep -c SSH_AKC_PHASE /build/openssh-portable/auth2-pubkey.c'
                 ' /build/openssh-portable/misc.c',
                 check=False)
    assert 'auth2-pubkey.c:' in (r.stdout or ''), \
        f'SSH_AKC_PHASE not in source: {r.stdout!r} {r.stderr!r}'
    r = lxc_exec(CONTAINER, 'sh', '-c',
                 'grep -cE \'"R", remote_ip\' '
                 '/build/openssh-portable/auth2-pubkey.c',
                 check=False)
    assert (r.stdout or '').strip() == '1', \
        f'%R token not in source: {r.stdout!r} {r.stderr!r}'

    section('Configuring and building sshd + sshd-session')
    lxc_exec(CONTAINER, 'sh', '-c',
             'cd /build/openssh-portable && autoreconf -f -i', timeout=120)
    lxc_exec(CONTAINER, 'sh', '-c',
             'cd /build/openssh-portable && ./configure '
             '--prefix=/opt/sshrt-sshd --sysconfdir=/opt/sshrt-sshd/etc '
             '--with-privsep-path=/var/empty-sshrt --without-pam',
             timeout=240)
    lxc_exec(CONTAINER, 'sh', '-c',
             'cd /build/openssh-portable && make sshd sshd-session -j$(nproc)',
             timeout=600)
    # Install just the binaries we need (avoids running `make install`'s
    # post-steps). ssh-sk-helper is only needed at runtime for FIDO/SK
    # keys, which we don't exercise — copy if present, skip otherwise.
    lxc_exec(CONTAINER, 'sh', '-c',
             'mkdir -p /opt/sshrt-sshd/sbin /opt/sshrt-sshd/libexec '
             '/var/empty-sshrt && '
             'cp /build/openssh-portable/sshd /opt/sshrt-sshd/sbin/sshd && '
             'cp /build/openssh-portable/sshd-session '
             '/opt/sshrt-sshd/libexec/sshd-session && '
             '(cp /build/openssh-portable/ssh-sk-helper '
             '/opt/sshrt-sshd/libexec/ssh-sk-helper 2>/dev/null || true) && '
             'chown root:root /opt/sshrt-sshd/sbin/sshd '
             '/opt/sshrt-sshd/libexec/sshd-session',
             timeout=30)

    section('Creating privsep user (required by sshd at startup)')
    # `make install` would create this; we did a partial install, so do it
    # manually. The privsep user only needs to exist; nothing else.
    lxc_exec(CONTAINER, 'sh', '-c',
             'id sshd >/dev/null 2>&1 || '
             'useradd -r -d /var/empty-sshrt -s /usr/sbin/nologin sshd')

    section('Generating host + user keys (in-container, root-owned)')
    lxc_exec(CONTAINER, 'sh', '-c',
             'mkdir -p /etc/sshrt-sshd && '
             "ssh-keygen -t ed25519 -N '' "
             "-f /etc/sshrt-sshd/host_ed25519 -q && "
             "ssh-keygen -t ed25519 -N '' "
             "-f /etc/sshrt-sshd/user_key -q && "
             'chmod 600 /etc/sshrt-sshd/host_ed25519 '
             '/etc/sshrt-sshd/user_key && '
             'chown -R root:root /etc/sshrt-sshd')

    section('Installing the test AKC shim (root-owned)')
    akc_shim = '''#!/bin/bash
# Logs env + argv to /tmp/akc.log on each call. Returns the test
# user's pubkey so auth succeeds.
{
  echo "=== $(date +%H:%M:%S.%N) ==="
  echo "SSH_AKC_PHASE=${SSH_AKC_PHASE:-<unset>}"
  echo "argv: $@"
} >> /tmp/akc.log
cat /etc/sshrt-sshd/user_key.pub
'''
    push_text(CONTAINER, akc_shim, '/usr/local/bin/akc-shim.sh')
    lxc_exec(CONTAINER, 'chmod', '755', '/usr/local/bin/akc-shim.sh')
    lxc_exec(CONTAINER, 'chown', 'root:root',
             '/usr/local/bin/akc-shim.sh')

    section('Writing sshd_config that exercises all four new tokens')
    sshd_conf = (
        f'ListenAddress 127.0.0.1\n'
        f'Port {SSHD_PORT}\n'
        f'HostKey /etc/sshrt-sshd/host_ed25519\n'
        f'PidFile /run/sshrt-sshd.pid\n'
        f'AuthenticationMethods publickey\n'
        f'PubkeyAuthentication yes\n'
        f'AuthorizedKeysFile /dev/null\n'
        # Pass user (%u), remote IP (%R), remote port (%r),
        # local IP (%L), local port (%l) — the new tokens from 0002.
        f'AuthorizedKeysCommand /usr/local/bin/akc-shim.sh '
        f'%u %R %r %L %l\n'
        f'AuthorizedKeysCommandUser root\n'
        f'PasswordAuthentication no\n'
        f'KbdInteractiveAuthentication no\n'
        # No UsePAM directive — sshd was built --without-pam so the
        # directive itself is rejected.
        f'StrictModes no\n'
        f'PrintMotd no\n'
        f'LogLevel VERBOSE\n'
    )
    push_text(CONTAINER, sshd_conf, '/etc/sshrt-sshd/sshd_config')

    section('Starting patched sshd')
    lxc_exec(CONTAINER, 'sh', '-c',
             'rm -f /tmp/akc.log /tmp/sshd.log && '
             '/opt/sshrt-sshd/sbin/sshd '
             '-f /etc/sshrt-sshd/sshd_config -E /tmp/sshd.log')
    wait_for_port(CONTAINER, SSHD_PORT, max_wait=15)

    section('Driving one SSH connection — exercises both query + verify '
            'phases')
    r = lxc_exec(CONTAINER, 'sh', '-c',
                 f'ssh -o BatchMode=yes -o StrictHostKeyChecking=no '
                 f'-o UserKnownHostsFile=/dev/null '
                 f'-o IdentitiesOnly=yes '
                 f'-i /etc/sshrt-sshd/user_key -p {SSHD_PORT} '
                 f'root@127.0.0.1 echo CONNECTED',
                 check=False, timeout=20)
    assert 'CONNECTED' in (r.stdout or ''), \
        f'ssh failed: rc={r.returncode} stdout={r.stdout!r} ' \
        f'stderr={r.stderr!r}'

    section('Inspecting AKC log')
    r = lxc_exec(CONTAINER, 'cat', '/tmp/akc.log')
    log = r.stdout or ''
    print(log, file=sys.stderr, flush=True)

    # ----- 0003 assertions: SSH_AKC_PHASE present, both query + verify -----
    assert 'SSH_AKC_PHASE=query' in log, \
        f'SSH_AKC_PHASE=query not seen in AKC log:\n{log}'
    assert 'SSH_AKC_PHASE=verify' in log, \
        f'SSH_AKC_PHASE=verify not seen in AKC log:\n{log}'

    # ----- 0002 assertions: tokens expanded correctly -----
    # Connection arrived from 127.0.0.1 on 127.0.0.1:SSHD_PORT.
    # argv per the AKC config: "%u %R %r %L %l" → "root 127.0.0.1 <rport> 127.0.0.1 <lport>"
    assert 'argv: root 127.0.0.1' in log, \
        f'%R did not expand to 127.0.0.1:\n{log}'
    assert f'127.0.0.1 {SSHD_PORT}' in log, \
        f'%L %l did not expand to 127.0.0.1 {SSHD_PORT}:\n{log}'

    # Sanity: the argv line should contain four non-empty fields after user.
    # Pull one of the argv lines out and parse it.
    argv_lines = [ln for ln in log.splitlines() if ln.startswith('argv: ')]
    assert argv_lines, f'no argv line in AKC log:\n{log}'
    for argv_line in argv_lines:
        parts = argv_line[len('argv: '):].split()
        assert len(parts) == 5, \
            f'expected 5 args (user remote_ip remote_port local_ip ' \
            f'local_port), got {parts!r} from {argv_line!r}'
        assert parts[0] == 'root', f'username arg wrong: {parts!r}'
        assert parts[1] == '127.0.0.1', f'%R wrong: {parts!r}'
        assert int(parts[2]) > 0, f'%r not an int: {parts!r}'
        assert parts[3] == '127.0.0.1', f'%L wrong: {parts!r}'
        assert int(parts[4]) == SSHD_PORT, \
            f'%l wrong (expected {SSHD_PORT}): {parts!r}'

    section('All assertions passed — both patches work end-to-end')

    if not keep:
        section('Tearing down container')
        subprocess.run(['lxc', 'delete', '--force', CONTAINER],
                       capture_output=True)
    else:
        section(f'--keep-containers: leaving {CONTAINER} for inspection')
