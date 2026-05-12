"""Cross-distro, multi-client connectivity matrix.

For every (source-container, target-server) pair we run **two** SSH clients
from inside the source container — the OpenSSH ``ssh`` binary and the
Dropbear ``dbclient`` binary — and verify the outcome matches the policy
that was registered for that user with the CA.

Why both clients:
  - The shim treats the wire format identically (raw SSH pubkey blob is
    forwarded to the CA), but the *clients* differ in how they negotiate
    PTY, key exchange, MACs, and authorized-key parsing. Both must produce
    the same authorization decision.
  - The Alpine container natively has Dropbear; the Ubuntu containers
    have it via ``dropbear-bin``. Each box therefore exercises both code
    paths.
"""
from __future__ import annotations

import sys

import pytest

from log_helpers import OpsLog, banner, pull_audit_tail, render_table, section
from lxc_helpers import (ALL_SSH_HOSTS, CA_HOST, SSHRT_ALPINE, lxc_exec)


pytestmark = pytest.mark.lxc


# ---------------------------------------------------------------------------
# In-container SSH-client invocation helpers
# ---------------------------------------------------------------------------

def _ssh_in_container(source: str, username: str,
                      target_ip: str, target_port: int,
                      command: str = 'echo OK',
                      timeout: int = 15) -> tuple[int, str, str]:
    """Run the OpenSSH `ssh` client from inside ``source`` as ``username``."""
    flags = (
        '-o BatchMode=yes -o StrictHostKeyChecking=no '
        '-o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes '
        '-o ConnectTimeout=6 '
        f'-i /home/{username}/.ssh/id_ed25519 '
        f'-p {target_port}'
    )
    cmd = (f'su - {username} -c '
           f'"ssh {flags} {username}@{target_ip} {command}"')
    r = lxc_exec(source, 'sh', '-c', cmd, check=False, timeout=timeout)
    return r.returncode, r.stdout or '', r.stderr or ''


_DBCLIENT_PATH_CACHE: dict[str, str] = {}


def _resolve_dbclient(container: str) -> str:
    """Find the absolute path of dbclient inside ``container``.

    Different distros place it differently:
      - Ubuntu (dropbear-bin):   /usr/lib/dropbear/dbclient
      - Alpine (dropbear):       /usr/bin/dbclient
    Busybox `su -` resets PATH, so we always invoke with an absolute path.
    """
    if container in _DBCLIENT_PATH_CACHE:
        return _DBCLIENT_PATH_CACHE[container]
    r = lxc_exec(
        container, 'sh', '-c',
        'for p in /usr/bin/dbclient /usr/lib/dropbear/dbclient '
        '/usr/local/bin/dbclient /usr/sbin/dbclient; do '
        '  [ -x "$p" ] && echo "$p" && exit 0; '
        'done; exit 1',
        check=False,
    )
    path = (r.stdout or '').strip()
    if not path:
        path = ''  # caller will treat as "dbclient unavailable"
    _DBCLIENT_PATH_CACHE[container] = path
    return path


def _dbclient_in_container(source: str, username: str,
                           target_ip: str, target_port: int,
                           command: str = 'echo OK',
                           timeout: int = 15) -> tuple[int, str, str]:
    """Run the Dropbear `dbclient` from inside ``source`` as ``username``.

    dbclient on Ubuntu 22.04 (v2020.81) and Alpine 3.21 (v2024.86) both
    refuse to read OpenSSH-format Ed25519 private keys directly ("String
    too long"), so we lazily convert each user's `id_ed25519` to a dropbear
    file (`id_ed25519.dropbear`) on first use, then point dbclient at that.
    """
    db = _resolve_dbclient(source)
    if not db:
        return 127, '', f'dbclient not present in {source}'
    convert = (
        f'test -f /home/{username}/.ssh/id_ed25519.dropbear || '
        f'dropbearconvert openssh dropbear '
        f'/home/{username}/.ssh/id_ed25519 '
        f'/home/{username}/.ssh/id_ed25519.dropbear >/dev/null 2>&1'
    )
    lxc_exec(source, 'sh', '-c', f'su - {username} -c "{convert}"',
             check=False, timeout=15)
    flags = (
        f'-y -y -i /home/{username}/.ssh/id_ed25519.dropbear '
        f'-p {target_port}'
    )
    cmd = (f'su - {username} -c '
           f'"{db} {flags} {username}@{target_ip} {command} 2>&1"')
    r = lxc_exec(source, 'sh', '-c', cmd, check=False, timeout=timeout)
    return r.returncode, r.stdout or '', r.stderr or ''


def _ensure_dbclient_on_path(container: str) -> None:
    """Prime the dbclient resolver cache for ``container``."""
    _resolve_dbclient(container)


# ---------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------

@pytest.fixture(scope='module', autouse=True)
def _prepare_clients(provisioned_env):
    """Ensure dbclient is on PATH in every container (Ubuntu hides it)."""
    for c in ALL_SSH_HOSTS:
        _ensure_dbclient_on_path(c)
    return provisioned_env


def test_cross_distro_client_matrix(provisioned_env):
    """For every (source container, target server, user, client-kind) tuple,
    verify the outcome matches the policy.

    Skip self-loops (source == target) — same machine self-SSHing isn't the
    test's concern.
    """
    scenario = provisioned_env['scenario']
    ips = provisioned_env['ips']
    ssh_port = provisioned_env['ssh_port']

    banner('Cross-distro multi-client connectivity matrix')

    rows: list[dict] = []
    failures: list[tuple] = []

    sources = [h.container_name for h in scenario.hosts]
    for source in sources:
        for host in scenario.hosts:
            if host.container_name == source:
                continue
            target_ip = ips[host.container_name]
            for user in scenario.users:
                allowed = host.canonical_name in user.allowed_hosts
                expect = 'granted' if allowed else 'denied'

                for client_kind, runner in (
                    ('ssh',      _ssh_in_container),
                    ('dbclient', _dbclient_in_container),
                ):
                    with OpsLog('client', source=source,
                                client=client_kind,
                                target=host.canonical_name,
                                user=user.username,
                                expect=expect) as op:
                        rc, stdout, stderr = runner(
                            source, user.username, target_ip, ssh_port,
                            command='echo OK')
                        # The AsyncSSH banner contains 'authorized session'
                        # regardless of which client connected.
                        actual = (
                            'granted'
                            if rc == 0 and
                               'ssh-rt-auth: authorized session' in stdout
                            else 'denied'
                        )
                        ok = (actual == expect)
                        op.record(actual=actual, ok=ok,
                                  rc=rc, stdout=stdout[-300:],
                                  stderr=stderr[-300:])
                        if not ok:
                            op.attach('audit_tail', pull_audit_tail(
                                lxc_exec, CA_HOST, n=5))
                            srvlog = lxc_exec(
                                host.container_name, 'tail', '-n', '20',
                                '/var/log/ssh-rt-auth-server.log',
                                check=False)
                            op.attach('asyncssh_log_tail',
                                      srvlog.stdout or srvlog.stderr)
                            failures.append((source, host.canonical_name,
                                             user.username, client_kind,
                                             expect, actual))
                    rows.append({
                        'source':  source.replace('sshrt-lxc-', ''),
                        'client':  client_kind,
                        'target':  host.canonical_name,
                        'user':    user.username,
                        'expect':  expect,
                        'actual':  actual if ok else f'!{actual}',
                        'ok':      '✓' if ok else '✗',
                    })

    section('Client × source × target × user matrix')
    print(render_table(rows, [
        'source', 'client', 'target', 'user', 'expect', 'actual', 'ok',
    ]), file=sys.stderr, flush=True)

    assert not failures, (
        f'{len(failures)} cross-distro client mismatches: '
        f'{failures[:6]}{"…" if len(failures) > 6 else ""}'
    )


def test_dbclient_works_from_alpine(provisioned_env):
    """Sanity check: Dropbear client on Alpine reaches a Ubuntu AsyncSSH server.

    This pins the cross-implementation interop assertion explicitly.
    """
    scenario = provisioned_env['scenario']
    ips = provisioned_env['ips']
    # Pick the first user with at least one allowed host.
    user = next((u for u in scenario.users if u.allowed_hosts), None)
    if user is None:
        pytest.skip('no user with allowed hosts in this scenario')
    canon = user.allowed_hosts[0]
    target = next(h for h in scenario.hosts if h.canonical_name == canon)
    target_ip = ips[target.container_name]
    with OpsLog('client', source=SSHRT_ALPINE, client='dbclient',
                target=canon, user=user.username,
                expect='granted') as op:
        rc, stdout, stderr = _dbclient_in_container(
            SSHRT_ALPINE, user.username, target_ip,
            provisioned_env['ssh_port'], command='echo OK')
        ok = rc == 0 and 'ssh-rt-auth: authorized session' in stdout
        op.record(actual='granted' if ok else 'denied',
                  ok=ok, rc=rc, stderr=stderr[-300:])
        if not ok:
            op.attach('audit_tail', pull_audit_tail(
                lxc_exec, CA_HOST, n=5))
    assert ok, f'Alpine dbclient → {canon} failed: rc={rc} stderr={stderr}'
