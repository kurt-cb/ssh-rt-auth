"""Authorization-model matrix test.

For every (user, server) pair in the scenario:

  - From SSHRT_U1 (or another client), ssh as the user to the AsyncSSH server
    on the target container's port 2222.
  - If the user's policy lists that server's canonical name, expect success
    (the SSH command returns 0 and the AsyncSSH banner appears).
  - Otherwise expect failure (auth denied by the shim).

Each connection produces one ``OpsLog`` row. On any failure, the diagnostic
attachments (CA audit tail, shim log tail, AsyncSSH server log) are dumped
inline.
"""
from __future__ import annotations

import json
import sys

import pytest

from log_helpers import (OpsLog, banner, pull_audit_tail, render_table, section)
from lxc_helpers import CA_HOST, SSHRT_U1, lxc_exec


pytestmark = pytest.mark.lxc


# ---------------------------------------------------------------------------
# SSH helper that runs from inside a container as a given Unix user
# ---------------------------------------------------------------------------

def _ssh_from(client_container: str, username: str,
              target_ip: str, target_port: int,
              command: str = 'echo OK',
              timeout: int = 15) -> tuple[int, str, str]:
    """Run ``ssh`` from inside ``client_container`` as ``username``.

    Strict host-key checking disabled — the AsyncSSH server's host key isn't
    pre-loaded into known_hosts and that's not what this test validates.
    """
    flags = (
        '-o BatchMode=yes -o StrictHostKeyChecking=no '
        '-o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes '
        '-o ConnectTimeout=8 '
        f'-i /home/{username}/.ssh/id_ed25519 '
        f'-p {target_port}'
    )
    cmd = (
        f'su - {username} -c '
        f'"ssh {flags} {username}@{target_ip} {command}"'
    )
    r = lxc_exec(client_container, 'sh', '-c', cmd, check=False,
                 timeout=timeout)
    return r.returncode, r.stdout or '', r.stderr or ''


# ---------------------------------------------------------------------------
# Matrix test
# ---------------------------------------------------------------------------

def test_full_matrix(provisioned_env):
    """Run user × server matrix from SSHRT_U1 and check every outcome."""
    scenario = provisioned_env['scenario']
    ips = provisioned_env['ips']
    ssh_port = provisioned_env['ssh_port']
    canonical_to_container = provisioned_env['canonical_to_container']

    banner('User × Server connectivity matrix')

    rows: list[dict] = []
    failures: list[tuple[str, str, str, str]] = []

    for user in scenario.users:
        for host in scenario.hosts:
            target_ip = ips[host.container_name]
            allowed = host.canonical_name in user.allowed_hosts
            expect = 'granted' if allowed else 'denied'
            with OpsLog('ssh', source=SSHRT_U1, target=host.canonical_name,
                        user=user.username, expect=expect) as op:
                rc, stdout, stderr = _ssh_from(
                    SSHRT_U1, user.username, target_ip, ssh_port,
                    command='echo OK')
                if rc == 0 and 'ssh-rt-auth: authorized session' in stdout:
                    actual = 'granted'
                else:
                    actual = 'denied'
                ok = (actual == expect)
                op.record(actual=actual, ok=ok,
                          rc=rc, stdout=stdout[-400:],
                          stderr=stderr[-400:])
                if not ok:
                    op.attach('audit_tail', pull_audit_tail(
                        lxc_exec, CA_HOST, n=8))
                    # Pull the AsyncSSH server log too — the most likely
                    # cause of a missing /v1/authorize call is rejection
                    # inside validate_public_key BEFORE the shim is invoked.
                    srvlog = lxc_exec(host.container_name, 'tail', '-n', '20',
                                      '/var/log/ssh-rt-auth-server.log',
                                      check=False)
                    op.attach('asyncssh_log_tail',
                              srvlog.stdout or srvlog.stderr)
                    failures.append((user.username, host.canonical_name,
                                     expect, actual))
            rows.append({
                'user': user.username,
                'role': user.role,
                'server': host.canonical_name,
                'container': host.container_name,
                'expect': expect,
                'actual': actual if ok else f'!{actual}',
                'ok': '✓' if ok else '✗',
            })

    section('Matrix result table')
    print(render_table(
        rows, ['user', 'role', 'server', 'container', 'expect', 'actual', 'ok']),
          file=sys.stderr, flush=True)

    if failures:
        section('Dumping CA audit log on failure')
        r = lxc_exec(CA_HOST, 'cat', '/var/log/ssh-rt-auth/audit.jsonl',
                     check=False)
        for line in (r.stdout or '').splitlines()[-50:]:
            try:
                obj = json.loads(line)
                print(f'  {obj}', file=sys.stderr)
            except Exception:
                print(f'  {line}', file=sys.stderr)
    assert not failures, f'{len(failures)} mismatches: {failures}'


# ---------------------------------------------------------------------------
# Symmetry test: connect from a different source container
# ---------------------------------------------------------------------------

def test_matrix_from_alternate_source(provisioned_env):
    """Repeat one slice of the matrix from a different source container.

    Picks each user once, ssh's them from their own server to another allowed
    server (or any if they have multiple). Verifies the authorization
    decision is independent of which container is acting as the client.
    """
    scenario = provisioned_env['scenario']
    ips = provisioned_env['ips']
    ssh_port = provisioned_env['ssh_port']
    canonical_to_container = provisioned_env['canonical_to_container']

    banner('Matrix sanity from alternate source containers')

    failures = []
    for user in scenario.users:
        if not user.allowed_hosts:
            continue
        # Pick a source != target.
        for target_canon in user.allowed_hosts:
            target_container = canonical_to_container[target_canon]
            source_canon = next(
                (c for c in user.allowed_hosts if c != target_canon),
                user.allowed_hosts[0])
            source_container = canonical_to_container[source_canon]
            target_ip = ips[target_container]
            with OpsLog('ssh', source=source_container, target=target_canon,
                        user=user.username, expect='granted') as op:
                rc, stdout, stderr = _ssh_from(
                    source_container, user.username, target_ip, ssh_port)
                ok = (rc == 0 and
                      'ssh-rt-auth: authorized session' in stdout)
                op.record(actual='granted' if ok else 'denied',
                          ok=ok, rc=rc, stderr=stderr[-400:])
                if not ok:
                    op.attach('audit_tail', pull_audit_tail(
                        lxc_exec, CA_HOST, n=5))
                    failures.append((user.username, source_canon,
                                     target_canon))
            break    # one source/target combo per user is enough

    assert not failures, f'cross-source failures: {failures}'
