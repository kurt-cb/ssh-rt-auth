"""End-to-end msshd-enforce coverage via the user matrix.

Parallel to the existing matrix/clients-in-containers tests (which run
against debug_sshd on port 2222), these tests use the `msshd_env`
fixture to drive real mssh client → msshd-enforce → CA → ephemeral
inner cert → hermetic inner sshd → shell sessions on port 2200.

Each msshd-enforce connection exercises the FULL production stack the
adhoc lab demonstrates, multiplied across every (user, target) pair in
the seed-driven scenario.

Marker: lxc (runs whenever the LXC suite runs).
"""
from __future__ import annotations

import pytest

# Re-use the LXC helpers loader trick used by sibling tests so we get
# `lxc_helpers` on sys.modules before importing CA_HOST.
import importlib.util as _ilu
import sys as _sys
from pathlib import Path as _Path
_HERE = _Path(__file__).resolve().parent
for _name in ('lxc_helpers', 'log_helpers'):
    _spec = _ilu.spec_from_file_location(_name, _HERE / f'{_name}.py')
    _mod = _ilu.module_from_spec(_spec)
    _sys.modules[_name] = _mod
    _spec.loader.exec_module(_mod)

from lxc_helpers import CA_HOST, SSHRT_U1


pytestmark = [pytest.mark.lxc]


# ---------------------------------------------------------------------------
# Allowed pairs — every (user, allowed-server) succeeds end-to-end
# ---------------------------------------------------------------------------

def test_each_user_reaches_every_allowed_server(msshd_env):
    """For every user in the scenario, mssh to every server in their
    allowed_hosts list and confirm the inner shell returns their
    username from `whoami`."""
    scenario = msshd_env['scenario']
    mssh_as  = msshd_env['mssh_as']

    failures = []
    for user in scenario.users:
        for target in user.allowed_hosts:
            # Run mssh FROM the CA container (it has all source + deps);
            # tests from-container variation in a separate test below.
            r = mssh_as(user.username, SSHRT_U1, target,
                        'whoami')
            if r.returncode != 0 or user.username not in (r.stdout or ''):
                failures.append(
                    f'{user.username}@{target}: rc={r.returncode} '
                    f'stdout={r.stdout!r} stderr={r.stderr!r}')

    assert not failures, (
        f'{len(failures)} allowed-pair mssh sessions failed:\n  '
        + '\n  '.join(failures[:10]))


# ---------------------------------------------------------------------------
# Denied pairs — every (user, disallowed-server) is refused by the CA
# ---------------------------------------------------------------------------

def test_each_user_denied_for_disallowed_servers(msshd_env):
    """For every user, mssh to every server NOT in their allowed_hosts
    list and confirm the CA denies the session (non-zero exit, username
    not in stdout)."""
    scenario = msshd_env['scenario']
    mssh_as  = msshd_env['mssh_as']
    all_canonicals = [h.canonical_name for h in scenario.hosts]

    leaks = []
    for user in scenario.users:
        disallowed = [c for c in all_canonicals if c not in user.allowed_hosts]
        for target in disallowed:
            r = mssh_as(user.username, SSHRT_U1, target,
                        'whoami', timeout=20)
            # Successful denial = non-zero rc AND no whoami output.
            if r.returncode == 0 and user.username in (r.stdout or ''):
                leaks.append(
                    f'{user.username}@{target}: UNEXPECTEDLY GRANTED '
                    f'(stdout={r.stdout!r})')

    assert not leaks, (
        f'{len(leaks)} mssh sessions should have been denied but were not:\n  '
        + '\n  '.join(leaks[:10]))


# ---------------------------------------------------------------------------
# Cross-distro — from Ubuntu to Alpine and back
# ---------------------------------------------------------------------------

def test_mssh_from_ubuntu_to_alpine(msshd_env):
    """An allowed user invokes mssh from an Ubuntu container targeting
    the Alpine SSH host. Confirms cross-distro behavior on the host
    side of msshd (Alpine's nohup-spawned msshd, dropbear-style users)."""
    from lxc_helpers import SSHRT_U1, SSHRT_ALPINE
    scenario = msshd_env['scenario']
    container_to_canonical = msshd_env['container_to_canonical']
    alpine_canon = container_to_canonical[SSHRT_ALPINE]

    # Pick any user whose allowed_hosts includes the Alpine canonical.
    user = next((u for u in scenario.users
                 if alpine_canon in u.allowed_hosts), None)
    if user is None:
        pytest.skip(f'no scenario user allowed on {alpine_canon}')

    r = msshd_env['mssh_as'](user.username, SSHRT_U1, alpine_canon, 'whoami')
    assert r.returncode == 0, (
        f'mssh {user.username}@{alpine_canon} from {SSHRT_U1} failed: '
        f'rc={r.returncode} stderr={r.stderr!r}')
    assert user.username in (r.stdout or ''), \
        f'expected {user.username!r} in stdout: {r.stdout!r}'


def test_mssh_from_alpine_to_ubuntu(msshd_env):
    """Symmetric: invoke mssh FROM Alpine targeting Ubuntu. Exercises
    the mssh client running in the Alpine container."""
    from lxc_helpers import SSHRT_ALPINE
    scenario = msshd_env['scenario']
    canon_to_container = msshd_env['canonical_to_container']

    # Pick any Ubuntu target a user is allowed on.
    ubuntu_targets = [h.canonical_name for h in scenario.hosts
                      if canon_to_container[h.canonical_name] != SSHRT_ALPINE]
    user = next((u for u in scenario.users
                 if any(t in u.allowed_hosts for t in ubuntu_targets)),
                None)
    if user is None:
        pytest.skip('no scenario user allowed on any Ubuntu host')

    target = next(t for t in ubuntu_targets if t in user.allowed_hosts)
    r = msshd_env['mssh_as'](user.username, SSHRT_ALPINE, target, 'whoami')
    assert r.returncode == 0, (
        f'mssh {user.username}@{target} from {SSHRT_ALPINE} failed: '
        f'rc={r.returncode} stderr={r.stderr!r}')
    assert user.username in (r.stdout or ''), \
        f'expected {user.username!r} in stdout: {r.stdout!r}'


# ---------------------------------------------------------------------------
# CA audit log
# ---------------------------------------------------------------------------

def test_enforce_grants_appear_in_ca_audit_log(msshd_env):
    """After driving a few mssh-enforce sessions, the CA's audit log
    should contain `granted` entries with `actor: <username>` and the
    target server canonical name."""
    from lxc_helpers import lxc_exec
    scenario = msshd_env['scenario']
    mssh_as  = msshd_env['mssh_as']

    # Pick the first allowed pair we find and drive a session.
    user = next(u for u in scenario.users if u.allowed_hosts)
    target = user.allowed_hosts[0]
    r = mssh_as(user.username, SSHRT_U1, target, 'whoami')
    assert r.returncode == 0, (
        f'precondition failed: mssh {user.username}@{target} '
        f'rc={r.returncode} stderr={r.stderr!r}')

    # Read the CA's audit log and look for our grant.
    ca = CA_HOST
    audit = lxc_exec(ca, 'cat', '/var/log/ssh-rt-auth/audit.jsonl',
                     check=False)
    assert audit.returncode == 0, \
        f'reading CA audit log failed: rc={audit.returncode} stderr={audit.stderr!r}'

    matching = [line for line in (audit.stdout or '').splitlines()
                if user.username in line and target in line
                and '"granted"' in line]
    assert matching, (
        f'no granted audit entry for {user.username}@{target} '
        f'in:\n{audit.stdout[-800:] if audit.stdout else "<empty>"}')
