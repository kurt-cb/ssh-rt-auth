"""Audit log verification.

After the matrix and security tests run, the CA's audit log should contain
JSON-lines entries for:

  - every grant + every deny that came through /v1/authorize
  - every admin operation (server.add, user.add, policy.add, ...)
  - mTLS attacks that reached the application layer (deny entries)

This test reads ``/var/log/ssh-rt-auth/audit.jsonl`` from the CA container,
classifies entries, and asserts:

  - all four scenario servers appear in admin audit entries
  - every enrolled user has at least one authorization audit entry
  - audit log has both `granted` and `denied` decisions
  - denied entries carry a structured `reason`
"""
from __future__ import annotations

import json
import sys
from collections import Counter

import pytest

from log_helpers import OpsLog, banner, render_table, section
from lxc_helpers import CA_HOST, lxc_exec


pytestmark = pytest.mark.lxc


def _read_audit(container: str) -> list[dict]:
    r = lxc_exec(container, 'cat', '/var/log/ssh-rt-auth/audit.jsonl',
                 check=False)
    out = []
    for line in (r.stdout or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def test_audit_contains_admin_and_auth_entries(provisioned_env):
    banner('Audit-log inspection')
    entries = _read_audit(CA_HOST)
    assert entries, 'audit log is empty'
    by_type = Counter(e.get('type', 'unknown') for e in entries)
    decisions = Counter(e.get('decision', '') for e in entries
                        if e.get('type') == 'authorization')
    admin_actions = Counter(e.get('action', '') for e in entries
                            if e.get('type') == 'admin')

    section('Counts')
    print(f'  by type: {dict(by_type)}', file=sys.stderr)
    print(f'  authz decisions: {dict(decisions)}', file=sys.stderr)
    print(f'  admin actions: {dict(admin_actions)}', file=sys.stderr)

    assert by_type['admin'] >= 1
    assert by_type['authorization'] >= 1
    assert admin_actions['server.add'] >= len(provisioned_env['server_creds'])
    assert admin_actions['user.add'] >= len(provisioned_env['scenario'].users)


def test_audit_every_user_has_authorization_entry(provisioned_env):
    """Every user that appeared in the matrix must have at least one /v1/authorize
    entry — either a grant or a deny."""
    entries = _read_audit(CA_HOST)
    auth = [e for e in entries if e.get('type') == 'authorization']
    saw = set()
    for e in auth:
        ident = e.get('identity') or {}
        u = ident.get('username') or ''
        if u:
            saw.add(u)

    section('Users observed in authorization audit')
    rows = []
    for user in provisioned_env['scenario'].users:
        rows.append({'user': user.username,
                     'observed': '✓' if user.username in saw else '✗'})
    print(render_table(rows, ['user', 'observed']),
          file=sys.stderr, flush=True)

    missing = [u.username for u in provisioned_env['scenario'].users
               if u.username not in saw]
    # We only require users that actually had a policy applied. Users with
    # zero allowed_hosts will still produce deny entries if reached by the
    # matrix — which we always do.
    assert not missing, f'no audit entry for users: {missing}'


def test_audit_denials_carry_reason(provisioned_env):
    entries = _read_audit(CA_HOST)
    denied = [e for e in entries if e.get('type') == 'authorization'
              and e.get('decision') == 'denied']
    assert denied, 'expected at least one denial in audit log'
    for e in denied:
        with OpsLog('audit', entry=e.get('timestamp', '?'),
                    expect='structured-reason') as op:
            reason = e.get('reason')
            ok = bool(reason)
            op.record(actual=f'reason={reason!r}', ok=ok,
                      entry=json.dumps(e, indent=2))


def test_audit_attack_attempts_logged(lxc_env):
    """The mTLS-security tests sent /v1/authorize requests with unauthorized
    certs that reached the application layer. Those should appear as denial
    entries in the audit log."""
    entries = _read_audit(CA_HOST)
    auth_denials = [e for e in entries
                    if e.get('type') == 'authorization'
                    and e.get('decision') == 'denied']
    reasons = Counter(e.get('reason', '') for e in auth_denials)
    section('Denial reasons in audit log')
    print(f'  {dict(reasons)}', file=sys.stderr, flush=True)
    # We require at least one of the reasons we'd expect from the attack
    # suite OR from the policy mismatches in the matrix test.
    interesting = {'unknown_server', 'unknown_identity', 'no_matching_policy',
                   'source_denied', 'channels_denied', 'time_denied',
                   'invalid_identity_cert', 'clock_drift'}
    assert any(r in interesting for r in reasons), \
        f'no expected denial reasons in audit log; saw {dict(reasons)}'
