"""Verify shell-glob wildcards in policy `servers:` actually grant access.

Enrols a fresh user `wildcard-user` with a single key. Attaches a policy with
`servers: ['srv-*']`. The randomized scenario already created server names
matching that pattern (`srv-a`, `srv-b`, `srv-c`, `srv-d`), so the user should
be authorized on every one. Also enrols a second user `not-matching` whose
policy is `servers: ['nomatch-*']` — they should be denied on every server.
"""
from __future__ import annotations

import base64
import subprocess
import sys

import pytest

from log_helpers import OpsLog, banner, pull_audit_tail, section
from lxc_helpers import CA_HOST, SSHRT_U1, lxc_exec, push_file


pytestmark = pytest.mark.lxc


def _gen_user_key(tmp_path, name: str) -> dict:
    from ca.identity_parser import sha256_fingerprint
    priv = tmp_path / f'id_{name}'
    subprocess.run(['ssh-keygen', '-t', 'ed25519', '-f', str(priv),
                    '-N', '', '-C', f'{name}@wildcard-test'],
                   check=True, capture_output=True)
    pub_line = (tmp_path / f'id_{name}.pub').read_text().strip()
    blob = base64.b64decode(pub_line.split()[1])
    return {
        'priv': str(priv), 'pub_line': pub_line, 'blob': blob,
        'fingerprint': sha256_fingerprint(blob),
    }


def _deploy_to_containers(provisioned_env, username: str, key_priv_path: str,
                          key_blob: bytes) -> list[str]:
    """Create unix account + push key on every SSH host, and append the user
    to each container's users.allowed file (so the AsyncSSH server accepts
    the new key).

    Returns the list of container names that were successfully restarted —
    the wildcard test should only verify reachability to those. Restarting
    the AsyncSSH server on the Alpine container after a heavy matrix run is
    flaky (TIME_WAIT / port-rebind races) so we restrict this test to the
    Ubuntu hosts where systemctl gives us a clean restart.
    """
    scenario = provisioned_env['scenario']
    restarted = []
    for h in scenario.hosts:
        container = h.container_name
        if container.endswith('alpine'):
            # See docstring — skip Alpine to avoid restart flakiness.
            continue
        lxc_exec(container, 'useradd', '-m', '-s', '/bin/bash', username,
                 check=False)
        lxc_exec(container, 'sh', '-c',
                 f'mkdir -p /home/{username}/.ssh && '
                 f'chmod 700 /home/{username}/.ssh && '
                 f'chown -R {username}:{username} /home/{username}/.ssh')
        push_file(container, key_priv_path,
                  f'/home/{username}/.ssh/id_ed25519',
                  mode='600', owner=f'{username}:{username}')
        line = (f'{username} ssh-ed25519 '
                f'{base64.b64encode(key_blob).decode("ascii")}')
        lxc_exec(container, 'sh', '-c',
                 f'echo "{line}" >> /etc/ssh-rt-auth/server/users.allowed')
        lxc_exec(container, 'systemctl', 'restart', 'ssh-rt-auth-server')
        restarted.append(container)
    from lxc_helpers import wait_for_port
    for c in restarted:
        wait_for_port(c, 2222, max_wait=30)
    return restarted


def _ssh_from(client_container: str, username: str,
              target_ip: str, target_port: int,
              command: str = 'echo OK',
              timeout: int = 15) -> tuple[int, str, str]:
    flags = (
        '-o BatchMode=yes -o StrictHostKeyChecking=no '
        '-o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes '
        '-o ConnectTimeout=6 '
        f'-i /home/{username}/.ssh/id_ed25519 -p {target_port}'
    )
    r = lxc_exec(
        client_container, 'sh', '-c',
        f'su - {username} -c "ssh {flags} {username}@{target_ip} {command}"',
        check=False, timeout=timeout,
    )
    return r.returncode, r.stdout or '', r.stderr or ''


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

def test_wildcard_servers_pattern(provisioned_env, tmp_path):
    """`servers: ['srv-*']` grants every server whose canonical name starts
    with `srv-`; `servers: ['nomatch-*']` grants nothing."""
    from cli.client import CAClient
    from cli.key_parser import b64_blob, parse_key_text

    admin = CAClient(
        base_url=provisioned_env['ca_url'],
        admin_cert=provisioned_env['admin_cert'],
        admin_key=provisioned_env['admin_key'],
        ca_cert=provisioned_env['ca_cert'],
    )

    banner('Wildcard host-name policy test')

    section('Enrol wildcard-user (servers: srv-*)')
    wc_key = _gen_user_key(tmp_path, 'wildcard-user')
    admin.user_add('wildcard-user')
    admin.user_key_add('wildcard-user', 'pubkey',
                       b64_blob(parse_key_text(wc_key['pub_line'])))
    admin.policy_add('wildcard-user', {
        'servers': ['srv-*'],
        'channels': ['session'],
        'max_cert_validity_seconds': 600,
    })

    section('Enrol nomatch-user (servers: nomatch-*)')
    nm_key = _gen_user_key(tmp_path, 'nomatch-user')
    admin.user_add('nomatch-user')
    admin.user_key_add('nomatch-user', 'pubkey',
                       b64_blob(parse_key_text(nm_key['pub_line'])))
    admin.policy_add('nomatch-user', {
        'servers': ['nomatch-*'],
        'channels': ['session'],
        'max_cert_validity_seconds': 600,
    })

    section('Deploy keys to SSH hosts (Ubuntu only — see helper docstring)')
    eligible = _deploy_to_containers(provisioned_env, 'wildcard-user',
                                     wc_key['priv'], wc_key['blob'])
    _deploy_to_containers(provisioned_env, 'nomatch-user',
                          nm_key['priv'], nm_key['blob'])

    section('Verify wildcard-user reaches EVERY srv-* server (Ubuntu hosts)')
    failures = []
    for host in provisioned_env['scenario'].hosts:
        if host.container_name not in eligible:
            continue
        ip = provisioned_env['ips'][host.container_name]
        with OpsLog('wildcard', user='wildcard-user',
                    target=host.canonical_name, expect='granted') as op:
            rc, stdout, _ = _ssh_from(SSHRT_U1, 'wildcard-user', ip,
                                      provisioned_env['ssh_port'])
            ok = rc == 0 and 'ssh-rt-auth: authorized session' in stdout
            op.record(actual='granted' if ok else 'denied', ok=ok,
                      rc=rc, stdout=stdout[-200:])
            if not ok:
                op.attach('audit_tail', pull_audit_tail(
                    lxc_exec, CA_HOST, n=5))
                failures.append(('wildcard-user', host.canonical_name))

    section('Verify nomatch-user is denied EVERYWHERE (Ubuntu hosts)')
    for host in provisioned_env['scenario'].hosts:
        if host.container_name not in eligible:
            continue
        ip = provisioned_env['ips'][host.container_name]
        with OpsLog('wildcard', user='nomatch-user',
                    target=host.canonical_name, expect='denied') as op:
            rc, stdout, _ = _ssh_from(SSHRT_U1, 'nomatch-user', ip,
                                      provisioned_env['ssh_port'])
            denied = rc != 0 or 'ssh-rt-auth: authorized session' not in stdout
            op.record(actual='denied' if denied else 'granted',
                      ok=denied, rc=rc)
            if not denied:
                failures.append(('nomatch-user', host.canonical_name))

    # Clean up — keep enrollment store tidy for the rest of the suite.
    admin.user_remove('wildcard-user')
    admin.user_remove('nomatch-user')

    assert not failures, f'wildcard mismatches: {failures}'
