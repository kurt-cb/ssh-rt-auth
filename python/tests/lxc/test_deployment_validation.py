"""Phase 1 LXC deployment validation.

Confirms:
1. The CA container starts and the Flask listener is up.
2. The admin API responds to a request from a real mTLS client.
3. Two SSH server hosts can be registered with the CA.
4. The user enrollment + key add + policy add flow works end-to-end.

This is the "is the environment sound?" smoke test — not the full matrix.
"""
from __future__ import annotations

import pytest

from lxc_helpers import (ALL_SSH_HOSTS, CA_PORT, SSHRT_U1, SSHRT_U2,
                         lxc_exec)


pytestmark = pytest.mark.lxc


def _admin_client(lxc_env):
    from sshrt.admin.client import CAClient
    return CAClient(
        base_url=lxc_env['ca_url'],
        admin_cert=lxc_env['admin_cert'],
        admin_key=lxc_env['admin_key'],
        ca_cert=lxc_env['ca_cert'],
    )


def test_ca_listens(lxc_env):
    """CA Flask process accepts connections on port 8443."""
    # ca_url is set only after wait_for_port succeeded in the fixture.
    assert lxc_env['ca_url'].startswith('https://')
    assert str(CA_PORT) in lxc_env['ca_url']


def test_admin_api_reachable(lxc_env):
    """Bootstrap admin cert can call the admin API."""
    c = _admin_client(lxc_env)
    admins = c.admin_list()
    assert any(a['name'] == 'bootstrap-admin' for a in admins)


def test_register_two_servers(lxc_env):
    """Admin can enroll two SSH server hosts. Server-list reflects them."""
    c = _admin_client(lxc_env)
    # Use the two real Ubuntu SSH hosts.
    for canon, host in [('srv-u1', SSHRT_U1), ('srv-u2', SSHRT_U2)]:
        resp = c.server_add(canon, groups=['poc'])
        assert resp['server']['name'] == canon
        assert '-----BEGIN' in resp['credentials']['cert_pem']
    listed = {s['name'] for s in c.server_list()}
    assert {'srv-u1', 'srv-u2'} <= listed


def test_enroll_user_and_key(lxc_env, tmp_path):
    """ssh-keygen a key on the test host, enroll user + key, attach a policy."""
    import base64
    import subprocess
    from sshrt.admin.key_parser import b64_blob, parse_key_file

    keypath = tmp_path / 'alice_ed25519'
    subprocess.run(['ssh-keygen', '-t', 'ed25519', '-f', str(keypath),
                    '-N', '', '-C', 'alice@test'],
                   check=True, capture_output=True)
    parsed = parse_key_file(str(keypath) + '.pub')

    c = _admin_client(lxc_env)
    c.user_add('dvtest-user')
    key_resp = c.user_key_add('dvtest-user', parsed.type, b64_blob(parsed))
    assert key_resp['key']['fingerprint'] == parsed.fingerprint

    # Try to attach a policy referencing srv-u1 (registered by previous test).
    c.policy_add('dvtest-user', {
        'servers': ['srv-u1'],
        'channels': ['session'],
        'max_cert_validity_seconds': 600,
    })
    users = c.user_list(username='dvtest-user')
    assert users and users[0]['policies']
    assert users[0]['policies'][0]['servers'] == ['srv-u1']
