"""Emergency-cert / break-glass test.

Models the design's "stolen credential is useless if you can't reach the CA"
property in reverse: when the CA is genuinely unreachable, an
administrator-provisioned, long-lived authorization cert (the emergency
cert) lets the holder still get in.

Flow:
  1. Pick a target SSH server and a source container.
  2. Mint an emergency authorization cert inside the CA container:
       - subject pubkey = superuser's pubkey
       - server_bind    = target server's canonical name
       - source_bind    = source container's IP
       - validity       = 30 days
     Signed by the regular signing key (the design separates emergency and
     authz trust roots — the PoC uses the same key for both).
  3. Push the cert PEM onto the target server's shim and update the shim
     config so `emergency_cert` points at it; restart the AsyncSSH server.
  4. STOP the CA on CA_HOST.
  5. From the source container, ssh as the superuser to the target — the
     shim exhausts its CA endpoint list, falls back to the emergency cert,
     auth succeeds.
  6. Verify the AsyncSSH server log shows "using emergency cert".
  7. Restart the CA.

This test is destructive (it stops the CA) and so runs after every other
test. The filename starts with ``test_zz_`` to ensure it runs after the
audit tests too — emergency-cert auth produces an *empty* server-side audit
trail (we never reach the CA), which would skew the audit-coverage tests.
"""
from __future__ import annotations

import base64
import sys
import time
from pathlib import Path

import pytest

from log_helpers import OpsLog, banner, section
from lxc_helpers import (CA_HOST, SSHRT_U1, SSHRT_U2,
                         lxc_exec, push_file, push_text, wait_for_port)


pytestmark = pytest.mark.lxc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _superuser_username(provisioned_env) -> str:
    """Pick a user who's allowed on every host (so the emergency cert covers
    a known principal). Falls back to the first user."""
    scenario = provisioned_env['scenario']
    for u in scenario.users:
        if len(u.allowed_hosts) == len(scenario.hosts):
            return u.username
    return scenario.users[0].username


def _mint_emergency_cert_in_ca(ca_container: str, *,
                               username: str,
                               user_pub_blob_b64: str,
                               server_bind: str,
                               source_bind: str,
                               validity_days: int = 30) -> str:
    """Run cert minter inside the CA container and return the cert PEM.

    Push the script to a file inside the container so we don't have to fight
    nested shell + Python quoting.
    """
    script = f"""\
import base64, datetime, sys
from cryptography.hazmat.primitives import serialization
from mssh.ca.cert_minter import (
    load_private_key, load_certificate, mint_authorization_cert,
)
signing_key = load_private_key('/etc/ssh-rt-auth/ca/signing-key.pem')
signing_cert = load_certificate('/etc/ssh-rt-auth/ca/signing-cert.pem')
pub_blob = base64.b64decode({user_pub_blob_b64!r})
now = datetime.datetime.now(tz=datetime.timezone.utc)
cert, serial = mint_authorization_cert(
    subject_username={username!r},
    subject_pubkey_blob=pub_blob,
    signing_key=signing_key, signing_cert=signing_cert,
    not_before=now - datetime.timedelta(minutes=1),
    not_after=now + datetime.timedelta(days={validity_days}),
    source_bind={source_bind!r},
    server_bind={server_bind!r},
    channels=['session'],
)
sys.stdout.write(cert.public_bytes(serialization.Encoding.PEM).decode())
sys.stderr.write('minted emergency cert serial=' + serial + chr(10))
"""
    push_text(ca_container, script, '/tmp/mint_emergency.py', mode='644')
    r = lxc_exec(ca_container, 'sh', '-c',
                 'cd /app && PYTHONPATH=/app/src python3 /tmp/mint_emergency.py',
                 timeout=30)
    return r.stdout


def _ssh_from(client_container: str, username: str,
              target_ip: str, target_port: int,
              key_path_in_container: str,
              command: str = 'echo OK',
              timeout: int = 20) -> tuple[int, str, str]:
    flags = (
        '-o BatchMode=yes -o StrictHostKeyChecking=no '
        '-o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes '
        '-o ConnectTimeout=8 '
        f'-i {key_path_in_container} -p {target_port}'
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

def test_emergency_cert_used_when_ca_offline(provisioned_env):
    """Confirm the shim falls back to the local emergency cert when the CA
    is unreachable, and that auth still completes."""
    scenario = provisioned_env['scenario']
    ips = provisioned_env['ips']
    ssh_port = provisioned_env['ssh_port']

    banner('Emergency cert: SSH succeeds while CA is offline')

    # 1. Identify a target host and a source.
    target_host = scenario.hosts[0]
    source = SSHRT_U1
    if target_host.container_name == source:
        target_host = scenario.hosts[1]
    target_container = target_host.container_name
    target_ip = ips[target_container]
    source_ip = ips[source]
    print(f'  source={source} ({source_ip}) -> '
          f'target={target_host.canonical_name} ({target_container}, {target_ip})',
          file=sys.stderr, flush=True)

    # 2. Pick a user (whoever is allowed on every host) and locate their pubkey.
    username = _superuser_username(provisioned_env)
    user_key = provisioned_env['user_keys'][username]
    user_pub_b64 = base64.b64encode(user_key.pub_blob).decode('ascii')

    # 3. Mint emergency cert in the CA container.
    section('Minting emergency cert')
    pem = _mint_emergency_cert_in_ca(
        CA_HOST,
        username=username, user_pub_blob_b64=user_pub_b64,
        server_bind=target_host.canonical_name, source_bind=source_ip,
        validity_days=30,
    )
    assert '-----BEGIN CERTIFICATE-----' in pem, f'no cert PEM: {pem[:200]!r}'

    # 4. Push to the target SSH host and update the shim config to point at it.
    section('Deploying emergency cert to target server')
    push_text(target_container, pem,
              '/etc/ssh-rt-auth/server/emergency-cert.pem', mode='644')
    # Rewrite shim.yaml: keep the original CA endpoints but ALSO add the
    # emergency_cert path. The emergency_trust_root isn't validated by the
    # PoC shim (TODO in code) — same cert works for both.
    shim_cfg = (
        'ca_endpoints:\n'
        f'  - {provisioned_env["ca_url"]}\n'
        'mtls_cert: /etc/ssh-rt-auth/server/mtls-cert.pem\n'
        'mtls_key:  /etc/ssh-rt-auth/server/mtls-key.pem\n'
        'ca_trust_root: /etc/ssh-rt-auth/server/ca-tls-root.pem\n'
        'auth_trust_root: /etc/ssh-rt-auth/server/auth-signing-root.pem\n'
        f'server_name: {target_host.canonical_name}\n'
        'cache: {max_entries: 100}\n'
        'timeouts: {connect: 2, read: 3}\n'
        'emergency_cert: /etc/ssh-rt-auth/server/emergency-cert.pem\n'
        'emergency_trust_root: '
        '/etc/ssh-rt-auth/server/auth-signing-root.pem\n'
    )
    push_text(target_container, shim_cfg,
              '/etc/ssh-rt-auth/server/shim.yaml', mode='644')

    # Restart the AsyncSSH server so the shim re-reads its config.
    if target_container.endswith('alpine'):
        lxc_exec(target_container, 'sh', '-c',
                 'fuser -k -9 2222/tcp 2>/dev/null; sleep 3')
        lxc_exec(target_container, 'sh', '-c',
                 'cd /app && PYTHONPATH=/app/src nohup /usr/bin/python3 '
                 '-m mssh.debug_sshd.ssh_server '
                 '--shim-config /etc/ssh-rt-auth/server/shim.yaml '
                 '--host-key /etc/ssh-rt-auth/server/host-key '
                 '--users-file /etc/ssh-rt-auth/server/users.allowed '
                 '--listen-host 0.0.0.0 --listen-port 2222 '
                 '> /var/log/ssh-rt-auth-server.log 2>&1 & '
                 'echo $! > /run/ssh-rt-auth-server.pid')
    else:
        lxc_exec(target_container, 'systemctl', 'restart',
                 'ssh-rt-auth-server')
    wait_for_port(target_container, ssh_port, max_wait=45)

    # 5. STOP THE CA. The shim's authorize() should fail to reach it.
    section('Stopping the CA')
    lxc_exec(CA_HOST, 'systemctl', 'stop', 'ssh-rt-auth-ca')
    try:
        # 6. SSH attempt — should succeed via emergency cert.
        section('SSH while CA is offline')
        with OpsLog('emergency', source=source, target=target_host.canonical_name,
                    user=username, expect='granted-via-emergency-cert') as op:
            rc, stdout, stderr = _ssh_from(
                source, username, target_ip, ssh_port,
                key_path_in_container=f'/home/{username}/.ssh/id_ed25519',
                command='echo HELLO_FROM_EMERGENCY',
            )
            ok = (rc == 0
                  and 'ssh-rt-auth: authorized session' in stdout
                  and 'HELLO_FROM_EMERGENCY' in stdout)
            op.record(actual='granted' if ok else 'denied',
                      ok=ok, rc=rc, stdout=stdout[-400:],
                      stderr=stderr[-400:])
            if not ok:
                # Pull the SSH server log on failure for diagnostics.
                srvlog = lxc_exec(target_container, 'tail', '-n', '40',
                                  '/var/log/ssh-rt-auth-server.log',
                                  check=False)
                op.attach('asyncssh_log_tail',
                          srvlog.stdout or srvlog.stderr)

        # 7. Confirm the server log mentions emergency-cert use.
        section('Verifying server log says "using emergency cert"')
        srvlog = lxc_exec(target_container, 'cat',
                          '/var/log/ssh-rt-auth-server.log', check=False)
        emergency_used = 'using emergency cert' in (srvlog.stdout or '')
        print(f'  emergency_used={emergency_used}',
              file=sys.stderr, flush=True)
    finally:
        # 8. Always restart the CA so subsequent tests can run.
        section('Restarting the CA')
        lxc_exec(CA_HOST, 'systemctl', 'start', 'ssh-rt-auth-ca')
        wait_for_port(CA_HOST, 8443, max_wait=30)

    assert ok, f'emergency-cert SSH failed: rc={rc} stderr={stderr[-300:]}'
    assert emergency_used, (
        'AsyncSSH server log does not mention emergency cert usage; '
        'the auth flow may have gone through the (still-down) CA path')
