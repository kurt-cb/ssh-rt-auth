"""OpenSSH shim prototype — end-to-end test against unmodified ``sshd``.

This is the spike that answers "can ssh-rt-auth plug into stock OpenSSH
without a sshd patch?". It wires our ``shim/openssh_shim.py`` into
``sshd_config``'s ``AuthorizedKeysCommand`` directive and runs three SSH
attempts:

  1. **alice** (enrolled at the CA with a policy granting access) →
     expected to succeed.
  2. **bob**   (enrolled, but no policy) → expected to be denied with
     ``no_matching_policy`` in the CA's audit log.
  3. **mallory** (NOT enrolled at all) → expected to be denied with
     ``unknown_identity`` in the CA's audit log.

Architecture:

```
  client (ssh from inside the same container)
    |
    | ssh alice@127.0.0.1
    v
  stock OpenSSH sshd (port 22, inside container)
    | AuthorizedKeysCommand=/usr/local/bin/ssh-rt-auth-openssh-shim
    v
  ssh-rt-auth-openssh-shim (Python, runs as user ``sshrt``)
    | mTLS POST /v1/authorize
    v
  CA container
```

Opt-in marker: ``-m openssh_shim``.

Container names:

  sshrt-openssh-ca       — CA + ssh-rt-admin
  sshrt-openssh-target   — stock sshd + ssh-rt-auth-openssh-shim
"""
from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest


# Re-use the same loader trick the LXC conftest does for in-folder helpers.
import importlib.util as _ilu
_HERE = Path(__file__).resolve().parent
for _name in ('lxc_helpers', 'log_helpers'):
    _spec = _ilu.spec_from_file_location(_name, _HERE / f'{_name}.py')
    _mod = _ilu.module_from_spec(_spec)
    sys.modules[_name] = _mod
    _spec.loader.exec_module(_mod)

from lxc_helpers import (
    UBUNTU_IMAGE, get_ip, lxc, lxc_exec, push_file, push_source, push_text,
    wait_for_port,
)
from log_helpers import OpsLog, banner, section


pytestmark = [pytest.mark.lxc, pytest.mark.openssh_shim]


CA_NAME     = 'sshrt-openssh-ca'
TARGET_NAME = 'sshrt-openssh-target'
CA_PORT     = 8443


# ---------------------------------------------------------------------------
# Small helpers (kept local — this test is meant to be self-contained)
# ---------------------------------------------------------------------------

def _gen_ed25519(host_dir: Path, name: str, comment: str) -> dict:
    from sshrt.ca.identity_parser import sha256_fingerprint
    priv = host_dir / name
    if priv.exists():
        priv.unlink()
    if (host_dir / f'{name}.pub').exists():
        (host_dir / f'{name}.pub').unlink()
    subprocess.run(['ssh-keygen', '-t', 'ed25519', '-f', str(priv),
                    '-N', '', '-C', comment],
                   check=True, capture_output=True)
    pub_line = (host_dir / f'{name}.pub').read_text().strip()
    blob = base64.b64decode(pub_line.split()[1])
    return {'priv': str(priv), 'pub_path': str(priv) + '.pub',
            'pub_line': pub_line, 'blob': blob,
            'fingerprint': sha256_fingerprint(blob)}


def _ssh_in_container(container: str, username: str, target_host: str,
                      *, key_path: str, command: str = 'echo OK',
                      timeout: int = 20) -> tuple[int, str, str]:
    """ssh to ``target_host`` as ``username`` from inside ``container``."""
    flags = (
        '-o BatchMode=yes -o StrictHostKeyChecking=no '
        '-o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes '
        '-o ConnectTimeout=8 '
        f'-i {key_path} -p 22'
    )
    cmd = (f'su - {username} -c '
           f'"ssh {flags} {username}@{target_host} {command}"')
    r = lxc_exec(container, 'sh', '-c', cmd, check=False, timeout=timeout)
    return r.returncode, r.stdout or '', r.stderr or ''


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

def test_openssh_shim_end_to_end(request, tmp_path_factory):
    """Provision CA + target, install the AuthorizedKeysCommand shim, drive
    three SSH attempts and verify each outcome."""

    keep = request.config.getoption('--keep-containers', default=False)

    banner('OpenSSH shim prototype — end-to-end')
    section('Tearing down any pre-existing containers')
    for c in (CA_NAME, TARGET_NAME):
        subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)

    section('Launching CA + target containers')
    lxc('launch', UBUNTU_IMAGE, CA_NAME,
        '--config', 'security.privileged=true', timeout=300)
    lxc('launch', UBUNTU_IMAGE, TARGET_NAME,
        '--config', 'security.privileged=true', timeout=300)
    ca_ip     = get_ip(CA_NAME)
    target_ip = get_ip(TARGET_NAME)
    print(f'  {CA_NAME:30s} {ca_ip}', file=sys.stderr, flush=True)
    print(f'  {TARGET_NAME:30s} {target_ip}', file=sys.stderr, flush=True)

    # Install deps (apt; no PyPI). Same pattern as the rest of the suite.
    app_root = Path(__file__).resolve().parent.parent.parent.parent
    pkgs = ['python3', 'python3-cryptography', 'python3-flask',
            'python3-yaml', 'python3-click', 'python3-requests',
            'python3-asyncssh',
            'openssh-server', 'openssh-client']
    section('Installing apt deps + project source')
    for c in (CA_NAME, TARGET_NAME):
        lxc_exec(c, 'apt-get', 'update', '-q', timeout=180)
        lxc_exec(c, 'apt-get', 'install', '-y', '-q', *pkgs, timeout=600)
        push_source(c, app_root)

    # ---- CA bootstrap + start ----------------------------------------------
    section('Bootstrapping CA')
    lxc_exec(CA_NAME, 'sh', '-c',
             'PYTHONPATH=/app/src python3 -c "'
             'from sshrt.ca.cert_minter import bootstrap_ca; '
             f"bootstrap_ca('/etc/ssh-rt-auth/ca', "
             f"tls_server_sans=['DNS:localhost','IP:127.0.0.1',"
             f"'IP:{ca_ip}'])\"",
             timeout=120)
    lxc_exec(CA_NAME, 'sh', '-c',
             'python3 -c "'
             'import yaml; '
             "open('/etc/ssh-rt-auth/ca/enrollment.yaml','w').write("
             "yaml.safe_dump({'admins': {'bootstrap-admin': "
             "{'role':'superuser','mtls_subject':'CN=bootstrap-admin',"
             "'enrolled_at':'','enrolled_by':'init'}}}))\"")
    push_text(CA_NAME,
              f'listen: 0.0.0.0:{CA_PORT}\n'
              'signing_key: /etc/ssh-rt-auth/ca/signing-key.pem\n'
              'signing_cert: /etc/ssh-rt-auth/ca/signing-cert.pem\n'
              'tls_cert: /etc/ssh-rt-auth/ca/tls-server-cert.pem\n'
              'tls_key:  /etc/ssh-rt-auth/ca/tls-server-key.pem\n'
              'client_ca_cert: /etc/ssh-rt-auth/ca/tls-ca-cert.pem\n'
              'identity_trust_roots: []\n'
              'enrollment: {path: /etc/ssh-rt-auth/ca/enrollment.yaml}\n'
              'audit: {path: /var/log/ssh-rt-auth/audit.jsonl}\n'
              'defaults: {max_cert_validity_seconds: 3600, '
              'timestamp_drift_seconds: 600}\n'
              'cert_generation: {key_type: ec, '
              'server_cert_validity_days: 30, '
              'admin_cert_validity_days: 30}\n',
              '/etc/ssh-rt-auth/ca-config.yaml')
    push_text(CA_NAME,
              '[Unit]\nDescription=ssh-rt-auth CA\nAfter=network.target\n'
              '[Service]\nWorkingDirectory=/app\nEnvironment="PYTHONPATH=/app/src"\n'
              'ExecStart=/usr/bin/python3 -m sshrt.ca.server --config '
              '/etc/ssh-rt-auth/ca-config.yaml\nRestart=on-failure\n'
              '[Install]\nWantedBy=multi-user.target\n',
              '/etc/systemd/system/ssh-rt-auth-ca.service')
    lxc_exec(CA_NAME, 'mkdir', '-p', '/var/log/ssh-rt-auth')
    lxc_exec(CA_NAME, 'systemctl', 'daemon-reload')
    lxc_exec(CA_NAME, 'systemctl', 'start', 'ssh-rt-auth-ca')
    wait_for_port(CA_NAME, CA_PORT, max_wait=60)

    # Pull bootstrap admin creds locally.
    creds_dir = tmp_path_factory.mktemp('admin-creds')
    for n in ('bootstrap-admin-cert.pem', 'bootstrap-admin-key.pem',
              'tls-ca-cert.pem', 'signing-cert.pem'):
        subprocess.run(['lxc', 'file', 'pull',
                        f'{CA_NAME}/etc/ssh-rt-auth/ca/{n}',
                        str(creds_dir / n)],
                       check=True, capture_output=True)
    os.chmod(creds_dir / 'bootstrap-admin-key.pem', 0o600)

    from sshrt.admin.client import CAClient
    from sshrt.admin.key_parser import b64_blob, parse_key_text
    admin = CAClient(
        base_url=f'https://{ca_ip}:{CA_PORT}',
        admin_cert=str(creds_dir / 'bootstrap-admin-cert.pem'),
        admin_key=str(creds_dir / 'bootstrap-admin-key.pem'),
        ca_cert=str(creds_dir / 'tls-ca-cert.pem'),
    )

    # ---- Enrol target as a server + pull its mTLS creds --------------------
    section('Enrolling target as an ssh-rt-auth server')
    resp = admin.server_add('srv-openssh', groups=['poc'])
    server_creds = resp['credentials']
    target_mtls_cert = creds_dir / 'srv-cert.pem'
    target_mtls_key  = creds_dir / 'srv-key.pem'
    target_mtls_cert.write_text(server_creds['cert_pem'])
    target_mtls_key.write_text(server_creds['key_pem'])
    os.chmod(target_mtls_key, 0o600)

    # ---- Generate user keys + enrol with the CA ---------------------------
    section('Generating user keys + enrolling with CA')
    keys_dir = tmp_path_factory.mktemp('user-keys')
    keys = {
        'alice':   _gen_ed25519(keys_dir, 'alice',   'alice@openssh-prot'),
        'bob':     _gen_ed25519(keys_dir, 'bob',     'bob@openssh-prot'),
        'mallory': _gen_ed25519(keys_dir, 'mallory', 'mallory@openssh-prot'),
    }
    # alice and bob are enrolled at the CA; mallory is NOT.
    for u in ('alice', 'bob'):
        admin.user_add(u)
        admin.user_key_add(u, 'pubkey',
                           b64_blob(parse_key_text(keys[u]['pub_line'])))
    # alice gets a policy; bob doesn't.
    admin.policy_add('alice', {
        'servers': ['srv-openssh'],
        'channels': ['session'],
        'source_cidrs': ['0.0.0.0/0'],     # see openssh_shim.py limitations
        'max_cert_validity_seconds': 600,
    })

    # ---- Set up the target: sshd, unprivileged sshrt user, shim ----------
    section('Provisioning target: sshrt user, shim config, AuthorizedKeysCommand')
    lxc_exec(TARGET_NAME, 'useradd', '-r', '-s', '/usr/sbin/nologin',
             '-d', '/nonexistent', 'sshrt', check=False)
    # Unix accounts the SSH clients will log in as.
    for u in ('alice', 'bob', 'mallory'):
        lxc_exec(TARGET_NAME, 'useradd', '-m', '-s', '/bin/bash', u,
                 check=False)
        lxc_exec(TARGET_NAME, 'sh', '-c',
                 f'mkdir -p /home/{u}/.ssh && chmod 700 /home/{u}/.ssh && '
                 f'chown -R {u}:{u} /home/{u}/.ssh')
        # Put each user's private key at ~/.ssh/id_ed25519 so we can ssh
        # localhost as them.
        push_file(TARGET_NAME, keys[u]['priv'],
                  f'/home/{u}/.ssh/id_ed25519',
                  mode='600', owner=f'{u}:{u}')

    # mTLS creds for the shim.
    lxc_exec(TARGET_NAME, 'mkdir', '-p', '/etc/ssh-rt-auth')
    push_file(TARGET_NAME, target_mtls_cert,
              '/etc/ssh-rt-auth/mtls-cert.pem', mode='640',
              owner='root:sshrt')
    push_file(TARGET_NAME, target_mtls_key,
              '/etc/ssh-rt-auth/mtls-key.pem', mode='640',
              owner='root:sshrt')
    push_file(TARGET_NAME, creds_dir / 'tls-ca-cert.pem',
              '/etc/ssh-rt-auth/ca-tls-root.pem', mode='644')
    push_file(TARGET_NAME, creds_dir / 'signing-cert.pem',
              '/etc/ssh-rt-auth/auth-signing-root.pem', mode='644')

    # Shim config — explicit sqlite cache so the second AuthorizedKeysCommand
    # invocation per accepted connection hits the persistent cache instead
    # of re-querying the CA.
    push_text(TARGET_NAME,
              'ca_endpoints:\n'
              f'  - https://{ca_ip}:{CA_PORT}\n'
              'mtls_cert: /etc/ssh-rt-auth/mtls-cert.pem\n'
              'mtls_key:  /etc/ssh-rt-auth/mtls-key.pem\n'
              'ca_trust_root: /etc/ssh-rt-auth/ca-tls-root.pem\n'
              'auth_trust_root: /etc/ssh-rt-auth/auth-signing-root.pem\n'
              'server_name: srv-openssh\n'
              'cache:\n'
              '  backend: sqlite\n'
              '  db_path: /var/cache/ssh-rt-auth/cert-cache.sqlite3\n'
              '  max_entries: 100\n'
              'timeouts: {connect: 3, read: 5}\n',
              '/etc/ssh-rt-auth/shim.yaml', mode='644')

    # Install the openssh shim script.
    push_file(TARGET_NAME, str(app_root / 'openssh' / 'openssh_shim.py'),
              '/usr/local/bin/ssh-rt-auth-openssh-shim',
              mode='755', owner='root:root')
    # SQLite cache directory; the sshrt user must own it because the shim
    # runs as that account (AuthorizedKeysCommandUser sshrt).
    lxc_exec(TARGET_NAME, 'mkdir', '-p', '/var/cache/ssh-rt-auth')
    lxc_exec(TARGET_NAME, 'chown', 'sshrt:sshrt', '/var/cache/ssh-rt-auth')
    lxc_exec(TARGET_NAME, 'chmod', '0700', '/var/cache/ssh-rt-auth')

    # sshd_config drop-in.
    push_text(TARGET_NAME,
              'PasswordAuthentication no\n'
              'PubkeyAuthentication yes\n'
              'AuthorizedKeysFile none\n'
              'AuthorizedKeysCommand /usr/local/bin/ssh-rt-auth-openssh-shim '
              '%u %t %k\n'
              'AuthorizedKeysCommandUser sshrt\n'
              # PAM tries to load environment from /etc/environment; make
              # sure SSHRT_SHIM_CONFIG can be picked up by the shim.
              'AcceptEnv SSHRT_SHIM_CONFIG\n',
              '/etc/ssh/sshd_config.d/ssh-rt-auth.conf', mode='644')

    # Reload sshd. On Ubuntu 22.04 the service is `ssh`.
    lxc_exec(TARGET_NAME, 'systemctl', 'restart', 'ssh')
    wait_for_port(TARGET_NAME, port=22, max_wait=30)
    print('  sshd restarted with AuthorizedKeysCommand active',
          file=sys.stderr, flush=True)

    # ---- Drive three SSH attempts ----------------------------------------
    section('SSH attempts (ssh to 127.0.0.1 from inside the target container)')

    expectations = [
        ('alice',   'granted', 'enrolled with policy'),
        ('bob',     'denied',  'enrolled but no policy'),
        ('mallory', 'denied',  'not enrolled'),
    ]
    failures = []
    for user, expected, why in expectations:
        with OpsLog('openssh', user=user, expect=expected,
                    note=why) as op:
            rc, stdout, stderr = _ssh_in_container(
                TARGET_NAME, user, '127.0.0.1',
                key_path=f'/home/{user}/.ssh/id_ed25519')
            granted = rc == 0 and 'OK' in stdout
            actual = 'granted' if granted else 'denied'
            ok = actual == expected
            op.record(actual=actual, ok=ok,
                      rc=rc, stdout=stdout[-300:],
                      stderr=stderr[-300:])
            if not ok:
                # Pull sshd journal for diagnostics.
                jr = lxc_exec(TARGET_NAME, 'journalctl', '-u', 'ssh',
                              '-n', '40', '--no-pager', check=False)
                op.attach('sshd_journal', jr.stdout)
                ar = lxc_exec(CA_NAME, 'tail', '-n', '10',
                              '/var/log/ssh-rt-auth/audit.jsonl',
                              check=False)
                op.attach('ca_audit_tail', ar.stdout)
                failures.append((user, expected, actual))

    # Confirm the SQLite cache absorbed the second sshd → shim call. With
    # `cache.backend: memory` this would produce two `granted` audit rows
    # for alice (issue 9.2); with SQLite there should be exactly one.
    section('Verifying SQLite cache de-duped the double AuthorizedKeysCommand call')
    audit = lxc_exec(CA_NAME, 'cat',
                     '/var/log/ssh-rt-auth/audit.jsonl', check=False)
    import json
    alice_grants = [
        e for e in (json.loads(line) for line in
                    (audit.stdout or '').splitlines() if line.strip())
        if e.get('type') == 'authorization'
        and e.get('decision') == 'granted'
        and (e.get('identity') or {}).get('username') == 'alice'
    ]
    print(f'  alice granted entries in audit log: {len(alice_grants)} '
          f'(expected 1 with sqlite cache)',
          file=sys.stderr, flush=True)
    cache_present = lxc_exec(
        TARGET_NAME, 'sh', '-c',
        'ls -la /var/cache/ssh-rt-auth/cert-cache.sqlite3 2>&1; '
        'echo "---"; '
        'sqlite3 /var/cache/ssh-rt-auth/cert-cache.sqlite3 '
        '"SELECT fingerprint, source_ip, serial FROM cert_cache" 2>&1 || true',
        check=False)
    print(f'  cache state on target:\n{cache_present.stdout}',
          file=sys.stderr, flush=True)

    if not keep:
        section('Cleaning up containers')
        for c in (CA_NAME, TARGET_NAME):
            subprocess.run(['lxc', 'delete', '--force', c],
                           capture_output=True)

    assert not failures, f'mismatches: {failures}'
    assert len(alice_grants) == 1, (
        f'expected exactly 1 granted audit entry for alice (SQLite cache '
        f'should dedupe the double sshd call) but got {len(alice_grants)}'
    )
