"""LXC fixtures for ssh-rt-auth integration tests.

Two-layer fixture model:

  ``lxc_env``        — minimal: 5 containers + CA up, no enrollments. Used by
                       the deployment-validation tests that exercise the bare
                       admin API.
  ``provisioned_env`` — depends on ``lxc_env``; enrolls all scenario servers and
                       users, pushes shim configs + AsyncSSH host keys + users
                       files + systemd units to every SSH host, starts the
                       AsyncSSH server on each. Used by the matrix and
                       security tests.

The scenario is generated from a seed (``--seed=N`` to replay). Every test
session prints its seed on stdout.
"""
from __future__ import annotations

import base64
import importlib.util as _ilu
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import pytest


# Load lxc_helpers + randomized + log_helpers by absolute path so we don't
# pollute sys.path with tests/lxc/.
_HERE = Path(__file__).resolve().parent
for _name in ('lxc_helpers', 'randomized', 'log_helpers'):
    _spec = _ilu.spec_from_file_location(_name, _HERE / f'{_name}.py')
    _mod = _ilu.module_from_spec(_spec)
    sys.modules[_name] = _mod
    _spec.loader.exec_module(_mod)

from lxc_helpers import (
    ALL_CONTAINERS, ALL_SSH_HOSTS, ALPINE_IMAGE, CA_HOST, CA_PORT,
    SSHRT_ALPINE, SSHRT_U1, SSHRT_U2, SSHRT_U3, UBUNTU_IMAGE,
    get_ip, install_snoopy_on_all, lxc, lxc_available, lxc_exec,
    push_file, push_source, push_text, wait_for_port,
)
from randomized import Scenario, build_scenario, render_scenario
from log_helpers import banner, section


# The AsyncSSH server inside each SSH host listens here. 22 stays with sshd.
SSHRT_SERVER_PORT = 2222


# ---------------------------------------------------------------------------
# pytest hooks
# ---------------------------------------------------------------------------

def pytest_configure(config):
    config.addinivalue_line(
        'markers', 'lxc: end-to-end LXC integration tests')
    config.addinivalue_line(
        'markers',
        'setup_only: provisioning-only tests (opt-in, no teardown). '
        'Run with `-m setup_only`.')
    config.addinivalue_line(
        'markers',
        'openssh_shim: tests the unmodified-OpenSSH AuthorizedKeysCommand '
        'shim prototype (opt-in, slower setup). '
        'Run with `-m openssh_shim`.')


def pytest_collection_modifyitems(config, items):
    skip_lxc = pytest.mark.skipif(not lxc_available(),
                                  reason='LXC not available')
    explicit_marker = config.getoption('-m', default='') or ''
    explicit_setup_only = 'setup_only' in explicit_marker
    explicit_openssh_shim = 'openssh_shim' in explicit_marker
    skip_setup = pytest.mark.skip(
        reason='setup_only test; run explicitly with -m setup_only')
    skip_openssh = pytest.mark.skip(
        reason='openssh_shim test; run explicitly with -m openssh_shim')
    for item in items:
        if item.get_closest_marker('lxc'):
            item.add_marker(skip_lxc)
        if (item.get_closest_marker('setup_only')
                and not explicit_setup_only):
            item.add_marker(skip_setup)
        if (item.get_closest_marker('openssh_shim')
                and not explicit_openssh_shim):
            item.add_marker(skip_openssh)


def pytest_addoption(parser):
    parser.addoption('--seed', type=int, default=None,
                     help='Seed for randomized scenarios (default: random).')
    parser.addoption('--keep-containers', action='store_true', default=False,
                     help='Leave containers running after tests for debugging.')
    parser.addoption('--install-snoopy', action='store_true', default=False,
                     help='Install Snoopy on every Ubuntu test container so '
                          'every command is logged to /root/systemlogs/'
                          'snoopy.log inside that container. Useful for '
                          'diagnosing what processes the shim/AsyncSSH server '
                          'actually invoke. Alpine is skipped (musl build '
                          'required — not packaged in apk).')


# ---------------------------------------------------------------------------
# Scenario fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def seed(request) -> int:
    s = request.config.getoption('--seed')
    if s is None:
        s = random.SystemRandom().randint(1, 2**31 - 1)
    banner(f'ssh-rt-auth LXC tests — seed={s} (replay with --seed={s})')
    return s


@pytest.fixture(scope='session')
def scenario(seed) -> Scenario:
    sc = build_scenario(seed, ALL_SSH_HOSTS)
    section('Generated scenario')
    print(render_scenario(sc), flush=True, file=sys.stderr)
    return sc


# ---------------------------------------------------------------------------
# Key-pair generation (host-side)
# ---------------------------------------------------------------------------

@dataclass
class _UserKey:
    username: str
    priv_path: str           # OpenSSH-format private key file (host filesystem)
    pub_blob: bytes          # raw SSH wire-format public key blob
    pub_openssh: str         # "ssh-ed25519 AAAA... comment"
    fingerprint: str


def _generate_user_keys(usernames: list[str], outdir: Path) -> dict[str, _UserKey]:
    """Generate one Ed25519 keypair per username via ssh-keygen."""
    out: dict[str, _UserKey] = {}
    for u in usernames:
        priv = outdir / f'id_{u}'
        if priv.exists():
            priv.unlink()
        if (outdir / f'id_{u}.pub').exists():
            (outdir / f'id_{u}.pub').unlink()
        subprocess.run(
            ['ssh-keygen', '-t', 'ed25519', '-f', str(priv),
             '-N', '', '-C', f'{u}@ssh-rt-auth-test'],
            check=True, capture_output=True,
        )
        pub_line = (outdir / f'id_{u}.pub').read_text().strip()
        parts = pub_line.split()
        blob = base64.b64decode(parts[1])
        from ca.identity_parser import sha256_fingerprint
        out[u] = _UserKey(
            username=u, priv_path=str(priv),
            pub_blob=blob, pub_openssh=pub_line,
            fingerprint=sha256_fingerprint(blob),
        )
    return out


# ---------------------------------------------------------------------------
# lxc_env: containers + CA (no enrollments)
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def lxc_env(request, tmp_path_factory):
    """Provision all 5 containers + start the CA. Yields a state dict."""
    keep = request.config.getoption('--keep-containers')

    section('Deleting any pre-existing containers')
    for c in ALL_CONTAINERS:
        subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)

    section('Launching containers')
    for img, name in [
        (UBUNTU_IMAGE, CA_HOST),
        (UBUNTU_IMAGE, SSHRT_U1),
        (UBUNTU_IMAGE, SSHRT_U2),
        (UBUNTU_IMAGE, SSHRT_U3),
        (ALPINE_IMAGE,  SSHRT_ALPINE),
    ]:
        print(f'  launch {name} ({img})', file=sys.stderr, flush=True)
        lxc('launch', img, name,
            '--config', 'security.privileged=true', timeout=300)

    state: dict = {}
    try:
        ips = {c: get_ip(c) for c in ALL_CONTAINERS}
        state['ips'] = ips
        section('Container IPs')
        for c, ip in ips.items():
            print(f'  {c:25s} {ip}', file=sys.stderr, flush=True)

        # Install dependencies via apt/apk.
        app_root = Path(__file__).resolve().parent.parent.parent
        ubuntu_pkgs = [
            'python3', 'python3-cryptography', 'python3-flask',
            'python3-yaml', 'python3-click', 'python3-requests',
            'python3-asyncssh',
            'openssh-server', 'openssh-client',
            # `dbclient` for cross-implementation SSH-client testing.
            'dropbear-bin',
        ]
        section('Installing deps (Ubuntu)')
        for c in [CA_HOST, SSHRT_U1, SSHRT_U2, SSHRT_U3]:
            print(f'  apt install on {c}', file=sys.stderr, flush=True)
            lxc_exec(c, 'apt-get', 'update', '-q', timeout=180)
            lxc_exec(c, 'apt-get', 'install', '-y', '-q', *ubuntu_pkgs,
                     timeout=600)
            push_source(c, app_root)
            lxc_exec(c, 'python3', '-c',
                     'import cryptography, flask, yaml, click, requests, asyncssh',
                     timeout=30)
        section('Installing deps (Alpine)')
        alpine_pkgs = [
            'python3', 'py3-cryptography', 'py3-flask', 'py3-yaml',
            'py3-click', 'py3-requests', 'py3-asyncssh',
            'openssh', 'openssh-server', 'openrc',
            # On Alpine the `dropbear` package only ships the server +
            # dropbearkey; we want the client binary + format converter too.
            'dropbear', 'dropbear-dbclient', 'dropbear-convert',
        ]
        lxc_exec(SSHRT_ALPINE, 'apk', 'add', '--no-cache',
                 *alpine_pkgs, timeout=600)
        push_source(SSHRT_ALPINE, app_root)
        lxc_exec(SSHRT_ALPINE, 'python3', '-c',
                 'import cryptography, flask, yaml, click, requests, asyncssh',
                 timeout=30)

        if request.config.getoption('--install-snoopy'):
            section('Installing Snoopy (command-execution logger)')
            install_snoopy_on_all(ALL_CONTAINERS)

        # Initialize the CA.
        section('Initializing CA')
        lxc_exec(CA_HOST, 'sh', '-c',
                 'PYTHONPATH=/app python3 -c "'
                 'from ca.cert_minter import bootstrap_ca; '
                 f"bootstrap_ca('/etc/ssh-rt-auth/ca', "
                 f"tls_server_sans=['DNS:localhost','IP:127.0.0.1',"
                 f"'IP:{ips[CA_HOST]}'])\"",
                 timeout=120)
        # Seed enrollment with bootstrap admin.
        lxc_exec(CA_HOST, 'sh', '-c',
                 'python3 -c "'
                 'import yaml; '
                 "open('/etc/ssh-rt-auth/ca/enrollment.yaml','w').write("
                 "yaml.safe_dump({'admins': {'bootstrap-admin': "
                 "{'role':'superuser','mtls_subject':'CN=bootstrap-admin',"
                 "'enrolled_at':'','enrolled_by':'init'}}}))\"")
        ca_cfg = (
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
            'server_cert_validity_days: 30, admin_cert_validity_days: 30}\n'
        )
        push_text(CA_HOST, ca_cfg, '/etc/ssh-rt-auth/ca-config.yaml')

        unit = (
            '[Unit]\nDescription=ssh-rt-auth CA\nAfter=network.target\n'
            '[Service]\nWorkingDirectory=/app\n'
            'ExecStart=/usr/bin/python3 -m ca.server --config '
            '/etc/ssh-rt-auth/ca-config.yaml\nRestart=on-failure\n'
            '[Install]\nWantedBy=multi-user.target\n'
        )
        push_text(CA_HOST, unit, '/etc/systemd/system/ssh-rt-auth-ca.service')
        lxc_exec(CA_HOST, 'mkdir', '-p', '/var/log/ssh-rt-auth')
        lxc_exec(CA_HOST, 'systemctl', 'daemon-reload')
        lxc_exec(CA_HOST, 'systemctl', 'start', 'ssh-rt-auth-ca')
        wait_for_port(CA_HOST, CA_PORT, max_wait=60)
        print(f'  CA up at https://{ips[CA_HOST]}:{CA_PORT}',
              file=sys.stderr, flush=True)

        state['ca_url'] = f'https://{ips[CA_HOST]}:{CA_PORT}'

        # Pull bootstrap admin cert/key + TLS CA cert locally.
        admin_dir = tmp_path_factory.mktemp('admin-creds')
        for name in ['bootstrap-admin-cert.pem', 'bootstrap-admin-key.pem',
                     'tls-ca-cert.pem', 'signing-cert.pem',
                     'tls-ca-key.pem']:
            subprocess.run(
                ['lxc', 'file', 'pull',
                 f'{CA_HOST}/etc/ssh-rt-auth/ca/{name}',
                 str(admin_dir / name)], check=True, capture_output=True)
        state['admin_cert'] = str(admin_dir / 'bootstrap-admin-cert.pem')
        state['admin_key'] = str(admin_dir / 'bootstrap-admin-key.pem')
        state['ca_cert'] = str(admin_dir / 'tls-ca-cert.pem')
        state['signing_cert'] = str(admin_dir / 'signing-cert.pem')
        state['tls_ca_key'] = str(admin_dir / 'tls-ca-key.pem')
        state['admin_dir'] = str(admin_dir)

        yield state
    finally:
        if not keep:
            section('Cleaning up containers')
            for c in ALL_CONTAINERS:
                subprocess.run(['lxc', 'delete', '--force', c],
                               capture_output=True)


# ---------------------------------------------------------------------------
# provisioned_env: full enrollment + AsyncSSH server on every SSH host
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def provisioned_env(lxc_env, scenario, tmp_path_factory):
    """Build the full ssh-rt-auth deployment: enrolled servers/users/policies,
    AsyncSSH server running on every SSH host, ready for matrix testing."""
    from cli.client import CAClient
    from cli.key_parser import b64_blob, parse_key_text

    admin = CAClient(
        base_url=lxc_env['ca_url'],
        admin_cert=lxc_env['admin_cert'],
        admin_key=lxc_env['admin_key'],
        ca_cert=lxc_env['ca_cert'],
    )

    keys_dir = tmp_path_factory.mktemp('user-keys')
    usernames = [u.username for u in scenario.users]
    section(f'Generating {len(usernames)} Ed25519 user keypairs')
    user_keys = _generate_user_keys(usernames, keys_dir)

    section('Enrolling users + keys + policies')
    for u in scenario.users:
        admin.user_add(u.username)
        admin.user_key_add(u.username, 'pubkey', b64_blob(
            parse_key_text(user_keys[u.username].pub_openssh)))
        print(f'  user {u.username:10s} fingerprint={user_keys[u.username].fingerprint}',
              file=sys.stderr, flush=True)

    # Enroll each scenario server (canonical-name → physical container).
    section('Enrolling SSH servers (mTLS certs issued by CA)')
    server_creds: dict[str, dict] = {}        # canonical_name → {cert,key,...}
    container_to_canonical: dict[str, str] = {}
    canonical_to_container: dict[str, str] = {}
    for host in scenario.hosts:
        resp = admin.server_add(host.canonical_name, groups=list(host.groups))
        server_creds[host.canonical_name] = resp['credentials']
        container_to_canonical[host.container_name] = host.canonical_name
        canonical_to_container[host.canonical_name] = host.container_name
        print(f'  {host.canonical_name:8s} groups={host.groups} '
              f'-> {host.container_name}', file=sys.stderr, flush=True)

    section('Adding policies for each user')
    for u in scenario.users:
        if not u.allowed_hosts:
            continue
        admin.policy_add(u.username, {
            'servers': list(u.allowed_hosts),
            'channels': ['session'],
            'max_cert_validity_seconds': 600,
        })
        print(f'  policy {u.username:10s} -> {u.allowed_hosts}',
              file=sys.stderr, flush=True)

    # Provision each SSH host: shim config, host key, users file, systemd unit.
    section('Provisioning SSH hosts (shim + AsyncSSH server)')
    ips = lxc_env['ips']
    host_keys_dir = tmp_path_factory.mktemp('asyncssh-host-keys')
    for host in scenario.hosts:
        container = host.container_name
        canon = host.canonical_name
        creds = server_creds[canon]

        _provision_ssh_host(
            container=container, canonical=canon, lxc_env=lxc_env, ips=ips,
            mtls_cert_pem=creds['cert_pem'], mtls_key_pem=creds['key_pem'],
            host_keys_dir=host_keys_dir, user_keys=user_keys,
            all_usernames=usernames,
        )

    # Push every user's private key to /home/<user>/.ssh/id_ed25519 on every
    # SSH host so we can SSH as any user from any host.
    section('Deploying user private keys to all SSH hosts')
    for host in scenario.hosts:
        for u in usernames:
            home_ssh = f'/home/{u}/.ssh'
            push_file(host.container_name, user_keys[u].priv_path,
                      f'{home_ssh}/id_ed25519',
                      mode='600', owner=f'{u}:{u}')

    yield {
        **lxc_env,
        'scenario': scenario,
        'user_keys': user_keys,
        'server_creds': server_creds,
        'container_to_canonical': container_to_canonical,
        'canonical_to_container': canonical_to_container,
        'ssh_port': SSHRT_SERVER_PORT,
    }


# ---------------------------------------------------------------------------
# Per-host provisioning helper
# ---------------------------------------------------------------------------

def _provision_ssh_host(*, container: str, canonical: str, lxc_env: dict,
                        ips: dict, mtls_cert_pem: str, mtls_key_pem: str,
                        host_keys_dir: Path, user_keys: dict[str, _UserKey],
                        all_usernames: list[str]) -> None:
    """Deploy mTLS creds + shim cfg + host key + users file + start AsyncSSH."""
    # 1. Push the server's mTLS client cert + key.
    lxc_exec(container, 'mkdir', '-p', '/etc/ssh-rt-auth/server')
    push_text(container, mtls_cert_pem,
              '/etc/ssh-rt-auth/server/mtls-cert.pem', mode='600')
    push_text(container, mtls_key_pem,
              '/etc/ssh-rt-auth/server/mtls-key.pem', mode='600')
    # 2. CA TLS root + auth signing root.
    push_file(container, lxc_env['ca_cert'],
              '/etc/ssh-rt-auth/server/ca-tls-root.pem', mode='644')
    push_file(container, lxc_env['signing_cert'],
              '/etc/ssh-rt-auth/server/auth-signing-root.pem', mode='644')

    # 3. Shim config.
    shim_cfg = (
        'ca_endpoints:\n'
        f'  - {lxc_env["ca_url"]}\n'
        'mtls_cert: /etc/ssh-rt-auth/server/mtls-cert.pem\n'
        'mtls_key:  /etc/ssh-rt-auth/server/mtls-key.pem\n'
        'ca_trust_root: /etc/ssh-rt-auth/server/ca-tls-root.pem\n'
        'auth_trust_root: /etc/ssh-rt-auth/server/auth-signing-root.pem\n'
        f'server_name: {canonical}\n'
        'cache: {max_entries: 100}\n'
        'timeouts: {connect: 3, read: 5}\n'
    )
    push_text(container, shim_cfg, '/etc/ssh-rt-auth/server/shim.yaml')

    # 4. Generate AsyncSSH host key (Ed25519) locally and push.
    host_priv = host_keys_dir / f'{container}-host-ed25519'
    if host_priv.exists():
        host_priv.unlink()
    if (host_keys_dir / f'{container}-host-ed25519.pub').exists():
        (host_keys_dir / f'{container}-host-ed25519.pub').unlink()
    subprocess.run(['ssh-keygen', '-t', 'ed25519', '-f', str(host_priv),
                    '-N', '', '-C', f'asyncssh-host-{canonical}'],
                   check=True, capture_output=True)
    push_file(container, host_priv,
              '/etc/ssh-rt-auth/server/host-key', mode='600')
    push_file(container, str(host_priv) + '.pub',
              '/etc/ssh-rt-auth/server/host-key.pub', mode='644')

    # 5. Users file: list every (user, blob) so the shim is the gatekeeper.
    lines = []
    for u in all_usernames:
        key = user_keys[u]
        lines.append(f'{u} ssh-ed25519 '
                     f'{base64.b64encode(key.pub_blob).decode("ascii")}')
    push_text(container, '\n'.join(lines) + '\n',
              '/etc/ssh-rt-auth/server/users.allowed', mode='644')

    # 6. Create unix accounts for every user (so AsyncSSH's auth flow can
    #    actually log them in; the shim is still the policy gatekeeper).
    for u in all_usernames:
        # On Alpine, useradd → adduser; we handle both.
        if container == SSHRT_ALPINE:
            lxc_exec(container, 'adduser', '-D', '-s', '/bin/sh', u,
                     check=False)
        else:
            lxc_exec(container, 'useradd', '-m', '-s', '/bin/bash', u,
                     check=False)
        lxc_exec(container, 'sh', '-c',
                 f'mkdir -p /home/{u}/.ssh && chmod 700 /home/{u}/.ssh && '
                 f'chown -R {u}:{u} /home/{u}/.ssh')

    # 7. systemd/openrc unit to run the AsyncSSH server.
    server_cmd = (
        '/usr/bin/python3 -m server.ssh_server '
        '--shim-config /etc/ssh-rt-auth/server/shim.yaml '
        '--host-key /etc/ssh-rt-auth/server/host-key '
        '--users-file /etc/ssh-rt-auth/server/users.allowed '
        f'--listen-host 0.0.0.0 --listen-port {SSHRT_SERVER_PORT}'
    )
    if container == SSHRT_ALPINE:
        # openrc init script.
        rc = (
            '#!/sbin/openrc-run\n'
            'name="ssh-rt-auth-server"\n'
            'command="/usr/bin/python3"\n'
            f'command_args="-m server.ssh_server --shim-config '
            '/etc/ssh-rt-auth/server/shim.yaml --host-key '
            '/etc/ssh-rt-auth/server/host-key --users-file '
            '/etc/ssh-rt-auth/server/users.allowed --listen-host 0.0.0.0 '
            f'--listen-port {SSHRT_SERVER_PORT}"\n'
            'command_background="yes"\n'
            'pidfile="/run/ssh-rt-auth-server.pid"\n'
            'output_log="/var/log/ssh-rt-auth-server.log"\n'
            'error_log="/var/log/ssh-rt-auth-server.log"\n'
            'directory="/app"\n'
            'export PYTHONUNBUFFERED=1\n'
        )
        push_text(container, rc, '/etc/init.d/ssh-rt-auth-server', mode='755')
        lxc_exec(container, 'mkdir', '-p', '/run')
        # Start directly in the background — openrc isn't running in the
        # container yet, so we just exec it as a nohup'd process.
        lxc_exec(container, 'sh', '-c',
                 f'cd /app && nohup {server_cmd} '
                 '> /var/log/ssh-rt-auth-server.log 2>&1 & echo $! > '
                 '/run/ssh-rt-auth-server.pid')
    else:
        unit = (
            '[Unit]\nDescription=ssh-rt-auth AsyncSSH server\n'
            'After=network.target\n'
            '[Service]\nWorkingDirectory=/app\n'
            f'ExecStart={server_cmd}\n'
            'Restart=on-failure\n'
            'StandardOutput=append:/var/log/ssh-rt-auth-server.log\n'
            'StandardError=append:/var/log/ssh-rt-auth-server.log\n'
            '[Install]\nWantedBy=multi-user.target\n'
        )
        push_text(container,
                  unit, '/etc/systemd/system/ssh-rt-auth-server.service')
        lxc_exec(container, 'systemctl', 'daemon-reload')
        lxc_exec(container, 'systemctl', 'start', 'ssh-rt-auth-server')

    # Wait for the AsyncSSH listener.
    wait_for_port(container, SSHRT_SERVER_PORT, max_wait=30)
    print(f'  AsyncSSH up on {container} ({canonical}) :{SSHRT_SERVER_PORT}',
          file=sys.stderr, flush=True)
