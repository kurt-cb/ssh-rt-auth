"""Set-up-only test for ad-hoc exploration of ssh-rt-auth.

What this test does (one big function, no assertions of substance):

  1. Provisions a fresh set of LXC containers with FIXED names:
       sshrt-adhoc-ca           CA + ssh-rt-admin
       sshrt-adhoc-acct         Accounting SSH server
       sshrt-adhoc-sales        Sales SSH server
       sshrt-adhoc-hr           HR SSH server
       sshrt-adhoc-eng          Engineering SSH server (Alpine, for variety)

  2. Enrolls four department servers and eight regular users (two per
     department), plus one **superuser** identity (``root-admin``) whose
     policy grants access to every server group.

  3. Pushes the Unix accounts + each user's private SSH key onto every SSH
     host AND adds the superuser's pubkey alongside each user's pubkey in
     the AsyncSSH server's ``users.allowed`` file. Effect: the superuser can
     ssh in as any Unix user; the CA's policy is the gatekeeper.

  4. Writes a ``README.md`` into each Unix user's home on every SSH host
     describing who they are, which servers they can reach, the enrollment
     commands that produced them, and how to ssh from this container to
     elsewhere.

  5. Writes ``cleanup_containers.sh`` and ``CONTAINER_OVERVIEW.md`` into the
     directory pytest was invoked from. The overview has cut-and-paste ssh
     commands using the superuser key.

  6. **Does not tear down** the containers — that's the whole point. Run
     ``./cleanup_containers.sh`` to remove them when finished.

Run with::

    pytest tests/lxc/test_setup_only.py -v -m setup_only
"""
from __future__ import annotations

import base64
import importlib.util as _ilu
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import pytest


# Re-use the LXC helper module (already loaded by the LXC-conftest).
_HERE = Path(__file__).resolve().parent
for _name in ('lxc_helpers', 'log_helpers'):
    _spec = _ilu.spec_from_file_location(_name, _HERE / f'{_name}.py')
    _mod = _ilu.module_from_spec(_spec)
    sys.modules[_name] = _mod
    _spec.loader.exec_module(_mod)

from lxc_helpers import (
    ALPINE_IMAGE, UBUNTU_IMAGE,
    get_ip, install_snoopy_on_all, lxc, lxc_exec,
    push_file, push_source, push_text, wait_for_port,
)
from log_helpers import banner, section


pytestmark = [pytest.mark.lxc, pytest.mark.setup_only]


# ---------------------------------------------------------------------------
# Fixed topology
# ---------------------------------------------------------------------------

CA_NAME    = 'sshrt-adhoc-ca'
ACCT_NAME  = 'sshrt-adhoc-acct'
SALES_NAME = 'sshrt-adhoc-sales'
HR_NAME    = 'sshrt-adhoc-hr'
ENG_NAME   = 'sshrt-adhoc-eng'

SSH_CONTAINERS = [ACCT_NAME, SALES_NAME, HR_NAME, ENG_NAME]
ALL_CONTAINERS = [CA_NAME] + SSH_CONTAINERS

CA_PORT     = 8443
SSHRT_PORT  = 2222


@dataclass
class _Server:
    container: str
    canonical: str            # CA-registered name
    image: str
    group: str                # "accounting", "sales", "hr", "engineering"


@dataclass
class _User:
    username: str
    department: str           # "accounting" / "sales" / "hr" / "engineering" / "superuser"
    description: str          # human-readable role description
    allowed_groups: list[str] # list of server groups the policy grants


SERVERS: list[_Server] = [
    _Server(ACCT_NAME,  'srv-acct',  UBUNTU_IMAGE, 'accounting'),
    _Server(SALES_NAME, 'srv-sales', UBUNTU_IMAGE, 'sales'),
    _Server(HR_NAME,    'srv-hr',    UBUNTU_IMAGE, 'hr'),
    _Server(ENG_NAME,   'srv-eng',   ALPINE_IMAGE, 'engineering'),
]

USERS: list[_User] = [
    # Accounting
    _User('alice',   'accounting', 'Accounting analyst', ['accounting']),
    _User('amy',     'accounting', 'Accounting manager', ['accounting']),
    # Sales
    _User('bob',     'sales',      'Sales rep',          ['sales']),
    _User('bart',    'sales',      'Sales engineer',     ['sales']),
    # HR
    _User('carol',   'hr',         'HR generalist',      ['hr']),
    _User('charlie', 'hr',         'HR director',        ['hr']),
    # Engineering
    _User('dave',    'engineering', 'Backend engineer',  ['engineering']),
    _User('diana',   'engineering', 'SRE',               ['engineering']),
    # Superuser — access everywhere
    _User('root-admin', 'superuser',
          'Superuser: cross-department break-glass identity',
          ['accounting', 'sales', 'hr', 'engineering']),
]

ALL_USERNAMES = [u.username for u in USERS]
SUPERUSER = next(u for u in USERS if u.department == 'superuser')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _primary_container_for(user: _User) -> str:
    """Where each user's keypair lives by default.

    Models a real onboarding workflow: the user logs into the box that
    belongs to their team and generates a key there. The superuser is
    treated as if they work from the CA host (because that's where they
    hold the admin certs).
    """
    if user.department == 'superuser':
        return CA_NAME
    return {
        'accounting':  ACCT_NAME,
        'sales':       SALES_NAME,
        'hr':          HR_NAME,
        'engineering': ENG_NAME,
    }[user.department]


def _keygen_tool_for(container: str) -> str:
    """Pick a native key-generation tool for ``container``.

    Alpine uses dropbearkey (+ dropbearconvert for an OpenSSH-format private
    key). Everything else uses ssh-keygen.
    """
    return 'dropbear' if container == ENG_NAME else 'ssh-keygen'


def _ensure_unix_account(container: str, username: str) -> None:
    """Idempotently create a Unix account + .ssh dir owned by ``username``."""
    if container == ENG_NAME:
        lxc_exec(container, 'adduser', '-D', '-s', '/bin/sh', username,
                 check=False)
    else:
        lxc_exec(container, 'useradd', '-m', '-s', '/bin/bash', username,
                 check=False)
    lxc_exec(container, 'sh', '-c',
             f'mkdir -p /home/{username}/.ssh && '
             f'chmod 700 /home/{username}/.ssh && '
             f'chown -R {username}:{username} /home/{username}/.ssh')


def _keygen_in_container(*, container: str, username: str, tool: str,
                         artifacts_dir: Path) -> dict:
    """Generate the user's Ed25519 keypair INSIDE their primary container.

    The user "owns" the key generation; the host test then pulls the
    resulting private and public key for later distribution and registration.

    On Alpine (``tool == 'dropbear'``) we exercise the actual dropbear
    tooling: ``dropbearkey`` generates a dropbear-format key, then
    ``dropbearconvert`` converts to OpenSSH format so the same key works
    with both ``ssh`` and ``dbclient``. The public-key line is extracted
    with ``dropbearkey -y``.
    """
    from sshrt.ca.identity_parser import sha256_fingerprint

    _ensure_unix_account(container, username)
    home_ssh = f'/home/{username}/.ssh'
    priv_in = f'{home_ssh}/id_ed25519'
    pub_in  = f'{priv_in}.pub'
    comment = f'{username}@adhoc-{container}'

    if tool == 'ssh-keygen':
        # Run ssh-keygen as the user (so file ownership is right from the start).
        lxc_exec(container, 'su', '-', username, '-c',
                 f'rm -f {priv_in} {pub_in}; '
                 f'ssh-keygen -t ed25519 -f {priv_in} -N "" -C "{comment}"',
                 timeout=30)
    elif tool == 'dropbear':
        # Dropbear path: generate dropbear-format → convert → extract pubkey.
        db_path = f'{home_ssh}/id_ed25519.dropbear'
        lxc_exec(container, 'su', '-', username, '-c',
                 f'rm -f {priv_in} {pub_in} {db_path}; '
                 f'dropbearkey -t ed25519 -f {db_path} >/dev/null; '
                 f'dropbearconvert dropbear openssh {db_path} {priv_in} '
                 f'>/dev/null 2>&1; chmod 600 {priv_in}; '
                 # extract the "ssh-ed25519 AAAA... comment" line into id_ed25519.pub
                 f'dropbearkey -y -f {db_path} | grep "^ssh-" '
                 f'| sed "s| dropbear@.*$| {comment}|" > {pub_in}; '
                 f'chmod 644 {pub_in}',
                 timeout=30)
    else:
        raise ValueError(f'unknown keygen tool: {tool}')

    # Pull the resulting key material out to the host so the test can
    # register it with the CA and distribute it to other containers.
    priv_host = artifacts_dir / username
    pub_host  = artifacts_dir / f'{username}.pub'
    for h, container_path in [(priv_host, priv_in), (pub_host, pub_in)]:
        if h.exists():
            h.unlink()
        subprocess.run(
            ['lxc', 'file', 'pull',
             f'{container}{container_path}', str(h)],
            check=True, capture_output=True)
    os.chmod(priv_host, 0o600)

    pub_line = pub_host.read_text().strip()
    blob = base64.b64decode(pub_line.split()[1])
    return {
        'priv':         str(priv_host),
        'pub_path':     str(pub_host),
        'pub_line':     pub_line,
        'blob':         blob,
        'fingerprint':  sha256_fingerprint(blob),
        'tool':         tool,
        'primary':      container,
    }


def _push_mtls_and_shim_config(server: _Server, ca_ip: str, *,
                               mtls_cert_pem: str, mtls_key_pem: str,
                               ca_tls_root: bytes,
                               auth_signing_root: bytes,
                               host_keys_dir: Path) -> None:
    """Push mTLS creds + shim config + AsyncSSH host key (no users yet)."""
    c = server.container
    lxc_exec(c, 'mkdir', '-p', '/etc/ssh-rt-auth/server')
    push_text(c, mtls_cert_pem, '/etc/ssh-rt-auth/server/mtls-cert.pem', mode='600')
    push_text(c, mtls_key_pem,  '/etc/ssh-rt-auth/server/mtls-key.pem', mode='600')
    push_text(c, ca_tls_root.decode('ascii'),
              '/etc/ssh-rt-auth/server/ca-tls-root.pem', mode='644')
    push_text(c, auth_signing_root.decode('ascii'),
              '/etc/ssh-rt-auth/server/auth-signing-root.pem', mode='644')
    shim_cfg = (
        'ca_endpoints:\n'
        f'  - https://{ca_ip}:{CA_PORT}\n'
        'mtls_cert: /etc/ssh-rt-auth/server/mtls-cert.pem\n'
        'mtls_key:  /etc/ssh-rt-auth/server/mtls-key.pem\n'
        'ca_trust_root: /etc/ssh-rt-auth/server/ca-tls-root.pem\n'
        'auth_trust_root: /etc/ssh-rt-auth/server/auth-signing-root.pem\n'
        f'server_name: {server.canonical}\n'
        'cache: {max_entries: 100}\n'
        'timeouts: {connect: 3, read: 5}\n'
    )
    push_text(c, shim_cfg, '/etc/ssh-rt-auth/server/shim.yaml')
    # AsyncSSH host key (generated on the host for convenience and pushed in).
    host_priv = host_keys_dir / f'{c}-host-ed25519'
    if host_priv.exists():
        host_priv.unlink()
    if (host_keys_dir / f'{c}-host-ed25519.pub').exists():
        (host_keys_dir / f'{c}-host-ed25519.pub').unlink()
    subprocess.run(['ssh-keygen', '-t', 'ed25519', '-f', str(host_priv),
                    '-N', '', '-C', f'asyncssh-host-{server.canonical}'],
                   check=True, capture_output=True)
    push_file(c, host_priv,
              '/etc/ssh-rt-auth/server/host-key', mode='600')
    push_file(c, str(host_priv) + '.pub',
              '/etc/ssh-rt-auth/server/host-key.pub', mode='644')


def _write_users_allowed(server: _Server, user_keys: dict[str, dict],
                         super_pub_blob: bytes) -> None:
    """Write the AsyncSSH server's users.allowed file binding (a) each user's
    own pubkey AND (b) the superuser's pubkey to that unix account."""
    super_b64 = base64.b64encode(super_pub_blob).decode('ascii')
    lines = []
    for u in ALL_USERNAMES:
        own_b64 = base64.b64encode(user_keys[u]['blob']).decode('ascii')
        lines.append(f'{u} ssh-ed25519 {own_b64}')
        if u != SUPERUSER.username:
            lines.append(f'{u} ssh-ed25519 {super_b64}')
    push_text(server.container, '\n'.join(lines) + '\n',
              '/etc/ssh-rt-auth/server/users.allowed', mode='644')


def _start_asyncssh_server(server: _Server) -> None:
    """systemd (Ubuntu) or nohup (Alpine) to start the AsyncSSH server."""
    c = server.container
    server_cmd = (
        '/usr/bin/python3 -m sshrt.asyncssh_ref.ssh_server '
        '--shim-config /etc/ssh-rt-auth/server/shim.yaml '
        '--host-key /etc/ssh-rt-auth/server/host-key '
        '--users-file /etc/ssh-rt-auth/server/users.allowed '
        f'--listen-host 0.0.0.0 --listen-port {SSHRT_PORT}'
    )
    if c == ENG_NAME:
        lxc_exec(c, 'mkdir', '-p', '/run')
        lxc_exec(c, 'sh', '-c',
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
        push_text(c, unit, '/etc/systemd/system/ssh-rt-auth-server.service')
        lxc_exec(c, 'systemctl', 'daemon-reload')
        lxc_exec(c, 'systemctl', 'start', 'ssh-rt-auth-server')
    wait_for_port(c, SSHRT_PORT, max_wait=30)


def _user_readme(user: _User, ips: dict, this_container: str) -> str:
    """Build the per-user README.md content for ``user``."""
    server_table = '\n'.join(
        f'| {s.canonical} | {s.group} | {s.container} | {ips[s.container]} |'
        for s in SERVERS
    )
    allowed = [s for s in SERVERS if s.group in user.allowed_groups]
    if user.department == 'superuser':
        allowed_section = (
            'You are the **superuser** (`root-admin`) — your policy grants '
            'access to every department\'s servers. You can also ssh in '
            'AS any other user (the AsyncSSH server\'s users.allowed file '
            'binds your pubkey to every Unix account on every host).\n')
    elif allowed:
        allowed_section = (
            f'Your CA policy grants access to the **{user.department}** '
            f'department\'s server(s) only:\n\n' +
            '\n'.join(f'- `{s.canonical}` ({s.container})' for s in allowed)
        )
    else:
        allowed_section = 'You have no policy in the CA — every SSH attempt is denied.'

    ssh_examples = '\n'.join(
        f'    ssh -i ~/.ssh/id_ed25519 -p {SSHRT_PORT} {user.username}@{ips[s.container]}'
        for s in allowed
    ) or '    (no allowed servers)'

    return f'''# {user.username} — {user.description}

You are signed in as **{user.username}** on container **{this_container}**.

## Department / role

  - Department: **{user.department}**
  - Description: {user.description}

## Policy summary

{allowed_section}

## Identity material

  - Private SSH key: `/home/{user.username}/.ssh/id_ed25519`
  - Public key:      `/home/{user.username}/.ssh/id_ed25519.pub`

## How you were configured

These are the exact admin commands run from the CA host that set you up:

```
# Enrol the user
ssh-rt-admin --admin-cert /etc/ssh-rt-auth/ca/bootstrap-admin-cert.pem \\
             --admin-key  /etc/ssh-rt-auth/ca/bootstrap-admin-key.pem \\
             --ca-cert    /etc/ssh-rt-auth/ca/tls-ca-cert.pem \\
             --ca-url     https://<ca-ip>:{CA_PORT} \\
             user add --user {user.username} --key /tmp/{user.username}.pub

# Attach a policy granting access to the {user.department} server group(s)
ssh-rt-admin policy add \\
    --user {user.username} \\
    --server-groups {','.join(user.allowed_groups)} \\
    --channels session \\
    --max-validity 600
```

## Trying it out

From this container, ssh to one of your allowed servers:

{ssh_examples}

If you try a denied server (any container outside your department) you
should see "Permission denied (publickey,password,…)". The CA's audit log
will show the denial reason; tail it on the CA host:

    lxc exec sshrt-adhoc-ca -- tail -f /var/log/ssh-rt-auth/audit.jsonl

## Server inventory

| canonical    | group        | container             | ipv4 |
|--------------|--------------|-----------------------|------|
{server_table}
'''


# ---------------------------------------------------------------------------
# The setup-only "test"
# ---------------------------------------------------------------------------

def test_setup_adhoc_environment(request, tmp_path_factory):
    """Provision the ad-hoc lab. Persists everything; does NOT tear down."""
    from ca import cert_minter
    from sshrt.admin.client import CAClient
    from sshrt.admin.key_parser import b64_blob, parse_key_text

    invocation_cwd = Path(os.getcwd()).resolve()
    artifacts_dir  = invocation_cwd / 'adhoc-keys'
    artifacts_dir.mkdir(exist_ok=True)
    ca_creds_dir   = invocation_cwd / 'adhoc-ca-creds'
    ca_creds_dir.mkdir(exist_ok=True)

    banner('Ad-hoc environment setup (no teardown)')
    section('Deleting any pre-existing adhoc containers')
    for c in ALL_CONTAINERS:
        subprocess.run(['lxc', 'delete', '--force', c],
                       capture_output=True)

    section('Launching containers')
    for s in SERVERS:
        print(f'  launch {s.container} ({s.image})',
              file=sys.stderr, flush=True)
        lxc('launch', s.image, s.container,
            '--config', 'security.privileged=true', timeout=300)
    print(f'  launch {CA_NAME} ({UBUNTU_IMAGE})',
          file=sys.stderr, flush=True)
    lxc('launch', UBUNTU_IMAGE, CA_NAME,
        '--config', 'security.privileged=true', timeout=300)

    ips = {c: get_ip(c) for c in ALL_CONTAINERS}
    section('Container IPs')
    for c, ip in ips.items():
        print(f'  {c:25s} {ip}', file=sys.stderr, flush=True)

    # Install deps.
    app_root = Path(__file__).resolve().parent.parent.parent.parent
    ubuntu_pkgs = ['python3', 'python3-cryptography', 'python3-flask',
                   'python3-yaml', 'python3-click', 'python3-requests',
                   'python3-asyncssh', 'openssh-server', 'openssh-client',
                   'dropbear-bin']
    section('Installing deps (Ubuntu)')
    for c in [CA_NAME, ACCT_NAME, SALES_NAME, HR_NAME]:
        print(f'  apt install on {c}', file=sys.stderr, flush=True)
        lxc_exec(c, 'apt-get', 'update', '-q', timeout=180)
        lxc_exec(c, 'apt-get', 'install', '-y', '-q', *ubuntu_pkgs,
                 timeout=600)
        push_source(c, app_root)
    section('Installing deps (Alpine)')
    alpine_pkgs = ['python3', 'py3-cryptography', 'py3-flask', 'py3-yaml',
                   'py3-click', 'py3-requests', 'py3-asyncssh',
                   'openssh', 'openssh-server',
                   # dropbear package on Alpine is server-only; we also need:
                   # - dropbear-convert  (private-key format converter)
                   # - dropbear-dbclient (client binary)
                   'dropbear', 'dropbear-convert', 'dropbear-dbclient']
    lxc_exec(ENG_NAME, 'apk', 'add', '--no-cache', *alpine_pkgs,
             timeout=600)
    push_source(ENG_NAME, app_root)

    if request.config.getoption('--install-snoopy', default=False):
        section('Installing Snoopy (command-execution logger)')
        install_snoopy_on_all(ALL_CONTAINERS)

    # Bootstrap CA.
    section('Initializing CA')
    lxc_exec(CA_NAME, 'sh', '-c',
             'PYTHONPATH=/app/src python3 -c "'
             'from sshrt.ca.cert_minter import bootstrap_ca; '
             f"bootstrap_ca('/etc/ssh-rt-auth/ca', "
             f"tls_server_sans=['DNS:localhost','IP:127.0.0.1',"
             f"'IP:{ips[CA_NAME]}'])\"",
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
    print(f'  CA up at https://{ips[CA_NAME]}:{CA_PORT}',
          file=sys.stderr, flush=True)

    # Pull the bootstrap admin creds locally.
    for name in ['bootstrap-admin-cert.pem', 'bootstrap-admin-key.pem',
                 'tls-ca-cert.pem', 'signing-cert.pem']:
        subprocess.run(
            ['lxc', 'file', 'pull',
             f'{CA_NAME}/etc/ssh-rt-auth/ca/{name}',
             str(ca_creds_dir / name)], check=True, capture_output=True)
    ca_tls_root_pem = (ca_creds_dir / 'tls-ca-cert.pem').read_bytes()
    auth_signing_root_pem = (ca_creds_dir / 'signing-cert.pem').read_bytes()
    os.chmod(ca_creds_dir / 'bootstrap-admin-key.pem', 0o600)

    admin = CAClient(
        base_url=f'https://{ips[CA_NAME]}:{CA_PORT}',
        admin_cert=str(ca_creds_dir / 'bootstrap-admin-cert.pem'),
        admin_key=str(ca_creds_dir / 'bootstrap-admin-key.pem'),
        ca_cert=str(ca_creds_dir / 'tls-ca-cert.pem'),
    )

    # ---- Realistic onboarding flow --------------------------------------
    #
    # Step 1: enrol the four department servers (admin work, on the CA).
    section('Enrolling servers (admin → CA)')
    server_creds: dict[str, dict] = {}
    for s in SERVERS:
        resp = admin.server_add(s.canonical, groups=[s.group])
        server_creds[s.canonical] = resp['credentials']
        print(f'  {s.canonical:10s} group={s.group:11s} -> {s.container}',
              file=sys.stderr, flush=True)

    # Step 2: push mTLS creds + shim config + AsyncSSH host key to each SSH
    # host. AsyncSSH server is NOT started yet — we need user pubkeys for
    # its users.allowed file first.
    section('Provisioning SSH-host mTLS + shim config')
    host_keys_dir = tmp_path_factory.mktemp('asyncssh-host-keys')
    for s in SERVERS:
        creds = server_creds[s.canonical]
        _push_mtls_and_shim_config(
            s, ips[CA_NAME],
            mtls_cert_pem=creds['cert_pem'],
            mtls_key_pem=creds['key_pem'],
            ca_tls_root=ca_tls_root_pem,
            auth_signing_root=auth_signing_root_pem,
            host_keys_dir=host_keys_dir,
        )

    # Step 3: create Unix accounts for every user on every SSH host. This
    # has to happen BEFORE in-container ssh-keygen because we run keygen
    # as the user.
    section('Creating Unix accounts on every SSH host')
    for s in SERVERS:
        for u in USERS:
            _ensure_unix_account(s.container, u.username)
    # The superuser's primary is the CA host, so they need an account there too.
    _ensure_unix_account(CA_NAME, SUPERUSER.username)

    # Step 4: each user generates their OWN keypair on their primary
    # container, using the native tool (ssh-keygen on Ubuntu, dropbear on
    # Alpine). The test acts on the user's behalf via `lxc exec`; in the
    # real workflow this would be the user logging into their box.
    section('Generating user keypairs INSIDE primary containers')
    user_keys: dict[str, dict] = {}
    for u in USERS:
        primary = _primary_container_for(u)
        tool = _keygen_tool_for(primary)
        print(f'  {u.username:12s} on {primary:22s} via {tool}',
              file=sys.stderr, flush=True)
        user_keys[u.username] = _keygen_in_container(
            container=primary, username=u.username, tool=tool,
            artifacts_dir=artifacts_dir,
        )
        print(f'    -> fingerprint={user_keys[u.username]["fingerprint"]}',
              file=sys.stderr, flush=True)

    # Step 5: the admin enrols each user and their pubkey at the CA.
    section('Enrolling users + keys at the CA via the admin client')
    for u in USERS:
        admin.user_add(u.username)
        admin.user_key_add(u.username, 'pubkey',
                           b64_blob(parse_key_text(
                               user_keys[u.username]['pub_line'])))

    # Step 6: the admin attaches each user's policy.
    section('Attaching policies')
    for u in USERS:
        admin.policy_add(u.username, {
            'server_groups': list(u.allowed_groups),
            'channels': ['session'],
            'max_cert_validity_seconds': 600,
        })
        print(f'  policy {u.username:12s} groups={u.allowed_groups}',
              file=sys.stderr, flush=True)

    # Step 7: write the AsyncSSH server's users.allowed file (now that we
    # have every user's pubkey) and start the server on each SSH host.
    section('Writing users.allowed + starting AsyncSSH server on each host')
    for s in SERVERS:
        _write_users_allowed(s, user_keys,
                             user_keys[SUPERUSER.username]['blob'])
        _start_asyncssh_server(s)
        print(f'  AsyncSSH up on {s.container} ({s.canonical})',
              file=sys.stderr, flush=True)

    # Step 8: copy each user's private + public key to every OTHER SSH host
    # where they have a Unix account (the user generated their key on
    # ``primary``; we mirror it so they can ssh from any container). Also
    # push the per-user README.
    section('Distributing user keys + README to non-primary containers')
    for s in SERVERS:
        for u in USERS:
            home_ssh = f'/home/{u.username}/.ssh'
            primary = _primary_container_for(u)
            if s.container != primary:
                push_file(s.container, user_keys[u.username]['priv'],
                          f'{home_ssh}/id_ed25519',
                          mode='600',
                          owner=f'{u.username}:{u.username}')
                push_file(s.container, user_keys[u.username]['pub_path'],
                          f'{home_ssh}/id_ed25519.pub',
                          mode='644',
                          owner=f'{u.username}:{u.username}')
            push_text(s.container,
                      _user_readme(u, ips, this_container=s.container),
                      f'/home/{u.username}/README.md',
                      mode='644', owner=f'{u.username}:{u.username}')

    # Write cleanup script + adhoc-env.sh + ADHOC_TEST_ENV.md into the
    # invocation cwd. Stale CONTAINER_OVERVIEW.md (older naming) is removed
    # so users don't get confused.
    section('Writing adhoc-env.sh, ADHOC_TEST_ENV.md, cleanup_containers.sh '
            f'to {invocation_cwd}')
    stale = invocation_cwd / 'CONTAINER_OVERVIEW.md'
    if stale.exists():
        stale.unlink()
    _write_cleanup_script(invocation_cwd / 'cleanup_containers.sh')
    _write_env_sh(
        invocation_cwd / 'adhoc-env.sh',
        ips=ips, artifacts_dir=artifacts_dir, ca_creds_dir=ca_creds_dir,
    )
    _write_overview_md(
        invocation_cwd / 'ADHOC_TEST_ENV.md',
        ips=ips, user_keys=user_keys,
        artifacts_dir=artifacts_dir, ca_creds_dir=ca_creds_dir,
    )

    section('Done — containers left RUNNING')
    print(f'  CA endpoint:        https://{ips[CA_NAME]}:{CA_PORT}',
          file=sys.stderr)
    print(f'  Bootstrap admin:    {ca_creds_dir}',
          file=sys.stderr)
    print(f'  User keys:          {artifacts_dir}',
          file=sys.stderr)
    print(f'  Source config:      {invocation_cwd / "adhoc-env.sh"}',
          file=sys.stderr)
    print(f'  Overview:           {invocation_cwd / "ADHOC_TEST_ENV.md"}',
          file=sys.stderr)
    print(f'  Cleanup:            {invocation_cwd / "cleanup_containers.sh"}',
          file=sys.stderr)


# ---------------------------------------------------------------------------
# Output artefacts
# ---------------------------------------------------------------------------

def _write_cleanup_script(path: Path) -> None:
    content = (
        '#!/usr/bin/env bash\n'
        '# Cleanup script generated by tests/lxc/test_setup_only.py\n'
        '# Removes all ad-hoc ssh-rt-auth containers.\n'
        'set -euo pipefail\n'
        '\n'
        'CONTAINERS=(\n'
        + '\n'.join(f'  {c}' for c in ALL_CONTAINERS) + '\n'
        ')\n'
        '\n'
        'for c in "${CONTAINERS[@]}"; do\n'
        '  if lxc info "$c" >/dev/null 2>&1; then\n'
        '    echo "Deleting $c..."\n'
        '    lxc delete --force "$c"\n'
        '  else\n'
        '    echo "(skip) $c is not present"\n'
        '  fi\n'
        'done\n'
        'echo "All ad-hoc containers removed."\n'
    )
    path.write_text(content)
    os.chmod(path, 0o755)


def _write_env_sh(path: Path, *, ips: dict, artifacts_dir: Path,
                  ca_creds_dir: Path) -> None:
    """Shell-sourceable env file: defines all paths/hosts as $VARs.

    Usage:
        source ./adhoc-env.sh
        ssh $SSH_FLAGS $SUPER@$ACCT_IP
    """
    lines = [
        '#!/usr/bin/env bash',
        '# ssh-rt-auth ad-hoc lab — environment variables',
        '#',
        '# Generated by tests/lxc/test_setup_only.py.',
        '# Source from any shell:    source ./adhoc-env.sh',
        '',
        '# ---- Directories --------------------------------------------------',
        f'export ADHOC_KEYS="{artifacts_dir}"',
        f'export ADHOC_CA_CREDS="{ca_creds_dir}"',
        '',
        '# ---- CA + admin credentials --------------------------------------',
        f'export CA_URL="https://{ips[CA_NAME]}:{CA_PORT}"',
        'export CA_CERT="$ADHOC_CA_CREDS/tls-ca-cert.pem"',
        'export CA_SIGNING_CERT="$ADHOC_CA_CREDS/signing-cert.pem"',
        'export ADMIN_CERT="$ADHOC_CA_CREDS/bootstrap-admin-cert.pem"',
        'export ADMIN_KEY="$ADHOC_CA_CREDS/bootstrap-admin-key.pem"',
        '',
        '# ---- Container IPs ------------------------------------------------',
        f'export CA_IP="{ips[CA_NAME]}"',
    ]
    for s in SERVERS:
        var = s.group.upper() + '_IP'
        lines.append(f'export {var}="{ips[s.container]}"')

    lines += [
        '',
        '# ---- User private-key paths --------------------------------------',
    ]
    for u in USERS:
        var = u.username.upper().replace('-', '_') + '_KEY'
        lines.append(f'export {var}="$ADHOC_KEYS/{u.username}"')

    super_var = SUPERUSER.username.upper().replace('-', '_') + '_KEY'
    lines += [
        '',
        '# ---- Convenience aliases -----------------------------------------',
        f'export SUPER_KEY="${super_var}"',
        f'export SSH_PORT="{SSHRT_PORT}"',
        ('export SSH_FLAGS="-i $SUPER_KEY -p $SSH_PORT '
         '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
         '-o IdentitiesOnly=yes"'),
        '',
        '# ---- Container names ---------------------------------------------',
        f'export CA_HOST="{CA_NAME}"',
        f'export ACCT_HOST="{ACCT_NAME}"',
        f'export SALES_HOST="{SALES_NAME}"',
        f'export HR_HOST="{HR_NAME}"',
        f'export ENG_HOST="{ENG_NAME}"',
        '',
        ('echo "ssh-rt-auth ad-hoc env loaded. '
         'Try:  ssh \\$SSH_FLAGS alice@\\$ACCOUNTING_IP"'),
    ]
    path.write_text('\n'.join(lines) + '\n')
    os.chmod(path, 0o644)


def _write_overview_md(path: Path, *, ips: dict, user_keys: dict,
                       artifacts_dir: Path, ca_creds_dir: Path) -> None:
    """Generate ADHOC_TEST_ENV.md — references everything via $VARs from
    adhoc-env.sh and includes the full CLI command log used to bootstrap."""

    def _group_var(group: str) -> str:
        return f'${group.upper()}_IP'

    def _user_var(username: str) -> str:
        return f'${username.upper().replace("-", "_")}_KEY'

    lines: list[str] = []
    lines += [
        '# ssh-rt-auth — Ad-hoc test environment',
        '',
        'Generated by `tests/lxc/test_setup_only.py`. The five LXC containers',
        'are left **RUNNING**; remove them with `./cleanup_containers.sh`.',
        '',
        '## 1. Activating the environment',
        '',
        'All paths and host addresses in this document are referenced via',
        'environment variables defined in `adhoc-env.sh`. Source it first:',
        '',
        '```bash',
        'source ./adhoc-env.sh',
        '```',
        '',
        '## 2. Hosts',
        '',
        '| container | role | image | ipv4 |',
        '|-----------|------|-------|------|',
        f'| `$CA_HOST` | Authorization CA + admin API | Ubuntu 22.04 | '
        f'`$CA_IP` |',
    ]
    for s in SERVERS:
        img = 'Alpine 3.21' if s.image == ALPINE_IMAGE else 'Ubuntu 22.04'
        var_host = '$' + (s.group.upper() + '_HOST')
        # Static host vars: ACCT_HOST, SALES_HOST, etc. Already defined in env.sh.
        lines.append(
            f'| `{var_host}` | {s.group.title()} SSH server '
            f'(`{s.canonical}`) | {img} | `{_group_var(s.group)}` |')

    lines += [
        '',
        '## 3. Users',
        '',
        '| username | department | allowed servers | fingerprint | key var |',
        '|----------|------------|-----------------|-------------|---------|',
    ]
    for u in USERS:
        allowed = ', '.join(
            s.canonical for s in SERVERS if s.group in u.allowed_groups
        ) or '—'
        lines.append(
            f'| `{u.username}` | {u.department} | {allowed} | '
            f'`{user_keys[u.username]["fingerprint"]}` | '
            f'`{_user_var(u.username)}` |')

    lines += [
        '',
        '## 4. CA + admin credentials',
        '',
        '```bash',
        'echo "CA URL:               $CA_URL"',
        'echo "CA TLS root:          $CA_CERT"',
        'echo "Authz signing cert:   $CA_SIGNING_CERT"',
        'echo "Bootstrap admin cert: $ADMIN_CERT"',
        'echo "Bootstrap admin key:  $ADMIN_KEY"',
        '```',
        '',
        '## 5. Quick logins as the SUPERUSER (`' + SUPERUSER.username + '`)',
        '',
        'The CA permits the superuser everywhere; the AsyncSSH server\'s',
        '`users.allowed` file binds the superuser pubkey to every Unix user,',
        'so the same key logs you in as anybody.',
        '',
    ]
    for s in SERVERS:
        var_ip = _group_var(s.group)
        lines.append(f'### `{s.canonical}` ({_group_var(s.group)})')
        lines.append('')
        lines.append('```bash')
        for u in USERS:
            lines.append(
                f'ssh $SSH_FLAGS {u.username}@{var_ip}'
                f'      # as {u.username} ({u.department})')
        lines.append('```')
        lines.append('')

    lines += [
        '## 6. Logins as each user (their own private key)',
        '',
        'Each user has their own key. Department users are restricted by the',
        'CA to their own department\'s server group; attempts to other groups',
        'are denied with `no_matching_policy` in the audit log.',
        '',
        '```bash',
    ]
    for u in USERS:
        if u.department == 'superuser':
            continue
        allowed = [s for s in SERVERS if s.group in u.allowed_groups]
        for s in allowed:
            lines.append(
                f'ssh -i {_user_var(u.username)} -p $SSH_PORT '
                '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
                '-o IdentitiesOnly=yes '
                f'{u.username}@{_group_var(s.group)}'
                f'   # {u.username} → {s.canonical}')
    lines += [
        '```',
        '',
        '## 7. Inspecting state inside containers',
        '',
        '```bash',
        '# Tail the CA audit log',
        'lxc exec $CA_HOST -- tail -f /var/log/ssh-rt-auth/audit.jsonl',
        '',
        '# Tail an AsyncSSH server log',
        'lxc exec $ACCT_HOST -- tail -f /var/log/ssh-rt-auth-server.log',
        '',
        '# Open a shell on a container',
        'lxc exec $ACCT_HOST -- bash',
        '',
        '# Read a user\'s README inside the container',
        'lxc exec $ACCT_HOST -- cat /home/alice/README.md',
        '```',
        '',
        '### Snoopy (optional command-execution log)',
        '',
        'If you launched the setup test with `--install-snoopy`, every',
        '`execve()` call inside every Ubuntu container is logged to',
        '`/root/systemlogs/snoopy.log` (Alpine is skipped — see the LXC',
        'README for why). Tail it while reproducing an issue:',
        '',
        '```bash',
        '# Watch every command run as the shim/AsyncSSH server work',
        'lxc exec $ACCT_HOST -- tail -f /root/systemlogs/snoopy.log',
        '',
        '# Or grep for a specific user\'s activity',
        'lxc exec $ACCT_HOST -- grep "uid=$(lxc exec $ACCT_HOST -- id -u alice)" \\',
        '    /root/systemlogs/snoopy.log',
        '```',
        '',
        'If you DID NOT pass `--install-snoopy`, the file does not exist;',
        're-run the setup test with the flag set.',
        '',
        '## 8. Cleanup',
        '',
        '```bash',
        './cleanup_containers.sh',
        '```',
        '',
    ]

    lines += _setup_command_log_section(ips=ips, user_keys=user_keys)

    path.write_text('\n'.join(lines))


def _setup_command_log_section(*, ips: dict, user_keys: dict) -> list[str]:
    """The "9. Setup command log" section — every CLI call the test makes
    to build the env, in the order they happen. Reproducible by hand."""

    lines = [
        '## 9. Setup command log',
        '',
        'Below is every command the setup-only test ran, in order. They are',
        'reproducible from the host machine with `ssh-rt-admin` once the CA',
        'is up.',
        '',
        '### 9.1. CA initialization (crypto-officer / `bootstrap-admin`)',
        '',
        'Run **inside the CA container** by the test as root. Generates the',
        'CA\'s signing key pair, mTLS-CA, TLS-listener cert, and the first',
        'superuser admin cert.',
        '',
        '```bash',
        '# (executed inside the CA container)',
        'mkdir -p /etc/ssh-rt-auth/ca',
        'python3 -c "',
        '  from sshrt.ca.cert_minter import bootstrap_ca',
        '  bootstrap_ca(\'/etc/ssh-rt-auth/ca\',',
        '               tls_server_sans=[\'DNS:localhost\',\'IP:127.0.0.1\','
        f'\'IP:$CA_IP\'])"',
        '```',
        '',
        'This produces the following key material in `/etc/ssh-rt-auth/ca/`:',
        '',
        '| file | role | trust path |',
        '|------|------|------------|',
        '| `signing-key.pem` | Authorization signing private key | authz |',
        '| `signing-cert.pem` | Authorization trust root (self-signed) | authz |',
        '| `tls-ca-key.pem` | mTLS CA private key | mTLS |',
        '| `tls-ca-cert.pem` | mTLS trust root | mTLS |',
        '| `tls-server-cert.pem` | CA\'s HTTPS listener cert | mTLS |',
        '| `tls-server-key.pem` | CA\'s HTTPS listener key | mTLS |',
        '| `bootstrap-admin-cert.pem` | Bootstrap admin (superuser) client cert | mTLS |',
        '| `bootstrap-admin-key.pem` | Bootstrap admin client key | mTLS |',
        '',
        'The `bootstrap-admin` admin is then seeded into',
        '`enrollment.yaml` with role `superuser` (so its mTLS subject',
        '`CN=bootstrap-admin` is recognized by the CA).',
        '',
        '### 9.2. Starting the CA',
        '',
        '```bash',
        '# (CA container) systemd unit configured by the test',
        'systemctl daemon-reload',
        'systemctl start ssh-rt-auth-ca',
        '```',
        '',
        '### 9.3. ssh-rt-admin authentication for the rest of the commands',
        '',
        'Every command in §9.4–§9.6 below is shown using `ssh-rt-admin`',
        'authenticated as the bootstrap admin. Adapt to your own admin cert',
        'as needed.',
        '',
        '```bash',
        ('alias admin="ssh-rt-admin --admin-cert $ADMIN_CERT '
         '--admin-key $ADMIN_KEY --ca-cert $CA_CERT --ca-url $CA_URL"'),
        '```',
        '',
        '### 9.4. Enrol the four SSH servers',
        '',
        'Each `server add` issues an mTLS client cert for that server which',
        'the test pulls and pushes onto the matching container.',
        '',
        '```bash',
    ]
    for s in SERVERS:
        lines.append(
            f'admin server add --name {s.canonical} --groups {s.group}    '
            f'# physical container: ${(s.group.upper() + "_HOST")[1:]}')
    lines += [
        '```',
        '',
        '### 9.5. Each user generates their OWN keypair on their primary host',
        '',
        'The user logs into the server matching their department and runs the',
        'native key-generation tool. The test runs these commands on their',
        'behalf via `lxc exec ... -- su - <user> -c "..."`.',
        '',
        'For Ubuntu boxes (`ssh-keygen`):',
        '',
        '```bash',
        '# Example: alice on the accounting server',
        'lxc exec $ACCT_HOST -- su - alice -c \\',
        '    "ssh-keygen -t ed25519 -f /home/alice/.ssh/id_ed25519 '
        '-N \'\' -C alice@accounting"',
        '```',
        '',
        'For the Alpine box (`dropbearkey` + `dropbearconvert`):',
        '',
        '```bash',
        '# Example: dave on the engineering server (Alpine + dropbear)',
        'lxc exec $ENG_HOST -- su - dave -c \'',
        '    dropbearkey -t ed25519 -f /home/dave/.ssh/id_ed25519.dropbear',
        '    dropbearconvert dropbear openssh \\',
        '        /home/dave/.ssh/id_ed25519.dropbear \\',
        '        /home/dave/.ssh/id_ed25519',
        '    chmod 600 /home/dave/.ssh/id_ed25519',
        '    dropbearkey -y -f /home/dave/.ssh/id_ed25519.dropbear \\',
        '        | grep ^ssh- > /home/dave/.ssh/id_ed25519.pub',
        '\'',
        '```',
        '',
        '### 9.6. Each user sends their pubkey to the admin, who enrols them',
        '',
        'Out-of-band the user hands their `.pub` to the admin. The admin then:',
        '',
        '```bash',
        '# Pull pubkey out of the user\'s container',
    ]
    for u in USERS:
        primary_var = '$' + ({
            'accounting':  'ACCT_HOST',
            'sales':       'SALES_HOST',
            'hr':          'HR_HOST',
            'engineering': 'ENG_HOST',
            'superuser':   'CA_HOST',
        }[u.department])
        lines.append(
            f'lxc file pull {primary_var}/home/{u.username}/.ssh/id_ed25519.pub '
            f'  /tmp/{u.username}.pub'
        )
    lines.append('')
    lines.append('# Register each user + pubkey at the CA')
    for u in USERS:
        lines.append(
            f'admin user add --user {u.username} '
            f'--key /tmp/{u.username}.pub'
            f'   # {u.description}')
    lines += [
        '```',
        '',
        '### 9.7. Attach policies',
        '',
        'Department users get a policy that grants their own server group.',
        f'The superuser (`{SUPERUSER.username}`) gets a policy that grants',
        'every server group.',
        '',
        '```bash',
    ]
    for u in USERS:
        groups = ','.join(u.allowed_groups)
        lines.append(
            f'admin policy add --user {u.username} '
            f'--server-groups {groups} --channels session --max-validity 600')
    lines += [
        '```',
        '',
        '### 9.8. Per-server provisioning (test-side, not via ssh-rt-admin)',
        '',
        'For each of the four SSH-host containers the test installs:',
        '',
        '| path inside container | content |',
        '|-----------------------|---------|',
        '| `/etc/ssh-rt-auth/server/shim.yaml` | shim config (`ca_endpoints`, mTLS paths, `server_name`) |',
        '| `/etc/ssh-rt-auth/server/mtls-cert.pem` | this server\'s mTLS client cert (from §9.4) |',
        '| `/etc/ssh-rt-auth/server/mtls-key.pem` | this server\'s mTLS client key |',
        '| `/etc/ssh-rt-auth/server/ca-tls-root.pem` | CA TLS trust root (= `tls-ca-cert.pem`) |',
        '| `/etc/ssh-rt-auth/server/auth-signing-root.pem` | authz trust root (= `signing-cert.pem`) |',
        '| `/etc/ssh-rt-auth/server/host-key` | AsyncSSH host private key |',
        '| `/etc/ssh-rt-auth/server/users.allowed` | (user, pubkey-blob) bindings for shim-gated auth |',
        '',
        'Plus a systemd unit (Ubuntu) or a `nohup`-launched process (Alpine) that runs:',
        '',
        '```',
        'python3 -m sshrt.asyncssh_ref.ssh_server \\',
        '   --shim-config /etc/ssh-rt-auth/server/shim.yaml \\',
        '   --host-key    /etc/ssh-rt-auth/server/host-key \\',
        '   --users-file  /etc/ssh-rt-auth/server/users.allowed \\',
        f'   --listen-host 0.0.0.0 --listen-port {SSHRT_PORT}',
        '```',
        '',
        '### 9.9. Per-user files inside each SSH container',
        '',
        'For each Unix user on each SSH host the test pushes:',
        '',
        '```',
        '/home/<user>/.ssh/id_ed25519       (mode 600)',
        '/home/<user>/.ssh/id_ed25519.pub   (mode 644)',
        '/home/<user>/README.md             (this user\'s individual doc)',
        '```',
        '',
    ]
    return lines
