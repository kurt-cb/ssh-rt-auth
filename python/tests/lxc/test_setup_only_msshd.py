"""Set-up-only test for the Tier-1 (msshd) adoption journey.

Walks the same containers through three states and leaves them at the
final state with helper scripts to flip between modes:

    Phase 0 — vanilla sshd on every server; users `ssh user@host` works.
    Phase 1 — drop msshd in fallback in front (port 2200); users now
              `ssh -p 2200 user@host`, still using their SSH keypair.
              No CA involvement; msshd is a transparent TCP proxy.
    Phase 2 — generate user-CA + per-user X.509 mTLS material, enroll
              users at the CA, flip msshd to enforce mode; users now
              `mssh user@host:2200` with cert-bound, CA-mediated auth.

End state is Phase 2. Helper scripts (flip-to-fallback.sh /
flip-to-enforce.sh) let the operator bounce between modes after
provisioning.

Containers (FIXED names, stomped on each run):

    sshrt-adhoc-ca       CA + ssh-rt-admin
    sshrt-adhoc-acct     Accounting SSH server
    sshrt-adhoc-sales    Sales SSH server
    sshrt-adhoc-hr       HR SSH server
    sshrt-adhoc-eng      Engineering server (Alpine, cross-distro)

Vanilla sshd lives on port 22 in every server (always alive — your
backdoor if msshd is misbehaving). msshd lives on port 2200 in
whichever mode you last flipped it to.

Run with::

    pytest tests/lxc/test_setup_only_msshd.py -v -m setup_only_msshd
"""
from __future__ import annotations

import base64
import datetime as _dt
import importlib.util as _ilu
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest


_HERE = Path(__file__).resolve().parent
for _name in ('lxc_helpers', 'log_helpers'):
    _spec = _ilu.spec_from_file_location(_name, _HERE / f'{_name}.py')
    _mod = _ilu.module_from_spec(_spec)
    sys.modules[_name] = _mod
    _spec.loader.exec_module(_mod)

from lxc_helpers import (
    ALPINE_IMAGE, UBUNTU_IMAGE,
    get_ip, lxc, lxc_exec, push_file, push_source, push_text,
    wait_for_apt_quiescent, wait_for_port,
)
from log_helpers import banner, section


pytestmark = [pytest.mark.lxc, pytest.mark.setup_only_msshd]


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------

CA_NAME    = 'sshrt-adhoc-ca'
ACCT_NAME  = 'sshrt-adhoc-acct'
SALES_NAME = 'sshrt-adhoc-sales'
HR_NAME    = 'sshrt-adhoc-hr'
ENG_NAME   = 'sshrt-adhoc-eng'

SSH_CONTAINERS = [ACCT_NAME, SALES_NAME, HR_NAME, ENG_NAME]
ALL_CONTAINERS = [CA_NAME] + SSH_CONTAINERS

CA_PORT     = 8443
VANILLA_SSHD_PORT = 22      # in-container; reachable from host via lxc IP
MSSHD_PORT  = 2200


@dataclass
class _Server:
    container: str
    canonical: str
    image: str
    group: str


@dataclass
class _User:
    username: str
    department: str
    description: str
    allowed_groups: list[str]


SERVERS: list[_Server] = [
    _Server(ACCT_NAME,  'srv-acct',  UBUNTU_IMAGE, 'accounting'),
    _Server(SALES_NAME, 'srv-sales', UBUNTU_IMAGE, 'sales'),
    _Server(HR_NAME,    'srv-hr',    UBUNTU_IMAGE, 'hr'),
    _Server(ENG_NAME,   'srv-eng',   ALPINE_IMAGE, 'engineering'),
]

USERS: list[_User] = [
    _User('alice',      'accounting',  'Accounting analyst', ['accounting']),
    _User('amy',        'accounting',  'Accounting manager', ['accounting']),
    _User('bob',        'sales',       'Sales rep',          ['sales']),
    _User('bart',       'sales',       'Sales engineer',     ['sales']),
    _User('carol',      'hr',          'HR generalist',      ['hr']),
    _User('charlie',    'hr',          'HR director',        ['hr']),
    _User('dave',       'engineering', 'Backend engineer',   ['engineering']),
    _User('diana',      'engineering', 'SRE',                ['engineering']),
    _User('root-admin', 'superuser',   'Cross-dept break-glass',
          ['accounting', 'sales', 'hr', 'engineering']),
]
ALL_USERNAMES = [u.username for u in USERS]
SUPERUSER = next(u for u in USERS if u.department == 'superuser')


def _primary_container_for(user: _User) -> str:
    if user.department == 'superuser':
        return CA_NAME
    return {'accounting': ACCT_NAME, 'sales': SALES_NAME,
            'hr': HR_NAME, 'engineering': ENG_NAME}[user.department]


def _allowed_servers_for(user: _User) -> list[_Server]:
    return [s for s in SERVERS if s.group in user.allowed_groups]


def _is_alpine(container: str) -> bool:
    return container == ENG_NAME


# ---------------------------------------------------------------------------
# Phase 0 — vanilla sshd + SSH keypair per user
# ---------------------------------------------------------------------------

def _ensure_unix_account(container: str, username: str) -> None:
    if _is_alpine(container):
        lxc_exec(container, 'adduser', '-D', '-s', '/bin/sh', username,
                 check=False)
        # Alpine adduser -D leaves the account locked ("!" in /etc/shadow);
        # sshd refuses login for locked accounts even on pubkey auth
        # ("User X not allowed because account is locked"). Flip to "*"
        # (no password set, but not locked).
        lxc_exec(container, 'sh', '-c',
                 f"sed -i 's|^{username}:!:|{username}:*:|' /etc/shadow",
                 check=False)
    else:
        lxc_exec(container, 'useradd', '-m', '-s', '/bin/bash', username,
                 check=False)
        lxc_exec(container, 'usermod', '-p', '*', username, check=False)
    lxc_exec(container, 'sh', '-c',
             f'mkdir -p /home/{username}/.ssh && '
             f'chmod 700 /home/{username}/.ssh && '
             f'chown -R {username}:{username} /home/{username}/.ssh')


def _keygen_in_container(container: str, username: str,
                         artifacts_dir: Path) -> dict:
    """Generate the user's Ed25519 keypair INSIDE their primary container,
    then pull both halves to ``artifacts_dir``.
    """
    from sshrt.ca.identity_parser import sha256_fingerprint

    _ensure_unix_account(container, username)
    priv = f'/home/{username}/.ssh/id_ed25519'
    pub  = f'{priv}.pub'
    comment = f'{username}@{container}'

    if _is_alpine(container):
        db_path = f'/home/{username}/.ssh/id_ed25519.dropbear'
        lxc_exec(container, 'su', '-', username, '-c',
                 f'rm -f {priv} {pub} {db_path}; '
                 f'dropbearkey -t ed25519 -f {db_path} >/dev/null; '
                 f'dropbearconvert dropbear openssh {db_path} {priv} '
                 f'>/dev/null 2>&1; chmod 600 {priv}; '
                 f'dropbearkey -y -f {db_path} | grep "^ssh-" '
                 f'| sed "s| dropbear@.*$| {comment}|" > {pub}; '
                 f'chmod 644 {pub}',
                 timeout=30)
    else:
        lxc_exec(container, 'su', '-', username, '-c',
                 f'rm -f {priv} {pub}; '
                 f'ssh-keygen -t ed25519 -f {priv} -N "" -C "{comment}"',
                 timeout=30)

    priv_host = artifacts_dir / username
    pub_host  = artifacts_dir / f'{username}.pub'
    for h, container_path in [(priv_host, priv), (pub_host, pub)]:
        if h.exists():
            h.unlink()
        subprocess.run(['lxc', 'file', 'pull',
                        f'{container}{container_path}', str(h)],
                       check=True, capture_output=True)
    os.chmod(priv_host, 0o600)

    pub_line = pub_host.read_text().strip()
    blob = base64.b64decode(pub_line.split()[1])
    return {
        'priv': str(priv_host),
        'pub_path': str(pub_host),
        'pub_line': pub_line,
        'blob': blob,
        'fingerprint': sha256_fingerprint(blob),
        'primary': container,
    }


def _provision_vanilla_sshd(server: _Server) -> None:
    """Make sure sshd is running on port 22 in ``server.container``.

    On Ubuntu containers openssh-server is installed and started during
    the deps step. On Alpine we install + enable openrc-style.
    """
    c = server.container
    if _is_alpine(c):
        lxc_exec(c, 'sh', '-c',
                 'rc-update add sshd default 2>/dev/null || true; '
                 'rc-service sshd start 2>/dev/null || true')
    else:
        lxc_exec(c, 'systemctl', 'enable', '--now', 'ssh', check=False)


def _push_authorized_keys(server: _Server,
                          user_keys: dict[str, dict]) -> None:
    """Concat the *allowed* users' pubkeys into each user's
    ~/.ssh/authorized_keys. The superuser's pubkey is appended to every
    user's authorized_keys (so the superuser can su-via-ssh to any user)
    AND added to /root/.ssh/authorized_keys (so the superuser can ssh
    in as root for admin config-push, modelling a real break-glass
    admin path).
    """
    superkey = user_keys[SUPERUSER.username]['pub_line']
    for u in USERS:
        if server.group not in u.allowed_groups:
            continue
        _ensure_unix_account(server.container, u.username)
        ak_lines = [user_keys[u.username]['pub_line']]
        if u.username != SUPERUSER.username:
            ak_lines.append(superkey)
        ak = '\n'.join(ak_lines) + '\n'
        push_text(server.container, ak,
                  f'/home/{u.username}/.ssh/authorized_keys', mode='600',
                  owner=f'{u.username}:{u.username}')
    # Superuser bypass: ssh root@server with their key works on every
    # box. This is how an operator would drive the flip scripts.
    lxc_exec(server.container, 'mkdir', '-p', '/root/.ssh')
    lxc_exec(server.container, 'chmod', '700', '/root/.ssh')
    push_text(server.container, superkey + '\n',
              '/root/.ssh/authorized_keys', mode='600', owner='root:root')


# ---------------------------------------------------------------------------
# Phase 1 / Phase 2 — msshd provisioning
# ---------------------------------------------------------------------------

def _ssh_pubkey_blob_from_ed25519(pubkey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    raw = pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    name = b'ssh-ed25519'
    return (struct.pack('>I', len(name)) + name
            + struct.pack('>I', len(raw)) + raw)


def _gen_user_ca_and_mtls_certs(out_dir: Path, *,
                                wrapper_host_sans: dict[str, str],
                                user_principals: list[str]) -> dict:
    """Generate a fresh Ed25519 user-CA and use it to sign:

      - one wrapper TLS server cert per container (CN/SAN = container IP)
      - one mTLS client cert per principal in ``user_principals``

    Returns paths + the ssh-ed25519 pubkey blob for each user (needed
    when enrolling the user at the CA).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    out_dir.mkdir(parents=True, exist_ok=True)
    user_ca_key = ed25519.Ed25519PrivateKey.generate()
    user_ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'mssh-adhoc-user-ca')])
    user_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(user_ca_name).issuer_name(user_ca_name)
        .public_key(user_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(minutes=5))
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .sign(user_ca_key, None))
    (out_dir / 'user-ca.crt').write_bytes(
        user_ca_cert.public_bytes(serialization.Encoding.PEM))

    # Wrapper TLS server cert per container (SAN = container's IP).
    wrapper_certs = {}
    for container, ip in wrapper_host_sans.items():
        ws_key = ed25519.Ed25519PrivateKey.generate()
        ws_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, ip)]))
            .issuer_name(user_ca_name)
            .public_key(ws_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(minutes=5))
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(_ipaddr(ip)),
                     x509.DNSName('localhost')]),
                critical=False)
            .sign(user_ca_key, None))
        cp = out_dir / f'wrapper-{container}.crt'
        kp = out_dir / f'wrapper-{container}.key'
        cp.write_bytes(ws_cert.public_bytes(serialization.Encoding.PEM))
        kp.write_bytes(ws_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
        os.chmod(kp, 0o600)
        wrapper_certs[container] = {'cert': str(cp), 'key': str(kp)}

    # Per-user mTLS client certs.
    clients = {}
    for principal in user_principals:
        ck = ed25519.Ed25519PrivateKey.generate()
        cc = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, principal)]))
            .issuer_name(user_ca_name)
            .public_key(ck.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(minutes=5))
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=30))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                           critical=False)
            .sign(user_ca_key, None))
        cert_path = out_dir / f'{principal}.crt'
        key_path  = out_dir / f'{principal}.key'
        cert_path.write_bytes(cc.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(ck.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
        clients[principal] = {
            'cert': str(cert_path), 'key': str(key_path),
            'ssh_pubkey_blob': _ssh_pubkey_blob_from_ed25519(ck.public_key()),
        }
    return {'user_ca_path': str(out_dir / 'user-ca.crt'),
            'wrapper_certs': wrapper_certs, 'clients': clients}


def _ipaddr(s):
    import ipaddress
    return ipaddress.ip_address(s)


def _gen_wrapper_user_ca(out_dir: Path) -> tuple[Path, Path]:
    """Local wrapper user-CA — signs the ephemeral OpenSSH user certs
    that msshd hands to the inner sshd."""
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = out_dir / 'wrapper-user-ca'
    pub  = out_dir / 'wrapper-user-ca.pub'
    for p in (priv, pub):
        if p.exists():
            p.unlink()
    subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '',
                    '-f', str(priv), '-q'],
                   check=True, capture_output=True)
    return priv, pub


# ---- wrapper.yaml renderers -------------------------------------------------

def _wrapper_yaml_fallback() -> str:
    return (
        'mode: fallback\n'
        f'fallback:\n'
        f'  host: 127.0.0.1\n'
        f'  port: {VANILLA_SSHD_PORT}\n'
        f'listen:\n'
        f'  external_address: 0.0.0.0\n'
        f'  external_port: {MSSHD_PORT}\n'
        f'  interfaces: []\n'
        f'logging:\n'
        f'  level: info\n'
        f'  destination: stderr\n'
        f'  audit_destination: file:/var/log/ssh-rt-auth/wrapper-audit.jsonl\n'
    )


def _wrapper_yaml_enforce(ca_ip: str) -> str:
    return (
        'mode: enforce\n'
        f'listen:\n'
        f'  external_address: 0.0.0.0\n'
        f'  external_port: {MSSHD_PORT}\n'
        f'  interfaces: []\n'
        f'tls:\n'
        f'  server_cert: /etc/ssh-rt-auth/wrapper-server.crt\n'
        f'  server_key:  /etc/ssh-rt-auth/wrapper-server.key\n'
        f'  user_ca_pubkey: /etc/ssh-rt-auth/user-ca.pub\n'
        f'ca:\n'
        f'  endpoints: [https://{ca_ip}:{CA_PORT}]\n'
        f'  client_cert: /etc/ssh-rt-auth/wrapper-mtls.crt\n'
        f'  client_key:  /etc/ssh-rt-auth/wrapper-mtls.key\n'
        f'  ca_pubkey:   /etc/ssh-rt-auth/server-mtls-ca.pub\n'
        f'  timeout_seconds: 5\n'
        f'inner:\n'
        f'  sshd_binary: /usr/sbin/sshd\n'
        f'  port_range: [49152, 65535]\n'
        f'users:\n'
        f'  allowed: ["*"]\n'
        f'logging:\n'
        f'  level: info\n'
        f'  destination: stderr\n'
        f'  audit_destination: file:/var/log/ssh-rt-auth/wrapper-audit.jsonl\n'
    )


def _systemd_msshd_unit() -> str:
    return (
        '[Unit]\nDescription=ssh-rt-auth wrapper (msshd)\n'
        'After=network-online.target\n'
        '[Service]\nWorkingDirectory=/app\n'
        'Environment="PYTHONPATH=/app/src"\n'
        'Environment="SSH_RT_AUTH_WRAPPER_STATE_DIR=/var/lib/ssh-rt-auth"\n'
        'ExecStart=/usr/bin/python3 -m sshrt.msshd '
        '--config /etc/ssh-rt-auth/wrapper.yaml\n'
        'Restart=on-failure\nStandardError=journal\n'
        '[Install]\nWantedBy=multi-user.target\n'
    )


def _install_msshd(c: str, *, mode: str,
                   ca_ip: str | None = None) -> None:
    """Install msshd in the given mode and (re)start it. ``mode`` ∈
    {'fallback', 'enforce'}. On Alpine we use a nohup-style spawn
    because openrc init scripts for arbitrary Python daemons are messy.
    """
    yaml = (_wrapper_yaml_fallback() if mode == 'fallback'
            else _wrapper_yaml_enforce(ca_ip))
    lxc_exec(c, 'mkdir', '-p',
             '/etc/ssh-rt-auth',
             '/var/lib/ssh-rt-auth',
             '/var/lib/ssh-rt-auth/inner-sshd',
             '/var/log/ssh-rt-auth')
    push_text(c, yaml, '/etc/ssh-rt-auth/wrapper.yaml', mode='644')

    if _is_alpine(c):
        # Kill any prior instance, then nohup.
        lxc_exec(c, 'sh', '-c',
                 'fuser -k -9 {p}/tcp 2>/dev/null; sleep 1'.format(p=MSSHD_PORT),
                 check=False)
        lxc_exec(c, 'sh', '-c',
                 'cd /app && PYTHONPATH=/app/src '
                 'SSH_RT_AUTH_WRAPPER_STATE_DIR=/var/lib/ssh-rt-auth '
                 'nohup /usr/bin/python3 -m sshrt.msshd '
                 '--config /etc/ssh-rt-auth/wrapper.yaml '
                 '> /var/log/ssh-rt-auth/msshd.log 2>&1 & '
                 'echo $! > /run/msshd.pid')
    else:
        push_text(c, _systemd_msshd_unit(),
                  '/etc/systemd/system/msshd.service')
        lxc_exec(c, 'systemctl', 'daemon-reload')
        lxc_exec(c, 'systemctl', 'restart', 'msshd')

    try:
        wait_for_port(c, MSSHD_PORT, max_wait=30)
    except Exception:
        if _is_alpine(c):
            log = lxc_exec(c, 'cat', '/var/log/ssh-rt-auth/msshd.log',
                           check=False)
            print(f'--- msshd log on {c} ---\n{log.stdout or ""}',
                  file=sys.stderr)
        else:
            log = lxc_exec(c, 'journalctl', '-u', 'msshd', '--no-pager',
                           '-n', '100', check=False)
            print(f'--- msshd journal on {c} ---\n{log.stdout or ""}',
                  file=sys.stderr)
        raise


def _push_msshd_cert_material(server: _Server, *,
                              wrapper_cert: str, wrapper_key: str,
                              user_ca_pub: str,
                              wrapper_mtls_cert: Path, wrapper_mtls_key: Path,
                              ca_tls_root: Path,
                              wrapper_user_ca_priv: Path,
                              wrapper_user_ca_pub: Path) -> None:
    """Push the cert material needed by enforce mode. Safe to push
    even when in fallback mode (msshd ignores it)."""
    c = server.container
    lxc_exec(c, 'mkdir', '-p',
             '/etc/ssh-rt-auth',
             '/var/lib/ssh-rt-auth',
             '/var/lib/ssh-rt-auth/inner-sshd')
    push_file(c, wrapper_cert, '/etc/ssh-rt-auth/wrapper-server.crt', mode='644')
    push_file(c, wrapper_key,  '/etc/ssh-rt-auth/wrapper-server.key', mode='600')
    push_file(c, user_ca_pub,  '/etc/ssh-rt-auth/user-ca.pub', mode='644')
    push_file(c, wrapper_mtls_cert, '/etc/ssh-rt-auth/wrapper-mtls.crt', mode='644')
    push_file(c, wrapper_mtls_key,  '/etc/ssh-rt-auth/wrapper-mtls.key', mode='600')
    push_file(c, ca_tls_root, '/etc/ssh-rt-auth/server-mtls-ca.pub', mode='644')
    push_file(c, str(wrapper_user_ca_priv),
              '/var/lib/ssh-rt-auth/wrapper-user-ca', mode='600')
    push_file(c, str(wrapper_user_ca_pub),
              '/var/lib/ssh-rt-auth/inner-sshd/wrapper-user-ca.pub', mode='644')


# ---------------------------------------------------------------------------
# In-container mssh shim — a 3-line shell wrapper around `python3 -m sshrt.mssh`
# ---------------------------------------------------------------------------

_MSSH_WRAPPER_SCRIPT = '''#!/bin/sh
# /usr/local/bin/mssh — invokes the Python mssh client with the
# in-tree source code (no pip install required inside the container).
# Looks for ~/.mssh/{cert,key,ca}.pem; pass them via env to mssh.
exec env \\
    MSSH_CERT="${MSSH_CERT:-$HOME/.mssh/cert.pem}" \\
    MSSH_KEY="${MSSH_KEY:-$HOME/.mssh/key.pem}" \\
    MSSH_CA="${MSSH_CA:-$HOME/.mssh/ca.pem}" \\
    PYTHONPATH=/app/src \\
    /usr/bin/python3 -m sshrt.mssh "$@"
'''


def _push_mssh_per_user(server: _Server, user: _User, pki: dict) -> None:
    """Drop per-user mssh material into /home/<user>/.mssh/."""
    c = server.container
    _ensure_unix_account(c, user.username)
    home_mssh = f'/home/{user.username}/.mssh'
    lxc_exec(c, 'sh', '-c',
             f'mkdir -p {home_mssh} && chmod 700 {home_mssh} && '
             f'chown -R {user.username}:{user.username} {home_mssh}')
    push_file(c, pki['clients'][user.username]['cert'],
              f'{home_mssh}/cert.pem', mode='600',
              owner=f'{user.username}:{user.username}')
    push_file(c, pki['clients'][user.username]['key'],
              f'{home_mssh}/key.pem', mode='600',
              owner=f'{user.username}:{user.username}')
    push_file(c, pki['user_ca_path'],
              f'{home_mssh}/ca.pem', mode='644',
              owner=f'{user.username}:{user.username}')


def _install_mssh_wrapper(c: str) -> None:
    push_text(c, _MSSH_WRAPPER_SCRIPT, '/usr/local/bin/mssh',
              mode='755')


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _verify_ssh(*, from_container: str, key_path: str, user: str,
                target_ip: str, target_port: int,
                expected_substr: str | None = None,
                expect_ok: bool = True) -> None:
    """Run a `whoami` over SSH and assert the outcome. ``from_container``
    is where the ssh binary runs; the keypair has been pushed there
    earlier as part of provisioning."""
    cmd = [
        'ssh', '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=10',
        '-i', key_path, '-p', str(target_port),
        f'{user}@{target_ip}', 'whoami',
    ]
    r = lxc_exec(from_container, *cmd, check=False, timeout=30)
    if expect_ok:
        assert r.returncode == 0, (
            f'ssh from {from_container} as {user}@{target_ip}:{target_port} '
            f'failed: rc={r.returncode} stdout={r.stdout!r} '
            f'stderr={r.stderr!r}')
        if expected_substr is not None:
            assert expected_substr in (r.stdout or ''), (
                f'expected {expected_substr!r} in stdout, got {r.stdout!r}')
    else:
        assert r.returncode != 0, (
            f'ssh from {from_container} as {user}@{target_ip}:{target_port} '
            f'unexpectedly succeeded: stdout={r.stdout!r}')


def _verify_mssh(*, from_container: str, user: str,
                 target_ip: str, target_port: int) -> None:
    """Run `mssh user@target:port -- whoami` from ``from_container`` (as
    root, using the user's mTLS material). Asserts success and that
    the remote whoami matches ``user``."""
    cmd = (
        f'MSSH_CERT=/home/{user}/.mssh/cert.pem '
        f'MSSH_KEY=/home/{user}/.mssh/key.pem '
        f'MSSH_CA=/home/{user}/.mssh/ca.pem '
        f'PYTHONPATH=/app/src '
        f'/usr/bin/python3 -m sshrt.mssh '
        f'{user}@{target_ip}:{target_port} -- whoami'
    )
    r = lxc_exec(from_container, 'sh', '-c', cmd, check=False, timeout=30)
    assert r.returncode == 0, (
        f'mssh from {from_container} as {user}@{target_ip}:{target_port} '
        f'failed: rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r}')
    assert user in (r.stdout or ''), (
        f'expected {user!r} in mssh stdout, got {r.stdout!r}')


# ---------------------------------------------------------------------------
# adhoc-env artifact writers
# ---------------------------------------------------------------------------

def _write_cleanup_script(path: Path) -> None:
    path.write_text(
        '#!/usr/bin/env bash\n'
        '# Delete every container provisioned by the msshd adhoc lab.\n'
        'set -u\n'
        'for c in ' + ' '.join(ALL_CONTAINERS) + '; do\n'
        '    echo "deleting $c"\n'
        '    lxc delete --force "$c" 2>/dev/null || true\n'
        'done\n')
    path.chmod(0o755)


def _msshd_restart_cmd(server: _Server) -> str:
    """Per-container shell snippet to restart msshd in-place."""
    if _is_alpine(server.container):
        return (
            f'fuser -k -9 {MSSHD_PORT}/tcp 2>/dev/null; sleep 1; '
            f'cd /app && PYTHONPATH=/app/src '
            f'SSH_RT_AUTH_WRAPPER_STATE_DIR=/var/lib/ssh-rt-auth '
            f'nohup /usr/bin/python3 -m sshrt.msshd '
            f'--config /etc/ssh-rt-auth/wrapper.yaml '
            f'> /var/log/ssh-rt-auth/msshd.log 2>&1 & '
            f'echo $! > /run/msshd.pid'
        )
    return 'systemctl restart msshd'


def _flip_script(target_mode: str, yaml: str, ips: dict,
                 ca_ip: str) -> str:
    """Render a self-contained flip script that runs on the CA container.

    Uses ssh root@<server> (root-admin's pubkey is in /root/authorized_keys
    on every server) for the config-push step; verifies the new mode using
    the transport that mode expects (mssh for enforce, ssh -p MSSHD_PORT
    for fallback); reverts on verification failure.

    Models an actual operator workflow — no `lxc exec` anywhere.
    """
    verify_cmd, verify_desc = ({
        'enforce':  ('mssh root-admin@$ip:$MSSHD_PORT -- whoami',
                     'mssh ↔ msshd (mTLS + CA-mediated)'),
        'fallback': ('ssh $SSH_N -p $MSSHD_PORT root-admin@$ip whoami',
                     'ssh -p ${MSSHD_PORT} (proxied via msshd to inner sshd)'),
    })[target_mode]

    rows = []
    for s in SERVERS:
        rows.append(f'{s.canonical}|{ips[s.container]}|{_msshd_restart_cmd(s)}')
    server_table = '\n'.join(rows)

    return f'''#!/bin/sh
# /home/root-admin/flip-to-{target_mode}.sh
#
# Operator-grade flip script. Runs on the CA container as root-admin.
# For each server: backs up the current wrapper.yaml, pushes the
# {target_mode}-mode config, restarts msshd, verifies via
# {verify_desc}, and reverts on failure.
#
# No `lxc exec` — only ssh (config push via the root@<server> backdoor
# that root-admin's pubkey was added to during lab setup) and mssh
# (post-flip verification when target=enforce).

set -u

SSH_KEY=/home/root-admin/.ssh/id_ed25519
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no \\
    -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10"
# -n on every ssh that doesn't consume stdin — otherwise ssh swallows
# the pipe feeding our `while read` loop and we only process one server.
SSH_N="$SSH_OPTS -n"
MSSHD_PORT={MSSHD_PORT}
CA_IP={ca_ip}

export MSSH_CERT=/home/root-admin/.mssh/cert.pem
export MSSH_KEY=/home/root-admin/.mssh/key.pem
export MSSH_CA=/home/root-admin/.mssh/ca.pem

# Heredoc would interfere with shell substitution; write the YAML to
# a temp file and scp/cat it across.
WRAPPER_YAML=$(cat <<'YAML'
{yaml}YAML
)

flip_one() {{
    name="$1"; ip="$2"; restart="$3"
    printf '%-12s (%s) ... ' "$name" "$ip"

    # Backup, push new, restart.
    if ! ssh $SSH_N root@$ip \\
            'cp /etc/ssh-rt-auth/wrapper.yaml /tmp/wrapper.yaml.bak' \\
            2>/dev/null; then
        echo "SSH UNREACHABLE — skipped"
        return 1
    fi
    printf '%s' "$WRAPPER_YAML" | ssh $SSH_OPTS root@$ip \\
        'cat > /etc/ssh-rt-auth/wrapper.yaml'
    ssh $SSH_N root@$ip "$restart" >/dev/null 2>&1
    sleep 3

    # Verify with the post-flip transport.
    if {verify_cmd} 2>/dev/null | grep -q '^root-admin$'; then
        echo "OK ({target_mode})"
        return 0
    fi
    # Verify failed: revert.
    echo "FAILED — reverting"
    ssh $SSH_N root@$ip \\
        'cp /tmp/wrapper.yaml.bak /etc/ssh-rt-auth/wrapper.yaml' \\
        2>/dev/null
    ssh $SSH_N root@$ip "$restart" >/dev/null 2>&1
    return 1
}}

SERVERS_TABLE='{server_table}'

echo "Flipping all servers to mode={target_mode}..."
echo "$SERVERS_TABLE" | while IFS='|' read -r name ip restart; do
    [ -z "$name" ] && continue
    # </dev/null protects the loop's pipe from being consumed by any
    # ssh/mssh inside flip_one (mssh forwards stdin to the remote PTY).
    flip_one "$name" "$ip" "$restart" </dev/null || true
done

echo
echo "Done. Verify a session by running, e.g.:"
echo "  mssh alice@$(echo \"$SERVERS_TABLE\" | head -1 | cut -d'|' -f2):$MSSHD_PORT -- whoami"
'''


def _push_flip_scripts_to_ca(ips: dict, ca_ip: str) -> None:
    """Generate the two flip scripts and push them to /home/root-admin/
    on the CA container."""
    enforce_yaml  = _wrapper_yaml_enforce(ca_ip)
    fallback_yaml = _wrapper_yaml_fallback()
    for target_mode, yaml in (('enforce', enforce_yaml),
                              ('fallback', fallback_yaml)):
        script = _flip_script(target_mode, yaml, ips, ca_ip)
        push_text(CA_NAME, script,
                  f'/home/root-admin/flip-to-{target_mode}.sh',
                  mode='755',
                  owner=f'{SUPERUSER.username}:{SUPERUSER.username}')


def _write_overview_md(path: Path, *, ips: dict, artifacts_dir: Path) -> None:
    user_lines = []
    for u in USERS:
        allowed = _allowed_servers_for(u)
        allowed_str = ', '.join(s.canonical.replace('srv-', '')
                                for s in allowed) or '(none)'
        user_lines.append(
            f'| {u.username} | {u.department} | {allowed_str} |')
    server_lines = '\n'.join(
        f'| {s.canonical.replace("srv-", "")} | {s.canonical} | '
        f'{s.group} | {ips[s.container]} |'
        for s in SERVERS)
    path.write_text(f'''# mssh adhoc lab — what you've got

5 machines: 4 SSH servers (acct, sales, hr, eng) + 1 CA. All driven
**from the host** via ssh/mssh — you don't need to know or care that
they're LXC containers underneath.

## One-liner setup

```bash
source ./adhoc-env.sh
```

That exports every IP, every key path, and a few helper functions
(`mssh_as`, `ssh_as`, `ssh_as_2200`, `flip_to_enforce`,
`flip_to_fallback`). Everything below assumes you've sourced it.

## Servers

| short | canonical | group | IP |
|---|---|---|---|
{server_lines}
| ca | — | — | {ips[CA_NAME]} |

## Users

| user | department | allowed servers |
|---|---|---|
{chr(10).join(user_lines)}

`root-admin` is the superuser — has access everywhere via CA policy,
and their SSH key is in every other user's `authorized_keys` plus
`/root/.ssh/authorized_keys` on every server (the break-glass admin
path the flip scripts use).

## Trying things — host commands only

The lab leaves you in **Phase 2 (enforce)** mode. mssh goes through
msshd → CA → inner sshd. Three transports are available:

```bash
# Phase 2: mssh as alice, talking to msshd-enforce on port 2200
mssh_as alice acct whoami            # OK (alice's policy grants accounting)
mssh_as alice sales whoami           # denied — out-of-policy
mssh_as root-admin sales whoami      # OK (superuser policy grants everything)

# Phase 0: plain ssh to vanilla sshd on port 22. Always works,
# bypasses msshd entirely. Useful as your backdoor.
ssh_as alice acct                    # interactive shell
ssh_as alice acct whoami             # one-shot

# Phase 1: ssh through msshd-fallback on port 2200. Only works after
# `flip_to_fallback` has been run.
flip_to_fallback                     # all 4 servers → fallback mode
ssh_as_2200 alice acct whoami        # ssh transparently proxied via msshd
flip_to_enforce                      # back to Phase 2
```

## Flipping modes — operator workflow

`flip_to_enforce` and `flip_to_fallback` are shell functions that
ssh to the CA as `root-admin` and run the actual flip scripts
(`/home/root-admin/flip-to-{{enforce,fallback}}.sh` on the CA). The
scripts loop over every server, push the new `wrapper.yaml`,
restart msshd, verify via the post-flip transport (mssh for enforce,
ssh -p 2200 for fallback), and revert that server's config if
verification fails.

No `lxc exec` anywhere — it's the same workflow a real operator
would use against an internet-routable CA.

## Per-user material (on the host)

```
adhoc-keys/
├── <user>                   # SSH Ed25519 private key      → $ALICE_KEY
├── <user>.pub               # SSH public key (Phase 0/1)
├── <user>.crt               # X.509 mTLS client cert (Phase 2) → $ALICE_CRT
├── <user>.key               # X.509 mTLS client key           → $ALICE_KEYPEM
└── user-ca.crt              # mTLS trust root                 → $USER_CA
```

Every per-user env var follows the same shape: `$ALICE_KEY`,
`$BOB_CRT`, `$ROOT_ADMIN_KEYPEM`, etc.

## Cleanup

```bash
./cleanup_containers.sh
```

## Advanced — when you actually want to be inside a container

You don't normally need this, but for debugging it's useful:

```bash
lxc exec {ACCT_NAME} -- su - alice    # interactive shell as alice in acct
lxc exec {CA_NAME}   -- cat /var/log/ssh-rt-auth/audit.jsonl
lxc exec {CA_NAME}   -- journalctl -u ssh-rt-auth-ca --no-pager -n 50
```

The full container names are `{CA_NAME}`, `{ACCT_NAME}`,
`{SALES_NAME}`, `{HR_NAME}`, `{ENG_NAME}`.
''')


def _write_env_sh(path: Path, *, ips: dict, artifacts_dir: Path) -> None:
    """adhoc-env.sh — source from the host. Exposes IPs, ports, key
    paths, and helper functions so the operator can act as any user
    via host-side ssh/mssh, with `lxc exec` nowhere in sight.
    """
    # Host-side mssh: invoke the in-tree module directly so we don't
    # depend on the venv's `mssh` entry-point shim being current.
    # app_root/python/src is the canonical PYTHONPATH for the
    # checked-out source tree.
    src_dir = Path(__file__).resolve().parent.parent.parent / 'src'
    # Server name → IP. Use short names (acct, sales, hr, eng, ca).
    server_env = []
    for s in SERVERS:
        short = s.canonical.replace('srv-', '')
        server_env.append(f'export {short}_IP={ips[s.container]}')
    server_env.append(f'export ca_IP={ips[CA_NAME]}')

    # User → key paths.
    user_env = []
    for u in USERS:
        n = u.username.upper().replace('-', '_')
        user_env += [
            f'export {n}_KEY={artifacts_dir}/{u.username}',
            f'export {n}_PUB={artifacts_dir}/{u.username}.pub',
            f'export {n}_CRT={artifacts_dir}/{u.username}.crt',
            f'export {n}_KEYPEM={artifacts_dir}/{u.username}.key',
        ]

    body = f'''# Source me from the directory that contains adhoc-keys/.
# Lets you run ssh/mssh as any user directly from the host — no
# `lxc exec` required. The lab containers are addressable by their
# bridged IPs (exposed below).

export USER_CA={artifacts_dir}/user-ca.crt
export MSSHD_PORT={MSSHD_PORT}
export SSHD_PORT={VANILLA_SSHD_PORT}
# Where to find the mssh Python module (host-side invocations).
export MSSH_SRC_DIR={src_dir}

# Server short-name → IP
{chr(10).join(server_env)}

# Per-user identity material
{chr(10).join(user_env)}

# ---- Helper functions ------------------------------------------------------
#
# Usage in all three forms:
#   mssh_as     <user> <server> [cmd...]   # Phase 2: mssh → msshd → CA → inner sshd
#   ssh_as      <user> <server> [cmd...]   # Phase 0: ssh → vanilla sshd on 22 (always works)
#   ssh_as_2200 <user> <server> [cmd...]   # Phase 1: ssh → msshd-fallback → sshd on 22
#
# <server> is the short name: acct | sales | hr | eng | ca
# <user> is any USERS entry: alice amy bob bart carol charlie dave diana root-admin
# Run with no [cmd] to land in an interactive shell.

_resolve_ip() {{
    local short="$1"
    eval "echo \\"\\${{${{short}}_IP:-}}\\""
}}

_user_envvar() {{
    # Helpers accept either form: root-admin or root_admin. The env
    # var is always uppercase-underscore (ROOT_ADMIN_*); the Unix
    # account / SSH login name is always lowercase-hyphen (root-admin).
    echo "$1" | tr 'a-z-' 'A-Z_'
}}

_user_unix_name() {{
    echo "$1" | tr '_' '-'
}}

# -o IdentitiesOnly=yes ensures ssh offers ONLY the -i key, not
# every key in the agent — otherwise the server hits MaxAuthTries
# and disconnects before our key gets tried.
_SSH_OPTS='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes'

mssh_as() {{
    local user="$1" server="$2"; shift 2
    local ip; ip=$(_resolve_ip "$server")
    if [ -z "$ip" ]; then
        echo "unknown server: $server (try acct/sales/hr/eng/ca)" >&2
        return 1
    fi
    local U unix
    U=$(_user_envvar "$user"); unix=$(_user_unix_name "$user")
    local cert key
    eval "cert=\\$${{U}}_CRT"
    eval "key=\\$${{U}}_KEYPEM"
    if [ "$#" -eq 0 ]; then
        MSSH_CERT="$cert" MSSH_KEY="$key" MSSH_CA="$USER_CA" \\
            PYTHONPATH="$MSSH_SRC_DIR" \\
            python3 -m sshrt.mssh "$unix@$ip:$MSSHD_PORT"
    else
        MSSH_CERT="$cert" MSSH_KEY="$key" MSSH_CA="$USER_CA" \\
            PYTHONPATH="$MSSH_SRC_DIR" \\
            python3 -m sshrt.mssh "$unix@$ip:$MSSHD_PORT" -- "$@"
    fi
}}

ssh_as() {{
    local user="$1" server="$2"; shift 2
    local ip; ip=$(_resolve_ip "$server")
    if [ -z "$ip" ]; then
        echo "unknown server: $server" >&2
        return 1
    fi
    local U unix
    U=$(_user_envvar "$user"); unix=$(_user_unix_name "$user")
    local key; eval "key=\\$${{U}}_KEY"
    ssh -i "$key" $_SSH_OPTS -p $SSHD_PORT "$unix@$ip" "$@"
}}

ssh_as_2200() {{
    local user="$1" server="$2"; shift 2
    local ip; ip=$(_resolve_ip "$server")
    if [ -z "$ip" ]; then
        echo "unknown server: $server" >&2
        return 1
    fi
    local U unix
    U=$(_user_envvar "$user"); unix=$(_user_unix_name "$user")
    local key; eval "key=\\$${{U}}_KEY"
    ssh -i "$key" $_SSH_OPTS -p $MSSHD_PORT "$unix@$ip" "$@"
}}

# Convenience: flip the lab between modes from the host. The script
# itself lives on the CA container at /home/root-admin/; we just invoke
# it via the superuser's ssh key (no `lxc exec`).

flip_to_enforce() {{
    ssh -i "$ROOT_ADMIN_KEY" $_SSH_OPTS \\
        "root-admin@$ca_IP" ./flip-to-enforce.sh
}}

flip_to_fallback() {{
    ssh -i "$ROOT_ADMIN_KEY" $_SSH_OPTS \\
        "root-admin@$ca_IP" ./flip-to-fallback.sh
}}

echo "adhoc env loaded. Try:"
echo "  mssh_as alice acct whoami           # mssh through msshd (Phase 2)"
echo "  ssh_as alice acct whoami            # plain ssh (Phase 0, always works)"
echo "  flip_to_fallback                    # all servers → msshd fallback mode"
echo "  flip_to_enforce                     # all servers → msshd enforce mode (default)"
'''
    path.write_text(body)


# ---------------------------------------------------------------------------
# The test
# ---------------------------------------------------------------------------

def test_setup_adhoc_msshd_journey(request, tmp_path_factory):
    invocation_cwd = Path(os.getcwd()).resolve()
    artifacts_dir  = invocation_cwd / 'adhoc-keys'
    artifacts_dir.mkdir(exist_ok=True)
    ca_creds_dir   = invocation_cwd / 'adhoc-ca-creds'
    ca_creds_dir.mkdir(exist_ok=True)

    banner('msshd adhoc lab — Phase 0 → 1 → 2')

    # ---- 0. Tear down + launch fresh -----------------------------------
    section('Deleting any pre-existing adhoc containers')
    for c in ALL_CONTAINERS:
        subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)

    section('Launching containers')
    for s in SERVERS:
        lxc('launch', s.image, s.container,
            '--config', 'security.privileged=true', timeout=300)
    lxc('launch', UBUNTU_IMAGE, CA_NAME,
        '--config', 'security.privileged=true', timeout=300)

    ips = {c: get_ip(c) for c in ALL_CONTAINERS}
    section('Container IPs')
    for c, ip in ips.items():
        print(f'  {c:24s} {ip}', file=sys.stderr, flush=True)

    # ---- 1. Install deps + push source --------------------------------
    app_root = Path(__file__).resolve().parent.parent.parent.parent
    ubuntu_pkgs = ['python3', 'python3-cryptography', 'python3-flask',
                   'python3-yaml', 'python3-click', 'python3-requests',
                   'python3-asyncssh', 'openssh-server', 'openssh-client']
    alpine_pkgs = ['python3', 'py3-cryptography', 'py3-flask', 'py3-yaml',
                   'py3-click', 'py3-requests', 'py3-asyncssh',
                   'openssh', 'openssh-server',
                   'dropbear', 'dropbear-convert', 'dropbear-dbclient']

    section('Installing deps (Ubuntu)')
    for c in [CA_NAME, ACCT_NAME, SALES_NAME, HR_NAME]:
        print(f'  {c}', file=sys.stderr, flush=True)
        wait_for_apt_quiescent(c, max_wait=120)
        lxc_exec(c, 'apt-get', 'update', '-q', timeout=180)
        lxc_exec(c, 'apt-get', 'install', '-y', '-q',
                 '--no-install-recommends', *ubuntu_pkgs, timeout=600)
        lxc_exec(c, 'apt-get', 'clean')
        push_source(c, app_root)

    section('Installing deps (Alpine)')
    lxc_exec(ENG_NAME, 'apk', 'add', '--no-cache', *alpine_pkgs, timeout=600)
    push_source(ENG_NAME, app_root)

    # ---- 2. Bootstrap CA (Phase 2 prerequisite; harmless in Phase 0/1) -
    section('Bootstrapping CA')
    lxc_exec(CA_NAME, 'sh', '-c',
             'PYTHONPATH=/app/src python3 -c "'
             'from sshrt.ca.cert_minter import bootstrap_ca; '
             f"bootstrap_ca('/etc/ssh-rt-auth/ca', "
             f"tls_server_sans=['DNS:localhost','IP:127.0.0.1',"
             f"'IP:{ips[CA_NAME]}'])\"", timeout=120)
    lxc_exec(CA_NAME, 'sh', '-c',
             'python3 -c "import yaml; '
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

    # Pull admin creds + build a CAClient for enrollment.
    for n in ('bootstrap-admin-cert.pem', 'bootstrap-admin-key.pem',
              'tls-ca-cert.pem', 'signing-cert.pem'):
        subprocess.run(['lxc', 'file', 'pull',
                        f'{CA_NAME}/etc/ssh-rt-auth/ca/{n}',
                        str(ca_creds_dir / n)],
                       check=True, capture_output=True)
    os.chmod(ca_creds_dir / 'bootstrap-admin-key.pem', 0o600)
    from sshrt.admin.client import CAClient
    admin = CAClient(
        base_url=f'https://{ips[CA_NAME]}:{CA_PORT}',
        admin_cert=str(ca_creds_dir / 'bootstrap-admin-cert.pem'),
        admin_key=str(ca_creds_dir / 'bootstrap-admin-key.pem'),
        ca_cert=str(ca_creds_dir / 'tls-ca-cert.pem'))

    # =====================================================================
    # Phase 0 — vanilla sshd + ssh keypairs + authorized_keys
    # =====================================================================
    section('PHASE 0: provisioning vanilla sshd on every server')
    for s in SERVERS:
        _provision_vanilla_sshd(s)
        try:
            wait_for_port(s.container, VANILLA_SSHD_PORT, max_wait=30)
        except Exception:
            print(f'  warning: sshd port {VANILLA_SSHD_PORT} not ready on '
                  f'{s.container} — continuing', file=sys.stderr)

    section('PHASE 0: keygen per user (in their primary container)')
    user_keys: dict[str, dict] = {}
    for u in USERS:
        primary = _primary_container_for(u)
        print(f'  {u.username} on {primary}', file=sys.stderr, flush=True)
        user_keys[u.username] = _keygen_in_container(
            primary, u.username, artifacts_dir)

    section('PHASE 0: distribute authorized_keys to every server')
    for s in SERVERS:
        _push_authorized_keys(s, user_keys)

    # Validate ssh from the CA host (it has openssh-client installed
    # and is the easiest "neutral" launchpad — not the user's primary).
    # We need to push the user's private key to the CA host first.
    section('PHASE 0 validation: ssh user@host:22 works')
    lxc_exec(CA_NAME, 'mkdir', '-p', '/root/.ssh')
    lxc_exec(CA_NAME, 'chmod', '700', '/root/.ssh')
    ca_keydir = '/root/adhoc-keys'
    lxc_exec(CA_NAME, 'mkdir', '-p', ca_keydir)
    for u in USERS:
        push_file(CA_NAME, str(artifacts_dir / u.username),
                  f'{ca_keydir}/{u.username}', mode='600')
    for u in USERS:
        for s in _allowed_servers_for(u):
            _verify_ssh(from_container=CA_NAME,
                        key_path=f'{ca_keydir}/{u.username}',
                        user=u.username, target_ip=ips[s.container],
                        target_port=VANILLA_SSHD_PORT,
                        expected_substr=u.username)
        print(f'  {u.username}: {len(_allowed_servers_for(u))} hosts OK',
              file=sys.stderr, flush=True)

    # =====================================================================
    # Phase 1 — msshd in fallback in front of sshd
    # =====================================================================
    section('PHASE 1: dropping msshd in fallback on every server')
    for s in SERVERS:
        _install_msshd(s.container, mode='fallback')

    section('PHASE 1 validation: ssh -p 2200 still works (proxied)')
    for u in USERS:
        for s in _allowed_servers_for(u):
            _verify_ssh(from_container=CA_NAME,
                        key_path=f'{ca_keydir}/{u.username}',
                        user=u.username, target_ip=ips[s.container],
                        target_port=MSSHD_PORT,
                        expected_substr=u.username)
        print(f'  {u.username}: ok through msshd:2200', file=sys.stderr,
              flush=True)

    # =====================================================================
    # Phase 2 — gen mTLS, enroll, flip msshd to enforce
    # =====================================================================
    section('PHASE 2: generating wrapper user-CA + per-user mTLS certs')
    pki_dir = tmp_path_factory.mktemp('msshd-pki')
    pki = _gen_user_ca_and_mtls_certs(
        pki_dir,
        wrapper_host_sans={s.container: ips[s.container] for s in SERVERS},
        user_principals=[u.username for u in USERS])
    # Wrapper user-CA (signs ephemeral OpenSSH inner certs).
    wrapper_user_ca_dir = tmp_path_factory.mktemp('wrapper-user-ca')
    w_ca_priv, w_ca_pub = _gen_wrapper_user_ca(wrapper_user_ca_dir)

    # Copy mTLS material into the host adhoc-keys/ dir for operator use.
    for u in USERS:
        for ext in ('crt', 'key'):
            shutil.copy(pki_dir / f'{u.username}.{ext}',
                        artifacts_dir / f'{u.username}.{ext}')
        os.chmod(artifacts_dir / f'{u.username}.key', 0o600)
    shutil.copy(pki_dir / 'user-ca.crt', artifacts_dir / 'user-ca.crt')

    section('PHASE 2: enrolling servers at the CA (mTLS creds for wrapper)')
    server_creds = {}
    for s in SERVERS:
        resp = admin.server_add(s.canonical, groups=[s.group])
        server_creds[s.canonical] = resp['credentials']
        (ca_creds_dir / f'{s.canonical}-mtls.crt').write_text(
            resp['credentials']['cert_pem'])
        (ca_creds_dir / f'{s.canonical}-mtls.key').write_text(
            resp['credentials']['key_pem'])
        os.chmod(ca_creds_dir / f'{s.canonical}-mtls.key', 0o600)

    section('PHASE 2: enrolling users + keys + policies at the CA')
    for u in USERS:
        admin.user_add(u.username)
        admin.user_key_add(u.username, 'pubkey',
                           base64.b64encode(
                               pki['clients'][u.username]['ssh_pubkey_blob']
                           ).decode('ascii'))
        admin.policy_add(u.username, {
            'server_groups': list(u.allowed_groups),
            'channels': ['session'],
            'max_cert_validity_seconds': 600,
        })

    section('PHASE 2: pushing wrapper cert material + flipping to enforce')
    for s in SERVERS:
        _push_msshd_cert_material(
            s,
            wrapper_cert=pki['wrapper_certs'][s.container]['cert'],
            wrapper_key=pki['wrapper_certs'][s.container]['key'],
            user_ca_pub=pki['user_ca_path'],
            wrapper_mtls_cert=ca_creds_dir / f'{s.canonical}-mtls.crt',
            wrapper_mtls_key=ca_creds_dir / f'{s.canonical}-mtls.key',
            ca_tls_root=ca_creds_dir / 'tls-ca-cert.pem',
            wrapper_user_ca_priv=w_ca_priv,
            wrapper_user_ca_pub=w_ca_pub)
        _install_msshd(s.container, mode='enforce', ca_ip=ips[CA_NAME])

    # CA host needs sshd + root-admin's authorized_keys so the host's
    # `flip_to_enforce`/`flip_to_fallback` helpers can ssh in.
    section('PHASE 2: enabling sshd on CA + root-admin authorized_keys')
    lxc_exec(CA_NAME, 'systemctl', 'enable', '--now', 'ssh', check=False)
    try:
        wait_for_port(CA_NAME, VANILLA_SSHD_PORT, max_wait=30)
    except Exception:
        print(f'  warning: CA sshd port {VANILLA_SSHD_PORT} not ready',
              file=sys.stderr, flush=True)
    _ensure_unix_account(CA_NAME, SUPERUSER.username)
    push_text(CA_NAME, user_keys[SUPERUSER.username]['pub_line'] + '\n',
              f'/home/{SUPERUSER.username}/.ssh/authorized_keys', mode='600',
              owner=f'{SUPERUSER.username}:{SUPERUSER.username}')

    section('PHASE 2: per-user mssh material + /usr/local/bin/mssh wrapper')
    for s in SERVERS:
        if not _is_alpine(s.container):
            _install_mssh_wrapper(s.container)
            for u in USERS:
                if s.group in u.allowed_groups:
                    _push_mssh_per_user(s, u, pki)
    # Also drop the superuser's material onto the CA host (their primary).
    _install_mssh_wrapper(CA_NAME)
    _push_mssh_per_user(SERVERS[0], SUPERUSER, pki)  # ensure account exists
    _ensure_unix_account(CA_NAME, SUPERUSER.username)
    home_mssh = f'/home/{SUPERUSER.username}/.mssh'
    lxc_exec(CA_NAME, 'sh', '-c',
             f'mkdir -p {home_mssh} && chmod 700 {home_mssh} && '
             f'chown -R {SUPERUSER.username}:{SUPERUSER.username} {home_mssh}')
    push_file(CA_NAME, pki['clients'][SUPERUSER.username]['cert'],
              f'{home_mssh}/cert.pem', mode='600',
              owner=f'{SUPERUSER.username}:{SUPERUSER.username}')
    push_file(CA_NAME, pki['clients'][SUPERUSER.username]['key'],
              f'{home_mssh}/key.pem', mode='600',
              owner=f'{SUPERUSER.username}:{SUPERUSER.username}')
    push_file(CA_NAME, pki['user_ca_path'],
              f'{home_mssh}/ca.pem', mode='644',
              owner=f'{SUPERUSER.username}:{SUPERUSER.username}')

    section('PHASE 2 validation: mssh user@host:2200 works')
    # Use the CA host as the "from" since it has Python deps + source.
    for u in USERS:
        for s in _allowed_servers_for(u):
            # Run mssh from the CA host using the user's mTLS material
            # pushed to that user's /home/<u>/.mssh on the CA host …
            # but only the superuser lives on CA_NAME. For others we
            # invoke mssh directly via env vars + host PKI material.
            cmd = (
                f'MSSH_CERT={pki_dir}/{u.username}.crt '
                f'MSSH_KEY={pki_dir}/{u.username}.key '
                f'MSSH_CA={pki_dir}/user-ca.crt '
                f'PYTHONPATH={app_root}/python/src '
                f'python3 -m sshrt.mssh '
                f'{u.username}@{ips[s.container]}:{MSSHD_PORT} -- whoami'
            )
            r = subprocess.run(['sh', '-c', cmd], capture_output=True,
                               text=True, timeout=30)
            assert r.returncode == 0, (
                f'mssh {u.username}@{s.canonical} failed: rc={r.returncode} '
                f'stdout={r.stdout!r} stderr={r.stderr!r}')
            assert u.username in r.stdout, (
                f'mssh {u.username}@{s.canonical}: expected username in '
                f'stdout, got {r.stdout!r}')
        print(f'  {u.username}: mssh OK on {len(_allowed_servers_for(u))} '
              f'host(s)', file=sys.stderr, flush=True)

    # =====================================================================
    # adhoc artifacts
    # =====================================================================
    section('Writing adhoc artifacts (cleanup, env, README)')
    _write_cleanup_script(invocation_cwd / 'cleanup_containers.sh')
    _write_env_sh(invocation_cwd / 'adhoc-env.sh',
                  ips=ips, artifacts_dir=artifacts_dir)
    _write_overview_md(invocation_cwd / 'ADHOC_TEST_ENV.md',
                       ips=ips, artifacts_dir=artifacts_dir)

    section('Pushing operator-grade flip scripts to /home/root-admin/ on CA')
    _push_flip_scripts_to_ca(ips, ips[CA_NAME])

    section('SUCCESS — msshd adhoc lab is up at Phase 2 (enforce)')
    print(
        f'\n  source ./adhoc-env.sh    # exports ips, ports, key paths\n'
        f'  cat ./ADHOC_TEST_ENV.md  # full overview + examples\n'
        f'\n  # Flip scripts live ON the CA container — operator workflow.\n'
        f'  # Drive them via lxc exec (no setup required) or by ssh-ing\n'
        f'  # to the CA first if you want the realistic experience.\n'
        f'\n  lxc exec {CA_NAME} -- su - root-admin -c ./flip-to-fallback.sh\n'
        f'  lxc exec {CA_NAME} -- su - root-admin -c ./flip-to-enforce.sh\n'
        f'\n  ./cleanup_containers.sh  # tear it all down\n',
        file=sys.stderr, flush=True)
