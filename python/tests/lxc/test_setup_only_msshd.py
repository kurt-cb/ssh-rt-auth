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
    user's authorized_keys (so the superuser can su-via-ssh to any user).
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


def _write_flip_scripts(out_dir: Path, ca_ip: str) -> None:
    fallback = out_dir / 'flip-to-fallback.sh'
    enforce  = out_dir / 'flip-to-enforce.sh'
    fallback.write_text(
        '#!/usr/bin/env bash\n'
        '# Push fallback-mode wrapper.yaml to every server and restart\n'
        '# msshd. After this, `ssh -p ' + str(MSSHD_PORT) + ' user@<ip>` works\n'
        '# (transparently proxied to in-container sshd on 22).\n'
        'set -eu\n'
        + ''.join(
            f'lxc exec {s.container} -- sh -c '
            f"'cat > /etc/ssh-rt-auth/wrapper.yaml' <<'YAML'\n"
            f'{_wrapper_yaml_fallback()}YAML\n'
            f'lxc exec {s.container} -- '
            + ('sh -c "fuser -k -9 ' + str(MSSHD_PORT) + '/tcp 2>/dev/null; '
               'sleep 1; cd /app && PYTHONPATH=/app/src nohup /usr/bin/python3 '
               '-m sshrt.msshd --config /etc/ssh-rt-auth/wrapper.yaml '
               '> /var/log/ssh-rt-auth/msshd.log 2>&1 & '
               'echo \\$! > /run/msshd.pid"\n'
               if s.container == ENG_NAME
               else 'systemctl restart msshd\n')
            for s in SERVERS
        )
        + 'echo "All servers in fallback mode."\n')
    enforce.write_text(
        '#!/usr/bin/env bash\n'
        '# Push enforce-mode wrapper.yaml to every server and restart\n'
        '# msshd. After this, `mssh user@<ip>:' + str(MSSHD_PORT) + '` works\n'
        '# (CA-mediated, mTLS to the wrapper).\n'
        'set -eu\n'
        + ''.join(
            f'lxc exec {s.container} -- sh -c '
            f"'cat > /etc/ssh-rt-auth/wrapper.yaml' <<'YAML'\n"
            f'{_wrapper_yaml_enforce(ca_ip)}YAML\n'
            f'lxc exec {s.container} -- '
            + ('sh -c "fuser -k -9 ' + str(MSSHD_PORT) + '/tcp 2>/dev/null; '
               'sleep 1; cd /app && PYTHONPATH=/app/src nohup /usr/bin/python3 '
               '-m sshrt.msshd --config /etc/ssh-rt-auth/wrapper.yaml '
               '> /var/log/ssh-rt-auth/msshd.log 2>&1 & '
               'echo \\$! > /run/msshd.pid"\n'
               if s.container == ENG_NAME
               else 'systemctl restart msshd\n')
            for s in SERVERS
        )
        + 'echo "All servers in enforce mode."\n')
    fallback.chmod(0o755)
    enforce.chmod(0o755)


def _write_overview_md(path: Path, *, ips: dict, artifacts_dir: Path) -> None:
    user_lines = []
    for u in USERS:
        primary = _primary_container_for(u)
        allowed = _allowed_servers_for(u)
        allowed_str = ', '.join(s.canonical for s in allowed) or '(none)'
        user_lines.append(
            f'| {u.username} | {u.department} | {primary} | {allowed_str} |')
    server_lines = '\n'.join(
        f'| {s.canonical} | {s.group} | {s.container} | {ips[s.container]} |'
        for s in SERVERS)
    path.write_text(f'''# ssh-rt-auth msshd adhoc lab — overview

The lab provisions 4 server containers and 1 CA, walks them through the
Tier-1 adoption journey (Phase 0 → Phase 1 → Phase 2), and leaves them
at Phase 2 with helpers to flip between modes.

## Containers

| canonical | group | container | IP |
|---|---|---|---|
{server_lines}
| ca-host | (n/a) | {CA_NAME} | {ips[CA_NAME]} |

## Users

| user | department | primary container | allowed servers |
|---|---|---|---|
{chr(10).join(user_lines)}

The superuser (`root-admin`) holds a CA policy that grants every
department; the SSH keypair is also added to every other user's
`authorized_keys` so the superuser can `ssh user@host` as anyone for
Phase 0 / 1 debugging.

## Modes (current state: **enforce** = Phase 2)

  - `mssh user@<ip>:{MSSHD_PORT}` — works in Phase 2 (mTLS to msshd, CA call).
  - `ssh -p {MSSHD_PORT} user@<ip>` — works ONLY when msshd is in fallback.
  - `ssh -p {VANILLA_SSHD_PORT} user@<ip>` — always works (bypasses msshd).

Flip with:

```bash
./flip-to-fallback.sh         # → Phase 1 behavior
./flip-to-enforce.sh          # → Phase 2 behavior (default after setup)
```

## Per-user material (host side)

Lives in `{artifacts_dir.name}/`:

```
{artifacts_dir.name}/
├── <user>                   # SSH ed25519 private key
├── <user>.pub               # SSH public key (registered for Phase 0/1)
├── <user>.crt               # X.509 mTLS client cert (Phase 2)
├── <user>.key               # X.509 mTLS client key  (Phase 2)
└── user-ca.crt              # mTLS trust root (verify wrapper TLS cert)
```

## Direct from the host

Make sure `mssh` is on PATH (`pip install -e ./python`), then:

```bash
export ALICE_CERT={artifacts_dir.name}/alice.crt
export ALICE_KEY={artifacts_dir.name}/alice.key
export USER_CA={artifacts_dir.name}/user-ca.crt
export ACCT_IP={ips[ACCT_NAME]}
export SALES_IP={ips[SALES_NAME]}

# Phase 2 — mssh via msshd-enforce on 2200
MSSH_CERT=$ALICE_CERT MSSH_KEY=$ALICE_KEY MSSH_CA=$USER_CA \\
    mssh alice@$ACCT_IP:{MSSHD_PORT} -- whoami

# Phase 0 — direct ssh to in-container sshd on 22 (always works)
ssh -i {artifacts_dir.name}/alice -p 22 alice@$ACCT_IP whoami
```

## From inside any user's primary container

```bash
lxc exec {ACCT_NAME} -- su - alice -c 'mssh amy@{ips[SALES_NAME]}:{MSSHD_PORT} -- whoami'
# (will be denied — alice's policy is accounting-only)

lxc exec {CA_NAME} -- su - root-admin -c 'mssh alice@{ips[HR_NAME]}:{MSSHD_PORT} -- whoami'
# (allowed — superuser policy grants every group)
```

## Cleanup

`./cleanup_containers.sh` deletes all 5 containers.
''')


def _write_env_sh(path: Path, *, ips: dict, artifacts_dir: Path) -> None:
    lines = [
        '# Source me from the directory that contains adhoc-keys/',
        f'export CA_HOST={CA_NAME}',
        f'export ACCT_HOST={ACCT_NAME}',
        f'export SALES_HOST={SALES_NAME}',
        f'export HR_HOST={HR_NAME}',
        f'export ENG_HOST={ENG_NAME}',
        f'export CA_IP={ips[CA_NAME]}',
        f'export ACCT_IP={ips[ACCT_NAME]}',
        f'export SALES_IP={ips[SALES_NAME]}',
        f'export HR_IP={ips[HR_NAME]}',
        f'export ENG_IP={ips[ENG_NAME]}',
        f'export MSSHD_PORT={MSSHD_PORT}',
        f'export SSHD_PORT={VANILLA_SSHD_PORT}',
        f'export USER_CA={artifacts_dir}/user-ca.crt',
    ]
    for u in USERS:
        n = u.username.upper().replace('-', '_')
        lines += [
            f'export {n}_KEY={artifacts_dir}/{u.username}',
            f'export {n}_CRT={artifacts_dir}/{u.username}.crt',
            f'export {n}_KEYPEM={artifacts_dir}/{u.username}.key',
        ]
    lines += [
        '',
        'alias mssh-alice="MSSH_CERT=$ALICE_CRT MSSH_KEY=$ALICE_KEYPEM '
        'MSSH_CA=$USER_CA mssh"',
        'alias mssh-superuser="MSSH_CERT=$ROOT_ADMIN_CRT '
        'MSSH_KEY=$ROOT_ADMIN_KEYPEM MSSH_CA=$USER_CA mssh"',
    ]
    path.write_text('\n'.join(lines) + '\n')


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
    section('Writing adhoc artifacts (cleanup, flip scripts, env, README)')
    _write_cleanup_script(invocation_cwd / 'cleanup_containers.sh')
    _write_flip_scripts(invocation_cwd, ips[CA_NAME])
    _write_env_sh(invocation_cwd / 'adhoc-env.sh',
                  ips=ips, artifacts_dir=artifacts_dir)
    _write_overview_md(invocation_cwd / 'ADHOC_TEST_ENV.md',
                       ips=ips, artifacts_dir=artifacts_dir)

    section('SUCCESS — msshd adhoc lab is up at Phase 2 (enforce)')
    print(
        f'\n  source ./adhoc-env.sh    # exports ips, ports, key paths\n'
        f'  cat ./ADHOC_TEST_ENV.md  # full overview + examples\n'
        f'  ./flip-to-fallback.sh    # Phase 1 (ssh -p 2200 works)\n'
        f'  ./flip-to-enforce.sh     # Phase 2 (mssh works) — current state\n'
        f'  ./cleanup_containers.sh  # tear it all down\n',
        file=sys.stderr, flush=True)
