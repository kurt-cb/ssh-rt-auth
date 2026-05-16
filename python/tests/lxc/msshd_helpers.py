"""Reusable provisioning helpers for msshd-enforce in LXC test fixtures.

Extracted from tests/lxc/test_setup_only_msshd.py so it can be shared
between the adhoc-lab provisioner and the `msshd_env` pytest fixture
that runs alongside `lxc_env` to give the regular suite end-to-end
msshd-enforce coverage.

Everything in here is provisioner-agnostic about *which* SSH server
runs alongside — msshd listens on a different port (2200 by default)
from debug_sshd (2222), so the two can coexist on the same container.
"""
from __future__ import annotations

import base64
import datetime as _dt
import ipaddress
import os
import struct
import subprocess
import sys  # noqa: F401  (used for stderr printing on the error path)
from pathlib import Path

from lxc_helpers import lxc_exec, push_file, push_text, wait_for_port


MSSHD_PORT = 2200


# ---------------------------------------------------------------------------
# X.509 / SSH-blob crypto helpers
# ---------------------------------------------------------------------------

def _ssh_pubkey_blob_from_ed25519(pubkey) -> bytes:
    """Encode an Ed25519 public key into the SSH wire-format ssh-ed25519 blob
    (what msshd extracts and sends to the CA as `identity_blob`)."""
    from cryptography.hazmat.primitives import serialization
    raw = pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    name = b'ssh-ed25519'
    return (struct.pack('>I', len(name)) + name
            + struct.pack('>I', len(raw)) + raw)


def gen_user_ca_and_mtls_certs(out_dir: Path, *,
                               wrapper_host_sans: dict[str, str],
                               user_principals: list[str]) -> dict:
    """Generate:

      - a fresh Ed25519 user-CA (signs the mTLS cert hierarchy below)
      - one wrapper TLS server cert per container (CN/SAN = container IP)
      - one mTLS client cert per principal in `user_principals`

    Returns:

      {
        'user_ca_path':   path to user-ca.crt,
        'wrapper_certs':  {container: {'cert': ..., 'key': ...}},
        'clients':        {principal: {'cert': ..., 'key': ...,
                                       'ssh_pubkey_blob': bytes}},
      }
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    out_dir.mkdir(parents=True, exist_ok=True)
    user_ca_key = ed25519.Ed25519PrivateKey.generate()
    user_ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'mssh-test-user-ca')])
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
                    [x509.IPAddress(ipaddress.ip_address(ip)),
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
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
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


def gen_wrapper_user_ca(out_dir: Path) -> tuple[Path, Path]:
    """Local wrapper user-CA — signs the ephemeral OpenSSH user certs
    msshd hands to the hermetic inner sshd. Returns (priv, pub) paths."""
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


# ---------------------------------------------------------------------------
# wrapper.yaml renderers
# ---------------------------------------------------------------------------

def wrapper_yaml_enforce(ca_ip: str, ca_port: int = 8443,
                         msshd_port: int = MSSHD_PORT) -> str:
    return (
        'mode: enforce\n'
        f'listen:\n'
        f'  external_address: 0.0.0.0\n'
        f'  external_port: {msshd_port}\n'
        f'  interfaces: []\n'
        f'tls:\n'
        f'  server_cert: /etc/ssh-rt-auth/wrapper-server.crt\n'
        f'  server_key:  /etc/ssh-rt-auth/wrapper-server.key\n'
        f'  user_ca_pubkey: /etc/ssh-rt-auth/user-ca.pub\n'
        f'ca:\n'
        f'  endpoints: [https://{ca_ip}:{ca_port}]\n'
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


def systemd_msshd_unit() -> str:
    return (
        '[Unit]\nDescription=mssh server-side gateway daemon\n'
        'After=network-online.target\n'
        '[Service]\nWorkingDirectory=/app\n'
        'Environment="PYTHONPATH=/app/src"\n'
        'Environment="SSH_RT_AUTH_WRAPPER_STATE_DIR=/var/lib/ssh-rt-auth"\n'
        'ExecStart=/usr/bin/python3 -m mssh.msshd '
        '--config /etc/ssh-rt-auth/wrapper.yaml\n'
        'Restart=on-failure\nStandardError=journal\n'
        '[Install]\nWantedBy=multi-user.target\n'
    )


# ---------------------------------------------------------------------------
# Container-side provisioning
# ---------------------------------------------------------------------------

def push_msshd_cert_material(container: str, *, alpine: bool = False,
                             wrapper_cert: str, wrapper_key: str,
                             user_ca_pub: str,
                             wrapper_mtls_cert, wrapper_mtls_key,
                             ca_tls_root,
                             wrapper_user_ca_priv: Path,
                             wrapper_user_ca_pub: Path) -> None:
    """Push every cert + key + trust root msshd-enforce needs."""
    lxc_exec(container, 'mkdir', '-p',
             '/etc/ssh-rt-auth',
             '/var/lib/ssh-rt-auth',
             '/var/lib/ssh-rt-auth/inner-sshd',
             '/var/log/ssh-rt-auth')
    push_file(container, wrapper_cert,
              '/etc/ssh-rt-auth/wrapper-server.crt', mode='644')
    push_file(container, wrapper_key,
              '/etc/ssh-rt-auth/wrapper-server.key', mode='600')
    push_file(container, user_ca_pub,
              '/etc/ssh-rt-auth/user-ca.pub', mode='644')
    push_file(container, str(wrapper_mtls_cert),
              '/etc/ssh-rt-auth/wrapper-mtls.crt', mode='644')
    push_file(container, str(wrapper_mtls_key),
              '/etc/ssh-rt-auth/wrapper-mtls.key', mode='600')
    push_file(container, str(ca_tls_root),
              '/etc/ssh-rt-auth/server-mtls-ca.pub', mode='644')
    push_file(container, str(wrapper_user_ca_priv),
              '/var/lib/ssh-rt-auth/wrapper-user-ca', mode='600')
    push_file(container, str(wrapper_user_ca_pub),
              '/var/lib/ssh-rt-auth/inner-sshd/wrapper-user-ca.pub',
              mode='644')


def start_msshd_enforce(container: str, *, ca_ip: str,
                        alpine: bool = False,
                        msshd_port: int = MSSHD_PORT) -> None:
    """Render wrapper.yaml + start msshd-enforce on `container`.

    On Ubuntu uses systemd; on Alpine uses nohup (no systemd in the
    LXC images we use).
    """
    yaml = wrapper_yaml_enforce(ca_ip, msshd_port=msshd_port)
    lxc_exec(container, 'mkdir', '-p',
             '/etc/ssh-rt-auth', '/var/lib/ssh-rt-auth',
             '/var/lib/ssh-rt-auth/inner-sshd', '/var/log/ssh-rt-auth')
    push_text(container, yaml, '/etc/ssh-rt-auth/wrapper.yaml', mode='644')

    if alpine:
        lxc_exec(container, 'sh', '-c',
                 f'fuser -k -9 {msshd_port}/tcp 2>/dev/null; sleep 1',
                 check=False)
        lxc_exec(container, 'sh', '-c',
                 'cd /app && PYTHONPATH=/app/src '
                 'SSH_RT_AUTH_WRAPPER_STATE_DIR=/var/lib/ssh-rt-auth '
                 'nohup /usr/bin/python3 -m mssh.msshd '
                 '--config /etc/ssh-rt-auth/wrapper.yaml '
                 '> /var/log/ssh-rt-auth/msshd.log 2>&1 & '
                 'echo $! > /run/msshd.pid')
    else:
        push_text(container, systemd_msshd_unit(),
                  '/etc/systemd/system/msshd.service')
        lxc_exec(container, 'systemctl', 'daemon-reload')
        lxc_exec(container, 'systemctl', 'restart', 'msshd')

    try:
        wait_for_port(container, msshd_port, max_wait=30)
    except Exception:
        if alpine:
            log = lxc_exec(container, 'cat',
                           '/var/log/ssh-rt-auth/msshd.log', check=False)
        else:
            log = lxc_exec(container, 'journalctl', '-u', 'msshd',
                           '--no-pager', '-n', '100', check=False)
        print(f'--- msshd log on {container} ---\n{log.stdout or ""}',
              file=sys.stderr)
        raise


def push_mssh_per_user(container: str, *, username: str,
                       user_cert: str, user_key: str, user_ca: str,
                       alpine: bool = False) -> None:
    """Drop per-user mssh material into /home/<username>/.mssh/."""
    home_mssh = f'/home/{username}/.mssh'
    lxc_exec(container, 'sh', '-c',
             f'mkdir -p {home_mssh} && chmod 700 {home_mssh} && '
             f'chown -R {username}:{username} {home_mssh}', check=False)
    push_file(container, user_cert,
              f'{home_mssh}/cert.pem', mode='600',
              owner=f'{username}:{username}')
    push_file(container, user_key,
              f'{home_mssh}/key.pem', mode='600',
              owner=f'{username}:{username}')
    push_file(container, user_ca,
              f'{home_mssh}/ca.pem', mode='644',
              owner=f'{username}:{username}')


_MSSH_WRAPPER_SCRIPT = '''#!/bin/sh
# /usr/local/bin/mssh — invokes the Python mssh client with the
# in-tree source code (no pip install required inside the container).
exec env \\
    MSSH_CERT="${MSSH_CERT:-$HOME/.mssh/cert.pem}" \\
    MSSH_KEY="${MSSH_KEY:-$HOME/.mssh/key.pem}" \\
    MSSH_CA="${MSSH_CA:-$HOME/.mssh/ca.pem}" \\
    PYTHONPATH=/app/src \\
    /usr/bin/python3 -m mssh.client "$@"
'''


def install_mssh_wrapper_script(container: str) -> None:
    """Drop a /usr/local/bin/mssh shell wrapper so users can just type `mssh`."""
    push_text(container, _MSSH_WRAPPER_SCRIPT,
              '/usr/local/bin/mssh', mode='755')


# ---------------------------------------------------------------------------
# CA enrollment helper
# ---------------------------------------------------------------------------

def enroll_user_mtls_pubkey(admin, username: str,
                            ssh_pubkey_blob: bytes,
                            label: str = 'mtls-cert') -> None:
    """Add the user's mTLS-cert-derived ssh-ed25519 pubkey blob as another
    enrolled key for this user, alongside any existing SSH-key enrollments.

    The CA stores keys by blob; mssh client presents an X.509 cert,
    msshd extracts the ed25519 pubkey and sends THIS blob as
    identity_blob — so the CA needs the blob enrolled to match it.
    """
    admin.user_key_add(
        username, 'pubkey',
        base64.b64encode(ssh_pubkey_blob).decode('ascii'))
