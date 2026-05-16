"""End-to-end Tier-1-wrapper integration test (enforce mode).

Provisions:

  - One CA container — runs ``ca.server`` over mTLS.
  - One wrapper-target container — runs ``msshd`` in
    ``enforce`` mode, with a hermetic inner sshd that the wrapper
    spawns and owns.

Drives one ``mssh alice@<target> -- whoami`` call through the
wrapper, verifies the auth path end-to-end:

  mssh (TLS+mTLS) ─► wrapper ─► CA (mTLS authorize) ─► wrapper
       │                              │
       │  (cert minted, JSON ack)     │  ← inner OpenSSH cert
       │                              │
       │  ◄────── stdout ───────  inner sshd (as 'alice')
       ▼
   prints "alice"

Opt-in marker: ``-m wrapper_enforce``.
"""
from __future__ import annotations

import base64
import datetime as _dt
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest


# Re-use the lxc helpers loader trick.
import importlib.util as _ilu
_HERE = Path(__file__).resolve().parent
for _name in ('lxc_helpers', 'log_helpers'):
    _spec = _ilu.spec_from_file_location(_name, _HERE / f'{_name}.py')
    _mod = _ilu.module_from_spec(_spec)
    sys.modules[_name] = _mod
    _spec.loader.exec_module(_mod)

from lxc_helpers import (
    UBUNTU_IMAGE, get_ip, lxc, lxc_exec, push_file, push_source, push_text,
    wait_for_apt_quiescent, wait_for_port,
)
from log_helpers import banner, section


pytestmark = [pytest.mark.lxc, pytest.mark.wrapper_enforce]


CA_NAME     = 'mssh-wrapper-ca'
TARGET_NAME = 'mssh-wrapper-target'
CA_PORT     = 8443
WRAPPER_PORT = 2200


# ---------------------------------------------------------------------------
# Crypto helpers — generate alice's mTLS material + the user-CA that
# signs her mTLS cert AND the wrapper's TLS server cert.
# ---------------------------------------------------------------------------

def _ssh_pubkey_blob_from_ed25519(pubkey) -> bytes:
    """Return the SSH wire-format ssh-ed25519 blob for an Ed25519 public
    key. Matches mssh.msshd.enforce_listener._ssh_pubkey_blob_from_cert.
    """
    from cryptography.hazmat.primitives import serialization
    raw = pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    name = b'ssh-ed25519'
    return (struct.pack('>I', len(name)) + name
            + struct.pack('>I', len(raw)) + raw)


def _gen_user_ca_and_mtls_certs(out_dir: Path, *,
                                wrapper_host_san: str,
                                user_principals: list[str]):
    """Generate:
      - a fresh Ed25519 user-CA (signs the mTLS client + server certs)
      - a wrapper TLS server cert (signed by user-CA, CN=wrapper-host)
      - one Ed25519 mTLS client cert per principal in user_principals

    Returns a dict with all the paths + the user-CA-signed-ed25519
    pubkey blobs the CA needs at enrollment time.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    out_dir.mkdir(parents=True, exist_ok=True)

    # User-CA keypair (also doubles as TLS-server-cert issuer, for test
    # simplicity).
    user_ca_key = ed25519.Ed25519PrivateKey.generate()
    user_ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'mssh-test-user-ca')])
    user_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(user_ca_name)
        .issuer_name(user_ca_name)
        .public_key(user_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(minutes=5))
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .sign(user_ca_key, None)
    )
    (out_dir / 'user-ca.crt').write_bytes(
        user_ca_cert.public_bytes(serialization.Encoding.PEM))

    # Wrapper TLS server cert — Ed25519, signed by user_ca.
    wrapper_server_key = ed25519.Ed25519PrivateKey.generate()
    wrapper_server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, wrapper_host_san)]))
        .issuer_name(user_ca_name)
        .public_key(wrapper_server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(minutes=5))
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(wrapper_host_san),
                 x509.DNSName('localhost')]),
            critical=False)
        .sign(user_ca_key, None)
    )
    (out_dir / 'wrapper-server.crt').write_bytes(
        wrapper_server_cert.public_bytes(serialization.Encoding.PEM))
    (out_dir / 'wrapper-server.key').write_bytes(
        wrapper_server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    os.chmod(out_dir / 'wrapper-server.key', 0o600)

    # mTLS client certs, one per principal.
    client_certs = {}
    for principal in user_principals:
        cli_key = ed25519.Ed25519PrivateKey.generate()
        cli_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, principal)]))
            .issuer_name(user_ca_name)
            .public_key(cli_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(minutes=5))
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=30))
            .add_extension(
                x509.ExtendedKeyUsage(
                    [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False)
            .sign(user_ca_key, None)
        )
        cert_path = out_dir / f'{principal}.crt'
        key_path = out_dir / f'{principal}.key'
        cert_path.write_bytes(
            cli_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(cli_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
        client_certs[principal] = {
            'cert': str(cert_path),
            'key': str(key_path),
            'ssh_pubkey_blob': _ssh_pubkey_blob_from_ed25519(
                cli_key.public_key()),
        }

    return {
        'user_ca_path': str(out_dir / 'user-ca.crt'),
        'wrapper_server_cert_path': str(out_dir / 'wrapper-server.crt'),
        'wrapper_server_key_path': str(out_dir / 'wrapper-server.key'),
        'clients': client_certs,
    }


def _gen_wrapper_user_ca(out_dir: Path) -> tuple[Path, Path]:
    """Generate the wrapper's *local* user-CA keypair (signs ephemeral
    OpenSSH user certs handed to inner sshd). Returns (priv, pub)
    paths in OpenSSH key format."""
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = out_dir / 'wrapper-user-ca'
    if priv.exists():
        priv.unlink()
    if (out_dir / 'wrapper-user-ca.pub').exists():
        (out_dir / 'wrapper-user-ca.pub').unlink()
    subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '',
                    '-f', str(priv), '-q'],
                   check=True, capture_output=True)
    return priv, out_dir / 'wrapper-user-ca.pub'


# ---------------------------------------------------------------------------
# The test
# ---------------------------------------------------------------------------

def test_wrapper_enforce_end_to_end(request, tmp_path_factory):
    keep = request.config.getoption('--keep-containers', default=False)

    banner('wrapper enforce mode — end-to-end')

    section('Tearing down any pre-existing containers')
    for c in (CA_NAME, TARGET_NAME):
        subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)

    section('Launching CA + target containers')
    lxc('launch', UBUNTU_IMAGE, CA_NAME,
        '--config', 'security.privileged=true', timeout=300)
    lxc('launch', UBUNTU_IMAGE, TARGET_NAME,
        '--config', 'security.privileged=true', timeout=300)
    ca_ip = get_ip(CA_NAME)
    target_ip = get_ip(TARGET_NAME)
    print(f'  {CA_NAME:25s} {ca_ip}', file=sys.stderr, flush=True)
    print(f'  {TARGET_NAME:25s} {target_ip}', file=sys.stderr, flush=True)

    app_root = Path(__file__).resolve().parent.parent.parent.parent
    pkgs = ['python3', 'python3-cryptography', 'python3-flask',
            'python3-yaml', 'python3-click', 'python3-requests',
            'python3-asyncssh', 'openssh-server', 'openssh-client']
    section('Installing apt deps + project source')
    for c in (CA_NAME, TARGET_NAME):
        # Freshly-launched Ubuntu containers run apt-daily /
        # unattended-upgrades on first boot. Racing them gives exit 100
        # ('Could not get dpkg lock'). Wait until apt is quiescent.
        wait_for_apt_quiescent(c, max_wait=120)
        lxc_exec(c, 'apt-get', 'update', '-q', timeout=180)
        # --no-install-recommends skips doc packages (python-asyncssh-doc,
        # libjs-sphinxdoc, etc.) that we never use; saves ~200MB per
        # container. Important when test_wrapper_enforce runs late in
        # the suite and the LXC storage pool is already crowded with
        # the session-scoped lxc_env containers.
        lxc_exec(c, 'apt-get', 'install', '-y', '-q',
                 '--no-install-recommends', *pkgs, timeout=600)
        # Free the downloaded .debs to make room for push_source.
        lxc_exec(c, 'apt-get', 'clean')
        push_source(c, app_root)

    # ---- 1. CA bootstrap + start ------------------------------------------
    section('Bootstrapping CA')
    lxc_exec(CA_NAME, 'sh', '-c',
             'PYTHONPATH=/app/src python3 -c "'
             'from mssh.ca.cert_minter import bootstrap_ca; '
             f"bootstrap_ca('/etc/ssh-rt-auth/ca', "
             f"tls_server_sans=['DNS:localhost','IP:127.0.0.1','IP:{ca_ip}'])"
             '"', timeout=120)
    lxc_exec(CA_NAME, 'sh', '-c',
             'python3 -c "'
             'import yaml; '
             "open('/etc/ssh-rt-auth/ca/enrollment.yaml','w').write("
             "yaml.safe_dump({'admins': {'bootstrap-admin': "
             "{'role':'superuser','mtls_subject':'CN=bootstrap-admin',"
             "'enrolled_at':'','enrolled_by':'init'}}}))"
             '"')
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
              'ExecStart=/usr/bin/python3 -m mssh.ca.server --config '
              '/etc/ssh-rt-auth/ca-config.yaml\nRestart=on-failure\n'
              '[Install]\nWantedBy=multi-user.target\n',
              '/etc/systemd/system/ssh-rt-auth-ca.service')
    lxc_exec(CA_NAME, 'mkdir', '-p', '/var/log/ssh-rt-auth')
    lxc_exec(CA_NAME, 'systemctl', 'daemon-reload')
    lxc_exec(CA_NAME, 'systemctl', 'start', 'ssh-rt-auth-ca')
    wait_for_port(CA_NAME, CA_PORT, max_wait=60)

    # ---- 2. Pull admin creds + enroll target as a server ------------------
    creds_dir = tmp_path_factory.mktemp('admin-creds')
    for n in ('bootstrap-admin-cert.pem', 'bootstrap-admin-key.pem',
              'tls-ca-cert.pem', 'signing-cert.pem'):
        subprocess.run(['lxc', 'file', 'pull',
                        f'{CA_NAME}/etc/ssh-rt-auth/ca/{n}',
                        str(creds_dir / n)],
                       check=True, capture_output=True)
    os.chmod(creds_dir / 'bootstrap-admin-key.pem', 0o600)

    from mssh.admin.client import CAClient
    admin = CAClient(
        base_url=f'https://{ca_ip}:{CA_PORT}',
        admin_cert=str(creds_dir / 'bootstrap-admin-cert.pem'),
        admin_key=str(creds_dir / 'bootstrap-admin-key.pem'),
        ca_cert=str(creds_dir / 'tls-ca-cert.pem'),
    )

    section('Enrolling wrapper-target at the CA')
    resp = admin.server_add('srv-wrapper', groups=['poc'])
    server_creds = resp['credentials']
    wrapper_mtls_cert = creds_dir / 'srv-mtls.crt'
    wrapper_mtls_key  = creds_dir / 'srv-mtls.key'
    wrapper_mtls_cert.write_text(server_creds['cert_pem'])
    wrapper_mtls_key.write_text(server_creds['key_pem'])
    os.chmod(wrapper_mtls_key, 0o600)

    # ---- 3. Generate mssh / wrapper-server certs locally ------------------
    section('Generating user-CA, wrapper TLS server cert, alice mTLS cert')
    pki_dir = tmp_path_factory.mktemp('pki')
    pki = _gen_user_ca_and_mtls_certs(
        pki_dir, wrapper_host_san=target_ip,
        user_principals=['alice'])

    # ---- 4. Enroll alice at the CA with her ed25519 pubkey ----------------
    admin.user_add('alice')
    admin.user_key_add('alice', 'pubkey',
                       base64.b64encode(
                           pki['clients']['alice']['ssh_pubkey_blob']
                       ).decode('ascii'))
    admin.policy_add('alice', {
        'servers': ['srv-wrapper'],
        'channels': ['session'],
        'source_cidrs': ['0.0.0.0/0'],
        'max_cert_validity_seconds': 600,
    })

    # ---- 5. Provision the wrapper-target ----------------------------------
    section('Provisioning wrapper-target: unix user, wrapper config, cert material')
    # Unix user the inner sshd will spawn shells as. usermod -p '*'
    # marks the account as having a disabled-but-not-locked password,
    # which sshd treats as "publickey-only login allowed". useradd
    # alone leaves the account in '!' (locked) which sshd rejects even
    # for pubkey auth.
    lxc_exec(TARGET_NAME, 'useradd', '-m', '-s', '/bin/bash', 'alice',
             check=False)
    lxc_exec(TARGET_NAME, 'usermod', '-p', '*', 'alice')

    # Generate the wrapper's local user-CA (signs ephemeral inner certs).
    wrapper_user_ca_dir = tmp_path_factory.mktemp('wrapper-user-ca')
    wrapper_user_ca_priv, wrapper_user_ca_pub = _gen_wrapper_user_ca(
        wrapper_user_ca_dir)

    # Push everything into the target.
    lxc_exec(TARGET_NAME, 'mkdir', '-p',
             '/etc/ssh-rt-auth',
             '/var/lib/ssh-rt-auth',
             '/var/lib/ssh-rt-auth/inner-sshd',
             '/var/log/ssh-rt-auth')

    # Wrapper's TLS server cert + key (presented to mssh clients).
    push_file(TARGET_NAME, pki['wrapper_server_cert_path'],
              '/etc/ssh-rt-auth/wrapper-server.crt', mode='644')
    push_file(TARGET_NAME, pki['wrapper_server_key_path'],
              '/etc/ssh-rt-auth/wrapper-server.key', mode='600')
    # User-CA trust root (verifies mssh client certs).
    push_file(TARGET_NAME, pki['user_ca_path'],
              '/etc/ssh-rt-auth/user-ca.pub', mode='644')
    # Wrapper's CA mTLS material (presented when calling the CA).
    push_file(TARGET_NAME, wrapper_mtls_cert,
              '/etc/ssh-rt-auth/wrapper-mtls.crt', mode='644')
    push_file(TARGET_NAME, wrapper_mtls_key,
              '/etc/ssh-rt-auth/wrapper-mtls.key', mode='600')
    push_file(TARGET_NAME, creds_dir / 'tls-ca-cert.pem',
              '/etc/ssh-rt-auth/server-mtls-ca.pub', mode='644')
    # Wrapper's local user-CA (signs inner OpenSSH certs).
    push_file(TARGET_NAME, str(wrapper_user_ca_priv),
              '/var/lib/ssh-rt-auth/wrapper-user-ca', mode='600')
    push_file(TARGET_NAME, str(wrapper_user_ca_pub),
              '/var/lib/ssh-rt-auth/inner-sshd/wrapper-user-ca.pub',
              mode='644')

    # wrapper.yaml (enforce mode).
    push_text(TARGET_NAME,
              f'mode: enforce\n'
              f'listen:\n'
              f'  external_address: 0.0.0.0\n'
              f'  external_port: {WRAPPER_PORT}\n'
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
              f'  allowed: [alice]\n'
              f'logging:\n'
              f'  level: info\n'
              f'  destination: stderr\n'
              f'  audit_destination: file:/var/log/ssh-rt-auth/wrapper-audit.jsonl\n',
              '/etc/ssh-rt-auth/wrapper.yaml')

    # systemd unit.
    push_text(TARGET_NAME,
              '[Unit]\nDescription=ssh-rt-auth wrapper\n'
              'After=network-online.target\n'
              '[Service]\nWorkingDirectory=/app\n'
              'Environment="PYTHONPATH=/app/src"\n'
              'Environment="SSH_RT_AUTH_WRAPPER_STATE_DIR=/var/lib/ssh-rt-auth"\n'
              'ExecStart=/usr/bin/python3 -m mssh.msshd '
              '--config /etc/ssh-rt-auth/wrapper.yaml\n'
              'Restart=on-failure\n'
              'StandardError=journal\n'
              '[Install]\nWantedBy=multi-user.target\n',
              '/etc/systemd/system/msshd.service')

    # ---- 6. Start the wrapper ---------------------------------------------
    section('Starting wrapper')
    lxc_exec(TARGET_NAME, 'systemctl', 'daemon-reload')
    lxc_exec(TARGET_NAME, 'systemctl', 'start', 'msshd')
    try:
        wait_for_port(TARGET_NAME, WRAPPER_PORT, max_wait=30)
    except Exception:
        # Dump the journal so we can see why startup failed.
        rj = lxc_exec(TARGET_NAME, 'journalctl', '-u', 'msshd',
                      '--no-pager', '-n', '100', check=False)
        print('--- wrapper journal ---', file=sys.stderr)
        print(rj.stdout or '', file=sys.stderr)
        print(rj.stderr or '', file=sys.stderr)
        raise

    # ---- 7. Drive an mssh call from inside the target ---------------------
    section('Pushing alice mTLS material into the target')
    lxc_exec(TARGET_NAME, 'mkdir', '-p', '/root/.mssh')
    push_file(TARGET_NAME, pki['clients']['alice']['cert'],
              '/root/.mssh/cert.pem', mode='600')
    push_file(TARGET_NAME, pki['clients']['alice']['key'],
              '/root/.mssh/key.pem', mode='600')
    push_file(TARGET_NAME, pki['user_ca_path'],
              '/root/.mssh/ca.pem', mode='644')

    section('Running mssh alice@target -- whoami')
    r = lxc_exec(TARGET_NAME, 'sh', '-c',
                 f'cd /app && PYTHONPATH=/app/src python3 -m mssh.client '
                 f'alice@{target_ip}:{WRAPPER_PORT} -- whoami',
                 check=False, timeout=30)
    print(f'mssh stdout: {r.stdout!r}', file=sys.stderr)
    print(f'mssh stderr: {r.stderr!r}', file=sys.stderr)

    if r.returncode != 0 or 'alice' not in (r.stdout or ''):
        # Dump the wrapper journal to help debug.
        rj = lxc_exec(TARGET_NAME, 'journalctl', '-u', 'msshd',
                      '--no-pager', '-n', '200', check=False)
        print('--- wrapper journal ---', file=sys.stderr)
        print(rj.stdout or '', file=sys.stderr)
        # Dump the CA audit log to help debug.
        ra = lxc_exec(CA_NAME, 'cat', '/var/log/ssh-rt-auth/audit.jsonl',
                      check=False)
        print('--- CA audit ---', file=sys.stderr)
        print(ra.stdout or '', file=sys.stderr)

    assert r.returncode == 0, f'mssh failed: rc={r.returncode}'
    assert 'alice' in (r.stdout or ''), \
        f'expected "alice" in stdout: {r.stdout!r}'

    section('Verifying CA audit log has the grant')
    ra = lxc_exec(CA_NAME, 'cat', '/var/log/ssh-rt-auth/audit.jsonl')
    assert 'granted' in (ra.stdout or ''), \
        f'no granted entries in CA audit log:\n{ra.stdout}'

    section('SUCCESS: mssh → wrapper → CA → inner sshd → "alice"')

    if not keep:
        section('Tearing down containers')
        for c in (CA_NAME, TARGET_NAME):
            subprocess.run(['lxc', 'delete', '--force', c],
                           capture_output=True)
    else:
        section(f'--keep-containers: leaving {CA_NAME}, {TARGET_NAME}')
