"""Three-process loopback end-to-end test.

  127.0.0.1 = CA (Flask + mTLS)
  127.0.0.2 = SSH client source
  127.0.0.3 = SSH server (AsyncSSH + shim)

All three processes run inside this pytest worker as background threads/asyncio
tasks. The test exercises the full path:

  enroll server → enroll user → add policy → start CA → start SSH server →
  SSH client connects from 127.0.0.2 → shim queries CA over mTLS → CA grants →
  client sees the banner.

Marked ``loopback`` so it can be deselected with ``-m 'not loopback'``.
"""
from __future__ import annotations

import asyncio
import base64
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest


pytestmark = pytest.mark.loopback


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _have_loopback_alias(ip: str) -> bool:
    """The test needs 127.0.0.2 and 127.0.0.3 bindable. Linux loopback usually
    aliases the whole 127.0.0.0/8, but check anyway."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _alloc_port(host: str = '127.0.0.1') -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_port(host: str, port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((host, port))
            s.close()
            return
        except OSError:
            time.sleep(0.1)
        finally:
            s.close()
    raise TimeoutError(f'port {host}:{port} not ready')


# ---------------------------------------------------------------------------
# Fixture: full loopback environment
# ---------------------------------------------------------------------------

@pytest.fixture
def loopback_env(tmp_path):
    """Build CA on .1, server on .3, give a key to use as the client.

    All wiring happens via in-process objects; we run a real Flask CA on a TLS
    port and a real AsyncSSH server.
    """
    if not _have_loopback_alias('127.0.0.2'):
        pytest.skip('127.0.0.2 not bindable on this host')
    if not _have_loopback_alias('127.0.0.3'):
        pytest.skip('127.0.0.3 not bindable on this host')

    from tests.conftest import TestKey
    from sshrt.ca import cert_minter
    from sshrt.ca.cert_minter import bootstrap_ca, issue_client_cert, load_certificate, load_private_key
    from sshrt.ca.enrollment import Enrollment, KeyBinding

    # ---- CA bootstrap ----
    ca_dir = tmp_path / 'ca'
    bootstrap_ca(ca_dir, tls_server_sans=['DNS:localhost', 'IP:127.0.0.1'])
    # Seed enrollment.
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    enroll.add_admin('bootstrap-admin', 'superuser', 'CN=bootstrap-admin')

    # Enroll the test server (issues an mTLS client cert for it).
    tls_ca_key = load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = load_certificate(ca_dir / 'tls-ca-cert.pem')
    srv_creds = issue_client_cert('srv1', tls_ca_key, tls_ca_cert)
    enroll.add_server('srv1', f'CN={srv_creds.subject_cn}', ['default'])

    # Write the server's mTLS cert/key + the CA's TLS root to disk for the shim.
    shim_dir = tmp_path / 'shim'
    shim_dir.mkdir()
    (shim_dir / 'srv1-cert.pem').write_bytes(srv_creds.cert_pem)
    (shim_dir / 'srv1-key.pem').write_bytes(srv_creds.key_pem)
    (shim_dir / 'ca-tls-root.pem').write_bytes(srv_creds.ca_cert_pem)
    (shim_dir / 'auth-signing-root.pem').write_bytes(
        (ca_dir / 'signing-cert.pem').read_bytes())

    # ---- User identity ----
    client_key = TestKey.generate('client@127.0.0.2')
    enroll.add_user('alice')
    enroll.add_user_key('alice',
                        KeyBinding(client_key.fingerprint, 'pubkey', 'ssh-ed25519'))
    enroll.add_policy('alice', {
        'servers': ['srv1'], 'channels': ['session'],
        'source_cidrs': ['127.0.0.0/8'],
        'max_cert_validity_seconds': 600,
    })

    # ---- CA config + run Flask in a background thread ----
    import yaml
    ca_port = _alloc_port('127.0.0.1')
    cfg_path = ca_dir / 'ca-config.yaml'
    cfg_path.write_text(yaml.safe_dump({
        'listen': f'127.0.0.1:{ca_port}',
        'signing_key': str(ca_dir / 'signing-key.pem'),
        'signing_cert': str(ca_dir / 'signing-cert.pem'),
        'tls_cert': str(ca_dir / 'tls-server-cert.pem'),
        'tls_key': str(ca_dir / 'tls-server-key.pem'),
        'client_ca_cert': str(ca_dir / 'tls-ca-cert.pem'),
        'identity_trust_roots': [],
        'enrollment': {'path': str(ca_dir / 'enrollment.yaml')},
        'audit': {'path': str(ca_dir / 'audit.jsonl')},
        'defaults': {'max_cert_validity_seconds': 3600,
                     'timestamp_drift_seconds': 600},
        'cert_generation': {'key_type': 'ec',
                            'server_cert_validity_days': 30,
                            'admin_cert_validity_days': 30},
    }))

    ca_log_path = ca_dir / 'ca-stderr.log'
    ca_log = ca_log_path.open('w')
    # python/src/ must be on the subprocess's PYTHONPATH so sshrt is importable.
    src_dir = Path(__file__).resolve().parent.parent / 'src'
    env = {**os.environ, 'PYTHONPATH': str(src_dir)}
    ca_proc = subprocess.Popen(
        [sys.executable, '-m', 'sshrt.ca.server', '--config', str(cfg_path)],
        cwd=str(Path(__file__).resolve().parent.parent),
        stdout=ca_log, stderr=subprocess.STDOUT,
        env=env,
    )
    try:
        _wait_for_port('127.0.0.1', ca_port, timeout=10.0)
    except TimeoutError:
        ca_proc.terminate()
        ca_proc.wait(timeout=5)
        raise RuntimeError(
            f'CA failed to start. Stderr:\n{ca_log_path.read_text()}')

    # ---- Shim config on disk for the server ----
    shim_cfg = shim_dir / 'shim.yaml'
    shim_cfg.write_text(yaml.safe_dump({
        'ca_endpoints': [f'https://127.0.0.1:{ca_port}'],
        'mtls_cert': str(shim_dir / 'srv1-cert.pem'),
        'mtls_key': str(shim_dir / 'srv1-key.pem'),
        'ca_trust_root': str(shim_dir / 'ca-tls-root.pem'),
        'auth_trust_root': str(shim_dir / 'auth-signing-root.pem'),
        'server_name': 'srv1',
        'cache': {'max_entries': 10},
        'timeouts': {'connect': 3, 'read': 5},
    }))

    yield {
        'ca_dir': ca_dir, 'shim_dir': shim_dir, 'shim_cfg': shim_cfg,
        'ca_port': ca_port, 'client_key': client_key, 'ca_proc': ca_proc,
    }

    ca_proc.terminate()
    try:
        ca_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        ca_proc.kill()


# ---------------------------------------------------------------------------
# Test: full SSH connect succeeds through the shim
# ---------------------------------------------------------------------------

def test_loopback_full_ssh_authorization(loopback_env, tmp_path):
    import asyncssh
    from sshrt.shim.config import ShimConfig
    from sshrt.shim.shim import Shim
    from sshrt.debug_sshd.ssh_server import _handle_session, make_server_factory

    cfg = ShimConfig.load(loopback_env['shim_cfg'])
    shim = Shim(cfg)

    # ---- AsyncSSH host key ----
    host_key = asyncssh.generate_private_key('ssh-ed25519')
    host_key_path = tmp_path / 'host_ed25519'
    host_key.write_private_key(str(host_key_path))

    per_user_keys = {'alice': [loopback_env['client_key'].public_blob]}

    async def _run():
        sshd_port = _alloc_port('127.0.0.3')
        acceptor = await asyncssh.create_server(
            server_factory=make_server_factory(shim, per_user_keys),
            host='127.0.0.3', port=sshd_port,
            server_host_keys=[asyncssh.read_private_key(str(host_key_path))],
            process_factory=_handle_session,
            allow_pty=True,
        )
        try:
            client_key_path = tmp_path / 'client_ed25519'
            client_key_path.write_bytes(loopback_env['client_key'].private_pem)
            os.chmod(client_key_path, 0o600)

            # Force the client's local socket to bind to 127.0.0.2.
            class _Bound(asyncssh.SSHClient):
                pass

            async with asyncssh.connect(
                '127.0.0.3', port=sshd_port,
                username='alice',
                client_keys=[str(client_key_path)],
                known_hosts=None,
                local_addr=('127.0.0.2', 0),
            ) as conn:
                proc = await conn.run('whoami', check=False)
                return proc.stdout, proc.exit_status
        finally:
            acceptor.close()
            await acceptor.wait_closed()

    stdout, status = asyncio.run(_run())
    # Our server echoes a banner that contains the cert serial.
    assert 'ssh-rt-auth: authorized session' in (stdout or '')
