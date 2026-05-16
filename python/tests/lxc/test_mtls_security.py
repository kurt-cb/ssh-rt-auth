"""mTLS security tests against the CA.

Every attack path covered here ends at one of two boundaries:

  TLS layer rejection — the CA's listener requires a client cert signed by
                        its mTLS CA. No cert / self-signed / wrong-CA-signed
                        certs are rejected at the handshake.
  Authorization rejection — the cert is valid mTLS, but the subject CN is
                        not enrolled (or is enrolled in the wrong role).

All attacks run from the host using ``requests`` (Session with
``trust_env=False`` so the corporate proxy is bypassed).
"""
from __future__ import annotations

import datetime as _dt
import os
import sys
import tempfile
from pathlib import Path

import pytest
import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import oid

from log_helpers import OpsLog, banner, section


pytestmark = pytest.mark.lxc


urllib3.disable_warnings()


def _session() -> requests.Session:
    s = requests.Session()
    s.trust_env = False
    return s


# ---------------------------------------------------------------------------
# 1. No client cert presented → TLS handshake fails (CA requires CERT_REQUIRED)
# ---------------------------------------------------------------------------

def test_attack_no_client_cert(lxc_env):
    banner('Attack: no client cert presented')
    with OpsLog('attack', name='no-cert',
                expect='tls-handshake-fails') as op:
        try:
            r = _session().get(
                lxc_env['ca_url'] + '/v1/admin/admin/list',
                verify=lxc_env['ca_cert'], timeout=5,
            )
            op.record(actual=f'http-{r.status_code}', ok=False,
                      response=r.text[:300])
        except (requests.exceptions.SSLError,
                requests.exceptions.ConnectionError) as e:
            op.record(actual='tls-handshake-fails', ok=True,
                      exception=type(e).__name__, message=str(e)[:300])


# ---------------------------------------------------------------------------
# 2. Self-signed client cert → TLS handshake fails (not signed by mTLS CA)
# ---------------------------------------------------------------------------

@pytest.fixture(scope='module')
def self_signed_cert(tmp_path_factory):
    """Generate a self-signed cert in a temp dir; return (cert_path, key_path)."""
    d = tmp_path_factory.mktemp('self-signed')
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, 'attacker')])
    not_before = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1234)
        .not_valid_before(not_before)
        .not_valid_after(not_before + _dt.timedelta(days=1))
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    (d / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / 'key.pem').write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    os.chmod(d / 'key.pem', 0o600)
    return str(d / 'cert.pem'), str(d / 'key.pem')


def test_attack_self_signed_cert(lxc_env, self_signed_cert):
    banner('Attack: self-signed client cert')
    cert_path, key_path = self_signed_cert
    with OpsLog('attack', name='self-signed',
                expect='tls-handshake-fails') as op:
        try:
            r = _session().get(
                lxc_env['ca_url'] + '/v1/admin/admin/list',
                cert=(cert_path, key_path),
                verify=lxc_env['ca_cert'], timeout=5,
            )
            op.record(actual=f'http-{r.status_code}', ok=False,
                      response=r.text[:300])
        except (requests.exceptions.SSLError,
                requests.exceptions.ConnectionError) as e:
            op.record(actual='tls-handshake-fails', ok=True,
                      exception=type(e).__name__, message=str(e)[:200])


# ---------------------------------------------------------------------------
# 3. Valid mTLS cert (signed by CA's mTLS CA) but not enrolled → 401
# ---------------------------------------------------------------------------

@pytest.fixture(scope='module')
def unenrolled_valid_cert(lxc_env, tmp_path_factory):
    """Issue a valid mTLS client cert signed by the CA's mTLS CA but never
    record the subject in the enrollment store.
    """
    from mssh.ca import cert_minter
    d = tmp_path_factory.mktemp('unenrolled-valid')
    tls_ca_key = cert_minter.load_private_key(lxc_env['tls_ca_key'])
    tls_ca_cert = cert_minter.load_certificate(lxc_env['ca_cert'])
    issued = cert_minter.issue_client_cert(
        'unenrolled-attacker', tls_ca_key, tls_ca_cert,
        validity_days=30, key_type='ec',
    )
    (d / 'cert.pem').write_bytes(issued.cert_pem)
    (d / 'key.pem').write_bytes(issued.key_pem)
    os.chmod(d / 'key.pem', 0o600)
    return str(d / 'cert.pem'), str(d / 'key.pem')


def test_attack_valid_cert_unenrolled(lxc_env, unenrolled_valid_cert):
    """Cert is cryptographically valid, but the CN isn't in enrollment.yaml."""
    banner('Attack: valid mTLS cert with unenrolled subject')
    cert_path, key_path = unenrolled_valid_cert
    with OpsLog('attack', name='valid-unenrolled',
                expect='http-401-or-403') as op:
        r = _session().get(
            lxc_env['ca_url'] + '/v1/admin/admin/list',
            cert=(cert_path, key_path),
            verify=lxc_env['ca_cert'], timeout=5,
        )
        # Admin endpoint with unenrolled cert → 401 unauthorized.
        ok = r.status_code in (401, 403)
        op.record(actual=f'http-{r.status_code}', ok=ok,
                  body=r.text[:300])


def test_attack_valid_cert_unenrolled_on_authorize(lxc_env, unenrolled_valid_cert):
    """Same cert on /v1/authorize should also be rejected (unknown server)."""
    banner('Attack: valid unenrolled cert on /v1/authorize')
    cert_path, key_path = unenrolled_valid_cert
    body = {
        'identity': {'type': 'pubkey', 'data': 'AAAA'},     # invalid but it
                                                            # shouldn't matter
        'connection': {
            'source_ip': '10.0.0.1', 'source_port': 1234,
            'timestamp': _dt.datetime.now(_dt.timezone.utc)
                          .strftime('%Y-%m-%dT%H:%M:%SZ'),
        },
    }
    with OpsLog('attack', name='unenrolled-authorize',
                expect='http-401') as op:
        r = _session().post(
            lxc_env['ca_url'] + '/v1/authorize',
            json=body, cert=(cert_path, key_path),
            verify=lxc_env['ca_cert'], timeout=5,
        )
        ok = r.status_code == 401
        op.record(actual=f'http-{r.status_code}', ok=ok,
                  body=r.text[:300])


# ---------------------------------------------------------------------------
# 4. Bootstrap admin cert hitting /v1/authorize → 401 (admin, not server)
# ---------------------------------------------------------------------------

def test_attack_admin_cert_on_authorize(lxc_env):
    """Admin certs are only valid on /v1/admin/*; on /v1/authorize the CA
    looks up a SERVER record by mTLS subject and finds none → 401."""
    banner('Attack: bootstrap admin cert on /v1/authorize')
    body = {
        'identity': {'type': 'pubkey', 'data': 'AAAA'},
        'connection': {
            'source_ip': '10.0.0.1', 'source_port': 1234,
            'timestamp': _dt.datetime.now(_dt.timezone.utc)
                          .strftime('%Y-%m-%dT%H:%M:%SZ'),
        },
    }
    with OpsLog('attack', name='admin-on-authorize',
                expect='http-401') as op:
        r = _session().post(
            lxc_env['ca_url'] + '/v1/authorize',
            json=body,
            cert=(lxc_env['admin_cert'], lxc_env['admin_key']),
            verify=lxc_env['ca_cert'], timeout=5,
        )
        ok = r.status_code == 401
        op.record(actual=f'http-{r.status_code}', ok=ok,
                  body=r.text[:300])


# ---------------------------------------------------------------------------
# 5. Server cert hitting an admin endpoint → 401
# ---------------------------------------------------------------------------

def test_attack_server_cert_on_admin_endpoint(provisioned_env):
    """A server's mTLS cert is enrolled in the servers table, not the admins
    table. Calling /v1/admin/server/list with it must return 401 — the CA
    doesn't recognise the subject as an admin."""
    banner('Attack: server cert on /v1/admin/server/list')
    server_creds = next(iter(provisioned_env['server_creds'].values()))
    with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as fc:
        fc.write(server_creds['cert_pem'])
        cert_path = fc.name
    with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as fk:
        fk.write(server_creds['key_pem'])
        key_path = fk.name
    os.chmod(key_path, 0o600)
    try:
        with OpsLog('attack', name='server-on-admin',
                    expect='http-401') as op:
            r = _session().get(
                provisioned_env['ca_url'] + '/v1/admin/server/list',
                cert=(cert_path, key_path),
                verify=provisioned_env['ca_cert'], timeout=5,
            )
            ok = r.status_code == 401
            op.record(actual=f'http-{r.status_code}', ok=ok,
                      body=r.text[:300])
    finally:
        os.unlink(cert_path)
        os.unlink(key_path)


# ---------------------------------------------------------------------------
# 6. Wrong-role admin tries forbidden operation → 403
# ---------------------------------------------------------------------------

def test_attack_auditor_role_cannot_add_server(lxc_env):
    """Issue an auditor admin cert, then try to add a server with it.

    Auditor role permits read-only ops; server.add must return 403 forbidden.
    """
    banner('Attack: auditor role attempting server.add')
    from mssh.admin.client import CAClient, CAClientError
    superuser = CAClient(
        base_url=lxc_env['ca_url'],
        admin_cert=lxc_env['admin_cert'],
        admin_key=lxc_env['admin_key'],
        ca_cert=lxc_env['ca_cert'],
    )
    # Create the auditor admin (unique name to avoid colliding across runs).
    auditor_name = f'auditor-test-{_dt.datetime.utcnow():%H%M%S}'
    resp = superuser.admin_add(auditor_name, 'auditor')

    with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as fc:
        fc.write(resp['credentials']['cert_pem'])
        a_cert = fc.name
    with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as fk:
        fk.write(resp['credentials']['key_pem'])
        a_key = fk.name
    os.chmod(a_key, 0o600)

    auditor = CAClient(
        base_url=lxc_env['ca_url'], admin_cert=a_cert, admin_key=a_key,
        ca_cert=lxc_env['ca_cert'],
    )
    try:
        with OpsLog('attack', name='auditor-server-add',
                    expect='http-403') as op:
            try:
                auditor.server_add('forbidden-srv', [])
                op.record(actual='accepted', ok=False)
            except CAClientError as e:
                ok = e.status == 403
                op.record(actual=f'http-{e.status}', ok=ok,
                          body=str(e.body)[:300])
    finally:
        os.unlink(a_cert)
        os.unlink(a_key)
        superuser.admin_remove(auditor_name)
