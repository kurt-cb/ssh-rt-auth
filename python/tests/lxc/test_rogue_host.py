"""Rogue-host tests.

Models an attacker who controls a Unix box on the same network as the CA but
is *not* enrolled. Attempts to:

  1. Reach the CA's /v1/authorize without any mTLS cert.
  2. Forge an mTLS cert (self-signed) and try again.
  3. Steal a USER's private SSH key, then try to authorize it from a
     non-enrolled host — must fail because the attacker doesn't have a server
     mTLS cert.

All three paths must be blocked at the CA, demonstrating the project's
central property: a stolen user credential is useless without reaching the CA
through a valid server mTLS cert.
"""
from __future__ import annotations

import datetime as _dt
import os
import socket
import ssl

import pytest

from log_helpers import OpsLog, banner


pytestmark = pytest.mark.lxc


def _raw_tls_handshake(host: str, port: int, *,
                       client_cert: str | None = None,
                       client_key: str | None = None,
                       ca_bundle: str | None = None,
                       timeout: float = 5.0) -> tuple[bool, str]:
    """Raw TLS handshake (no HTTP). Returns (handshake_ok, diagnostic_text).

    We always disable hostname checking — we want the test to focus on
    *client-cert* acceptance, not server-cert hostname matching.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    if ca_bundle:
        ctx.load_verify_locations(cafile=ca_bundle)
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE
    if client_cert and client_key:
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        peer = ssock.getpeercert()
        ssock.close()
        return True, f'handshake ok; peer cert subject={peer.get("subject")}'
    except ssl.SSLError as e:
        return False, f'SSLError: {e}'
    except OSError as e:
        return False, f'OSError: {e}'


# ---------------------------------------------------------------------------
# 1. Rogue host without any cert can't even complete the handshake
# ---------------------------------------------------------------------------

def test_rogue_no_cert_handshake_fails(lxc_env):
    banner('Rogue host: no client cert (raw TLS handshake)')
    ips = lxc_env['ips']
    host, port = ips['mssh-lxc-ca'], 8443
    with OpsLog('rogue', name='no-cert',
                expect='handshake-fails') as op:
        ok, msg = _raw_tls_handshake(host, port, ca_bundle=lxc_env['ca_cert'])
        op.record(actual='handshake-ok' if ok else 'handshake-fails',
                  ok=(not ok), detail=msg[:300])


# ---------------------------------------------------------------------------
# 2. Rogue host with self-signed cert can't complete the handshake either
# ---------------------------------------------------------------------------

@pytest.fixture(scope='module')
def rogue_self_signed_cert(tmp_path_factory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509 import oid

    d = tmp_path_factory.mktemp('rogue-self-signed')
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME,
                                            'rogue-host.example')])
    now = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(99)
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(days=1))
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    (d / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / 'key.pem').write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    os.chmod(d / 'key.pem', 0o600)
    return str(d / 'cert.pem'), str(d / 'key.pem')


def test_rogue_self_signed_handshake_fails(lxc_env, rogue_self_signed_cert):
    banner('Rogue host: self-signed cert (raw TLS handshake)')
    ips = lxc_env['ips']
    host, port = ips['mssh-lxc-ca'], 8443
    cert_path, key_path = rogue_self_signed_cert
    with OpsLog('rogue', name='self-signed',
                expect='handshake-fails') as op:
        ok, msg = _raw_tls_handshake(
            host, port,
            client_cert=cert_path, client_key=key_path,
            ca_bundle=lxc_env['ca_cert'],
        )
        op.record(actual='handshake-ok' if ok else 'handshake-fails',
                  ok=(not ok), detail=msg[:300])


# ---------------------------------------------------------------------------
# 3. The central property: stolen user key is useless without server mTLS
# ---------------------------------------------------------------------------

def test_rogue_stolen_user_key_is_useless(provisioned_env, rogue_self_signed_cert):
    """An attacker exfiltrates a legitimate user's private SSH key. They try
    to authorize it from a rogue host that does not have a server mTLS cert.
    The CA must reject the request at the TLS layer."""
    import datetime as dt
    import requests
    import urllib3

    urllib3.disable_warnings()

    banner('Rogue host: stolen user key without server mTLS cert')
    cert_path, key_path = rogue_self_signed_cert
    # Pick any enrolled user's key (we don't actually need to send it correctly
    # — the TLS layer rejects us before we get to authorize).
    body = {
        'identity': {'type': 'pubkey', 'data': 'AAAA'},
        'connection': {
            'source_ip': '10.0.0.1', 'source_port': 5555,
            'timestamp': dt.datetime.now(dt.timezone.utc)
                          .strftime('%Y-%m-%dT%H:%M:%SZ'),
        },
    }
    s = requests.Session()
    s.trust_env = False
    with OpsLog('rogue', name='stolen-key-no-server-mtls',
                expect='request-rejected') as op:
        try:
            r = s.post(provisioned_env['ca_url'] + '/v1/authorize',
                       json=body,
                       cert=(cert_path, key_path),
                       verify=provisioned_env['ca_cert'], timeout=5)
            # If we somehow got an HTTP response, it should be 4xx/5xx, never
            # 200/granted.
            ok = r.status_code != 200 or 'granted' not in r.text
            op.record(actual=f'http-{r.status_code}', ok=ok,
                      body=r.text[:300])
        except (requests.exceptions.SSLError,
                requests.exceptions.ConnectionError) as e:
            op.record(actual='tls-handshake-fails', ok=True,
                      exception=type(e).__name__, message=str(e)[:200])
