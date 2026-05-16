"""Unit tests for the authorize handler (logic-only, no HTTP)."""
from __future__ import annotations

import base64
import datetime as _dt
from pathlib import Path

import pytest

from mssh.ca import authorize, cert_minter
from mssh.ca.audit import AuditLog
from mssh.ca.authorize import AuthorizeContext, handle_authorize
from mssh.ca.enrollment import Enrollment, KeyBinding


def _b64(b): return base64.b64encode(b).decode('ascii')


def _ts_now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


@pytest.fixture
def ctx(tmp_path, ca_dir):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    signing_key = cert_minter.load_private_key(ca_dir / 'signing-key.pem')
    signing_cert = cert_minter.load_certificate(ca_dir / 'signing-cert.pem')
    return AuthorizeContext(
        enrollment=enroll, audit=audit,
        signing_key=signing_key, signing_cert=signing_cert,
        identity_trust_root_fingerprints=set(),
        default_max_cert_validity_seconds=3600,
        timestamp_drift_seconds=3600,
    )


def _basic_setup(ctx, test_key):
    ctx.enrollment.add_server('srv1', 'CN=srv1', ['prod'])
    ctx.enrollment.add_user('alice')
    ctx.enrollment.add_user_key('alice',
        KeyBinding(test_key.fingerprint, 'pubkey', 'ssh-ed25519'))
    ctx.enrollment.add_policy('alice', {
        'servers': ['srv1'], 'channels': ['session', 'direct-tcpip'],
        'max_cert_validity_seconds': 1800,
    })


def test_unknown_server_rejected(ctx, test_key):
    _basic_setup(ctx, test_key)
    status, body = handle_authorize(ctx, 'CN=ghost', _body(test_key))
    assert status == 401
    assert body['status'] == 'denied'


def test_unknown_identity_rejected(ctx, test_key):
    ctx.enrollment.add_server('srv1', 'CN=srv1', [])
    status, body = handle_authorize(ctx, 'CN=srv1', _body(test_key))
    assert status == 403
    assert body['reason'] == 'unknown_identity'


def test_grant_basic_flow(ctx, test_key):
    _basic_setup(ctx, test_key)
    status, body = handle_authorize(ctx, 'CN=srv1', _body(test_key))
    assert status == 200, body
    assert body['status'] == 'granted'
    assert body['policy_summary']['server_bind'] == 'srv1'
    assert 'session' in body['policy_summary']['channels']
    # And we got a real cert back.
    der = base64.b64decode(body['cert'])
    from cryptography import x509
    from cryptography.x509 import oid
    cert = x509.load_der_x509_certificate(der)
    cn = cert.subject.get_attributes_for_oid(oid.NameOID.COMMON_NAME)
    assert cn and cn[0].value == 'alice'


def test_grant_writes_audit(ctx, test_key):
    _basic_setup(ctx, test_key)
    handle_authorize(ctx, 'CN=srv1', _body(test_key))
    entries = ctx.audit.read_all()
    assert any(e.get('decision') == 'granted' for e in entries)


def test_source_cidr_deny_path(ctx, test_key):
    ctx.enrollment.add_server('srv1', 'CN=srv1', [])
    ctx.enrollment.add_user('alice')
    ctx.enrollment.add_user_key('alice',
        KeyBinding(test_key.fingerprint, 'pubkey', 'ssh-ed25519'))
    ctx.enrollment.add_policy('alice', {
        'servers': ['srv1'], 'channels': ['session'],
        'source_cidrs': ['10.0.0.0/8'],
    })
    body = _body(test_key, source_ip='192.168.1.1')
    status, resp = handle_authorize(ctx, 'CN=srv1', body)
    assert status == 403
    assert resp['reason'] == 'source_denied'


def test_clock_drift_rejected(ctx, test_key):
    _basic_setup(ctx, test_key)
    # Override the per-test drift limit.
    ctx.timestamp_drift_seconds = 1
    far = (_dt.datetime.now(tz=_dt.timezone.utc)
           + _dt.timedelta(seconds=120)).strftime('%Y-%m-%dT%H:%M:%SZ')
    body = _body(test_key, timestamp=far)
    status, resp = handle_authorize(ctx, 'CN=srv1', body)
    assert status == 403
    assert resp['reason'] == 'clock_drift'


def test_bad_request(ctx):
    status, resp = handle_authorize(ctx, 'CN=srv1', {})
    assert status in (401, 500)        # unknown server beats parse error


def _body(test_key, *, source_ip='10.0.0.1', source_port=12345,
          timestamp=None, channels=None) -> dict:
    return {
        'identity': {
            'type': 'pubkey',
            'data': _b64(test_key.public_blob),
        },
        'connection': {
            'source_ip': source_ip,
            'source_port': source_port,
            'timestamp': timestamp or _ts_now(),
        },
        **({'requested_channels': channels} if channels is not None else {}),
    }
