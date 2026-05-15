"""Unit tests for the shim cache and end-to-end shim behavior (mocked CA)."""
from __future__ import annotations

import base64
import datetime as _dt
from unittest.mock import MagicMock, patch

import pytest

from sshrt.shim.ca_client import AuthorizeResult, CAClientFailedOver
from sshrt.shim.cache import CacheEntry, CertCache
from sshrt.shim.shim import STATUS_AUTHORIZED, STATUS_DENIED, STATUS_ERROR


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def test_cache_hit_miss():
    c = CertCache(max_entries=10)
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    e = CacheEntry(cert_der=b'x', serial='s',
                   not_after=now + _dt.timedelta(seconds=60),
                   created_at=now)
    c.put('fp1', '10.0.0.1', e)
    assert c.get('fp1', '10.0.0.1') is e
    assert c.get('fp1', '10.0.0.2') is None
    assert c.get('fp2', '10.0.0.1') is None


def test_cache_expiry_evicts():
    c = CertCache()
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    e = CacheEntry(cert_der=b'x', serial='s',
                   not_after=now - _dt.timedelta(seconds=1),
                   created_at=now)
    c.put('fp1', '10.0.0.1', e)
    assert c.get('fp1', '10.0.0.1') is None
    assert len(c) == 0


def test_cache_lru_eviction():
    c = CertCache(max_entries=2)
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    future = now + _dt.timedelta(minutes=1)
    for i in range(3):
        c.put(f'fp{i}', '10.0.0.1',
              CacheEntry(b'x', 's', future, now))
    # fp0 should have been evicted.
    assert c.get('fp0', '10.0.0.1') is None
    assert c.get('fp1', '10.0.0.1') is not None
    assert c.get('fp2', '10.0.0.1') is not None


# ---------------------------------------------------------------------------
# Shim end-to-end (mocked CA client)
# ---------------------------------------------------------------------------

def _make_shim(ca_dir, monkeypatch):
    """Build a Shim with all certs from ca_dir and a stubbed CA client."""
    from sshrt.shim.config import ShimConfig
    from sshrt.shim.shim import Shim
    # Re-use the bootstrap admin's mTLS cert as the "server" mTLS cert just to
    # have a real key pair on disk. The shim never actually connects in tests.
    cfg = ShimConfig(
        ca_endpoints=['https://127.0.0.1:65535'],
        mtls_cert=str(ca_dir / 'bootstrap-admin-cert.pem'),
        mtls_key=str(ca_dir / 'bootstrap-admin-key.pem'),
        ca_trust_root=str(ca_dir / 'tls-ca-cert.pem'),
        auth_trust_root=str(ca_dir / 'signing-cert.pem'),
        server_name='srv1',
    )
    return Shim(cfg)


def test_shim_returns_authorized_and_caches(ca_dir, test_key, monkeypatch):
    from sshrt.ca import cert_minter
    from cryptography.hazmat.primitives import serialization

    shim = _make_shim(ca_dir, monkeypatch)

    # Mint a real cert so the shim's verifier passes.
    signing_key = cert_minter.load_private_key(ca_dir / 'signing-key.pem')
    signing_cert = cert_minter.load_certificate(ca_dir / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, serial = cert_minter.mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now - _dt.timedelta(minutes=1),
        not_after=now + _dt.timedelta(minutes=30),
        source_bind='10.0.0.5', server_bind='srv1',
        channels=['session'],
    )
    der = cert.public_bytes(serialization.Encoding.DER)

    granted = AuthorizeResult(
        status='granted', http_status=200,
        body={'status': 'granted',
              'cert': base64.b64encode(der).decode('ascii'),
              'serial': serial,
              'not_after': (now + _dt.timedelta(minutes=30))
                           .strftime('%Y-%m-%dT%H:%M:%SZ')})
    shim.ca_client.authorize = MagicMock(return_value=granted)

    out = shim.authorize('pubkey', test_key.public_blob,
                         '10.0.0.5', 1234, int(now.timestamp()))
    assert out.status == STATUS_AUTHORIZED
    assert out.serial == serial

    # Second call should be a cache hit.
    out2 = shim.authorize('pubkey', test_key.public_blob,
                          '10.0.0.5', 1234, int(now.timestamp()))
    assert out2.cache_hit
    assert shim.ca_client.authorize.call_count == 1


def test_shim_denial_passthrough(ca_dir, test_key):
    shim = _make_shim(ca_dir, None)
    shim.ca_client.authorize = MagicMock(return_value=AuthorizeResult(
        status='denied', http_status=403,
        body={'status': 'denied', 'reason': 'unknown_identity',
              'detail': 'nope'}))
    out = shim.authorize('pubkey', test_key.public_blob,
                         '10.0.0.5', 1234,
                         int(_dt.datetime.now(tz=_dt.timezone.utc).timestamp()))
    assert out.status == STATUS_DENIED
    assert out.deny_reason == 'unknown_identity'


def test_shim_failover_returns_error(ca_dir, test_key):
    shim = _make_shim(ca_dir, None)
    shim.ca_client.authorize = MagicMock(
        side_effect=CAClientFailedOver('all down'))
    out = shim.authorize('pubkey', test_key.public_blob,
                         '10.0.0.5', 1234,
                         int(_dt.datetime.now(tz=_dt.timezone.utc).timestamp()))
    assert out.status == STATUS_ERROR
    assert 'unreachable' in out.detail


def test_shim_rejects_invalid_cert(ca_dir, test_key):
    """Defense in depth: if the CA returns garbage in the cert field, reject."""
    shim = _make_shim(ca_dir, None)
    shim.ca_client.authorize = MagicMock(return_value=AuthorizeResult(
        status='granted', http_status=200,
        body={'status': 'granted',
              'cert': base64.b64encode(b'not-a-cert').decode('ascii'),
              'serial': 'aa', 'not_after': '2099-01-01T00:00:00Z'}))
    out = shim.authorize('pubkey', test_key.public_blob,
                         '10.0.0.5', 1234,
                         int(_dt.datetime.now(tz=_dt.timezone.utc).timestamp()))
    assert out.status == STATUS_ERROR
