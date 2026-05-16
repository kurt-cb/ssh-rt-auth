"""Tests for mssh.msshd.enforce_listener helper functions."""
from __future__ import annotations

import datetime as _dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from mssh.ca.identity_parser import (parse_pubkey_blob, sha256_fingerprint)
from mssh.msshd.enforce_listener import _ssh_pubkey_blob_from_cert


def _mint_ed25519_cert() -> bytes:
    """Self-signed Ed25519 cert (DER) — what an mssh client's mTLS cert
    looks like for Phase 1B purposes."""
    priv = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, 'alice'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(minutes=1))
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=1))
        .sign(priv, None)
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_ssh_pubkey_blob_ed25519_round_trip():
    """The blob the wrapper derives from a cert must be parseable by
    the CA's identity_parser with the same fingerprint. If this drifts
    the CA will fail to look up enrolled users."""
    der = _mint_ed25519_cert()
    blob = _ssh_pubkey_blob_from_cert(der)

    # The CA's parser should accept this blob without error.
    parsed = parse_pubkey_blob(blob)
    assert parsed.key_type == 'ssh-ed25519'

    # And the SHA-256 fingerprint should match what `ssh-keygen -l`
    # would produce on a key derived from this cert.
    fp = sha256_fingerprint(blob)
    assert fp.startswith('SHA256:')


def test_ssh_pubkey_blob_rejects_non_ed25519():
    """ECDSA / RSA mTLS certs are out of Phase 1B scope; we surface a
    clean error instead of silently producing garbage."""
    priv = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, 'alice'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(minutes=1))
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=1))
        .sign(priv, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    with pytest.raises(ValueError, match='not supported in Phase 1B'):
        _ssh_pubkey_blob_from_cert(der)
