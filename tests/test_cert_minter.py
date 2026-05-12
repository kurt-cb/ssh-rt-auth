"""Unit tests for ca/cert_minter.py — bootstrap and authorization-cert minting."""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ca.cert_minter import (OID_CHANNEL_POLICY, OID_SERVER_BIND,
                            OID_SOURCE_BIND, bootstrap_ca, issue_client_cert,
                            load_certificate, load_private_key,
                            mint_authorization_cert)


def test_bootstrap_produces_files(tmp_path):
    d = tmp_path / 'ca'
    artifacts = bootstrap_ca(d)
    for f in [
        'signing-key.pem', 'signing-cert.pem',
        'tls-ca-cert.pem', 'tls-ca-key.pem',
        'tls-server-cert.pem', 'tls-server-key.pem',
        'bootstrap-admin-cert.pem', 'bootstrap-admin-key.pem',
    ]:
        assert (d / f).exists(), f
    # Bootstrap admin cert subject CN matches what we expect.
    assert artifacts.bootstrap_admin_subject == 'CN=bootstrap-admin'


def test_issue_client_cert_chain(tmp_path):
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    tls_ca_key = load_private_key(d / 'tls-ca-key.pem')
    tls_ca_cert = load_certificate(d / 'tls-ca-cert.pem')
    issued = issue_client_cert('srv1', tls_ca_key, tls_ca_cert)
    cert = x509.load_pem_x509_certificate(issued.cert_pem)
    assert cert.subject.rfc4514_string() == 'CN=srv1'
    assert cert.issuer == tls_ca_cert.subject


def test_mint_authorization_cert_extensions(tmp_path, test_key):
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, serial = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session', 'direct-tcpip'],
        force_command='/bin/echo',
    )
    assert serial
    # Inspect extensions.
    oids = {ext.oid.dotted_string: ext for ext in cert.extensions}
    assert OID_SOURCE_BIND.dotted_string in oids
    assert OID_SERVER_BIND.dotted_string in oids
    assert OID_CHANNEL_POLICY.dotted_string in oids
    # Source-bind extension is critical.
    assert oids[OID_SOURCE_BIND.dotted_string].critical


def test_mint_authorization_cert_signature_verifies(tmp_path, test_key):
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _ = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session'],
    )
    # Use the shim's verifier (defense in depth path).
    from shim.shim import _verify_cert_signed_by
    assert _verify_cert_signed_by(cert, signing_cert)
