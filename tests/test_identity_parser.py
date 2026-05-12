"""Unit tests for ca/identity_parser.py."""
from __future__ import annotations

import base64
import struct

import pytest

from ca.identity_parser import (CertIdentity, IdentityParseError, PubkeyIdentity,
                                parse_identity, parse_openssh_cert,
                                parse_pubkey_blob, sha256_fingerprint)


def test_sha256_fingerprint_format():
    fp = sha256_fingerprint(b'hello world')
    assert fp.startswith('SHA256:')
    # The base64 body should be url-safe-ish; OpenSSH style strips padding.
    assert '=' not in fp


def test_parse_pubkey_blob_ed25519(test_key):
    info = parse_pubkey_blob(test_key.public_blob)
    assert isinstance(info, PubkeyIdentity)
    assert info.key_type == 'ssh-ed25519'
    assert info.fingerprint == test_key.fingerprint


def test_parse_pubkey_rejects_cert(test_key):
    # Manually fabricate a cert-type blob.
    fake_blob = struct.pack('>I', len('ssh-ed25519-cert-v01@openssh.com')) \
        + b'ssh-ed25519-cert-v01@openssh.com'
    with pytest.raises(IdentityParseError):
        parse_pubkey_blob(fake_blob)


def test_parse_identity_dispatch(test_key):
    info = parse_identity('pubkey', test_key.public_blob)
    assert isinstance(info, PubkeyIdentity)
    with pytest.raises(IdentityParseError):
        parse_identity('unknown-type', b'x')


def test_parse_pubkey_rejects_empty():
    with pytest.raises(IdentityParseError):
        parse_pubkey_blob(b'')


def test_parse_pubkey_rejects_truncated():
    # 4-byte length header claims 100 bytes follow, but we give 0.
    bad = struct.pack('>I', 100)
    with pytest.raises(IdentityParseError):
        parse_pubkey_blob(bad)


def test_parse_openssh_cert_via_ssh_keygen(tmp_path):
    """Use ssh-keygen to mint a real cert and parse it."""
    import shutil
    if shutil.which('ssh-keygen') is None:
        pytest.skip('ssh-keygen not available')
    import subprocess
    # CA key
    ca_priv = tmp_path / 'ca'
    subprocess.run(['ssh-keygen', '-t', 'ed25519', '-f', str(ca_priv),
                    '-N', '', '-C', 'ca'], check=True, capture_output=True)
    # User key
    user_priv = tmp_path / 'user'
    subprocess.run(['ssh-keygen', '-t', 'ed25519', '-f', str(user_priv),
                    '-N', '', '-C', 'user'], check=True, capture_output=True)
    # Sign user pubkey as a user cert with key_id "alice@example", principals=alice
    subprocess.run([
        'ssh-keygen', '-s', str(ca_priv),
        '-I', 'alice@example',
        '-n', 'alice',
        '-V', '+1h',
        str(user_priv) + '.pub',
    ], check=True, capture_output=True)
    cert_line = (tmp_path / 'user-cert.pub').read_text().strip()
    parts = cert_line.split()
    blob = base64.b64decode(parts[1])
    info = parse_openssh_cert(blob)
    assert isinstance(info, CertIdentity)
    assert info.key_type == 'ssh-ed25519-cert-v01@openssh.com'
    assert info.key_id == 'alice@example'
    assert info.principals == ['alice']
    assert info.cert_type == 1
    # signature_key_fingerprint should equal the CA's pubkey fingerprint
    from ca.identity_parser import sha256_fingerprint
    ca_pub_line = (tmp_path / 'ca.pub').read_text().strip().split()
    ca_pub_blob = base64.b64decode(ca_pub_line[1])
    assert info.signature_key_fingerprint == sha256_fingerprint(ca_pub_blob)
