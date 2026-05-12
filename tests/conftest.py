"""Shared test fixtures.

Shared utilities for generating Ed25519 SSH keys (raw blobs + OpenSSH wire),
minting test OpenSSH user certs, and constructing a CA in a tmpdir.
"""
from __future__ import annotations

import base64
import os
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

# Make the repo root importable.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Small SSH-key helpers (no shelling out)
# ---------------------------------------------------------------------------

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


def _ssh_string(b: bytes) -> bytes:
    return struct.pack('>I', len(b)) + b


def ed25519_pubkey_blob(pub: ed25519.Ed25519PublicKey) -> bytes:
    raw = pub.public_bytes(serialization.Encoding.Raw,
                           serialization.PublicFormat.Raw)
    return _ssh_string(b'ssh-ed25519') + _ssh_string(raw)


def rsa_pubkey_blob(pub: rsa.RSAPublicKey) -> bytes:
    nums = pub.public_numbers()
    def _mpint(n: int) -> bytes:
        nb = (n.bit_length() + 8) // 8 or 1
        body = n.to_bytes(nb, 'big', signed=False)
        if body[0] & 0x80:
            body = b'\x00' + body
        return _ssh_string(body)
    return _ssh_string(b'ssh-rsa') + _mpint(nums.e) + _mpint(nums.n)


@dataclass
class TestKey:
    private: ed25519.Ed25519PrivateKey
    public_blob: bytes
    fingerprint: str
    openssh_line: str       # "ssh-ed25519 AAAA... comment"
    private_pem: bytes

    @classmethod
    def generate(cls, comment: str = 'test') -> 'TestKey':
        key = ed25519.Ed25519PrivateKey.generate()
        blob = ed25519_pubkey_blob(key.public_key())
        from ca.identity_parser import sha256_fingerprint
        return cls(
            private=key,
            public_blob=blob,
            fingerprint=sha256_fingerprint(blob),
            openssh_line=f'ssh-ed25519 {base64.b64encode(blob).decode("ascii")} {comment}',
            private_pem=key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption()),
        )


@pytest.fixture
def test_key():
    return TestKey.generate('test')


@pytest.fixture
def test_keys():
    return [TestKey.generate(f'k{i}') for i in range(3)]


# ---------------------------------------------------------------------------
# CA / bootstrap fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def ca_dir(tmp_path):
    """A freshly bootstrapped CA directory (no Flask running yet)."""
    from ca.cert_minter import bootstrap_ca
    d = tmp_path / 'ca'
    bootstrap_ca(d, tls_server_sans=['DNS:localhost', 'IP:127.0.0.1'])
    # Seed enrollment file with bootstrap admin (as the CLI's `init` does).
    import yaml
    enroll = {
        'admins': {
            'bootstrap-admin': {
                'role': 'superuser',
                'mtls_subject': 'CN=bootstrap-admin',
                'enrolled_at': '',
                'enrolled_by': 'init',
            }
        }
    }
    (d / 'enrollment.yaml').write_text(yaml.safe_dump(enroll, sort_keys=True))
    (d / 'audit.jsonl').write_text('')
    return d


@pytest.fixture
def ca_config_path(ca_dir):
    """Write a CA YAML config pointing to the bootstrapped CA."""
    import yaml
    cfg = {
        'listen': '127.0.0.1:0',
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
    }
    p = ca_dir / 'ca-config.yaml'
    p.write_text(yaml.safe_dump(cfg, sort_keys=True))
    return p
