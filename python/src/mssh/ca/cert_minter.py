"""Generate keys and mint X.509 certs.

Two responsibilities:
1. CA bootstrap (signing key + self-signed root, TLS server cert, mTLS-CA cert,
   issued mTLS client certs for servers and admins).
2. Authorization-cert minting (X.509 with custom policy extensions, signed by
   the authorization signing key).
"""
from __future__ import annotations

import datetime as _dt
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509 import oid

# OID arc for custom extensions. 1.3.6.1.4.1.55555 is a PoC placeholder under
# the private-enterprise-number arc (55555 is not officially assigned; that's
# fine for the PoC, the design doc says XXXXX TBD).
_OID_BASE = '1.3.6.1.4.1.55555.1'
OID_SOURCE_BIND     = x509.ObjectIdentifier(f'{_OID_BASE}.1')
OID_SERVER_BIND     = x509.ObjectIdentifier(f'{_OID_BASE}.2')
OID_CHANNEL_POLICY  = x509.ObjectIdentifier(f'{_OID_BASE}.3')
OID_FORCE_COMMAND   = x509.ObjectIdentifier(f'{_OID_BASE}.4')
OID_ENVIRONMENT     = x509.ObjectIdentifier(f'{_OID_BASE}.5')
OID_MAX_SESSION     = x509.ObjectIdentifier(f'{_OID_BASE}.6')
OID_2FA_EVIDENCE    = x509.ObjectIdentifier(f'{_OID_BASE}.7')


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_signing_key(key_type: str = 'ed25519'):
    if key_type == 'ed25519':
        return ed25519.Ed25519PrivateKey.generate()
    if key_type == 'ec':
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == 'rsa':
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raise ValueError(f'unknown key type: {key_type}')


def _sig_hash_for(key) -> hashes.HashAlgorithm | None:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return None
    return hashes.SHA256()


def serialize_private_key(key, password: bytes | None = None) -> bytes:
    enc = (serialization.BestAvailableEncryption(password) if password
           else serialization.NoEncryption())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def load_private_key(path: str | Path, password: bytes | None = None):
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=password)


def serialize_certificate(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def load_certificate(path: str | Path) -> x509.Certificate:
    data = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(data)


# ---------------------------------------------------------------------------
# CA bootstrap
# ---------------------------------------------------------------------------

@dataclass
class BootstrapArtifacts:
    signing_key_pem: bytes
    signing_cert_pem: bytes        # authorization trust root
    tls_ca_cert_pem: bytes         # signs server/admin mTLS certs
    tls_ca_key_pem: bytes
    tls_server_cert_pem: bytes     # CA's own listener cert
    tls_server_key_pem: bytes
    bootstrap_admin_cert_pem: bytes
    bootstrap_admin_key_pem: bytes
    bootstrap_admin_subject: str


def _self_signed(subject_cn: str, key, validity_days: int = 3650,
                 is_ca: bool = True) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, subject_cn)])
    not_before = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(minutes=1)
    not_after = not_before + _dt.timedelta(days=validity_days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(secrets.token_bytes(16), 'big') | 1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    return builder.sign(private_key=key, algorithm=_sig_hash_for(key))


def _issue_leaf(subject_cn: str, leaf_key, ca_key, ca_cert: x509.Certificate,
                validity_days: int = 365,
                server_auth: bool = False, client_auth: bool = True,
                sans: list[str] | None = None) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, subject_cn)])
    not_before = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(minutes=1)
    not_after = not_before + _dt.timedelta(days=validity_days)
    eku = []
    if server_auth:
        eku.append(oid.ExtendedKeyUsageOID.SERVER_AUTH)
    if client_auth:
        eku.append(oid.ExtendedKeyUsageOID.CLIENT_AUTH)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(int.from_bytes(secrets.token_bytes(16), 'big') | 1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                       critical=False)
    )
    san_entries: list[x509.GeneralName] = []
    if sans:
        for s in sans:
            # Accept "DNS:..." / "IP:..." / bare string (treated as DNS).
            if s.startswith('IP:'):
                import ipaddress
                san_entries.append(x509.IPAddress(ipaddress.ip_address(s[3:])))
            elif s.startswith('DNS:'):
                san_entries.append(x509.DNSName(s[4:]))
            else:
                san_entries.append(x509.DNSName(s))
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False)
    return builder.sign(private_key=ca_key, algorithm=_sig_hash_for(ca_key))


def bootstrap_ca(ca_dir: str | Path, *, key_type: str = 'ec',
                 mtls_key_type: str = 'ec',
                 bootstrap_admin_cn: str = 'bootstrap-admin',
                 tls_server_cn: str = 'ssh-rt-auth-ca',
                 tls_server_sans: list[str] | None = None) -> BootstrapArtifacts:
    """First-time init: create the CA's keys, root certs, and bootstrap admin.

    Writes everything into ``ca_dir`` and returns the in-memory PEMs.
    """
    ca_dir = Path(ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)

    # Authorization signing key (signs short-lived X.509 authorization certs).
    signing_key = generate_signing_key(key_type)
    signing_cert = _self_signed('ssh-rt-auth-authorization-root', signing_key)

    # mTLS CA (signs server + admin client certs and the CA's TLS server cert).
    tls_ca_key = generate_signing_key(mtls_key_type)
    tls_ca_cert = _self_signed('ssh-rt-auth-mtls-root', tls_ca_key)

    # CA's TLS server cert (what shims/admins see when connecting).
    tls_server_key = generate_signing_key(mtls_key_type)
    tls_server_cert = _issue_leaf(
        tls_server_cn, tls_server_key, tls_ca_key, tls_ca_cert,
        server_auth=True, client_auth=False,
        sans=tls_server_sans or ['DNS:localhost', 'IP:127.0.0.1'],
    )

    # Bootstrap superuser admin cert.
    boot_admin_key = generate_signing_key(mtls_key_type)
    boot_admin_cert = _issue_leaf(
        bootstrap_admin_cn, boot_admin_key, tls_ca_key, tls_ca_cert,
        server_auth=False, client_auth=True,
    )

    artifacts = BootstrapArtifacts(
        signing_key_pem=serialize_private_key(signing_key),
        signing_cert_pem=serialize_certificate(signing_cert),
        tls_ca_cert_pem=serialize_certificate(tls_ca_cert),
        tls_ca_key_pem=serialize_private_key(tls_ca_key),
        tls_server_cert_pem=serialize_certificate(tls_server_cert),
        tls_server_key_pem=serialize_private_key(tls_server_key),
        bootstrap_admin_cert_pem=serialize_certificate(boot_admin_cert),
        bootstrap_admin_key_pem=serialize_private_key(boot_admin_key),
        bootstrap_admin_subject=f'CN={bootstrap_admin_cn}',
    )

    # Persist.
    (ca_dir / 'signing-key.pem').write_bytes(artifacts.signing_key_pem)
    (ca_dir / 'signing-cert.pem').write_bytes(artifacts.signing_cert_pem)
    (ca_dir / 'tls-ca-cert.pem').write_bytes(artifacts.tls_ca_cert_pem)
    (ca_dir / 'tls-ca-key.pem').write_bytes(artifacts.tls_ca_key_pem)
    (ca_dir / 'tls-server-cert.pem').write_bytes(artifacts.tls_server_cert_pem)
    (ca_dir / 'tls-server-key.pem').write_bytes(artifacts.tls_server_key_pem)
    (ca_dir / 'bootstrap-admin-cert.pem').write_bytes(artifacts.bootstrap_admin_cert_pem)
    (ca_dir / 'bootstrap-admin-key.pem').write_bytes(artifacts.bootstrap_admin_key_pem)
    for p in [
        'signing-key.pem', 'tls-ca-key.pem', 'tls-server-key.pem',
        'bootstrap-admin-key.pem',
    ]:
        os.chmod(ca_dir / p, 0o600)
    return artifacts


# ---------------------------------------------------------------------------
# Server / admin mTLS cert issuance
# ---------------------------------------------------------------------------

@dataclass
class IssuedClientCert:
    cert_pem: bytes
    key_pem: bytes
    ca_cert_pem: bytes
    subject_cn: str


def issue_client_cert(common_name: str, tls_ca_key, tls_ca_cert: x509.Certificate,
                      *, validity_days: int = 365,
                      key_type: str = 'ec') -> IssuedClientCert:
    key = generate_signing_key(key_type)
    cert = _issue_leaf(common_name, key, tls_ca_key, tls_ca_cert,
                       validity_days=validity_days,
                       server_auth=False, client_auth=True)
    return IssuedClientCert(
        cert_pem=serialize_certificate(cert),
        key_pem=serialize_private_key(key),
        ca_cert_pem=serialize_certificate(tls_ca_cert),
        subject_cn=common_name,
    )


# ---------------------------------------------------------------------------
# Authorization cert minting
# ---------------------------------------------------------------------------

def _load_ssh_pub_from_blob(blob: bytes):
    """cryptography's load_ssh_public_key takes "ssh-rsa AAAA... comment" format.

    We have just the raw SSH wire blob, so wrap it in a one-line ssh format.
    """
    import base64 as _b64
    from .identity_parser import parse_pubkey_blob
    info = parse_pubkey_blob(blob)
    line = f'{info.key_type} {_b64.b64encode(blob).decode("ascii")}'.encode('ascii')
    return serialization.load_ssh_public_key(line)


def mint_authorization_cert(
    *,
    subject_username: str,
    subject_pubkey_blob: bytes,
    signing_key,
    signing_cert: x509.Certificate,
    not_before: _dt.datetime,
    not_after: _dt.datetime,
    source_bind: str,
    server_bind: str,
    channels: list[str],
    force_command: str | None = None,
    environment: dict[str, str] | None = None,
    max_session_seconds: int | None = None,
    two_fa_evidence: str | None = None,
) -> tuple[x509.Certificate, str]:
    """Mint an X.509 authorization cert.

    Returns (cert, serial_hex).
    """
    subject = x509.Name([
        x509.NameAttribute(oid.NameOID.COMMON_NAME, subject_username),
        x509.NameAttribute(oid.NameOID.ORGANIZATION_NAME, 'ssh-rt-auth'),
    ])
    serial_int = int.from_bytes(secrets.token_bytes(16), 'big') | 1
    serial_hex = format(serial_int, 'x')
    pub = _load_ssh_pub_from_blob(subject_pubkey_blob)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(signing_cert.subject)
        .public_key(pub)
        .serial_number(serial_int)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # Critical policy extensions
        .add_extension(_utf8_ext(OID_SOURCE_BIND, source_bind), critical=True)
        .add_extension(_utf8_ext(OID_SERVER_BIND, server_bind), critical=True)
        .add_extension(_seq_utf8_ext(OID_CHANNEL_POLICY, sorted(channels)), critical=True)
    )
    if force_command:
        builder = builder.add_extension(
            _utf8_ext(OID_FORCE_COMMAND, force_command), critical=False)
    if environment:
        kv = [f'{k}={v}' for k, v in sorted(environment.items())]
        builder = builder.add_extension(
            _seq_utf8_ext(OID_ENVIRONMENT, kv), critical=False)
    if max_session_seconds is not None:
        builder = builder.add_extension(
            _int_ext(OID_MAX_SESSION, max_session_seconds), critical=False)
    if two_fa_evidence:
        builder = builder.add_extension(
            _utf8_ext(OID_2FA_EVIDENCE, two_fa_evidence), critical=False)

    cert = builder.sign(private_key=signing_key, algorithm=_sig_hash_for(signing_key))
    return cert, serial_hex


# ---------------------------------------------------------------------------
# ASN.1 helpers for custom extensions (minimal DER hand-rolling).
# ---------------------------------------------------------------------------

def _utf8_ext(oid_: x509.ObjectIdentifier, value: str) -> x509.UnrecognizedExtension:
    return x509.UnrecognizedExtension(oid_, _der_utf8(value))


def _seq_utf8_ext(oid_: x509.ObjectIdentifier,
                  values: list[str]) -> x509.UnrecognizedExtension:
    body = b''.join(_der_utf8(v) for v in values)
    return x509.UnrecognizedExtension(oid_, _der_tag(0x30, body))  # SEQUENCE


def _int_ext(oid_: x509.ObjectIdentifier, value: int) -> x509.UnrecognizedExtension:
    return x509.UnrecognizedExtension(oid_, _der_int(value))


def _der_tag(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    length_bytes = []
    n = len(body)
    while n:
        length_bytes.insert(0, n & 0xff)
        n >>= 8
    return bytes([tag, 0x80 | len(length_bytes)]) + bytes(length_bytes) + body


def _der_utf8(s: str) -> bytes:
    return _der_tag(0x0c, s.encode('utf-8'))     # UTF8String


def _der_int(n: int) -> bytes:
    if n == 0:
        body = b'\x00'
    else:
        nb = (n.bit_length() + 8) // 8
        body = n.to_bytes(nb, 'big', signed=False)
        if body[0] & 0x80:
            body = b'\x00' + body
    return _der_tag(0x02, body)
