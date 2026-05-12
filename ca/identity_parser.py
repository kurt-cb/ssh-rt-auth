"""Parse SSH public-key and OpenSSH-cert blobs.

The CA parses raw identity blobs forwarded by the shim. sshd does not parse
these — it only validates the signature against the blob.
"""
from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass


# OpenSSH cert key-types end in "-cert-v01@openssh.com".
_CERT_SUFFIX = '-cert-v01@openssh.com'


class IdentityParseError(ValueError):
    """Raised when an identity blob cannot be parsed."""


@dataclass
class PubkeyIdentity:
    key_type: str            # e.g. "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"
    raw_blob: bytes          # the SSH wire-format public key
    fingerprint: str         # "SHA256:<base64-of-sha256>"


@dataclass
class CertIdentity:
    key_type: str            # e.g. "ssh-ed25519-cert-v01@openssh.com"
    raw_blob: bytes          # full cert blob
    fingerprint: str         # SHA256 fingerprint of the cert's public key blob
    nonce: bytes
    public_key_blob: bytes   # the cert's embedded public key (wire format, with type prefix)
    serial: int
    cert_type: int           # 1 = user, 2 = host
    key_id: str
    principals: list[str]
    valid_after: int         # unix seconds
    valid_before: int        # unix seconds
    critical_options: dict[str, str]
    extensions: dict[str, str]
    signature_key_blob: bytes
    signature_key_fingerprint: str
    signed_bytes: bytes      # cert bytes up to but not including the signature
    signature: bytes


def _read_uint32(buf: memoryview, pos: int) -> tuple[int, int]:
    if pos + 4 > len(buf):
        raise IdentityParseError('truncated uint32')
    return struct.unpack('>I', bytes(buf[pos:pos + 4]))[0], pos + 4


def _read_uint64(buf: memoryview, pos: int) -> tuple[int, int]:
    if pos + 8 > len(buf):
        raise IdentityParseError('truncated uint64')
    return struct.unpack('>Q', bytes(buf[pos:pos + 8]))[0], pos + 8


def _read_string(buf: memoryview, pos: int) -> tuple[bytes, int]:
    length, pos = _read_uint32(buf, pos)
    if pos + length > len(buf):
        raise IdentityParseError(f'truncated string (need {length}, have {len(buf) - pos})')
    return bytes(buf[pos:pos + length]), pos + length


def _read_string_utf8(buf: memoryview, pos: int) -> tuple[str, int]:
    data, pos = _read_string(buf, pos)
    return data.decode('utf-8', errors='replace'), pos


def sha256_fingerprint(blob: bytes) -> str:
    """OpenSSH-style SHA256 fingerprint: SHA256:<base64-without-padding>."""
    digest = hashlib.sha256(blob).digest()
    b64 = base64.b64encode(digest).decode('ascii').rstrip('=')
    return f'SHA256:{b64}'


def _parse_kv_pairs(buf: bytes) -> dict[str, str]:
    """Parse the critical-options / extensions section of an OpenSSH cert.

    Each entry: string name, string data (the data is an SSH string that may
    contain a UTF-8 value, e.g. force-command's argument).
    """
    out: dict[str, str] = {}
    mv = memoryview(buf)
    pos = 0
    while pos < len(mv):
        name, pos = _read_string_utf8(mv, pos)
        data, pos = _read_string(mv, pos)
        if data:
            # Most option values are themselves an SSH string.
            try:
                inner_mv = memoryview(data)
                value, _ = _read_string_utf8(inner_mv, 0)
            except IdentityParseError:
                value = data.decode('utf-8', errors='replace')
        else:
            value = ''
        out[name] = value
    return out


def parse_pubkey_blob(blob: bytes) -> PubkeyIdentity:
    """Parse a bare SSH public key blob (wire format)."""
    if not blob:
        raise IdentityParseError('empty pubkey blob')
    mv = memoryview(blob)
    key_type_b, _ = _read_string(mv, 0)
    key_type = key_type_b.decode('ascii', errors='replace')
    if key_type.endswith(_CERT_SUFFIX):
        raise IdentityParseError(
            f'blob is an OpenSSH cert ({key_type}), not a bare pubkey'
        )
    return PubkeyIdentity(
        key_type=key_type,
        raw_blob=blob,
        fingerprint=sha256_fingerprint(blob),
    )


def parse_openssh_cert(blob: bytes) -> CertIdentity:
    """Parse an OpenSSH user/host certificate blob (wire format).

    Format reference: PROTOCOL.certkeys in the OpenSSH source.
    """
    if not blob:
        raise IdentityParseError('empty cert blob')
    mv = memoryview(blob)

    key_type_b, pos = _read_string(mv, 0)
    key_type = key_type_b.decode('ascii', errors='replace')
    if not key_type.endswith(_CERT_SUFFIX):
        raise IdentityParseError(f'not an OpenSSH cert: key_type={key_type}')

    nonce, pos = _read_string(mv, pos)

    # The embedded public key fields depend on the key type. For our purposes
    # we don't need to dissect them — we just record the public-key blob in
    # "with type" form (which is what SSH uses everywhere except inside certs).
    pk_inner_start = pos
    inner_type = key_type[: -len(_CERT_SUFFIX)]
    if inner_type == 'ssh-ed25519':
        _, pos = _read_string(mv, pos)        # pubkey (32 bytes)
    elif inner_type == 'ssh-rsa':
        _, pos = _read_string(mv, pos)        # e
        _, pos = _read_string(mv, pos)        # n
    elif inner_type.startswith('ecdsa-sha2-'):
        _, pos = _read_string(mv, pos)        # curve identifier
        _, pos = _read_string(mv, pos)        # Q (public point)
    elif inner_type == 'ssh-dss':
        for _ in range(4):
            _, pos = _read_string(mv, pos)
    else:
        raise IdentityParseError(f'unsupported cert inner key type: {inner_type}')
    pk_inner_end = pos

    # Compose the "type-prefixed" pubkey blob (SSH wire format).
    inner_type_b = inner_type.encode('ascii')
    public_key_blob = (
        struct.pack('>I', len(inner_type_b)) + inner_type_b
        + bytes(mv[pk_inner_start:pk_inner_end])
    )

    serial, pos = _read_uint64(mv, pos)
    cert_type, pos = _read_uint32(mv, pos)
    key_id, pos = _read_string_utf8(mv, pos)

    # principals is an SSH string whose body is a list of strings
    principals_blob, pos = _read_string(mv, pos)
    principals: list[str] = []
    pmv = memoryview(principals_blob)
    ppos = 0
    while ppos < len(pmv):
        p, ppos = _read_string_utf8(pmv, ppos)
        principals.append(p)

    valid_after, pos = _read_uint64(mv, pos)
    valid_before, pos = _read_uint64(mv, pos)

    critical_blob, pos = _read_string(mv, pos)
    extensions_blob, pos = _read_string(mv, pos)
    critical_options = _parse_kv_pairs(critical_blob)
    extensions = _parse_kv_pairs(extensions_blob)

    _, pos = _read_string(mv, pos)            # reserved
    signature_key_blob, pos = _read_string(mv, pos)
    signed_end = pos
    signature, pos = _read_string(mv, pos)

    return CertIdentity(
        key_type=key_type,
        raw_blob=blob,
        fingerprint=sha256_fingerprint(public_key_blob),
        nonce=nonce,
        public_key_blob=public_key_blob,
        serial=serial,
        cert_type=cert_type,
        key_id=key_id,
        principals=principals,
        valid_after=valid_after,
        valid_before=valid_before,
        critical_options=critical_options,
        extensions=extensions,
        signature_key_blob=signature_key_blob,
        signature_key_fingerprint=sha256_fingerprint(signature_key_blob),
        signed_bytes=bytes(mv[:signed_end]),
        signature=signature,
    )


def parse_identity(identity_type: str, blob: bytes):
    """Dispatch to the right parser based on the API's identity.type."""
    if identity_type == 'pubkey':
        return parse_pubkey_blob(blob)
    if identity_type == 'openssh-cert':
        return parse_openssh_cert(blob)
    raise IdentityParseError(f'unknown identity type: {identity_type!r}')
