"""Parse SSH key/cert files into ``(type, raw_blob, metadata)`` tuples.

Accepts:
  - SSH public key file ("ssh-ed25519 AAAA... [comment]")
  - OpenSSH cert file ("ssh-ed25519-cert-v01@openssh.com AAAA...")
  - authorized_keys entries (options prefix before the key type)
  - Bare base64 blob (recover type from the embedded SSH wire format)
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

from sshrt.ca.identity_parser import (CertIdentity, IdentityParseError,
                                PubkeyIdentity, parse_identity,
                                parse_openssh_cert, parse_pubkey_blob,
                                sha256_fingerprint)


@dataclass
class ParsedKey:
    type: str            # "pubkey" | "openssh-cert"
    raw_blob: bytes
    key_type: str        # e.g. "ssh-ed25519"
    fingerprint: str
    key_id: str = ''
    principals: list[str] = None     # type: ignore[assignment]


def _decode_b64_token(tok: str) -> bytes:
    pad = '=' * ((4 - len(tok) % 4) % 4)
    return base64.b64decode(tok + pad)


def parse_key_file(path: str | Path) -> ParsedKey:
    text = Path(path).read_text().strip()
    return parse_key_text(text)


def parse_key_text(text: str) -> ParsedKey:
    text = text.strip()
    if not text:
        raise IdentityParseError('empty key text')
    # An authorized_keys line may have leading options. Find the first token
    # that is a known SSH key type by trying decode-and-match.
    tokens = text.split()
    blob = None
    for i, tok in enumerate(tokens):
        if tok in {'ssh-rsa', 'ssh-ed25519', 'ssh-dss',
                   'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
                   'ecdsa-sha2-nistp521'} or tok.endswith('-cert-v01@openssh.com'):
            if i + 1 < len(tokens):
                blob = _decode_b64_token(tokens[i + 1])
                break
    if blob is None:
        # Treat the whole input as a bare base64 blob.
        cleaned = ''.join(text.split())
        try:
            blob = _decode_b64_token(cleaned)
        except Exception as e:
            raise IdentityParseError(f'not an SSH key or base64 blob: {e}')

    # Dispatch on the embedded key type.
    try:
        cert = parse_openssh_cert(blob)
        return ParsedKey(
            type='openssh-cert', raw_blob=blob,
            key_type=cert.key_type, fingerprint=cert.fingerprint,
            key_id=cert.key_id, principals=list(cert.principals),
        )
    except IdentityParseError:
        pass
    pub = parse_pubkey_blob(blob)
    return ParsedKey(
        type='pubkey', raw_blob=blob,
        key_type=pub.key_type, fingerprint=pub.fingerprint,
        principals=[],
    )


def b64_blob(parsed: ParsedKey) -> str:
    return base64.b64encode(parsed.raw_blob).decode('ascii')
