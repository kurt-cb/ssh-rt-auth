"""Policy translator — X.509 authz cert → OpenSSH cert critical-options.

The CA returns an X.509 authorization cert whose **critical extensions**
encode the policy decision: source-bind, server-bind, channel-policy,
force-command, environment, max-session, etc.

For the wrapper to enforce those at the inner sshd, we have to:

  1. Translate the X.509 extensions that map cleanly onto OpenSSH user
     cert fields (force_command, source_address) → pass them as kwargs
     to ``userca.UserCA.mint_user_cert``.
  2. Carry the remainder ourselves at the wrapper level (max-session
     timer, server-bind check, channel-policy when we add Variant B
     parsing).

This module is intentionally a thin parser + translator. No I/O.

See:
- [detailed-wrapper.md §8 translation table](../../design/ssh-rt-auth-detailed-wrapper.md)
- ca/cert_minter.py — the DER format we have to parse here
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from cryptography import x509


log = logging.getLogger('msshd.policy')


# Must match ca/cert_minter.py exactly.
OID_SOURCE_BIND     = '1.3.6.1.4.1.55555.1.1'
OID_SERVER_BIND     = '1.3.6.1.4.1.55555.1.2'
OID_CHANNEL_POLICY  = '1.3.6.1.4.1.55555.1.3'
OID_FORCE_COMMAND   = '1.3.6.1.4.1.55555.1.4'
OID_ENVIRONMENT     = '1.3.6.1.4.1.55555.1.5'
OID_MAX_SESSION     = '1.3.6.1.4.1.55555.1.6'
OID_2FA_EVIDENCE    = '1.3.6.1.4.1.55555.1.7'

# Critical extensions the wrapper recognises. If the CA returns a
# cert with a critical extension NOT in this set, reject the cert
# entirely (defense in depth) — see shim/shim.py:_KNOWN_CRITICAL.
KNOWN_CRITICAL = {
    OID_SOURCE_BIND,
    OID_SERVER_BIND,
    OID_CHANNEL_POLICY,
    '2.5.29.19',                   # basicConstraints
    '2.5.29.15',                   # keyUsage
}


@dataclass
class CertPolicy:
    """Parsed-out view of an X.509 authz cert's policy extensions.

    Empty-string defaults indicate "not present". Use the inner-sshd
    translation below to project this onto OpenSSH cert kwargs.
    """
    source_bind: str = ''
    server_bind: str = ''
    channels: list[str] = field(default_factory=list)
    force_command: str = ''
    environment: dict[str, str] = field(default_factory=dict)
    max_session_seconds: int | None = None
    two_fa_evidence: str = ''


def parse_cert_policy(cert_der: bytes) -> CertPolicy:
    """Parse the X.509 authz cert's policy extensions into a
    ``CertPolicy``. The CA's extension encoding is hand-rolled DER —
    see ca/cert_minter.py for the writer side.

    Critical extensions outside KNOWN_CRITICAL are silently ignored
    here; the cert-validation layer (shim/Shim._validate_cert) rejects
    them earlier and we never reach this function in that case.
    """
    cert = x509.load_der_x509_certificate(cert_der)
    p = CertPolicy()
    for ext in cert.extensions:
        oid_s = ext.oid.dotted_string
        # cryptography wraps unknown OIDs in UnrecognizedExtension;
        # `.value.value` is the raw extension bytes.
        raw = ext.value.value if hasattr(ext.value, 'value') else b''
        if oid_s == OID_SOURCE_BIND:
            p.source_bind = _decode_der_utf8(raw)
        elif oid_s == OID_SERVER_BIND:
            p.server_bind = _decode_der_utf8(raw)
        elif oid_s == OID_CHANNEL_POLICY:
            p.channels = _decode_der_seq_utf8(raw)
        elif oid_s == OID_FORCE_COMMAND:
            p.force_command = _decode_der_utf8(raw)
        elif oid_s == OID_ENVIRONMENT:
            entries = _decode_der_seq_utf8(raw)
            for e in entries:
                if '=' in e:
                    k, v = e.split('=', 1)
                    p.environment[k] = v
        elif oid_s == OID_MAX_SESSION:
            p.max_session_seconds = _decode_der_integer(raw)
        elif oid_s == OID_2FA_EVIDENCE:
            p.two_fa_evidence = _decode_der_utf8(raw)
    return p


@dataclass
class InnerCertKwargs:
    """Output of ``translate_to_inner_cert_kwargs``. Passed as **kwargs
    to ``UserCA.mint_user_cert`` along with the principal."""
    force_command: str | None = None
    source_address: list[str] | None = None


def translate_to_inner_cert_kwargs(p: CertPolicy) -> InnerCertKwargs:
    """Project the parts of ``CertPolicy`` that OpenSSH user certs can
    express natively into kwargs for ``UserCA.mint_user_cert``.

    What does NOT translate here (enforced elsewhere by the wrapper):
      - source_bind: ALREADY enforced by the CA at the outer-mTLS
        layer (the CA's grant is conditional on the client's source
        IP matching the policy's source_cidrs). Propagating source-
        bind onto the inner cert would mean the inner sshd refuses
        the wrapper's localhost handoff, because the inner connection
        comes from 127.0.0.1 — not the outer client's IP.
      - server_bind: validated pre-mint in enforce_listener
      - channels: enforced in proxy (Variant B; Variant A relies on
        the hermetic inner sshd disabling non-session channels globally)
      - environment: applied to the spawned child env in the wrapper's
        proxy/exec layer
      - max_session_seconds: wrapper-side timer
    """
    kw = InnerCertKwargs()
    if p.force_command:
        kw.force_command = p.force_command
    return kw


# ---------------------------------------------------------------------------
# Minimal DER decoder. Mirrors the writer in ca/cert_minter.py and the
# reader in server/ssh_server.py — duplicated here so the wrapper has no
# import-back into the SSH server module.
# ---------------------------------------------------------------------------

def _read_len(buf: bytes, pos: int) -> tuple[int, int]:
    first = buf[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7f
    length = int.from_bytes(buf[pos:pos + n], 'big')
    return length, pos + n


def _decode_der_utf8(buf: bytes) -> str:
    if not buf or buf[0] != 0x0c:
        return ''
    length, pos = _read_len(buf, 1)
    return buf[pos:pos + length].decode('utf-8', errors='replace')


def _decode_der_seq_utf8(buf: bytes) -> list[str]:
    if not buf or buf[0] != 0x30:
        return []
    length, pos = _read_len(buf, 1)
    end = pos + length
    out: list[str] = []
    while pos < end:
        if buf[pos] != 0x0c:
            break
        elen, p2 = _read_len(buf, pos + 1)
        out.append(buf[p2:p2 + elen].decode('utf-8', errors='replace'))
        pos = p2 + elen
    return out


def _decode_der_integer(buf: bytes) -> int | None:
    if not buf or buf[0] != 0x02:
        return None
    length, pos = _read_len(buf, 1)
    body = buf[pos:pos + length]
    if not body:
        return 0
    # Standard DER integers are big-endian two's complement, but the
    # CA writes only positive values via _der_int. Decode as unsigned.
    return int.from_bytes(body, 'big', signed=True)
