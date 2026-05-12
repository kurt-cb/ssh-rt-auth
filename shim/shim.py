"""Main shim logic — the interface sshd calls into.

Owns: cache, CA client, response validation, emergency cert handling.

The shim's job is narrow:
  1. Receive identity proof + connection context
  2. Check cache (fingerprint, source_ip)
  3. On miss, query CA over mTLS (failover)
  4. Validate the returned cert (signature, expiry, critical extensions)
  5. Return (status, cert_der, serial)
"""
from __future__ import annotations

import base64
import datetime as _dt
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from ca.identity_parser import sha256_fingerprint
from .ca_client import CAClient, CAClientFailedOver
from .cache import CacheEntry, CertCache
from .config import ShimConfig


log = logging.getLogger('ssh-rt-auth-shim')


# Critical extension OIDs the shim recognizes. If the CA returns a cert with a
# critical extension not in this set, the shim rejects it (defense in depth).
# These must match ca/cert_minter.py exactly.
_KNOWN_CRITICAL = {
    '1.3.6.1.4.1.55555.1.1',       # source-bind
    '1.3.6.1.4.1.55555.1.2',       # server-bind
    '1.3.6.1.4.1.55555.1.3',       # channel-policy
    '2.5.29.19',                   # basicConstraints
    '2.5.29.15',                   # keyUsage
}


# Status codes returned to sshd.
STATUS_AUTHORIZED = 0
STATUS_DENIED = -1
STATUS_ERROR = -2


@dataclass
class AuthorizeOutcome:
    status: int
    cert_der: bytes | None
    serial: str | None
    deny_reason: str = ''
    detail: str = ''
    cache_hit: bool = False


def _now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _cert_not_after_utc(cert):
    """Return cert's notAfter as a tz-aware UTC datetime.

    Works on both cryptography < 42 (no ``_utc`` attrs, tz-naive UTC datetime)
    and cryptography >= 42 (deprecates the tz-naive attr).
    """
    dt = getattr(cert, 'not_valid_after_utc', None)
    if dt is None:
        dt = cert.not_valid_after
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt


def _cert_not_before_utc(cert):
    dt = getattr(cert, 'not_valid_before_utc', None)
    if dt is None:
        dt = cert.not_valid_before
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt


def _load_pem_cert(path: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def _verify_cert_signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Verify ``cert`` was signed by ``issuer``'s public key."""
    pub = issuer.public_key()
    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes)
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                cert.signature, cert.tbs_certificate_bytes,
                padding.PKCS1v15(), cert.signature_hash_algorithm,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                cert.signature, cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        log.warning('cert verify error: %s', e)
        return False


class Shim:
    """Long-lived shim state. sshd creates one of these at startup."""

    def __init__(self, config: ShimConfig):
        self.config = config
        config.validate()
        self.cache = CertCache(max_entries=config.cache_max_entries)
        self.ca_client = CAClient(
            endpoints=config.ca_endpoints,
            mtls_cert=config.mtls_cert,
            mtls_key=config.mtls_key,
            ca_trust_root=config.ca_trust_root,
            connect_timeout=config.connect_timeout,
            read_timeout=config.read_timeout,
        )
        self.auth_trust_cert = _load_pem_cert(config.auth_trust_root)

    @property
    def server_name(self) -> str:
        return self.config.server_name

    def authorize(self, identity_type: str, identity_data: bytes,
                  source_ip: str, source_port: int,
                  timestamp: int,
                  channels: list[str] | None = None) -> AuthorizeOutcome:
        # 1. Compute cache key.
        fp = sha256_fingerprint(identity_data)

        # 2. Cache lookup.
        hit = self.cache.get(fp, source_ip)
        if hit is not None:
            log.debug('cache hit fp=%s ip=%s serial=%s', fp, source_ip, hit.serial)
            return AuthorizeOutcome(
                status=STATUS_AUTHORIZED, cert_der=hit.cert_der,
                serial=hit.serial, cache_hit=True,
            )

        # 3. CA query with failover.
        ts = _dt.datetime.fromtimestamp(timestamp, tz=_dt.timezone.utc)
        body = {
            'identity': {
                'type': identity_type,
                'data': base64.b64encode(identity_data).decode('ascii'),
            },
            'connection': {
                'source_ip': source_ip,
                'source_port': source_port,
                'timestamp': ts.strftime('%Y-%m-%dT%H:%M:%SZ'),
            },
        }
        if channels:
            body['requested_channels'] = list(channels)

        try:
            result = self.ca_client.authorize(body)
        except CAClientFailedOver as e:
            log.warning('all CA endpoints unreachable: %s', e)
            emergency = self._try_emergency_cert()
            if emergency is not None:
                return emergency
            return AuthorizeOutcome(
                status=STATUS_ERROR, cert_der=None, serial=None,
                detail=f'all CA endpoints unreachable: {e}',
            )

        if result.status == 'granted':
            cert_b64 = result.body.get('cert')
            if not cert_b64:
                return AuthorizeOutcome(
                    status=STATUS_ERROR, cert_der=None, serial=None,
                    detail='CA granted but returned no cert')
            try:
                cert_der = base64.b64decode(cert_b64)
            except Exception as e:
                return AuthorizeOutcome(
                    status=STATUS_ERROR, cert_der=None, serial=None,
                    detail=f'bad base64 in CA response: {e}')
            valid, why = self._validate_cert(cert_der)
            if not valid:
                return AuthorizeOutcome(
                    status=STATUS_ERROR, cert_der=None, serial=None,
                    detail=f'CA returned invalid cert: {why}')
            serial = str(result.body.get('serial') or '')
            not_after = self._parse_iso(result.body.get('not_after') or '')
            self.cache.put(fp, source_ip, CacheEntry(
                cert_der=cert_der, serial=serial,
                not_after=not_after, created_at=_now(),
            ))
            return AuthorizeOutcome(
                status=STATUS_AUTHORIZED, cert_der=cert_der, serial=serial,
            )

        if result.status == 'denied':
            return AuthorizeOutcome(
                status=STATUS_DENIED, cert_der=None, serial=None,
                deny_reason=str(result.body.get('reason') or 'denied'),
                detail=str(result.body.get('detail') or ''),
            )

        # Error or unexpected.
        return AuthorizeOutcome(
            status=STATUS_ERROR, cert_der=None, serial=None,
            detail=f'unexpected CA response: {result.body}',
        )

    # ---- helpers ----

    def _validate_cert(self, cert_der: bytes) -> tuple[bool, str]:
        try:
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception as e:
            return False, f'cannot parse cert: {e}'
        now = _now()
        if _cert_not_after_utc(cert) < now:
            return False, 'cert expired'
        if _cert_not_before_utc(cert) > now + _dt.timedelta(seconds=60):
            return False, 'cert not yet valid'
        for ext in cert.extensions:
            if ext.critical and ext.oid.dotted_string not in _KNOWN_CRITICAL:
                return False, f'unrecognized critical extension {ext.oid.dotted_string}'
        if not _verify_cert_signed_by(cert, self.auth_trust_cert):
            return False, 'cert signature does not verify against auth_trust_root'
        return True, ''

    def _try_emergency_cert(self) -> AuthorizeOutcome | None:
        if not self.config.emergency_cert:
            return None
        try:
            der = Path(self.config.emergency_cert).read_bytes()
            cert = x509.load_pem_x509_certificate(der)
            now = _now()
            if _cert_not_after_utc(cert) < now:
                log.warning('emergency cert expired')
                return None
            log.warning('using emergency cert')
            cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
            return AuthorizeOutcome(
                status=STATUS_AUTHORIZED, cert_der=cert_der,
                serial=format(cert.serial_number, 'x'),
            )
        except Exception as e:
            log.warning('emergency cert load failed: %s', e)
            return None

    def _parse_iso(self, ts: str) -> _dt.datetime:
        if ts.endswith('Z'):
            ts = ts[:-1] + '+00:00'
        try:
            return _dt.datetime.fromisoformat(ts)
        except Exception:
            return _now() + _dt.timedelta(seconds=60)
