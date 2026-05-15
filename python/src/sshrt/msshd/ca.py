"""CA client adapter for the wrapper.

Thin wrapper around ``shim.ca_client.CAClient`` that:

  - Builds the ``POST /v1/authorize`` request body in v1 schema
    (the v2 enrichments from
    [design/ssh-rt-auth-v2-enhancements.md](../../design/ssh-rt-auth-v2-enhancements.md)
    are deferred to Phase 1B+).
  - Calls the CA in an executor (CAClient uses blocking ``requests``).
  - Returns a typed result with the cert (DER), serial, and notAfter,
    or the deny reason.

The actual mTLS / failover / proxy-handling logic lives in
``shim.ca_client.CAClient`` — no point duplicating it.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as _dt
import logging
from dataclasses import dataclass
from typing import Any, Union

from sshrt.shim.ca_client import (AuthorizeResult, CAClient, CAClientFailedOver)

from .config import WrapperConfig


log = logging.getLogger('ssh-rt-wrapperd.ca')


@dataclass
class AuthorizationGrant:
    cert_der: bytes
    serial: str
    not_after: _dt.datetime


@dataclass
class AuthorizationDeny:
    reason: str
    detail: str = ''
    http_status: int = 0


@dataclass
class AuthorizationError:
    """All CA endpoints unreachable, or a malformed response."""
    message: str


AuthorizationResult = Union[AuthorizationGrant, AuthorizationDeny, AuthorizationError]


class WrapperCAClient:
    """Async-friendly CA-call adapter.

    Builds on top of the blocking ``shim.ca_client.CAClient`` (which is
    deliberately ``requests``-based — see issue 2.1 in
    [tests/issues.md](../../tests/issues.md)). We run the blocking call
    in the default executor so the wrapper's asyncio loop stays
    responsive.
    """

    def __init__(self, cfg: WrapperConfig):
        if not cfg.ca.endpoints:
            raise ValueError('WrapperCAClient requires cfg.ca.endpoints')
        self._client = CAClient(
            endpoints=cfg.ca.endpoints,
            mtls_cert=cfg.ca.client_cert,
            mtls_key=cfg.ca.client_key,
            ca_trust_root=cfg.ca.ca_pubkey,
            connect_timeout=cfg.ca.timeout_seconds,
            read_timeout=cfg.ca.timeout_seconds * 2,
        )
        self._cfg = cfg

    async def authorize(
        self,
        *,
        identity_blob: bytes,
        identity_type: str,
        source_ip: str,
        source_port: int,
        requested_channels: list[str] | None = None,
    ) -> AuthorizationResult:
        """Call POST /v1/authorize. ``identity_blob`` is the raw SSH
        wire-format pubkey or OpenSSH cert bytes."""
        body: dict[str, Any] = {
            'identity': {
                'type': identity_type,
                'data': base64.b64encode(identity_blob).decode('ascii'),
            },
            'connection': {
                'source_ip': source_ip,
                'source_port': source_port,
                'timestamp': _now_iso8601(),
            },
        }
        if requested_channels is not None:
            body['requested_channels'] = list(requested_channels)

        loop = asyncio.get_running_loop()
        try:
            result: AuthorizeResult = await loop.run_in_executor(
                None, self._client.authorize, body)
        except CAClientFailedOver as e:
            return AuthorizationError(message=f'all CA endpoints failed: {e}')
        except Exception as e:
            log.exception('CA call raised unexpectedly')
            return AuthorizationError(message=f'unexpected CA error: {e}')

        return _parse_result(result)


def _parse_result(result: AuthorizeResult) -> AuthorizationResult:
    status = result.status
    body = result.body
    if status == 'granted':
        cert_b64 = body.get('cert')
        if not isinstance(cert_b64, str):
            return AuthorizationError(message='granted response missing cert')
        try:
            cert_der = base64.b64decode(cert_b64)
        except Exception as e:
            return AuthorizationError(message=f'cert base64 decode failed: {e}')
        serial = str(body.get('serial', ''))
        not_after_s = str(body.get('not_after', ''))
        try:
            not_after = _parse_iso8601(not_after_s)
        except Exception:
            return AuthorizationError(
                message=f'unparseable not_after {not_after_s!r}')
        return AuthorizationGrant(
            cert_der=cert_der, serial=serial, not_after=not_after)

    if status == 'denied':
        return AuthorizationDeny(
            reason=str(body.get('reason', 'unspecified')),
            detail=str(body.get('detail', '')),
            http_status=result.http_status,
        )

    return AuthorizationError(
        message=f'CA returned status={status} body={body!r}')


def _now_iso8601() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _parse_iso8601(s: str) -> _dt.datetime:
    # Accept both Z-suffix and +00:00 forms.
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    return _dt.datetime.fromisoformat(s)
