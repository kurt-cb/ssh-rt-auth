"""mTLS HTTP client used by the shim, with failover across ca_endpoints."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import requests


log = logging.getLogger('ssh-rt-auth-shim.ca_client')


@dataclass
class AuthorizeResult:
    status: str            # "granted" | "denied" | "error"
    http_status: int
    body: dict[str, Any]


class CAClientFailedOver(RuntimeError):
    """All CA endpoints unreachable or returned 5xx."""


class CACommunicationError(RuntimeError):
    """Unrecoverable communication error (e.g., bad cert config)."""


class CAClient:
    def __init__(self, endpoints: list[str], mtls_cert: str, mtls_key: str,
                 ca_trust_root: str,
                 connect_timeout: float = 5.0, read_timeout: float = 10.0):
        if not endpoints:
            raise ValueError('CAClient requires at least one endpoint')
        self.endpoints = list(endpoints)
        self.mtls_cert = mtls_cert
        self.mtls_key = mtls_key
        self.ca_trust_root = ca_trust_root
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        # The CA is on a private network; never route shim ↔ CA through
        # HTTP_PROXY/HTTPS_PROXY env vars.
        self._session = requests.Session()
        self._session.trust_env = False

    def authorize(self, request_body: dict) -> AuthorizeResult:
        last_err: Exception | None = None
        for endpoint in self.endpoints:
            url = endpoint.rstrip('/') + '/v1/authorize'
            try:
                resp = self._session.post(
                    url, json=request_body,
                    cert=(self.mtls_cert, self.mtls_key),
                    verify=self.ca_trust_root,
                    timeout=(self.connect_timeout, self.read_timeout),
                )
            except (requests.ConnectionError, requests.Timeout) as e:
                log.warning('CA endpoint %s unreachable: %s; trying next', endpoint, e)
                last_err = e
                continue
            try:
                body = resp.json()
            except Exception:
                body = {'status': 'error', 'reason': 'bad_response',
                        'detail': resp.text[:200]}
            # Granted or denied: return immediately. 5xx → failover.
            if resp.status_code >= 500:
                log.warning('CA endpoint %s returned %d: %s; trying next',
                            endpoint, resp.status_code, body)
                last_err = RuntimeError(f'HTTP {resp.status_code}')
                continue
            return AuthorizeResult(
                status=str(body.get('status', 'error')),
                http_status=resp.status_code, body=body,
            )
        raise CAClientFailedOver(
            f'all {len(self.endpoints)} CA endpoints failed: {last_err}')
