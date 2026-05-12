"""mTLS HTTP client for the admin API."""
from __future__ import annotations

from typing import Any

import requests


class CAClientError(RuntimeError):
    """API call returned a non-2xx response."""

    def __init__(self, status: int, body: dict | str):
        super().__init__(f'CA returned HTTP {status}: {body}')
        self.status = status
        self.body = body


class CAClient:
    """Admin API mTLS client. Bypasses HTTP_PROXY env vars."""

    def __init__(self, base_url: str, admin_cert: str, admin_key: str,
                 ca_cert: str, timeout: float = 10.0):
        self.base_url = base_url
        self.admin_cert = admin_cert
        self.admin_key = admin_key
        self.ca_cert = ca_cert
        self.timeout = timeout
        self._session = requests.Session()
        self._session.trust_env = False

    def _request(self, method: str, path: str, *,
                 json: dict[str, Any] | None = None,
                 params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self.base_url.rstrip('/') + path
        resp = self._session.request(
            method=method, url=url,
            json=json, params=params,
            cert=(self.admin_cert, self.admin_key),
            verify=self.ca_cert,
            timeout=self.timeout,
        )
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        if not (200 <= resp.status_code < 300):
            raise CAClientError(resp.status_code, body)
        return body

    # ---- server ----
    def server_add(self, name: str, groups: list[str] | None = None) -> dict[str, Any]:
        return self._request('POST', '/v1/admin/server/add',
                             json={'name': name, 'groups': groups or []})

    def server_remove(self, name: str) -> dict[str, Any]:
        return self._request('DELETE', f'/v1/admin/server/{name}')

    def server_set_groups(self, name: str, groups: list[str]) -> dict[str, Any]:
        return self._request('PUT', f'/v1/admin/server/{name}/groups',
                             json={'groups': groups})

    def server_list(self, *, group: str | None = None,
                    name_prefix: str | None = None) -> list[dict[str, Any]]:
        params = {}
        if group:
            params['group'] = group
        if name_prefix:
            params['name'] = name_prefix
        return self._request('GET', '/v1/admin/server/list',
                             params=params)['servers']

    # ---- user ----
    def user_add(self, username: str) -> dict[str, Any]:
        return self._request('POST', '/v1/admin/user/add',
                             json={'username': username})

    def user_remove(self, username: str) -> dict[str, Any]:
        return self._request('DELETE', f'/v1/admin/user/{username}')

    def user_key_add(self, username: str, type_: str,
                     data_b64: str) -> dict[str, Any]:
        return self._request('POST', f'/v1/admin/user/{username}/key',
                             json={'type': type_, 'data': data_b64})

    def user_key_remove(self, username: str,
                        fingerprint: str) -> dict[str, Any]:
        return self._request('DELETE',
                             f'/v1/admin/user/{username}/key/{fingerprint}')

    def user_list(self, *, username: str | None = None,
                  fingerprint: str | None = None) -> list[dict[str, Any]]:
        params = {}
        if username:
            params['username'] = username
        if fingerprint:
            params['fingerprint'] = fingerprint
        return self._request('GET', '/v1/admin/user/list',
                             params=params)['users']

    # ---- policy ----
    def policy_add(self, username: str,
                   policy: dict[str, Any]) -> dict[str, Any]:
        return self._request('POST', '/v1/admin/policy/add',
                             json={'username': username, 'policy': policy})

    def policy_remove(self, policy_id: str) -> dict[str, Any]:
        return self._request('DELETE', f'/v1/admin/policy/{policy_id}')

    # ---- admin ----
    def admin_add(self, name: str, role: str) -> dict[str, Any]:
        return self._request('POST', '/v1/admin/admin/add',
                             json={'name': name, 'role': role})

    def admin_remove(self, name: str) -> dict[str, Any]:
        return self._request('DELETE', f'/v1/admin/admin/{name}')

    def admin_list(self) -> list[dict[str, Any]]:
        return self._request('GET', '/v1/admin/admin/list')['admins']

    # ---- audit ----
    def audit(self, **filters) -> dict[str, Any]:
        return self._request('GET', '/v1/admin/audit', params=filters)
