# ssh-rt-auth Detailed Design: REST API

**Project:** ssh-rt-auth  
**Status:** Detailed design v0.1  
**Author:** Kurt Godwin (github.com/kurt-cb)  
**Scope:** Complete REST API specification for the authorization CA  

---

## Overview

The CA exposes a REST API over mTLS. There are two API categories distinguished by
the caller's mTLS cert type:

- **Authorization API** — called by the ssh-rt-auth shim on each server. Server mTLS certs.
- **Admin API** — called by `ssh-rt-admin` CLI. Admin mTLS certs with role-based access.

All requests and responses use `Content-Type: application/json`. All timestamps are
ISO 8601 UTC. All binary data (certs, keys, blobs) is base64-encoded.

---

## Common response envelope

Every response follows the same envelope:

```json
{
  "status": "<granted|denied|error|ok>",
  "...": "endpoint-specific fields"
}
```

### Common error response

Any endpoint may return:

```
HTTP 400 Bad Request
{
  "status": "error",
  "reason": "bad_request",
  "detail": "missing required field: identity.type"
}

HTTP 401 Unauthorized
{
  "status": "error",
  "reason": "unauthorized",
  "detail": "mTLS cert not recognized"
}

HTTP 403 Forbidden
{
  "status": "error",
  "reason": "forbidden",
  "detail": "admin role 'auditor' cannot perform 'user.add'"
}

HTTP 500 Internal Server Error
{
  "status": "error",
  "reason": "internal",
  "detail": "enrollment database unavailable"
}
```

`reason` is a machine-readable string suitable for programmatic handling.
`detail` is human-readable for logging and debugging.

---

## Authorization API

### POST /v1/authorize

Called by the shim after sshd validates the client's signature.

**Caller:** Server (identified by server mTLS cert)  
**Authentication:** Server mTLS cert → CA looks up server canonical name and groups  

#### Request

```json
{
  "identity": {
    "type": "pubkey",
    "data": "AAAAC3NzaC1lZDI1NTE5AAAAI..."
  },
  "connection": {
    "source_ip": "10.0.1.42",
    "source_port": 52341,
    "timestamp": "2026-05-11T14:23:07Z"
  },
  "requested_channels": ["session", "direct-tcpip"]
}
```

#### Request fields

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `identity.type` | string | Yes | One of: `pubkey`, `openssh-cert`. |
| `identity.data` | string | Yes | Base64-encoded raw identity blob. Max 64 KB. |
| `connection.source_ip` | string | Yes | IPv4 or IPv6 address. |
| `connection.source_port` | integer | Yes | 1–65535. |
| `connection.timestamp` | string | Yes | ISO 8601 UTC. CA may reject if drift exceeds a configurable threshold (default: 60 seconds). |
| `requested_channels` | array of string | No | SSH channel type strings. If absent, CA uses policy defaults. |

#### Response: granted (HTTP 200)

```json
{
  "status": "granted",
  "cert": "MIICxTCCAa2gAwIBAgIGAY...",
  "serial": "a1b2c3d4e5f6",
  "not_after": "2026-05-11T15:23:07Z",
  "policy_summary": {
    "channels": ["session", "direct-tcpip"],
    "source_bound": true,
    "server_bind": "prod-db-01",
    "force_command": null,
    "max_session_seconds": null,
    "environment": {"TMPDIR": "/var/tmp"}
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `cert` | string | Base64-encoded DER X.509 authorization cert. |
| `serial` | string | Hex-encoded cert serial. Correlation handle for audit. |
| `not_after` | string | ISO 8601 UTC. Cert expiry. Shim uses this for cache TTL. |
| `policy_summary` | object | Informational summary of the cert's policy extensions. Not authoritative — the cert itself is. Exists for logging and debugging. |

#### Response: denied (HTTP 403)

```json
{
  "status": "denied",
  "reason": "no_matching_policy",
  "detail": "user 'alice' has no policy granting access to server 'prod-db-01'"
}
```

Denial reason codes:

| reason | Meaning |
|--------|---------|
| `unknown_identity` | Identity blob fingerprint not found in enrollment. |
| `invalid_identity_cert` | OpenSSH cert failed trust chain validation. |
| `no_matching_policy` | User is enrolled but has no policy for this server. |
| `source_denied` | Policy exists but source IP is outside allowed CIDRs. |
| `time_denied` | Policy exists but current time is outside the allowed window. |
| `channels_denied` | All requested channels are outside the allowed set. |

#### Response: error (HTTP 500)

```json
{
  "status": "error",
  "reason": "internal",
  "detail": "cert generation failed: signing key unavailable"
}
```

---

## Admin API

All admin endpoints require an admin mTLS cert. The CA validates the cert, looks up
the admin's role in the enrollment database, and checks permissions before processing.

### Role permissions

| Endpoint | superuser | server-admin | user-admin | auditor |
|----------|-----------|--------------|------------|---------|
| `POST /v1/admin/server/add` | ✓ | ✓ | — | — |
| `DELETE /v1/admin/server/{name}` | ✓ | ✓ | — | — |
| `PUT /v1/admin/server/{name}/groups` | ✓ | ✓ | — | — |
| `GET /v1/admin/server/list` | ✓ | ✓ | ✓ | ✓ |
| `POST /v1/admin/user/add` | ✓ | — | ✓ | — |
| `DELETE /v1/admin/user/{username}` | ✓ | — | ✓ | — |
| `POST /v1/admin/user/{username}/key` | ✓ | — | ✓ | — |
| `DELETE /v1/admin/user/{username}/key/{fingerprint}` | ✓ | — | ✓ | — |
| `POST /v1/admin/policy/add` | ✓ | — | ✓ | — |
| `DELETE /v1/admin/policy/{id}` | ✓ | — | ✓ | — |
| `GET /v1/admin/user/list` | ✓ | ✓ | ✓ | ✓ |
| `GET /v1/admin/audit` | ✓ | ✓ | ✓ | ✓ |
| `POST /v1/admin/admin/add` | ✓ | — | — | — |
| `DELETE /v1/admin/admin/{name}` | ✓ | — | — | — |
| `GET /v1/admin/admin/list` | ✓ | — | — | ✓ |

---

### Server management

#### POST /v1/admin/server/add

Register a new server. The CA generates an mTLS client cert for the server.

**Required role:** superuser, server-admin

**Request:**

```json
{
  "name": "prod-db-01",
  "groups": ["production", "databases"]
}
```

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique. 1–128 chars. Alphanumeric, hyphens, dots. |
| `groups` | array of string | No | Group names. 1–64 chars each. Created implicitly if they don't exist. |

**Response (HTTP 201):**

```json
{
  "status": "ok",
  "server": {
    "name": "prod-db-01",
    "groups": ["production", "databases"],
    "mtls_subject": "CN=prod-db-01"
  },
  "credentials": {
    "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
    "key_pem": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
    "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
  }
}
```

The `credentials` block contains everything needed to configure the shim on the
new server: the server's mTLS client cert, private key, and the CA's cert for
server-side validation.

**Error (HTTP 409):** Server name already exists.

#### DELETE /v1/admin/server/{name}

Remove a server enrollment. Active cached authorization certs for this server remain
valid until TTL expires.

**Required role:** superuser, server-admin

**Response (HTTP 200):**

```json
{
  "status": "ok",
  "removed": "prod-db-01"
}
```

**Error (HTTP 404):** Server not found.

#### PUT /v1/admin/server/{name}/groups

Update a server's group memberships.

**Required role:** superuser, server-admin

**Request:**

```json
{
  "groups": ["production", "databases", "critical"]
}
```

Replaces the server's group list entirely.

**Response (HTTP 200):**

```json
{
  "status": "ok",
  "server": {
    "name": "prod-db-01",
    "groups": ["production", "databases", "critical"]
  }
}
```

#### GET /v1/admin/server/list

List enrolled servers.

**Required role:** any admin role

**Query parameters:**

| Param | Description |
|-------|-------------|
| `group` | Filter by group name. |
| `name` | Filter by name prefix. |

**Response (HTTP 200):**

```json
{
  "status": "ok",
  "servers": [
    {
      "name": "prod-db-01",
      "groups": ["production", "databases"],
      "mtls_subject": "CN=prod-db-01",
      "enrolled_at": "2026-05-11T10:00:00Z"
    },
    {
      "name": "dev-server-01",
      "groups": ["development"],
      "mtls_subject": "CN=dev-server-01",
      "enrolled_at": "2026-05-11T10:05:00Z"
    }
  ]
}
```

---

### User management

#### POST /v1/admin/user/add

Register a new user.

**Required role:** superuser, user-admin

**Request:**

```json
{
  "username": "alice"
}
```

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `username` | string | Yes | Unique. 1–64 chars. POSIX username characters. |

**Response (HTTP 201):**

```json
{
  "status": "ok",
  "user": {
    "username": "alice",
    "keys": [],
    "policies": []
  }
}
```

**Error (HTTP 409):** Username already exists.

#### POST /v1/admin/user/{username}/key

Add an identity key binding to a user.

**Required role:** superuser, user-admin

**Request:**

```json
{
  "type": "pubkey",
  "data": "AAAAC3NzaC1lZDI1NTE5AAAAI..."
}
```

The `data` field is the raw SSH public key or OpenSSH cert blob, base64-encoded. The
CA parses it to extract the fingerprint, key type, and (for certs) key-id and principals.

**Response (HTTP 201):**

```json
{
  "status": "ok",
  "key": {
    "type": "pubkey",
    "fingerprint": "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcd",
    "key_type": "ssh-ed25519"
  }
}
```

For `openssh-cert` type, the response also includes:

```json
{
  "status": "ok",
  "key": {
    "type": "openssh-cert",
    "fingerprint": "SHA256:AbCdEf...",
    "key_type": "ssh-ed25519-cert-v01@openssh.com",
    "key_id": "alice@example.com",
    "principals": ["alice"],
    "valid_after": "2026-01-01T00:00:00Z",
    "valid_before": "2027-01-01T00:00:00Z",
    "signing_ca_fingerprint": "SHA256:CaKeY..."
  }
}
```

**Error (HTTP 409):** Fingerprint already bound to this user.  
**Error (HTTP 400):** Unparseable key/cert data.

#### DELETE /v1/admin/user/{username}/key/{fingerprint}

Remove a key binding.

**Required role:** superuser, user-admin

**Response (HTTP 200):**

```json
{
  "status": "ok",
  "removed_fingerprint": "SHA256:AbCdEf..."
}
```

#### DELETE /v1/admin/user/{username}

Remove a user and all their key bindings and policies.

**Required role:** superuser, user-admin

**Response (HTTP 200):**

```json
{
  "status": "ok",
  "removed": "alice"
}
```

#### GET /v1/admin/user/list

List enrolled users.

**Required role:** any admin role

**Query parameters:**

| Param | Description |
|-------|-------------|
| `username` | Filter by username. |
| `fingerprint` | Find the user bound to this key fingerprint. |

**Response (HTTP 200):**

```json
{
  "status": "ok",
  "users": [
    {
      "username": "alice",
      "keys": [
        {
          "type": "pubkey",
          "fingerprint": "SHA256:AbCdEf...",
          "key_type": "ssh-ed25519"
        }
      ],
      "policies": [
        {
          "id": "pol-001",
          "servers": ["prod-db-01", "prod-db-02"],
          "server_groups": [],
          "channels": ["session", "direct-tcpip", "subsystem:sftp"],
          "source_cidrs": ["10.0.0.0/8"],
          "time_window": {
            "days": ["mon","tue","wed","thu","fri"],
            "hours": {"start":"08:00","end":"18:00"},
            "timezone": "America/New_York"
          },
          "max_cert_validity_seconds": 3600,
          "environment": {"TMPDIR": "/var/tmp"},
          "force_command": null
        }
      ],
      "enrolled_at": "2026-05-11T10:00:00Z"
    }
  ]
}
```

---

### Policy management

#### POST /v1/admin/policy/add

Add a policy rule for a user.

**Required role:** superuser, user-admin

**Request:**

```json
{
  "username": "alice",
  "policy": {
    "servers": ["prod-db-01", "prod-db-02"],
    "server_groups": ["databases"],
    "channels": ["session", "direct-tcpip", "subsystem:sftp"],
    "source_cidrs": ["10.0.0.0/8"],
    "time_window": {
      "days": ["mon", "tue", "wed", "thu", "fri"],
      "hours": {"start": "08:00", "end": "18:00"},
      "timezone": "America/New_York"
    },
    "max_cert_validity_seconds": 3600,
    "environment": {
      "TMPDIR": "/var/tmp"
    },
    "force_command": null
  }
}
```

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `username` | string | Yes | Must exist in enrollment. |
| `policy.servers` | array of string | No | Server canonical names. Each must exist in enrollment. At least one of `servers` or `server_groups` required. |
| `policy.server_groups` | array of string | No | Server group names. At least one of `servers` or `server_groups` required. |
| `policy.channels` | array of string | Yes | At least one channel. Valid values: `session`, `direct-tcpip`, `forwarded-tcpip`, `subsystem:sftp`, `subsystem:*`, `x11`. |
| `policy.source_cidrs` | array of string | No | CIDR notation. If absent, no source restriction (any IP). |
| `policy.time_window` | object | No | If absent, no time restriction. |
| `policy.time_window.days` | array of string | Yes (if time_window) | `mon`–`sun`. |
| `policy.time_window.hours` | object | Yes (if time_window) | `start` and `end` in HH:MM 24-hour format. |
| `policy.time_window.timezone` | string | Yes (if time_window) | IANA timezone name. |
| `policy.max_cert_validity_seconds` | integer | No | Default: CA-configured default (e.g., 3600). Range: 60–86400. |
| `policy.environment` | object | No | Key-value string pairs. Keys must be valid environment variable names. |
| `policy.force_command` | string | No | If present, restricts sessions to this command. |

**Validation:**

- Referenced servers must exist in server enrollment.
- Referenced server groups must have at least one server.
- CIDR strings must be valid.
- Time window hours: `start` must be before `end` (or the rule means "not this window").
- Timezone must be a valid IANA timezone.

**Response (HTTP 201):**

```json
{
  "status": "ok",
  "policy_id": "pol-002",
  "username": "alice"
}
```

The CA assigns a policy ID for future reference and deletion.

**Error (HTTP 400):** Validation failure (invalid CIDR, unknown server, etc.).  
**Error (HTTP 404):** User not found.

#### DELETE /v1/admin/policy/{id}

Remove a policy rule.

**Required role:** superuser, user-admin

**Response (HTTP 200):**

```json
{
  "status": "ok",
  "removed_policy": "pol-002"
}
```

---

### Admin management

#### POST /v1/admin/admin/add

Add a new admin.

**Required role:** superuser only

**Request:**

```json
{
  "name": "ops-alice",
  "role": "server-admin"
}
```

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique. 1–64 chars. |
| `role` | string | Yes | One of: `superuser`, `server-admin`, `user-admin`, `auditor`. |

**Response (HTTP 201):**

```json
{
  "status": "ok",
  "admin": {
    "name": "ops-alice",
    "role": "server-admin",
    "mtls_subject": "CN=ops-alice"
  },
  "credentials": {
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
    "key_pem": "-----BEGIN PRIVATE KEY-----\n...",
    "ca_cert_pem": "-----BEGIN CERTIFICATE-----\n..."
  }
}
```

#### DELETE /v1/admin/admin/{name}

Remove an admin. Cannot remove the last superuser.

**Required role:** superuser only

**Response (HTTP 200):**

```json
{
  "status": "ok",
  "removed": "ops-alice"
}
```

**Error (HTTP 409):** Cannot remove the last superuser.

#### GET /v1/admin/admin/list

List admins.

**Required role:** superuser, auditor

**Response (HTTP 200):**

```json
{
  "status": "ok",
  "admins": [
    {
      "name": "bootstrap",
      "role": "superuser",
      "mtls_subject": "CN=bootstrap-admin",
      "enrolled_at": "2026-05-11T09:00:00Z"
    },
    {
      "name": "ops-alice",
      "role": "server-admin",
      "mtls_subject": "CN=ops-alice",
      "enrolled_at": "2026-05-11T10:00:00Z"
    }
  ]
}
```

---

### Audit log

#### GET /v1/admin/audit

Query the CA's audit log.

**Required role:** any admin role

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `type` | string | Filter by entry type: `authorization`, `admin`, or `all` (default: `all`). |
| `since` | string | ISO 8601 UTC. Return entries after this time. |
| `until` | string | ISO 8601 UTC. Return entries before this time. |
| `username` | string | Filter authorization entries by username. |
| `server` | string | Filter authorization entries by server canonical name. |
| `decision` | string | Filter authorization entries: `granted` or `denied`. |
| `admin` | string | Filter admin entries by admin name. |
| `limit` | integer | Max entries to return (default: 100, max: 10000). |
| `offset` | integer | Pagination offset (default: 0). |

**Response (HTTP 200):**

```json
{
  "status": "ok",
  "total": 247,
  "entries": [
    {
      "timestamp": "2026-05-11T14:23:07Z",
      "type": "authorization",
      "decision": "granted",
      "serial": "a1b2c3d4e5f6",
      "identity": {
        "type": "pubkey",
        "fingerprint": "SHA256:AbCd...",
        "username": "alice"
      },
      "server": {
        "canonical_name": "prod-db-01",
        "groups": ["production", "databases"]
      },
      "connection": {
        "source_ip": "10.0.1.42",
        "source_port": 52341
      },
      "cert_validity": {
        "not_before": "2026-05-11T14:23:07Z",
        "not_after": "2026-05-11T15:23:07Z"
      },
      "policy_applied": {
        "policy_id": "pol-001",
        "channels": ["session", "direct-tcpip"],
        "source_bound": true
      }
    },
    {
      "timestamp": "2026-05-11T10:00:00Z",
      "type": "admin",
      "action": "user.add",
      "admin": {
        "name": "ops-alice",
        "role": "user-admin"
      },
      "target": {
        "username": "alice"
      }
    }
  ]
}
```

---

## API versioning

The API is versioned in the URL path (`/v1/`). Breaking changes require a new
version (`/v2/`). Non-breaking additions (new optional fields, new endpoints) can
be added within the same version.

## Rate limiting

The authorization endpoint (`POST /v1/authorize`) is not rate-limited — it's called
on every SSH connection and latency matters. Admin endpoints may be rate-limited
in production to prevent abuse (e.g., 100 requests/minute per admin cert).

## Request size limits

- Authorization request body: max 128 KB (identity blobs are typically < 10 KB)
- Admin request body: max 1 MB
- Response body: no explicit limit, but authorization responses are typically < 10 KB
