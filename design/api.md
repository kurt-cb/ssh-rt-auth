# mssh — API contract

The CA exposes two URL prefixes. Both are mTLS-only.

  - `/v1/authorize` — called by msshd at every incoming connection
    to get an authorization decision + cert.
  - `/v1/admin/…` — called by `mssh-admin` to enrol servers, users,
    policies, and to query the audit log.

All requests and responses are JSON. All responses share a common
envelope.

For the canonical, exhaustive field-by-field reference of every
historical field shape, see
[archive/design/ssh-rt-auth-detailed-rest-api.md](../archive/design/ssh-rt-auth-detailed-rest-api.md).
This document describes the current contract — the shape future
implementations target — and omits historical-only fields.

---

## Common response envelope

Every CA response carries:

```json
{
  "request_id": "<opaque-correlation-id>",
  "ca_server_id": "<server-name-as-enrolled>",
  "issued_at": "<ISO-8601 UTC>",
  "result": "granted" | "denied" | "error",
  // exactly one of the following, matching `result`:
  "credentials": { … },     // when result=granted
  "denied_reason": "…",     // when result=denied
  "error": { "code": …, "message": … }  // when result=error
}
```

`request_id` is server-issued; clients log it on every call so
operator + CA logs can be correlated.

HTTP status codes:

  - `200 OK` — `result: "granted"`
  - `403 Forbidden` — `result: "denied"` (auth/policy refused)
  - `400 Bad Request` — malformed input (still wrapped in envelope)
  - `401 Unauthorized` — mTLS handshake / cert validation failed
  - `5xx` — CA internal error

---

## `POST /v1/authorize`

msshd's per-connection call. Asks the CA: *"Should this client be
allowed to reach this server right now? If yes, mint the
authorization cert."*

### Request

```json
{
  "version": 1,
  "request_id": "<msshd-generated>",
  "server_id": "<msshd's-enrolled-name>",
  "client": {
    "principal": "alice",
    "identity_blob": "<base64 raw ed25519 ssh-pubkey blob>",
    "identity_kind": "ssh-pubkey" | "ssh-cert" | "x509-cert"
  },
  "connection": {
    "remote_addr": "203.0.113.5",
    "remote_port": 51234,
    "channel": "session",
    "requested_command": ["whoami"]      // optional
  },
  "issued_at": "<ISO-8601 UTC>"
}
```

Key choices:

  - **msshd does not parse the client's identity.** Whatever blob
    the client presented goes to the CA verbatim. The CA owns
    parsing and validation.
  - **`channel`** is set per SSH session (session / direct-tcpip /
    forwarded-tcpip etc.). The CA matches this against the
    user's policy.
  - **`issued_at`** lets the CA reject stale requests (clock skew
    detection — see [architecture.md § Trust model](architecture.md#trust-model)).

### Response — granted

```json
{
  "result": "granted",
  "credentials": {
    "cert_pem": "<X.509 PEM, signed by CA's signing key>",
    "valid_from": "<ISO-8601 UTC>",
    "valid_to":   "<ISO-8601 UTC>",
    "ext": {
      "source_bind": ["203.0.113.0/24"],   // CIDRs allowed
      "channel_policy": ["session"],       // allowed channels
      "max_session_seconds": 3600
    }
  },
  …envelope fields…
}
```

`cert_pem` is the authoritative artifact — msshd verifies the
signature against the CA's signing root, then enforces the
extensions inline at the gateway. The extensions are duplicated in
the JSON for convenience; the cert is the source of truth.

### Response — denied

```json
{
  "result": "denied",
  "denied_reason": "policy_no_match" |
                   "policy_time_window" |
                   "policy_source_cidr" |
                   "user_unknown" |
                   "user_key_unenrolled" |
                   "server_unknown" |
                   …,
  …envelope fields…
}
```

`denied_reason` is a stable enum that admin tooling can switch on.
Free-text detail (which key fingerprint, which policy rule) goes
in the audit log, not the API response.

---

## Admin API — `/v1/admin/…`

Operator-facing endpoints called by `mssh-admin`. Three roles:

  - **superuser** — every endpoint.
  - **admin** — enrol/edit servers, users, keys, policies. No
    admin-management endpoints.
  - **auditor** — read-only. Lists, audit log search, no writes.

The CA derives the caller's role from the admin's mTLS cert
subject matched against the enrollment record. Each call audit-logs
the caller's subject + the action attempted.

### Server management

```
POST   /v1/admin/server/add            → enrol new server (returns mTLS creds)
DELETE /v1/admin/server/{name}         → revoke + remove
PUT    /v1/admin/server/{name}/groups  → update group memberships
GET    /v1/admin/server/list           → enumerate enrolled servers
```

`POST /v1/admin/server/add` request:

```json
{
  "name": "srv-acct-01",
  "groups": ["accounting", "production"]
}
```

Response includes the freshly minted mTLS cert + key for this
server. **The CA does not retain the private key**; the operator
must capture the response and provision it onto the target machine.

### User management

```
POST   /v1/admin/user/add                                  → enrol
POST   /v1/admin/user/{username}/key                       → add pubkey
DELETE /v1/admin/user/{username}/key/{fingerprint}         → revoke key
DELETE /v1/admin/user/{username}                           → revoke + remove
GET    /v1/admin/user/list                                 → enumerate
```

Adding a key:

```json
{
  "label": "alice-laptop-2026",
  "key_kind": "ssh-pubkey" | "ssh-cert" | "x509-cert",
  "key_blob": "<base64>"
}
```

The CA stores the blob and a derived fingerprint. The blob is
hashed and matched against the `identity_blob` field in future
authorize calls.

### Policy management

```
POST   /v1/admin/policy/add             → attach policy to a user
DELETE /v1/admin/policy/{id}            → remove
```

`POST /v1/admin/policy/add` request:

```json
{
  "user": "alice",
  "servers":       ["srv-acct-01"],          // explicit, OR
  "server_groups": ["accounting"],           // group-matched
  "channels":      ["session"],
  "source_cidrs":  ["10.0.0.0/8"],
  "time_window":   { "after": "08:00Z", "before": "18:00Z" },
  "max_cert_validity_seconds": 600
}
```

`servers` and `server_groups` are unioned. `source_cidrs` and
`time_window` are intersected with the request context. Empty
fields default to "no constraint."

### Admin management

```
POST   /v1/admin/admin/add        → enrol another admin (superuser only)
DELETE /v1/admin/admin/{name}     → revoke + remove (superuser only)
GET    /v1/admin/admin/list       → enumerate
```

Adding an admin returns mTLS creds (cert + key) the same way
server enrollment does.

### Audit log

```
GET /v1/admin/audit?since=…&until=…&actor=…&result=…
```

JSON-Lines stream. Each line:

```json
{
  "ts": "<ISO-8601 UTC>",
  "request_id": "<correlation-id>",
  "actor": "alice" | "admin:bob" | "ca:internal",
  "action": "authorize" | "server.add" | "policy.delete" | …,
  "target": "srv-acct-01",
  "result": "granted" | "denied" | "ok" | "error",
  "detail": { …action-specific… }
}
```

The audit log is append-only on disk; the API filters on read.

---

## Enrollment YAML schema

The CA persists enrollment to a single YAML file on disk. Admin
API writes serialize against a lock; concurrent reads are cheap.

```yaml
servers:
  srv-acct-01:
    groups: [accounting, production]
    mtls_subject: "CN=srv-acct-01,O=mssh"
    enrolled_at: "2026-01-15T10:00:00Z"
    enrolled_by: "admin:bob"

users:
  alice:
    enrolled_at: "2026-01-15T10:05:00Z"
    enrolled_by: "admin:bob"
    keys:
      - label: alice-laptop-2026
        key_kind: ssh-pubkey
        fingerprint: "SHA256:…"
        enrolled_at: "2026-01-15T10:05:00Z"
    policies:
      - servers:       ["srv-acct-01"]
        channels:      ["session"]
        source_cidrs:  ["10.0.0.0/8"]
        max_cert_validity_seconds: 600

admins:
  bob:
    role: admin
    mtls_subject: "CN=bob,O=mssh-ops"
    enrolled_at: "2026-01-01T00:00:00Z"
    enrolled_by: "init"
```

YAML is the persistence format for ease of human inspection in
v1. Production CA implementations are expected to move to a
sqlite or proper RDBMS backing store; the on-disk schema is the
abstraction the admin API operates on.

---

## API versioning

URL path carries the major version (`/v1/…`). Within a major
version, additions are non-breaking (new optional fields, new
endpoints, new enum values that older clients can ignore).
Breaking changes go to `/v2/…` and run side-by-side during
deprecation.

Server response envelopes carry a `version: <int>` field; clients
should warn on mismatches.

---

## Rate limiting + request limits

  - Authorize calls: msshd should not call more than once per
    connection. CA may rate-limit to 10/s per source IP.
  - Admin calls: 1/s per admin subject is conservative.
  - Request bodies: 256 KB hard cap (identity blobs are small;
    anything bigger is malformed).
  - Audit log queries: server may paginate at 1000 entries/page;
    clients follow the `next_cursor` field.

These are defaults the CA enforces; operators can tune them in
the CA config.
