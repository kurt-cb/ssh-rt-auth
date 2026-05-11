# ssh-rt-auth Design Doc 02: CA design

**Project:** ssh-rt-auth (runtime, CA-mediated SSH authorization)  
**Status:** Design phase v0.1  
**Author:** Kurt Godwin (github.com/kurt-cb)  
**Scope:** CA design goals, API specification, admin authentication, authorization cert profile, enrollment, management tool, and PoC implementation  

---

## Design goals

The CA is the authorization decision point for ssh-rt-auth. It receives identity and connection context from the ssh-rt-auth shim (running on each server alongside sshd), evaluates policy, and returns an X.509 authorization cert or a denial. Everything about "who can do what, when, from where" lives here.

### Goals

1. **Minimal API surface.** One primary endpoint: the shim sends identity + context, CA responds with authorization cert or denial. Enrollment and administration are separate endpoints, not on the critical auth path.
2. **Policy is opaque to sshd and the shim.** The shim sends context, receives a cert, returns it to sshd. Neither the shim nor sshd interprets policy rules.
3. **Offline-capable.** No internet connectivity, no OIDC providers, no cloud services required.
4. **Small footprint.** Final reference implementation targets under 10 MB on Alpine. PoC has no footprint constraint.
5. **Authenticated transport.** mTLS between the shim and the CA. mTLS between admin tools and the CA.
6. **Auditable.** Every authorization decision and every administrative action is logged.
7. **HA-ready.** The design supports multiple CA instances behind a failover list. The shim is configured with multiple CA endpoints and tries them in order. The v1 PoC doesn't need to implement shared backends, but the architecture must not prevent HA.

### Non-goals for the CA

- **HA deployment in v1.** The architecture supports multiple CA instances (shim has a failover list). v1 doesn't need to ship HA tooling or replication guides, but the design must not prevent it.
- **Complex policy engine.** PoC uses a flat config file. Database/LDAP/rule-engine is a deployment concern.
- **Identity management.** The CA maps identity proofs to authorization decisions. Identity lifecycle is administrative.

---

## CA component architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Authorization CA                           │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                   mTLS Listener                        │  │
│  │  - Validates server mTLS certs (auth path)             │  │
│  │  - Validates admin mTLS certs (admin path)             │  │
│  │  - Identifies caller from cert → enrollment lookup     │  │
│  └────────────┬──────────────────────┬────────────────────┘  │
│               │                      │                       │
│     ┌─────────▼─────────┐  ┌─────────▼─────────┐            │
│     │  Authorization    │  │  Admin             │            │
│     │  Endpoint         │  │  Endpoints         │            │
│     │                   │  │                    │            │
│     │  POST /v1/authorize│  │  /v1/admin/server │            │
│     │                   │  │  /v1/admin/user   │            │
│     │  Called by the    │  │  /v1/admin/policy │            │
│     │  ssh-rt-auth shim │  │                    │            │
│     │  on each server   │  │  Called by         │            │
│     └─────────┬─────────┘  │  ssh-rt-admin CLI  │            │
│               │            └─────────┬──────────┘            │
│               │                      │                       │
│     ┌─────────▼──────────────────────▼──────────┐            │
│     │            Policy Engine                   │            │
│     │                                            │            │
│     │  - Identity parsing (SSH key / cert blobs) │            │
│     │  - Identity trust chain validation         │            │
│     │  - Server + user policy matching           │            │
│     │  - Source CIDR / time window checks        │            │
│     │  - Channel grant evaluation                │            │
│     └─────────────────────┬──────────────────────┘            │
│                           │                                  │
│     ┌─────────────────────▼──────────────────────┐            │
│     │         Enrollment Database                 │            │
│     │                                            │            │
│     │  - Servers (canonical name, mTLS cert,     │            │
│     │           groups)                          │            │
│     │  - Users (username, key fingerprints,      │            │
│     │          policies)                         │            │
│     │  - Admins (role, mTLS cert)                │            │
│     │                                            │            │
│     │  PoC: YAML file.  Prod: database.          │            │
│     └────────────────────────────────────────────┘            │
│                                                              │
│     ┌────────────────────────────────────────────┐            │
│     │         Cert Minter                         │            │
│     │                                            │            │
│     │  - X.509 authorization cert generation     │            │
│     │  - Custom extensions (policy constraints)  │            │
│     │  - Signing with CA private key             │            │
│     └────────────────────────────────────────────┘            │
│                                                              │
│     ┌────────────────────────────────────────────┐            │
│     │         Audit Log                           │            │
│     │                                            │            │
│     │  - JSON Lines, every decision + admin op   │            │
│     │  - Cert serial as correlation handle       │            │
│     └────────────────────────────────────────────┘            │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Admin authentication and authorization

The CA's admin interface must be secured. Only authorized administrators should be able to enroll servers, enroll users, modify policies, or inspect audit logs.

### Bootstrap sequence

```
┌─────────────────────────────────────────────────────────────┐
│  1. CA starts for the first time                            │
│     - Generates its own signing key pair                    │
│     - Generates its own mTLS server cert                    │
│     - Generates ONE bootstrap admin mTLS cert (superuser)   │
│     - Writes bootstrap cert + key to a secure location      │
│                                                             │
│  2. Admin uses bootstrap cert to authenticate               │
│     ssh-rt-admin --admin-cert bootstrap.pem \               │
│                  --admin-key bootstrap-key.pem \             │
│                  user add ...                                │
│                                                             │
│  3. Admin enrolls additional admins with specific roles     │
│     ssh-rt-admin admin add --name ops-alice \                │
│                            --role server-admin              │
│                                                             │
│  4. Admin enrolls servers                                   │
│     ssh-rt-admin server add --name prod-db-01 \             │
│                             --groups production,databases   │
│                                                             │
│  5. Admin enrolls users and policies                        │
│     ssh-rt-admin user add --user alice \                    │
│                           --key ~/.ssh/id_ed25519.pub       │
│                                                             │
│  6. Bootstrap cert should be stored securely (HSM, safe)    │
│     and used only for recovery                              │
└─────────────────────────────────────────────────────────────┘
```

### Admin roles

All admin operations are authenticated via mTLS client certs. The CA checks the admin cert's role against the requested operation.

| Role | Permissions |
|------|-------------|
| `superuser` | All operations. Bootstrap cert has this role. Should be rare. |
| `server-admin` | Enroll/remove servers, manage server groups. Cannot modify user policies. |
| `user-admin` | Enroll/remove users, manage user policies. Cannot modify server enrollment. |
| `auditor` | Read-only access to enrollment data and audit logs. Cannot modify anything. |

The admin cert's role is stored in the CA's enrollment database, not in the cert itself. The CA looks up the admin's mTLS cert, determines their role, and checks permissions before executing any admin operation.

### Admin data flow

```
 ssh-rt-admin CLI                         Authorization CA
       │                                        │
       │  mTLS connection (admin cert)           │
       │────────────────────────────────────────►│
       │                                        │
       │                      Validate admin cert│
       │                      Look up admin role │
       │                      Check permissions  │
       │                                        │
       │  POST /v1/admin/server/add             │
       │  {name: "prod-db-01", groups: [...]}   │
       │────────────────────────────────────────►│
       │                                        │
       │                      Validate request   │
       │                      Update enrollment  │
       │                      Generate mTLS cert │
       │                      for the new server │
       │                      Log admin action   │
       │                                        │
       │  Response                               │
       │  {server mTLS cert + key}              │
       │◄────────────────────────────────────────│
       │                                        │
       │  Admin deploys cert to server           │
```

---

## API specification

The CA exposes a REST API over mTLS. Two categories of endpoints: the authorization path (server mTLS certs) and the administrative path (admin mTLS certs).

### Authorization endpoint

#### POST /v1/authorize

The ssh-rt-auth shim calls this endpoint after sshd has verified the client's signature and passed the identity blob to the shim. The shim forwards the raw identity material — it does not parse identity cert internals. The CA does all identity parsing and independently validates cert trust chains.

> **Why raw blobs, not parsed fields.** This keeps both the sshd patch and the shim minimal. Neither needs to understand identity cert internals, extract specific fields, or be updated when new identity formats are added. The CA parses the blob, extracts what it needs, and validates independently.

> **No server identity in the request.** The CA identifies the server from the mTLS handshake and looks up the server's canonical name in its own enrollment database. The server never self-reports its identity.

**Request:**

```json
{
  "identity": {
    "type": "pubkey | openssh-cert",
    "data": "<base64-encoded raw public key or cert blob>"
  },
  "connection": {
    "source_ip": "10.0.1.42",
    "source_port": 52341,
    "timestamp": "2026-05-11T14:23:07Z"
  },
  "requested_channels": ["session", "direct-tcpip"]
}
```

**Request fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `identity.type` | Yes | `pubkey` for bare SSH key, `openssh-cert` for OpenSSH cert. Tells the CA which parser to use. Extensible for future identity types without changing sshd. |
| `identity.data` | Yes | Base64-encoded raw identity material. For `pubkey`: SSH public key blob. For `openssh-cert`: full OpenSSH certificate blob. |
| `connection.source_ip` | Yes | Source IP of the SSH connection. |
| `connection.source_port` | Yes | Source port of the SSH connection. |
| `connection.timestamp` | Yes | ISO 8601 timestamp. Server's local time. |
| `requested_channels` | No | SSH channel types the client intends to use. If omitted, the CA decides based on policy defaults. |

**Response — authorization granted:**

```
HTTP 200 OK
Content-Type: application/json

{
  "status": "granted",
  "cert": "<base64-encoded DER X.509 authorization cert>",
  "serial": "a1b2c3d4e5f6",
  "not_after": "2026-05-11T15:23:07Z",
  "policy_summary": {
    "channels": ["session", "direct-tcpip"],
    "source_bound": true,
    "command_restriction": null
  }
}
```

The `cert` field is the complete X.509 authorization cert, DER-encoded and base64-wrapped. The shim caches this and returns it to sshd, which enforces its constraints. The `policy_summary` is informational for logging — sshd uses the cert's extensions as the authoritative source.

**Response — authorization denied:**

```
HTTP 403 Forbidden

{
  "status": "denied",
  "reason": "user not authorized for this server",
  "detail": "fingerprint SHA256:... not enrolled for server prod-db-01"
}
```

**Response — error:**

```
HTTP 500 Internal Server Error

{
  "status": "error",
  "reason": "internal",
  "detail": "policy evaluation failed: config parse error at line 42"
}
```

> **Fail-closed by default.** If all CA endpoints are unreachable, return errors, or return anything the shim doesn't understand, the connection is denied. The only exception is the admin emergency cert.

### Administrative endpoints

These are not on the critical auth path. Authenticated via admin mTLS certs with role-based access control.

#### POST /v1/admin/server/add

Register a server with the CA. Returns an mTLS client cert for the server.

```json
{
  "name": "prod-db-01",
  "groups": ["production", "databases"]
}
```

Response includes the generated mTLS client cert and private key for the server.

#### DELETE /v1/admin/server/{name}

Remove a server enrollment.

#### POST /v1/admin/user/add

Register a user identity and associate it with authorization policies.

```json
{
  "identity": {
    "type": "pubkey",
    "fingerprint": "SHA256:...",
    "key_type": "ssh-ed25519"
  },
  "username": "alice",
  "policies": [
    {
      "servers": ["prod-db-01", "prod-db-02"],
      "server_groups": ["production-databases"],
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
  ]
}
```

The `servers` field references servers by canonical name as registered in the CA. The `server_groups` field references named groups. Both resolved against the CA's server enrollment — not DNS.

#### DELETE /v1/admin/user/{username}

Remove a user enrollment. Cached authorization certs remain valid until TTL expires (revocation by expiration).

#### GET /v1/admin/enrolled

List enrolled servers, users, and their policies.

#### GET /v1/admin/audit

Query the CA's authorization decision log and admin action log.

---

## Authorization cert profile

The authorization cert is a standard X.509 v3 certificate with custom extensions encoding the policy constraints. The shim returns the cert to sshd, which parses the extensions and enforces them during the session.

### Standard X.509 fields

| Field | Value |
|-------|-------|
| Version | v3 |
| Serial | Unique per cert, used as session correlation handle in logs |
| Issuer | CA's DN |
| Subject | Authorized principal: `CN=alice, O=ssh-rt-auth` |
| Not Before | Start of validity window (typically: now) |
| Not After | End of validity window. This is the cache expiry time for sshd. |
| Subject Public Key | The client's public key (the identity key that was proven) |
| Issuer Signature | CA's signature over the cert |

### Custom extensions

OID namespace TBD (experimental arc for PoC, registered arc for the public spec). Working prefix: `sshrtauth-`.

| Extension | Critical | Description |
|-----------|----------|-------------|
| `sshrtauth-source-bind` | Yes | Source IP or CIDR the cert is valid from. sshd must reject connections from other sources. |
| `sshrtauth-server-bind` | Yes | The server's canonical name as registered in the CA's enrollment database. Set by the CA from its own records. Prevents cross-server cert reuse. |
| `sshrtauth-channel-policy` | Yes | Allowed SSH channel types. List of channel type strings (`session`, `direct-tcpip`, `forwarded-tcpip`, `subsystem:sftp`). sshd rejects channel open requests not in this list. |
| `sshrtauth-force-command` | No | Restricts the session to this command. Per-connection, CA-decided. |
| `sshrtauth-environment` | No | Environment variables to set. Key=value pairs. Per-connection, CA-decided. |
| `sshrtauth-max-session` | No | Maximum session duration in seconds. Distinct from cert validity (which controls cache TTL). |
| `sshrtauth-2fa-evidence` | No | Evidence of second-factor verification during CA policy evaluation. Informational; sshd logs it. |

> **Critical vs. non-critical.** Critical extensions must be understood by sshd; if sshd encounters an unrecognized critical extension, it must reject the cert. Source binding, server binding, and channel policy are critical because ignoring them would widen authorization beyond what the CA intended.

---

## Enrollment model

The CA maintains two enrollment registries: servers and users. Admin enrollment is a third category.

### Server enrollment

Every server that participates must be enrolled. Server enrollment stores:

- **Canonical name:** The CA's authoritative name for this server (e.g., "prod-db-01"). An administrative label, not a DNS hostname (though it may match by convention). Used in policy rules and in the `sshrtauth-server-bind` extension.
- **mTLS cert identity:** The subject/SAN from the server's mTLS client cert. The CA matches the mTLS cert against this to identify which server is asking.
- **Server groups:** Optional group memberships (e.g., "production", "databases") for policy rules that apply to multiple servers.

The server's OpenSSH host cert (for client-facing SSH) is entirely separate. Different certs, different purposes, managed independently.

### User enrollment

For each enrolled user:

- **Username:** The principal name (e.g., "alice").
- **Identity bindings:** One or more key fingerprints and/or OpenSSH cert key-ids. The management tool computes fingerprints from key files.
- **Policies:** One or more rules specifying: which servers (by canonical name or group), which channels, which source CIDRs, what time windows, what cert validity, what environment, what command restrictions.

At authorization time, the CA parses the raw identity blob to compute the fingerprint and matches against the enrollment store.

### PoC enrollment config

```yaml
# Server enrollment
servers:
  prod-db-01:
    mtls_subject: "CN=prod-db-01.internal"
    groups: [production, databases]
  prod-db-02:
    mtls_subject: "CN=prod-db-02.internal"
    groups: [production, databases]
  dev-server-01:
    mtls_subject: "CN=dev-server-01.internal"
    groups: [development]
  jump-host:
    mtls_subject: "CN=jump.internal"
    groups: [infrastructure]

# Admin enrollment
admins:
  bootstrap:
    mtls_subject: "CN=bootstrap-admin"
    role: superuser
  ops-alice:
    mtls_subject: "CN=ops-alice"
    role: server-admin
  sec-bob:
    mtls_subject: "CN=sec-bob"
    role: auditor

# User enrollment
users:
  alice:
    keys:
      - type: pubkey
        fingerprint: "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcd"
        key_type: ssh-ed25519
    policies:
      - servers: [prod-db-01, prod-db-02]
        channels: [session, direct-tcpip, "subsystem:sftp"]
        source_cidrs: ["10.0.0.0/8"]
        time_window:
          days: [mon, tue, wed, thu, fri]
          hours: {start: "08:00", end: "18:00"}
          timezone: America/New_York
        max_cert_validity: 3600
        environment:
          TMPDIR: /var/tmp
      - server_groups: [development]
        channels: [session, direct-tcpip, forwarded-tcpip, "subsystem:sftp"]
        source_cidrs: ["0.0.0.0/0"]
        max_cert_validity: 7200

  bob:
    keys:
      - type: pubkey
        fingerprint: "SHA256:ZyXwVuTsRqPoNmLkJiHgFeDcBa0987654321zyxw"
        key_type: ssh-rsa
    policies:
      - server_groups: [development]
        channels: [session, direct-tcpip, forwarded-tcpip, "subsystem:sftp"]
        source_cidrs: ["0.0.0.0/0"]
        max_cert_validity: 7200
      - server_groups: [production]
        channels: [session]
        source_cidrs: ["10.0.1.0/24"]
        time_window:
          days: [mon, tue, wed, thu, fri]
          hours: {start: "09:00", end: "17:00"}
          timezone: America/New_York
        max_cert_validity: 1800
```

Production deployments replace the config file with a database. The API contract is the same.

---

## Management tool (ssh-rt-admin)

CLI-first management interface. All operations authenticated via admin mTLS certs.

### Core operations

```bash
# --- Bootstrap ---

# First-time CA initialization (generates signing key + bootstrap admin cert)
ssh-rt-admin init --ca-dir /etc/ssh-rt-auth/ca

# --- Admin management ---

# Add an admin with a specific role
ssh-rt-admin admin add --name ops-alice --role server-admin
# Returns: mTLS cert + key for ops-alice

# List admins
ssh-rt-admin admin list

# Remove an admin
ssh-rt-admin admin remove --name ops-alice

# --- Server enrollment ---

# Register a server (generates mTLS cert for it)
ssh-rt-admin server add --name prod-db-01 --groups production,databases
# Returns: mTLS cert + key to deploy to the server

# Add a server to a group
ssh-rt-admin server group --name prod-db-01 --add-group databases

# List enrolled servers
ssh-rt-admin server list
ssh-rt-admin server list --group production

# Remove a server
ssh-rt-admin server remove --name prod-db-01

# --- User enrollment ---

# Enroll a user with their public key file
ssh-rt-admin user add --user alice --key ~/.ssh/id_ed25519.pub

# Enroll a user with an OpenSSH cert (extracts key-id, principals, fingerprint)
ssh-rt-admin user add --user alice --cert /path/to/alice-cert.pub

# Add a policy rule (servers by canonical name or group)
ssh-rt-admin policy add --user alice \
  --servers prod-db-01,prod-db-02 \
  --channels session,direct-tcpip,subsystem:sftp \
  --source-cidrs 10.0.0.0/8 \
  --time-window "mon-fri 08:00-18:00 America/New_York" \
  --max-validity 3600

# Policy using server groups
ssh-rt-admin policy add --user bob \
  --server-groups development \
  --channels session,direct-tcpip,forwarded-tcpip,subsystem:sftp \
  --max-validity 7200

# List enrolled users and their policies
ssh-rt-admin user list
ssh-rt-admin user list --user alice

# Remove a user
ssh-rt-admin user remove --user alice

# Remove a specific key binding
ssh-rt-admin user remove-key --user alice --fingerprint SHA256:AbCdEf...

# --- Operations ---

# Audit log
ssh-rt-admin audit --last 50
ssh-rt-admin audit --user alice --since 2026-05-01

# Validate enrollment config
ssh-rt-admin validate

# Reload (sends SIGHUP or calls admin API)
ssh-rt-admin reload
```

### Authentication

The CLI uses `--admin-cert` and `--admin-key` flags (or reads from a config file at `~/.ssh-rt-admin/config`) to authenticate to the CA. The CA validates the admin cert, looks up the admin's role, and checks permissions before executing any operation.

```bash
# Explicit cert flags
ssh-rt-admin --admin-cert /path/to/cert.pem \
             --admin-key /path/to/key.pem \
             --ca-url https://ca.internal:8443 \
             server list

# Or via config file (~/.ssh-rt-admin/config)
# ca_url: https://ca.internal:8443
# admin_cert: /path/to/cert.pem
# admin_key: /path/to/key.pem
```

### Enrollment store interface

The management tool writes to whatever backing store the CA uses. `--store` flag selects the backend: `--store file:/path/to/config.yaml` for PoC, `--store api:https://ca.internal:8443/v1/admin` for API-backed.

---

## Policy evaluation

```
Authorization Request Arrives
         │
         ▼
┌─────────────────────┐
│ 1. Server ID        │  CA identifies server from mTLS cert.
│    (from mTLS)      │  Looks up canonical name + groups.
│                     │  Unknown server → reject connection.
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 2. Parse identity   │  Decode raw blob.
│    blob             │  pubkey → extract fingerprint.
│                     │  openssh-cert → parse full cert,
│                     │  validate trust chain.
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 3. Identity lookup  │  Match fingerprint or key-id
│                     │  against enrolled users.
│                     │  No match → deny.
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 4. Server match     │  Check user's policies for this
│                     │  server (by canonical name or group).
│                     │  No matching policy → deny.
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 5. Source check     │  If policy has CIDR restrictions,
│                     │  check source IP.
│                     │  Outside CIDRs → deny.
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 6. Time check       │  If policy has time window,
│                     │  check timestamp.
│                     │  Outside window → deny.
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 7. Channel check    │  If requested_channels provided,
│                     │  check against policy.
│                     │  Grant allowed subset or deny.
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 8. Mint cert        │  All checks pass.
│                     │  Generate X.509 authorization cert
│                     │  with policy extensions.
│                     │  sshrtauth-server-bind = canonical
│                     │  name from CA's own records.
└─────────────────────┘
```

> **Policy complexity is the CA's problem.** The above is the PoC's simple linear check. A production CA could implement RBAC, ABAC, approval workflows, or arbitrary policy engines. The API doesn't change.

---

## Transport security and server identity

### mTLS between the shim and the CA

All communication between the ssh-rt-auth shim and the CA uses mTLS. The mTLS connection serves two purposes: transport security and server identification.

- **CA authenticates the shim:** Validates the server's mTLS client cert and matches it against the server enrollment database. This simultaneously authenticates and identifies the server — the server never self-reports its identity.
- **Shim authenticates the CA:** CA's server cert (or trust root) is pinned in the shim's configuration.

> **Server identity is decoupled from SSH host certs.** The server's mTLS cert (for the authorization CA) is separate from its OpenSSH host cert (for SSH clients). Different certs, different names, different purposes, managed independently. The authorization system is not affected by how many DNS aliases a server has or what names clients use to connect.

### CA failover

The shim's config supports multiple CA endpoints:

```yaml
ca_endpoints:
  - https://ca1.internal:8443
  - https://ca2.internal:8443
```

The shim tries endpoints in order. If the primary is unreachable, it falls back to the secondary. This is the same pattern as `nameserver` lines in resolv.conf. How the CA instances share state (replicated database, shared signing key) is a deployment concern — the shim just needs to know where to send the request.

### mTLS between admin tools and the CA

The same mTLS infrastructure secures admin operations. Admin certs are distinct from server certs and carry role information in the CA's enrollment database.

### Trust model: three distinct trust roots

1. **User identity trust root:** For validating client OpenSSH certs. Only needed for `openssh-cert` identity proof type.
2. **Server identity trust root:** For validating server mTLS client certs. The CA that issued the mTLS certs.
3. **Authorization signing key:** The authorization CA's own key pair, for signing the X.509 authorization certs it mints.

These can (and typically should) be different CAs in production.

### Network placement

The CA should be on a network reachable only from the servers it authorizes. Typical deployment: CA on a management VLAN or private subnet, servers have a route to it, clients do not.

---

## Audit logging

The CA logs every authorization decision and every administrative action in JSON Lines format.

**Authorization decision log entry:**

```json
{
  "timestamp": "2026-05-11T14:23:07Z",
  "type": "authorization",
  "decision": "granted",
  "serial": "a1b2c3d4e5f6",
  "identity": {
    "type": "pubkey",
    "fingerprint": "SHA256:...",
    "username": "alice"
  },
  "server": {
    "canonical_name": "prod-db-01",
    "groups": ["production", "databases"],
    "mtls_subject": "CN=prod-db-01.internal"
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
    "channels": ["session", "direct-tcpip"],
    "source_bound": true,
    "force_command": null
  }
}
```

**Administrative action log entry:**

```json
{
  "timestamp": "2026-05-11T10:00:00Z",
  "type": "admin",
  "action": "user.add",
  "admin": {
    "name": "ops-alice",
    "role": "user-admin",
    "mtls_subject": "CN=ops-alice"
  },
  "target": {
    "username": "alice",
    "fingerprint": "SHA256:AbCdEf..."
  }
}
```

The cert serial serves as the correlation handle between the CA's audit log and sshd's session log.

---

## PoC implementation sketch

The proof-of-concept validates the architecture. It is not the production deliverable.

### Scope

- Single-process HTTPS server
- mTLS for both server auth path and admin path
- YAML config file for enrollment (reloaded on SIGHUP)
- `POST /v1/authorize` with full request/response format
- Parses raw SSH public key blobs and OpenSSH cert blobs
- Validates OpenSSH cert trust chains
- Mints X.509 authorization certs with custom extensions
- Admin authentication with role-based access control
- Logs decisions and admin actions to JSON Lines
- `ssh-rt-admin` CLI tool for enrollment, policy, and admin management

### Language

Any language that validates the architecture fastest. Python is reasonable for the PoC: quick to iterate, good X.509 libraries (`cryptography` package), easy mTLS setup, libraries for SSH key/cert parsing. The Alpine footprint concern applies to the final C + Mbed TLS reference implementation, not the PoC.

### Dependencies (Python PoC)

- `cryptography` — X.509 cert generation, key handling, OpenSSH key/cert parsing
- `flask` or `http.server` — HTTPS endpoint
- `pyyaml` — config file parsing
- Standard library for the rest (json, logging, ssl, ipaddress, datetime, struct)

### What the PoC proves

- The authorization flow works end-to-end: sshd patch → CA query → cert response → cached authorization → session
- Raw identity blob forwarding works — sshd doesn't parse identity cert internals
- Server identity via mTLS works — no self-reported server identity needed
- The CA independently validates OpenSSH cert trust chains
- Policy changes at the CA take effect on the next cache miss without touching sshd
- The cert profile's custom extensions are parseable and enforceable by sshd
- The audit trail links CA decisions to sshd session logs via cert serial
- Admin authentication and role-based access control work
- The management tool provides a usable admin workflow

---

## Open design questions

### Cache key semantics

When sshd has a cached cert for user alice, and alice connects again from a different source IP, should sshd use the cached cert (which may be source-bound to the previous IP) or re-query the CA? Recommendation: if the cached cert's extensions would reject this connection (e.g., source-bind doesn't match), re-query.

### Partial channel grants

If a user requests channels the policy doesn't fully cover, does the CA deny entirely or grant the allowed subset? Both are defensible. Granting the subset is more practical; sshd already handles channel-open rejections.

### Cert validity vs. session duration

The cert's notAfter controls cache TTL. `sshrtauth-max-session` controls session duration. These are independent. Recommendation: cert validity is only relevant at connection time; an existing session is not killed when the cached cert expires. The `max-session` extension handles session duration independently.

### OID arc for custom extensions

Use an experimental arc under 1.3.6.1.4.1 for the PoC. Register a proper OID arc if the project produces a public spec.
