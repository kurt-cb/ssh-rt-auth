# ssh-rt-auth Detailed Design: CA and Admin

**Project:** ssh-rt-auth  
**Status:** Detailed design v0.1  
**Author:** Kurt Godwin (github.com/kurt-cb)  
**Scope:** CA internal architecture, enrollment database, cert minting, policy engine, admin tool  

---

## CA internal architecture

```
                    Incoming mTLS connection
                            │
                            ▼
                 ┌─────────────────────┐
                 │  TLS Termination    │
                 │  + Cert Extraction  │
                 │                     │
                 │  Extract client     │
                 │  cert subject/SAN   │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │  Caller             │
                 │  Identification     │
                 │                     │
                 │  Lookup cert in     │
                 │  enrollment DB:     │
                 │  server? admin?     │
                 │  unknown → reject   │
                 └──────┬───────┬──────┘
                        │       │
              server cert│       │admin cert
                        ▼       ▼
              ┌──────────┐    ┌──────────┐
              │ Auth     │    │ Admin    │
              │ Handler  │    │ Handler  │
              │          │    │          │
              │ /v1/     │    │ /v1/     │
              │ authorize│    │ admin/*  │
              └────┬─────┘    └────┬─────┘
                   │               │
                   ▼               ▼
              ┌─────────────────────────┐
              │    Enrollment DB        │
              │                         │
              │  ┌─────────┐            │
              │  │ Servers │            │
              │  └─────────┘            │
              │  ┌─────────┐            │
              │  │ Users   │            │
              │  └─────────┘            │
              │  ┌─────────┐            │
              │  │ Admins  │            │
              │  └─────────┘            │
              │  ┌─────────┐            │
              │  │ Policies│            │
              │  └─────────┘            │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │    Cert Minter          │
              │                         │
              │  Signing key (in memory │
              │  or HSM-backed)         │
              │                         │
              │  X.509 cert generation  │
              │  Custom extensions      │
              └─────────────────────────┘
              │    Audit Logger          │
              │                         │
              │  JSON Lines output      │
              │  File / syslog / DB     │
              └─────────────────────────┘
```

---

## Startup and initialization

### First-time init (`ssh-rt-admin init`)

```
1. Generate CA signing key pair (Ed25519 or ECDSA P-256)
2. Generate self-signed CA cert (the authorization trust root)
3. Generate CA's own TLS server cert (for the mTLS listener)
4. Generate bootstrap admin mTLS cert (role: superuser)
5. Write to CA data directory:
   ca-dir/
     signing-key.pem          # CA private signing key (protect!)
     signing-cert.pem         # CA self-signed cert (auth trust root)
     tls-server-cert.pem      # CA's TLS server cert
     tls-server-key.pem       # CA's TLS server private key
     tls-ca-cert.pem          # trust root for server/admin mTLS certs
     bootstrap-admin-cert.pem # bootstrap admin cert
     bootstrap-admin-key.pem  # bootstrap admin private key
     enrollment.yaml          # empty enrollment database (PoC)
     audit.jsonl              # empty audit log
6. Print bootstrap admin cert path to stdout
7. Print instructions: "Use this cert to set up admins, servers, users"
```

### Normal startup (`ssh-rt-auth-ca start`)

```
1. Load CA config file
2. Load signing key into memory
3. Load TLS server cert and key
4. Load trust root for server/admin mTLS certs
5. Load enrollment database
6. Load identity trust roots (for OpenSSH cert validation)
7. Open audit log for append
8. Start mTLS listener on configured port
9. Register SIGHUP handler for enrollment reload
```

### CA config file

```yaml
# /etc/ssh-rt-auth/ca-config.yaml

listen: 0.0.0.0:8443

# CA's own signing key and cert
signing_key: /etc/ssh-rt-auth/ca/signing-key.pem
signing_cert: /etc/ssh-rt-auth/ca/signing-cert.pem

# TLS server cert (what servers/admins see when connecting)
tls_cert: /etc/ssh-rt-auth/ca/tls-server-cert.pem
tls_key: /etc/ssh-rt-auth/ca/tls-server-key.pem

# Trust root for validating server and admin mTLS client certs
client_ca_cert: /etc/ssh-rt-auth/ca/tls-ca-cert.pem

# Identity trust roots for validating OpenSSH user certs
# (only needed if openssh-cert identity type is in use)
identity_trust_roots:
  - /etc/ssh-rt-auth/ca/user-ca.pub

# Enrollment database
enrollment:
  type: file                 # "file" for PoC, "database" for production
  path: /etc/ssh-rt-auth/ca/enrollment.yaml

# Audit log
audit:
  type: file                 # "file", "syslog", "database"
  path: /var/log/ssh-rt-auth/audit.jsonl

# Policy defaults
defaults:
  max_cert_validity_seconds: 3600
  timestamp_drift_seconds: 60

# mTLS cert generation settings
cert_generation:
  key_type: ec               # "ec" (P-256) or "ed25519"
  server_cert_validity_days: 365
  admin_cert_validity_days: 365
```

---

## Enrollment database

### Schema (logical)

The enrollment database has four tables. The PoC implements these as sections in a
YAML file. Production uses a relational database.

#### Servers

| Field | Type | Constraints |
|-------|------|-------------|
| `name` | string | Primary key. 1–128 chars. |
| `mtls_subject` | string | Unique. The CN or SAN from the server's mTLS cert. |
| `groups` | array of string | Group memberships. |
| `enrolled_at` | timestamp | |
| `enrolled_by` | string | Admin who enrolled this server. |

#### Users

| Field | Type | Constraints |
|-------|------|-------------|
| `username` | string | Primary key. 1–64 chars. |
| `enrolled_at` | timestamp | |
| `enrolled_by` | string | Admin who enrolled this user. |

#### Keys (child of Users)

| Field | Type | Constraints |
|-------|------|-------------|
| `fingerprint` | string | Primary key. SHA-256 fingerprint. |
| `username` | string | Foreign key → Users. |
| `type` | string | `pubkey` or `openssh-cert`. |
| `key_type` | string | `ssh-ed25519`, `ssh-rsa`, etc. |
| `key_id` | string | For openssh-cert only. |
| `principals` | array of string | For openssh-cert only. |
| `added_at` | timestamp | |
| `added_by` | string | Admin who added this key. |

#### Policies

| Field | Type | Constraints |
|-------|------|-------------|
| `id` | string | Primary key. Auto-generated (e.g., `pol-001`). |
| `username` | string | Foreign key → Users. |
| `servers` | array of string | Server canonical names (each must exist). |
| `server_groups` | array of string | Group names. |
| `channels` | array of string | Allowed channel types. |
| `source_cidrs` | array of string | CIDR notation. Empty = any. |
| `time_window` | object or null | Days, hours, timezone. |
| `max_cert_validity_seconds` | integer | |
| `environment` | object | Key-value pairs. |
| `force_command` | string or null | |
| `created_at` | timestamp | |
| `created_by` | string | Admin who created this policy. |

#### Admins

| Field | Type | Constraints |
|-------|------|-------------|
| `name` | string | Primary key. 1–64 chars. |
| `role` | string | `superuser`, `server-admin`, `user-admin`, `auditor`. |
| `mtls_subject` | string | Unique. The CN from the admin's mTLS cert. |
| `enrolled_at` | timestamp | |
| `enrolled_by` | string | Admin who enrolled this admin. |

### PoC: YAML file

The YAML file mirrors the logical schema directly. The CA reads it at startup and
on SIGHUP. The `ssh-rt-admin` CLI tool reads and writes this file directly (when
using `--store file:` mode).

### Production: database

The CA connects to a database (SQLite for single-instance, PostgreSQL for
multi-instance). The schema maps directly from the logical schema above. The
`ssh-rt-admin` CLI tool uses the admin API (`--store api:`) rather than accessing
the database directly.

For HA deployments, multiple CA instances connect to the same database. The
database handles concurrency. The CA does not cache enrollment data in memory
beyond the current request — it reads from the database on every authorization
query. This is simple and correct; if performance requires it, a read-through
cache with a short TTL (e.g., 5 seconds) can be added without changing the
architecture.

---

## Authorization request processing

Detailed walkthrough of what happens inside the CA when `POST /v1/authorize` arrives.

### Step 1: Server identification

The mTLS handshake has already validated the server's client cert. The CA extracts
the cert's subject CN (or SAN) and looks it up in the servers table.

```python
# Pseudocode
server_subject = tls_connection.client_cert.subject_cn
server = enrollment.servers.find_by_mtls_subject(server_subject)
if server is None:
    # This shouldn't happen — the mTLS cert was signed by our CA,
    # but the server was removed from enrollment after cert issuance.
    return 401 Unauthorized
```

Result: `server.name` (canonical name) and `server.groups`.

### Step 2: Parse request body

Validate JSON structure. Extract `identity.type`, `identity.data`,
`connection.source_ip`, `connection.source_port`, `connection.timestamp`,
and optionally `requested_channels`.

Check timestamp drift: if `abs(now - timestamp) > defaults.timestamp_drift_seconds`,
reject with `reason: "clock_drift"`.

### Step 3: Parse identity blob

Decode `identity.data` from base64 to raw bytes.

**For `type: pubkey`:**

```python
# Parse SSH public key wire format
key_type, key_data = parse_ssh_pubkey_blob(raw_bytes)
fingerprint = sha256_fingerprint(raw_bytes)
```

**For `type: openssh-cert`:**

```python
# Parse OpenSSH certificate
cert = parse_openssh_cert(raw_bytes)
# Fields available: cert.key_type, cert.nonce, cert.public_key,
#   cert.serial, cert.type (must be 1 = user cert),
#   cert.key_id, cert.principals, cert.valid_after, cert.valid_before,
#   cert.critical_options, cert.extensions, cert.signature_key,
#   cert.signature

# Validate trust chain
signing_ca_pubkey = cert.signature_key
if signing_ca_pubkey not in identity_trust_roots:
    return 403 denied, reason: "invalid_identity_cert",
           detail: "signing CA not in identity trust roots"

# Verify cert signature
if not verify_cert_signature(cert):
    return 403 denied, reason: "invalid_identity_cert",
           detail: "cert signature verification failed"

# Check cert validity window
if now < cert.valid_after or now > cert.valid_before:
    return 403 denied, reason: "invalid_identity_cert",
           detail: "identity cert expired or not yet valid"

fingerprint = sha256_fingerprint(cert.public_key)
```

### Step 4: Identity lookup

```python
# Try fingerprint match first (works for both pubkey and openssh-cert)
key_record = enrollment.keys.find_by_fingerprint(fingerprint)

if key_record is None and identity_type == "openssh-cert":
    # Try key-id match (some deployments enroll by key-id rather than fingerprint)
    key_record = enrollment.keys.find_by_key_id(cert.key_id)

if key_record is None:
    return 403 denied, reason: "unknown_identity"

user = enrollment.users.get(key_record.username)
```

### Step 5: Policy evaluation

```python
# Find all policies for this user that match this server
matching_policies = []
for policy in user.policies:
    server_match = (
        server.name in policy.servers or
        any(g in server.groups for g in policy.server_groups)
    )
    if not server_match:
        continue

    # Source check
    if policy.source_cidrs:
        if not any(ip_in_cidr(source_ip, cidr) for cidr in policy.source_cidrs):
            continue

    # Time check
    if policy.time_window:
        if not time_in_window(timestamp, policy.time_window):
            continue

    matching_policies.append(policy)

if not matching_policies:
    return 403 denied, reason: "no_matching_policy"
```

### Step 6: Policy merging

If multiple policies match (e.g., user has access via both a server name and a
group membership), merge them:

```python
# Merge: union of channels, most permissive source, shortest validity
merged_channels = set()
merged_environment = {}
merged_force_command = None
merged_max_validity = defaults.max_cert_validity_seconds

for policy in matching_policies:
    merged_channels.update(policy.channels)
    merged_environment.update(policy.environment)
    if policy.force_command:
        merged_force_command = policy.force_command  # last wins
    merged_max_validity = min(merged_max_validity, policy.max_cert_validity_seconds)
```

Policy merging strategy: **channels are unioned, validity takes the shortest,
environment is merged (last wins on conflicts), force_command takes the most
restrictive (if any policy has a force_command, it wins).**

If `requested_channels` is provided and no requested channel is in the merged set,
deny. Otherwise, the cert grants the merged set regardless of what was requested.

### Step 7: Cert generation

```python
not_before = now
not_after = now + min(merged_max_validity, defaults.max_cert_validity_seconds)

cert = X509Certificate()
cert.version = 3
cert.serial = generate_unique_serial()
cert.issuer = ca_signing_cert.subject
cert.subject = DN(CN=user.username, O="ssh-rt-auth")
cert.not_before = not_before
cert.not_after = not_after
cert.public_key = extract_public_key(identity_blob)

# Custom extensions
cert.add_extension("sshrtauth-source-bind", critical=True,
                   value=source_ip)
cert.add_extension("sshrtauth-server-bind", critical=True,
                   value=server.name)
cert.add_extension("sshrtauth-channel-policy", critical=True,
                   value=sorted(merged_channels))
if merged_force_command:
    cert.add_extension("sshrtauth-force-command", critical=False,
                       value=merged_force_command)
if merged_environment:
    cert.add_extension("sshrtauth-environment", critical=False,
                       value=merged_environment)

cert.sign(ca_signing_key)
```

### Step 8: Audit and respond

```python
# Write audit log entry
audit.write({
    "timestamp": now_iso8601(),
    "type": "authorization",
    "decision": "granted",
    "serial": cert.serial_hex,
    "identity": {
        "type": identity_type,
        "fingerprint": fingerprint,
        "username": user.username
    },
    "server": {
        "canonical_name": server.name,
        "groups": server.groups
    },
    "connection": {
        "source_ip": source_ip,
        "source_port": source_port
    },
    "cert_validity": {
        "not_before": not_before_iso8601,
        "not_after": not_after_iso8601
    },
    "policy_applied": {
        "policy_ids": [p.id for p in matching_policies],
        "channels": sorted(merged_channels),
        "source_bound": True,
        "force_command": merged_force_command
    }
})

# Return response
return 200, {
    "status": "granted",
    "cert": base64_encode(cert.to_der()),
    "serial": cert.serial_hex,
    "not_after": not_after_iso8601,
    "policy_summary": { ... }
}
```

---

## Admin request processing

### Authentication and authorization

Every admin request goes through:

```python
admin_subject = tls_connection.client_cert.subject_cn
admin = enrollment.admins.find_by_mtls_subject(admin_subject)
if admin is None:
    return 401 Unauthorized

if not admin.role.permits(requested_operation):
    audit.write({
        "timestamp": now_iso8601(),
        "type": "admin",
        "action": requested_operation,
        "admin": {"name": admin.name, "role": admin.role},
        "result": "forbidden"
    })
    return 403 Forbidden
```

### mTLS cert generation for servers and admins

When enrolling a server or admin, the CA generates an mTLS client cert:

```python
def generate_mtls_cert(common_name, validity_days):
    key = generate_private_key(config.cert_generation.key_type)

    cert = X509Certificate()
    cert.subject = DN(CN=common_name)
    cert.issuer = tls_ca_cert.subject    # signed by the mTLS CA
    cert.not_before = now
    cert.not_after = now + days(validity_days)
    cert.public_key = key.public_key()
    cert.sign(tls_ca_key)

    return cert, key
```

The generated cert and key are returned to the admin in the API response. The admin
deploys them to the server (for server certs) or to the admin's workstation (for
admin certs).

### Audit logging for admin actions

Every admin action is logged, including the admin's identity, role, the action
performed, and the target:

```json
{
  "timestamp": "2026-05-11T10:00:00Z",
  "type": "admin",
  "action": "server.add",
  "admin": {
    "name": "ops-alice",
    "role": "server-admin"
  },
  "target": {
    "server_name": "prod-db-01",
    "groups": ["production", "databases"]
  },
  "result": "ok"
}
```

---

## Cert minting details

### Serial number generation

Serials must be unique across all certs ever issued by this CA. The PoC uses a
monotonically increasing counter stored on disk (or derived from a high-resolution
timestamp + random suffix). Production should use a cryptographically random 128-bit
value to avoid predictability.

### Extension encoding

Custom extensions are encoded as ASN.1 within the X.509 extension framework.

| Extension | OID (PoC) | ASN.1 encoding |
|-----------|-----------|----------------|
| `sshrtauth-source-bind` | 1.3.6.1.4.1.XXXXX.1.1 | UTF8String (IP or CIDR) |
| `sshrtauth-server-bind` | 1.3.6.1.4.1.XXXXX.1.2 | UTF8String (canonical server name) |
| `sshrtauth-channel-policy` | 1.3.6.1.4.1.XXXXX.1.3 | SEQUENCE OF UTF8String |
| `sshrtauth-force-command` | 1.3.6.1.4.1.XXXXX.1.4 | UTF8String |
| `sshrtauth-environment` | 1.3.6.1.4.1.XXXXX.1.5 | SEQUENCE OF UTF8String (key=value pairs) |
| `sshrtauth-max-session` | 1.3.6.1.4.1.XXXXX.1.6 | INTEGER (seconds) |
| `sshrtauth-2fa-evidence` | 1.3.6.1.4.1.XXXXX.1.7 | UTF8String |

XXXXX is a placeholder for the private enterprise number. The PoC can use any
unused arc under 1.3.6.1.4.1.

### Signing algorithm

The CA signs authorization certs using the same algorithm as its signing key:

- Ed25519 key → Ed25519 signature
- ECDSA P-256 key → ECDSA with SHA-256

RSA signing keys are not supported. Ed25519 is preferred for the PoC.

---

## ssh-rt-admin CLI

### Architecture

The CLI is a thin client that talks to the CA's admin API over mTLS. For the PoC
file-based mode, it reads/writes the YAML enrollment file directly.

```
ssh-rt-admin
  ├── main.py                # argument parsing, dispatch
  ├── client.py              # mTLS HTTP client for API mode
  ├── file_store.py          # direct YAML read/write for file mode
  ├── key_parser.py          # SSH public key and cert parsing
  ├── formatters.py          # output formatting (table, json, yaml)
  └── config.py              # CLI config (~/.ssh-rt-admin/config)
```

### CLI config file

```yaml
# ~/.ssh-rt-admin/config
ca_url: https://ca1.internal:8443
admin_cert: /home/alice/.ssh-rt-admin/cert.pem
admin_key: /home/alice/.ssh-rt-admin/key.pem
ca_cert: /home/alice/.ssh-rt-admin/ca-cert.pem
output_format: table         # table, json, yaml
```

Override with flags: `--ca-url`, `--admin-cert`, `--admin-key`, `--format`.

### Key parsing

The CLI accepts SSH keys and certs in multiple input formats:

```python
def parse_key_input(path):
    """
    Accepts:
    - SSH public key file (ssh-ed25519 AAAA... user@host)
    - OpenSSH cert file (ssh-ed25519-cert-v01@openssh.com AAAA...)
    - authorized_keys entry (options ssh-ed25519 AAAA...)
    - Bare base64 blob

    Returns: (type, raw_blob, metadata)
      type: "pubkey" or "openssh-cert"
      raw_blob: bytes
      metadata: {fingerprint, key_type, key_id?, principals?}
    """
```

This is the core value of the CLI: admins never handle fingerprints manually.
They point at a key file, the CLI extracts everything.

### Output formatting

```
$ ssh-rt-admin user list

USERNAME    KEYS    POLICIES    ENROLLED
alice       1       2           2026-05-11 10:00
bob         1       2           2026-05-11 10:05

$ ssh-rt-admin user list --user alice

Username: alice
Enrolled: 2026-05-11 10:00 by ops-alice

Keys:
  ssh-ed25519  SHA256:AbCdEf...

Policies:
  pol-001: servers=[prod-db-01,prod-db-02] channels=[session,direct-tcpip,subsystem:sftp]
           source=10.0.0.0/8 time=mon-fri 08:00-18:00 ET validity=3600s
  pol-002: server_groups=[development] channels=[session,direct-tcpip,forwarded-tcpip,subsystem:sftp]
           source=any time=any validity=7200s

$ ssh-rt-admin user list --format json
[{"username":"alice","keys":[...],"policies":[...]}]
```

### Error handling

The CLI exits with:

- `0` — success
- `1` — request error (bad input, validation failure)
- `2` — auth error (cert rejected, insufficient role)
- `3` — connection error (CA unreachable)
- `4` — internal error

Error messages go to stderr. Normal output goes to stdout.

---

## PoC implementation plan

### Phase 1: CA and admin tool

1. Implement `ssh-rt-admin init` (generates CA keys, bootstrap cert)
2. Implement enrollment YAML read/write
3. Implement `POST /v1/authorize` with identity parsing and policy evaluation
4. Implement X.509 cert minting with custom extensions
5. Implement admin API endpoints (server add, user add, key add, policy add)
6. Implement admin authentication and role checking
7. Implement audit logging
8. Test with `curl` and hand-crafted requests

### Phase 2: Shim (Python)

1. Implement Python shim with mTLS client
2. Implement cache (in-memory dict for Python PoC)
3. Implement failover logic
4. Test shim against CA

### Phase 3: sshd integration

1. Integrate Python shim with Paramiko/AsyncSSH server for PoC
2. Test end-to-end: SSH client → Python sshd → shim → CA → authorized session
3. Verify cert constraint enforcement (channel policy, source bind)

### Phase 4: OpenSSH patch

1. Write C shim (shared library)
2. Patch OpenSSH to call the C shim
3. Test end-to-end with real OpenSSH

### Dependencies (Python PoC)

| Package | Purpose |
|---------|---------|
| `cryptography` | X.509 cert generation, key handling, OpenSSH key/cert parsing |
| `flask` | HTTPS API server |
| `pyyaml` | Enrollment config parsing |
| `click` | CLI argument parsing for ssh-rt-admin |
| `requests` | HTTP client for CLI → CA communication |
| `ipaddress` (stdlib) | CIDR matching |
| `datetime` (stdlib) | Time window evaluation |
| `ssl` (stdlib) | mTLS setup |
