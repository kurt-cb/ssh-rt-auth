# ssh-rt-auth v2 enhancement plan

**Status:** Forward-looking design. Not implemented in the PoC. This
document is the reference for the **v2 reference CA implementation**.

**Audience:** Future maintainers, upstream OpenSSH reviewers, anyone
extending the policy DSL or the X.509 extension set.

---

## 1. Goal

The PoC's authorization decision rests on a thin context blob:
`(identity, source_ip, source_port, timestamp, requested_channels)`. That
is enough to validate the end-to-end model but leaves several classes of
policy unstateable. v2 broadens the context the CA receives, records it
in the audit log, and reserves OID space for new cert extensions that
consume it.

Three principles guide the design:

1. **Unpatched sshd must keep working.** The v2 OpenSSH patch series
   ([../../ssh-rt-auth-openssh/NOTES.md](../../ssh-rt-auth-openssh/NOTES.md))
   is an *enhancement*, never a prerequisite. The CA continues to
   authorize against stock distro sshds via `AuthorizedKeysCommand`.
   Admins choose per-policy whether to *require* patched sshds, and
   what minimum sshd version is acceptable — but the org must never
   be forced to wait on a distro update to deploy ssh-rt-auth.
   Spec: § 5.
2. **Capture even what we don't yet consume.** The audit log is the
   forensics record; every additional field is one more thing an
   incident responder can pivot on six months from now. Cost is low
   (bytes); benefit is unbounded.
3. **Plumbing first, policy second.** Land the sshd-side patches and
   the CA-side schema in v1 form so that turning on a v2 feature is a
   pure CA-side change. No coordinated sshd redeploy needed once the
   context is flowing.

---

## 2. Wire format: `connection` blob v2

Extends the existing `POST /v1/authorize` request body
([ssh-rt-auth-detailed-rest-api.md](ssh-rt-auth-detailed-rest-api.md)
§ Request fields). All new fields are **optional** — the CA must accept
v1 requests unchanged. The patched sshd populates as many fields as it
can; absent fields are treated as "unknown", never as a constraint
violation.

```jsonc
{
  "identity": { "type": "pubkey", "data": "…" },

  "connection": {
    // v1 — already in scope
    "source_ip": "10.0.1.42",
    "source_port": 52341,
    "timestamp": "2026-05-11T14:23:07Z",

    // v2 — network leg
    "local_ip":   "10.0.1.7",         // which interface accepted the conn
    "local_port": 22,
    "interface":  "eth1",             // optional, where sshd knows it

    // v2 — SSH transport
    "ssh_session_id": "base64(H)",    // RFC 4253 §7.2 exchange hash
    "ssh_version_client": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
    "ssh_version_server": "SSH-2.0-OpenSSH_9.9p1",   // sshd-supplied; see § 2.1
    "sshd_version_local":   "OpenSSH_9.9p1, OpenSSL 3.0.13",
                                                     // shim-supplied fallback
                                                     // when sshd doesn't speak v2
    "sshd_build_info": {                              // optional, sshd-supplied
      "openssl_version": "OpenSSL 3.0.13",
      "compile_flags":   ["WITH_PAM", "WITH_SELINUX"]
    },
    "negotiated": {
      "kex":      "curve25519-sha256",
      "cipher_cs": "chacha20-poly1305@openssh.com",
      "cipher_sc": "chacha20-poly1305@openssh.com",
      "mac_cs":   "hmac-sha2-256-etm@openssh.com",
      "mac_sc":   "hmac-sha2-256-etm@openssh.com",
      "compression_cs": "none",
      "compression_sc": "none",
      "host_key_alg": "ssh-ed25519"
    },
    "server_host_key_fp": "SHA256:abc…",  // which host key the server presented

    // v2 — userauth
    "auth_method": "publickey",       // or hostbased, keyboard-interactive, …
    "auth_attempts_this_session": 1,
    "have_signature": true,           // false on the "query" half of pubkey auth
    "signature_alg": "ssh-ed25519",   // alg actually used to sign userauth req

    // v2 — for openssh-cert identity only; mirrored from the cert blob
    // for convenience. CA still does authoritative parsing.
    "openssh_cert": {
      "issuer_ca_fp": "SHA256:def…",
      "key_id": "alice@corp",
      "principals": ["alice"],
      "valid_after":  "2026-05-11T00:00:00Z",
      "valid_before": "2026-05-12T00:00:00Z"
    },

    // v2 — process / sshd context
    "sshd_pid":    12345,
    "sshd_uptime_seconds": 3600,
    "server_canonical_name": "prod-db-01"   // sshd's view; CA cross-checks
  },

  "requested_channels": ["session", "direct-tcpip"],

  // v2 — sshd implementation tag, lets the CA tune behaviour per-impl
  "client_impl": {
    "name": "openssh-portable",
    "version": "9.9p1",
    "patches": ["ssh-rt-auth-v2"]      // list of well-known patch tags applied
  }
}
```

### 2.1 Server version: belt and suspenders

`ssh_version_server` is the SSH banner the sshd advertised on the
wire (`SSH-2.0-OpenSSH_9.9p1`). It is the canonical answer for
"what sshd accepted this connection" and the patched sshd is the
right authority to set it.

For unpatched sshds — including the legacy `AuthorizedKeysCommand`
path that ships in the PoC — the shim can derive an equivalent
locally without sshd's cooperation:

| Source                              | Reliability                       | Cost                |
|-------------------------------------|-----------------------------------|---------------------|
| `sshd -V` (where supported)         | Authoritative on portable OpenSSH | One subprocess      |
| `/proc/$PPID/exe` → readlink + version flag | Authoritative                | One readlink + exec |
| Package manager: `dpkg-query -W openssh-server`, `rpm -q openssh-server`, `apk info openssh-server` | Build/distro version | One subprocess |
| `uname -a`                           | OS/kernel context only            | One syscall         |

The shim should populate `connection.sshd_version_local` from one of
those when `ssh_version_server` is absent from the inbound context —
the audit log then has *something* even when the sshd doesn't speak
v2. This is the same "best-effort fallback" pattern the PoC already
uses for `source_ip` (issue 9.1).

### Encoding rules

- All new fields are optional. CA must default-tolerate omission.
- Strings are UTF-8, max 256 bytes each unless noted otherwise.
- The request body must stay under 64 KB total (existing limit).
- Unknown top-level keys in `connection` are silently preserved by the
  CA into the audit log but ignored for policy decisions. This is the
  forward-compat hook for sshd implementations that get there first.

---

## 3. Audit log: capture everything

The audit log entry written by `ca/authorize.py`
([detailed-ca-admin.md](ssh-rt-auth-detailed-ca-admin.md) § Step 8) is
extended to include the **complete** `connection` blob received, plus
the negotiated set above, regardless of whether any policy referenced
those fields.

```jsonc
{
  "timestamp": "2026-05-11T14:23:07Z",
  "type": "authorization",
  "decision": "granted",
  "serial": "a1b2…",
  "identity": { … },             // v1
  "server":   { … },             // v1
  "connection": { … },           // entire v2 blob, verbatim
  "cert_validity": { … },        // v1
  "policy_applied": { … },       // v1
  "v2_features_consumed": [      // which v2 fields actually drove the decision
    "negotiated.cipher_cs",
    "server_host_key_fp"
  ]
}
```

`v2_features_consumed` is the inversion that makes the log useful:
forensics can grep for "did this decision rely on the SSH session ID
binding being present?" without re-running policy.

**Storage cost:** ~1–2 KB extra per authorization decision; for a fleet
doing ≤10 logins/sec that's <2 GB/day uncompressed. JSONL compresses
~10×; cheap.

---

## 4. Reserved OIDs for v2 cert extensions

Current PoC uses `1.3.6.1.4.1.55555.1.{1..7}`
([detailed-ca-admin.md](ssh-rt-auth-detailed-ca-admin.md) § Custom
extensions). The arc `1.3.6.1.4.1.55555.1.{8..31}` is **reserved for
v2** — minted certs may include these critical-or-noncritical extensions
once the v2 reference CA implements them.

**Enforcement scope:** the v2 extensions in this arc are enforced **only
by Tier 1 (reference server) and Tier 2 (library integrations)**, per
[ssh-rt-auth-server-strategy.md](ssh-rt-auth-server-strategy.md). Tier 3
(OpenSSH compatibility mode) does not enforce them — minted certs sent
to Tier 3 hosts will simply have their v2 extensions ignored. Policies
that depend on v2 extensions should therefore be gated on
`sshd_requirements.patched: required` (§ 5.2) or on a Tier 1 / Tier 2
server tag in the enrollment DB, so the CA refuses to issue them to
Tier 3 endpoints in the first place.

| OID                                | Name                            | ASN.1                           | Consumes (from §2)                | Critical |
|------------------------------------|---------------------------------|---------------------------------|-----------------------------------|----------|
| `1.3.6.1.4.1.55555.1.8`            | `sshrtauth-session-bind`        | OCTET STRING (32 bytes, H)      | `ssh_session_id`                  | Yes      |
| `1.3.6.1.4.1.55555.1.9`            | `sshrtauth-crypto-floor`        | SEQUENCE OF UTF8String          | `negotiated.*`                    | Yes      |
| `1.3.6.1.4.1.55555.1.10`           | `sshrtauth-client-version-allow`| SEQUENCE OF UTF8String (globs)  | `ssh_version_client`              | No       |
| `1.3.6.1.4.1.55555.1.11`           | `sshrtauth-host-key-pin`        | OCTET STRING (SHA256 fp)        | `server_host_key_fp`              | Yes      |
| `1.3.6.1.4.1.55555.1.12`           | `sshrtauth-auth-method-allow`   | SEQUENCE OF UTF8String          | `auth_method`                     | Yes      |
| `1.3.6.1.4.1.55555.1.13`           | `sshrtauth-issuer-ca-pin`       | OCTET STRING (SHA256 fp)        | `openssh_cert.issuer_ca_fp`       | Yes      |
| `1.3.6.1.4.1.55555.1.14`           | `sshrtauth-local-bind`          | UTF8String (IP/CIDR or iface)   | `local_ip`, `interface`           | Yes      |
| `1.3.6.1.4.1.55555.1.15`           | `sshrtauth-step-up-required`    | UTF8String (method tag)         | (CA-side; out-of-band 2FA hint)   | No       |
| `1.3.6.1.4.1.55555.1.16` … `.1.31` | *Reserved for future v2 work*   | —                               | —                                 | —        |

Reservation policy: anyone who wants to claim one of these for an
intermediate experiment must commit a note to this file naming the OID,
the field, and the consuming policy DSL key, so collisions don't happen.

---

## 5. sshd implementation policy (patched / unpatched gate)

**A core property of ssh-rt-auth is that it MUST keep working against
unmodified, upstream sshd.** The v2 patch series is an enhancement, not
a prerequisite. An organization rolling out ssh-rt-auth should be able
to:

1. Stand the CA up on day one against a fleet of stock distro sshds.
2. Decide per-policy whether a given role / server group / user must
   come from a patched sshd, and what minimum sshd version is allowed.
3. Migrate at its own pace, with the audit log surfacing exactly which
   connections are riding on the legacy path.

This section specifies the CA-side policy DSL and decision logic for
that gate.

### 5.1 Detection: patched vs unpatched

The CA classifies each request from the v2 `connection` blob:

| Condition                                                              | Classification                |
|------------------------------------------------------------------------|-------------------------------|
| `_schema == "ssh-rt-auth-v2.0"` AND `client_impl.patches` contains `"ssh-rt-auth-v2"` | **patched**          |
| `_schema` present but `client_impl.patches` does not list the tag      | **partial** (some patches)    |
| `_schema` absent (v1 wire format only)                                 | **unpatched** (legacy)        |

The shim is required to populate `sshd_version_local` on the unpatched
path (per § 2.1) so the CA always has *something* to evaluate against
`min_version`.

### 5.2 Policy DSL

New policy keys, all optional, none required for v1 compat:

```yaml
sshd_requirements:
  patched: required | preferred | optional   # default: optional
  required_patches: ["ssh-rt-auth-v2"]       # only meaningful when patched=required
  min_version: "OpenSSH_9.6"                 # version floor (impl-aware)
  allow_implementations: ["openssh", "dropbear"]
                                             # default: any
  deny_implementations: []
```

### 5.3 Decision logic

```
if sshd_requirements.patched == "required":
    if classification != "patched":
        DENY  reason=unpatched_sshd_required
if sshd_requirements.patched == "preferred":
    if classification != "patched":
        GRANT but set audit.degraded = true

if sshd_requirements.min_version is set:
    v = connection.ssh_version_server or connection.sshd_version_local
    if v is None:
        DENY  reason=sshd_version_unknown
    if parse(v).impl_version < parse(min_version).impl_version:
        DENY  reason=sshd_version_below_floor

if connection.implementation not in allow_implementations:
    DENY  reason=sshd_implementation_not_allowed
if connection.implementation in deny_implementations:
    DENY  reason=sshd_implementation_denied
```

### 5.4 Defaults

For PoC v0.2 (capture-only), every policy defaults to:

```yaml
sshd_requirements:
  patched: optional
  # no min_version, no implementation restrictions
```

This is intentional — flipping any of these on must be an explicit
admin decision, because a wrong default could lock the org out of its
own fleet during rollout.

### 5.5 Trust caveats

`client_impl`, `sshd_version_local`, and `connection._schema` are
**attestation-grade signals, not security claims**. The sshd and the
shim live on the same host as the mTLS client cert; a host compromise
can forge any of these values.

The actual security boundary remains where v1 put it:

- **Server identity:** the mTLS client cert presented to the CA. A
  rogue server without an enrolled cert cannot reach the CA at all.
- **User identity:** the cryptographic signature produced by the
  client's SSH private key.

`sshd_requirements` is therefore best understood as a **fleet-management
control**, not an attack mitigation: it lets the org enforce the
contract "every machine in production runs a patched sshd ≥ 9.6" and
makes drift loudly visible in the audit log. It is NOT a defence
against a compromised host claiming to be patched.

### 5.6 Audit additions

Every authorization entry gains an `sshd_attestation` block:

```jsonc
"sshd_attestation": {
  "classification": "patched",          // patched | partial | unpatched
  "implementation":  "openssh",
  "version":         "OpenSSH_9.9p1",
  "version_source":  "ssh_version_server",  // or sshd_version_local
  "patches_claimed": ["ssh-rt-auth-v2"],
  "degraded":        false              // true when patched=preferred fell through
}
```

This makes `jq '.sshd_attestation.classification == "unpatched"'` the
single query a security team needs to identify legacy-path traffic.

### 5.7 Migration sketch

| Phase    | Setting                                                     | Outcome                                                                              |
|----------|-------------------------------------------------------------|--------------------------------------------------------------------------------------|
| Day 0    | `patched: optional` everywhere                              | Stock sshd works. Audit log already differentiates patched vs unpatched.             |
| Day 30   | `patched: preferred` per role                               | Admins watch the audit log; `degraded=true` rows surface lagging hosts. No denials.  |
| Day 90   | `patched: required` for admin / privileged roles            | Privileged paths force the migration; regular-user roles still permissive.           |
| Eventual | Org-default `patched: required` + `min_version` floor       | Patched is the contract; legacy path remains for emergency rollback only.            |

The legacy `AuthorizedKeysCommand` path is never deprecated. Distros
ship what they ship; ssh-rt-auth's value proposition includes
working with the openssh-server package the org already has.

### 5.8 Deny reasons added to the audit schema

Adds to the existing reason vocabulary
([detailed-ca-admin.md](ssh-rt-auth-detailed-ca-admin.md) § Decision
reasons):

- `unpatched_sshd_required`
- `sshd_version_below_floor`
- `sshd_version_unknown`
- `sshd_implementation_not_allowed`
- `sshd_implementation_denied`

---

## 6. Per-feature TODO list

Each row is a v2 reference-CA feature. "Plumbing" lists what must be
true upstream of the CA before the feature can be turned on. The CA
side is always *just* policy DSL + cert-minter changes.

| # | Feature                            | Why                                                                 | Plumbing                                                       | Policy DSL key                | Cert ext           | Risk if naïve            |
|---|------------------------------------|---------------------------------------------------------------------|----------------------------------------------------------------|-------------------------------|--------------------|--------------------------|
| 1 | **SSH-session binding**            | Authz cert un-replayable across sessions even if leaked in flight    | sshd 0004 must surface `ssh_session_id`                        | `bind_to_session: true`       | `.1.8`             | False rejects on session resumption; verify on initial auth only |
| 2 | **Crypto floor**                   | Centrally enforced "no weak algs for admin role"                     | sshd 0004 surfaces `negotiated.*`                              | `min_cipher_strength: 256`    | `.1.9`             | Locks out clients on legacy boxes; ship as warn-only first |
| 3 | **Client-banner allowlist**        | Quick fleet-wide CVE response                                        | sshd 0004 surfaces `ssh_version_client`                        | `client_versions: ["OpenSSH_>=9.0"]` | `.1.10`     | Banner is trivially spoofable — informational signal only, not a hard gate |
| 4 | **Host-key pinning in the cert**   | Lets the CA "stamp" which server-instance keypair this cert is for   | sshd 0004 surfaces `server_host_key_fp`                        | `pin_host_key: true`          | `.1.11`            | Breaks host-key rotation unless mint-on-rotate path exists |
| 5 | **Auth-method gate**               | "Admin role requires hardware-backed key (`publickey` + ed25519-sk)" | sshd 0004 surfaces `auth_method` and `signature_alg`           | `require_methods: ["publickey-sk"]` | `.1.12`      | Need the matching SSH server config; ssh-rt-auth alone can't compel hardware |
| 6 | **OpenSSH-cert issuer pin**        | Multi-CA deployments: lab CA can't issue prod certs                  | OpenSSH cert blob already arrives; CA needs to parse + surface | `issuer_ca_pin: "SHA256:…"`   | `.1.13`            | Operationally heavy: rotation needs coordinated update |
| 7 | **Local-bind / mgmt VLAN policy**  | "Admin role only authorizable on `eth1`"                             | sshd 0004 surfaces `local_ip` / `interface`                    | `local_bind: ["mgmt-net"]`    | `.1.14`            | Need consistent interface naming across the fleet |
| 8 | **Step-up second-channel auth**    | Push-to-phone for high-risk roles                                    | CA-side: out-of-band confirmation service                       | `step_up: "push-totp"`        | `.1.15`            | Latency budget at login time; per-org confirmation infra |
| 9 | **Passive client OS fingerprint**  | "Stolen key + wrong OS = deny"                                       | sshd 0004 + new kernel-side TCP fp source                      | `client_os_profile: "linux"`  | TBD                | Noisy signal; only combine, never alone |
|10 | **Failed-attempt history**         | CA-side rate-limit / lockout aware of fleet-wide patterns            | sshd 0004 surfaces `auth_attempts_this_session`; CA maintains  cross-host counter | `rate_limit: {…}`     | TBD                | Need eventually-consistent counter store; not a thin-Flask job |

Items 1, 2, 4, 6 are the highest value/effort ratio. Item 1
(session-binding) is the only one that closes a genuinely new attack
class (cross-session cert replay); the rest tighten existing controls.

These features compose with the § 5 implementation gate: a policy can
require `patched + min_version` AND any of these, since some (e.g.
session-binding, item 1) are only populatable by a patched sshd.

---

## 7. Migration plan

1. **PoC v0.1 (current).** v1 wire format, OIDs `.1.1`–`.1.7`. No v2
   fields anywhere.
2. **PoC v0.2: capture-only.** Patched sshd populates the full v2
   `connection` blob. CA accepts and audit-logs the full blob, but
   policy evaluation is unchanged. No new cert extensions are minted.
   This is the right point at which to ship the OpenSSH patch series
   upstream — the upstream value is "richer context for any
   AuthorizationModule consumer", independent of ssh-rt-auth's policy
   choices.
3. **PoC v0.3+: per-feature enable.** Turn on items 1–N from §5 one at
   a time. Each adds a policy DSL key + a cert extension; the existing
   shim/server need a parser update only for `critical=true` extensions.
4. **Production (out of PoC scope).** C reference shim + Mbed TLS,
   long-lived daemon ([issues.md § 9.5](../tests/issues.md)), multi-CA
   replication.

---

## 8. Cross-references

- Wire format authority: [ssh-rt-auth-detailed-rest-api.md](ssh-rt-auth-detailed-rest-api.md)
- Audit log authority: [ssh-rt-auth-detailed-ca-admin.md](ssh-rt-auth-detailed-ca-admin.md) § "Audit and respond"
- OID arc authority: [ssh-rt-auth-detailed-ca-admin.md](ssh-rt-auth-detailed-ca-admin.md) § "Custom extensions"
- OpenSSH patch series: [../../ssh-rt-auth-openssh/NOTES.md](../../ssh-rt-auth-openssh/NOTES.md)
- Security review: [ssh-rt-auth-security-analysis.md](ssh-rt-auth-security-analysis.md)
