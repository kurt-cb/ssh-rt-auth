# ssh-rt-auth Design Doc 00: Overview

**Project:** ssh-rt-auth (runtime, CA-mediated SSH authorization)  
**Status:** Design phase v0.1  
**Author:** Kurt Godwin (github.com/kurt-cb)  

---

## What this project is

ssh-rt-auth is a runtime, CA-mediated SSH authorization system.

> Existing cert-based SSH puts the authorization cert on the client. This project moves the authorization cert to the server, where the server fetches it from a CA at connection time based on the client's identity proof. The client retains only a long-lived identity credential (their existing SSH key or an OpenSSH cert) — no cert lifecycle management on the client side, no client-held authorization that can be stolen and replayed.

### The architectural property this enables

A stolen client credential is useless if the attacker cannot reach the CA. This is structurally different from every other cert-based SSH system. In systems with client-held certs, the defense against credential theft is "short cert validity bounds the damage window." Here, the defense is "isolation of the CA on a private network eliminates the threat entirely." Place the CA on a network reachable only from inside your security perimeter; an attacker who exfiltrates a private key off a developer's laptop can prove identity all they want, but cannot receive the CA's authorization response on a server that will not talk to them.

---

## Component overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     SECURITY PERIMETER                          │
│                                                                 │
│  ┌──────────┐            ┌──────────────┐            ┌────────────────────┐
│  │          │  call out  │              │   mTLS     │                    │
│  │  sshd    │───────────►│  ssh-rt-auth │◄──────────►│  Authorization     │
│  │          │  (module)  │  shim        │  auth query│  CA (primary)      │
│  │          │            │              │  + response│                    │
│  └────▲─────┘            │  Owns:       │            └────────────────────┘
│       │                  │  - CA list   │
│       │ SSH              │  - mTLS cert │            ┌────────────────────┐
│       │                  │  - cache     │   mTLS     │                    │
│       │                  │  - shim cfg  │◄──────────►│  Authorization     │
│       │                  │              │  (failover)│  CA (secondary)    │
│       │                  └──────────────┘            │                    │
│       │                                              └─────────▲──────────┘
│       │                                                        │
│       │                                              mTLS (admin cert)
│       │                                              ┌─────────┴──────────┐
│       │                                              │  ssh-rt-admin      │
│       │                                              │  (CLI tool)        │
│       │                                              └────────────────────┘
└───────┼─────────────────────────────────────────────────────────────────────┘
        │
        │ SSH (standard protocol)
        │
┌───────┴─────────┐
│  SSH Client     │
│  (unmodified)   │
│  - bare key     │
│  - OpenSSH cert │
└─────────────────┘
```

sshd's only integration point is a call to the ssh-rt-auth shim module. The shim owns
all ssh-rt-auth configuration: CA endpoints, mTLS certs, cache, failover. sshd_config
has a single directive pointing to the shim. Everything else lives in the shim's own
config file.

---

## Trust model: three independent trust roots

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  1. User Identity Trust Root                                │
│     ┌────────────────────┐                                  │
│     │  User Identity CA  │  Signs OpenSSH user certs        │
│     │  (existing PKI)    │  (only needed for openssh-cert   │
│     └────────────────────┘   identity proof type)           │
│                                                             │
│  2. Server Identity Trust Root                              │
│     ┌────────────────────┐                                  │
│     │  mTLS CA           │  Signs server mTLS client certs  │
│     │                    │  (identifies servers to the      │
│     └────────────────────┘   authorization CA)              │
│                                                             │
│  3. Authorization Signing Key                               │
│     ┌────────────────────┐                                  │
│     │  Authorization CA  │  Signs X.509 authorization certs │
│     │  (this project)    │  (carries policy constraints)    │
│     └────────────────────┘                                  │
│                                                             │
│  These can all be different CAs. The identity authority,    │
│  the server identity authority, and the authorization       │
│  authority are independent.                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Authorization flow

```
 SSH Client              sshd            ssh-rt-auth shim       Authorization CA
     │                    │                     │                      │
     │  1. SSH connect    │                     │                      │
     │  + userauth        │                     │                      │
     │───────────────────►│                     │                      │
     │                    │                     │                      │
     │        2. Validate signature             │                      │
     │           (existing sshd logic)          │                      │
     │                    │                     │                      │
     │                    │  3. Call shim        │                      │
     │                    │  {identity blob,    │                      │
     │                    │   connection ctx}   │                      │
     │                    │────────────────────►│                      │
     │                    │                     │                      │
     │                    │         4. Check cache                     │
     │                    │            (hit → return cached cert)      │
     │                    │                     │                      │
     │                    │                     │  5. POST /v1/authorize
     │                    │                     │     over mTLS        │
     │                    │                     │─────────────────────►│
     │                    │                     │                      │
     │                    │                     │      6. CA identifies server
     │                    │                     │         from mTLS cert
     │                    │                     │      7. CA parses identity
     │                    │                     │      8. CA evaluates policy
     │                    │                     │      9. CA mints X.509 cert
     │                    │                     │                      │
     │                    │                     │  10. Response         │
     │                    │                     │  {cert, serial}      │
     │                    │                     │◄─────────────────────│
     │                    │                     │                      │
     │                    │        11. Cache cert│                      │
     │                    │                     │                      │
     │                    │  12. Return cert    │                      │
     │                    │◄────────────────────│                      │
     │                    │                     │                      │
     │       13. Enforce constraints            │                      │
     │                    │                     │                      │
     │  14. Auth success  │                     │                      │
     │◄───────────────────│                     │                      │
     │                    │                     │                      │
     │  15. Session       │                     │                      │
     │◄──────────────────►│                     │                      │
```

If the primary CA is unreachable, the shim tries the next CA endpoint in its
configuration. If all CAs are unreachable, the shim returns denial (fail-closed)
unless an admin emergency cert applies.

---

## Architectural decisions, settled

**Authorization cert format: X.509 with policy extensions.** The cert that lives in the server's cache and carries the policy is X.509. This is settled.

**Authorization cert lifecycle: short-lived, server-cached.** The CA mints these on demand. Typical validity: seconds to hours. The server caches for the validity window. Cache miss → server queries CA → CA returns cert → server caches and uses.

**Identity proof: two formats, both natively supported by sshd.**

1. **Bare SSH public key + signature** — Classic SSH userauth. sshd validates the signature, forwards the raw public key blob to the CA.
2. **OpenSSH cert + signature** — sshd validates the cert against a configured identity trust root, forwards the raw cert blob to the CA. The CA parses the cert independently.

These are the formats sshd already validates natively. v1 is intentionally scoped to what sshd does without modification to its userauth logic.

**Server identity via mTLS.** Each server is enrolled with the CA and has an mTLS client cert. The CA identifies the server from the mTLS handshake and looks up the server's canonical name in its own enrollment database. The server never self-reports its identity. The server's OpenSSH host cert (used for client-facing SSH connections) is entirely separate.

**Raw identity blob forwarding.** sshd does not parse identity cert internals. It validates the cryptographic proof (signature check), then forwards the raw public key or cert blob to the CA. The CA does all identity parsing and independently validates cert trust chains.

**Final reference implementation: C with Mbed TLS.** CA footprint under 10 MB on Alpine. However, the initial proof of concept may be written in any language — whatever validates the architecture fastest. The PoC is not the deliverable.

**Licensing: Apache 2.0 implementation, CC-BY-4.0 specification.**

**Server cache: per-(principal, server) scope, TTL-bounded.** Each server independently maintains a cache of authorization certs. Cache TTL is the cert's notAfter. No cross-server cache replication.

**Admin emergency cert as escape hatch.** A long-lived authorization cert that an administrator can hold client-side for use when the CA is unreachable. Validated against a separate, heavily-protected trust root. This is the only client-held authorization in the system.

**Session logging: command-level, mandatory for non-interactive.** Exec commands, SFTP mutations, port forwards logged in JSON Lines format with cert serial as correlation handle. Byte-stream session recording is explicitly out of scope.

**DNSSEC required for name resolution.**

**No password authentication.** Not as a fallback, not as recovery, not in legacy mode.

---

## The CA as policy engine

All policy decisions live in the CA, not in sshd_config. The CA identifies the server from the mTLS handshake and receives from sshd: the raw identity proof blob, connection context (source IP, source port, timestamp), and optionally the channel types the client intends to use.

The CA evaluates policy and issues an X.509 authorization cert encoding:

- **Time window:** notBefore/notAfter matching the policy's allowed hours
- **Source binding:** valid only from the source IP/CIDR the policy allows
- **Channel grants:** which SSH channel types are allowed (session, direct-tcpip, subsystem:sftp, etc.)
- **Server binding:** the server's canonical name (from the CA's records, not self-reported)
- **Environment:** variables to set for the session
- **Command restrictions:** if applicable, a forced command

### Consequence: sshd_config simplifies

sshd_config gets a single new directive pointing to the shim:

```
# sshd_config — one line
AuthorizationModule /usr/lib/ssh-rt-auth/authorize
```

All ssh-rt-auth configuration lives in the shim's own config file:

```yaml
# /etc/ssh-rt-auth/config.yaml
ca_endpoints:
  - https://ca1.internal:8443
  - https://ca2.internal:8443
mtls_cert: /etc/ssh-rt-auth/server.pem
mtls_key: /etc/ssh-rt-auth/server-key.pem
ca_trust_root: /etc/ssh-rt-auth/ca-root.pem
auth_trust_root: /etc/ssh-rt-auth/auth-ca-root.pem
identity_trust_roots: /etc/ssh-rt-auth/identity-ca.pub
cache_dir: /var/cache/ssh-rt-auth
emergency_cert: /etc/ssh-rt-auth/emergency.pem
```

This keeps the sshd patch minimal (just "call this module") and puts all ssh-rt-auth
configuration in one place independent of sshd's config format. The same shim works
with OpenSSH, Dropbear, and Python SSH servers.

Everything else — who can do what, when, from where — is policy in the CA. Policy changes take effect on the next cache miss without touching sshd or the shim.

---

## sshd integration

The sshd patch is minimal: after userauth succeeds, sshd calls the ssh-rt-auth shim module. The shim handles everything else — CA communication, mTLS, caching, failover, cert enforcement.

### What sshd needs to change

- After successful userauth, call the authorization module with the raw identity proof blob and connection context
- Receive a yes/no + authorization cert from the module
- Enforce the cert's policy constraints during the session (channel type grants, time window, etc.)
- One new sshd_config directive: `AuthorizationModule` pointing to the shim

### What the shim handles (not sshd)

- CA endpoint configuration and failover (multiple `ca_endpoints`)
- mTLS client cert for server identity
- Authorization cert caching (cache dir, TTL management)
- Authorization CA trust root validation
- Identity trust root configuration
- Emergency cert handling
- All ssh-rt-auth-specific configuration

### What sshd does not change

- sshd's userauth logic remains unchanged. It validates bare SSH keys and OpenSSH certs the same way it always has.
- sshd does not implement policy logic. All policy decisions happen in the CA.
- sshd does not modify its channel handling beyond enforcing the constraints in the authorization cert.
- sshd does not know about CA endpoints, mTLS, or failover. That's the shim's job.

### Target SSH implementations

The sshd patch targets multiple SSH server implementations: OpenSSH, Dropbear, and Python-based servers (Paramiko, AsyncSSH). The shim interface must be clean enough that patching any of them is tractable. The shim itself is the same regardless of which sshd calls it.

---

## Architectural decisions, deferred or out of scope

**Hop chain attestation.** Deferred, probably out of scope for v1. With unmodified SSH clients, the client cannot construct a hop chain message.

**Channel plugin framework as a separate doc.** The authorization cert can grant access to specific channel types; no separate framework doc needed in v1.

**Constrained profile for embedded targets.** Not needed. Embedded clients do not parse certs; they do classic SSH userauth.

**OIDC ID token as native identity proof.** Future. Requires SSH protocol extension work.

**Multi-tier CA replication / HA.** Designed-around in v1 by the admin emergency cert.

**In-session cert rotation.** Not applicable. Cache TTL handles this.

---

## Decisions explicitly rejected

- **X.509 client cert support in v1:** RFC 6187 is niche. Bare SSH keys and OpenSSH certs are sufficient and are already validated natively by sshd.
- **Build on top of Smallstep step-ca:** Go, ~100k lines, requires accepting Smallstep's architectural choices.
- **Use Python for the reference CA:** Python's dependency footprint defeats the Alpine offline use case. C + Mbed TLS is the final reference.
- **Add session recording (byte-stream replay):** Session logging (command-level) is in. Byte-stream recording is a deliberate non-goal.
- **Modify sshadmin to issue X.509 certs:** sshadmin stays focused on OpenSSH cert administration.
- **Two cert formats in one tool:** One format per role.

---

## Open questions

- **Final project name:** "ssh-rt-auth" is a placeholder. Other candidates: `cassh`, `vouch-ssh`.
- **Whether v1 PoC supports both identity proof formats or starts with one:** Both are in scope at the protocol level; the PoC might implement bare key first.
- **Whether v1 reference CA includes SSO/OIDC integration:** Not strictly required; could be added as v1.1.
- **Relationship statement to mssh in the new README.**

---

## Constraints to preserve

- **Embedded reach.** Alpine-class systems are first-class targets. CA footprint under 10 MB. Server-side cache implementable on Dropbear-class hardware.
- **Offline / air-gapped deployment.** First-class use case. No internet, no OIDC, no cloud services required.
- **Compatible with existing SSH clients.** No required client-side changes. Standard OpenSSH, Paramiko, libssh, Dropbear clients all work.
- **Open specification.** CC-BY-4.0 spec, Apache 2.0 reference implementation.
- **No additional infrastructure beyond the CA.** Only the CA and the modified sshd.

---

## Design doc roadmap

1. **Doc 00 (this document):** High-level overview and settled decisions.
2. **Doc 01 — sshd integration:** Precise specification of sshd changes, authorization module interface, sshd_config additions, cache semantics, constraint enforcement.
3. **Doc 02 — CA design:** CA API specification, server and user enrollment, management tool, admin authentication, authorization cert profile, policy evaluation, PoC implementation sketch.
4. **Doc 03 — Authorization cert profile:** X.509 extensions for policy. Port from mssh doc 02.
5. **Doc 04 — Threat model:** Port mssh doc 12 with revisions for CA-reach and stolen-credential resistance.
6. **Doc 05 — Session logging:** Command-level logging, JSON Lines format, cert serial correlation. Port mssh doc 16.

Pace discipline: lock down Doc 01 and Doc 02 after one pass of revisions, then start implementation. Design changes after that are scoped to "things we learned from building it."

---

## What exists in mssh that we can adapt

| mssh doc | Title | Applicability |
|----------|-------|---------------|
| 02 | Cert profile | X.509 extensions port to authorization cert profile; rename namespace. |
| 06 | CA REST API | Endpoint structure ports; orientation flips (servers talk to CA, not clients). |
| 12 | Threat model | Ports with revisions for CA-reach and stolen-credential resistance. |
| 14 | Debuggability | Ports nearly as-is. Cert serial correlation handle still works. |
| 16 | Session logging | Ports nearly as-is. |
| 15 | SSH-key compatibility | Useful framing for identity binding. |

mssh's doc 04 (handshake) and the protocol spec do *not* port — wire format changes meaningfully.
