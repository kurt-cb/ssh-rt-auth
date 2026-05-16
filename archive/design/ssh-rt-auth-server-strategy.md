# ssh-rt-auth server strategy

**Status:** Revised 2026-05-14. Tier 1 changed from "greenfield C/Mbed
TLS server" to "wrap-and-proxy around unmodified OpenSSH" — see
[ssh-rt-auth-wrapper-research.md](ssh-rt-auth-wrapper-research.md) for
the supporting research and CVE-burden analysis that drove the change.
Tier 1 ships in three variants under `wrapper/` (python → go → alpine).

**Author:** Kurt Godwin

---

## 1. Decision

ssh-rt-auth offers **three deployment tiers**, each with a clear
feature/effort trade-off. We invest fully in Tier 1 and Tier 2.
Tier 3 (OpenSSH compatibility mode) is intentionally degraded relative
to Tier 1/2, and is meant to *motivate* migration to a modern transport
and attestation story — not to be the production endpoint.

| Tier | Target                                | Authorization     | Constraints enforced            | v1 deliverable                            |
|------|---------------------------------------|-------------------|---------------------------------|-------------------------------------------|
| 1    | **ssh-rt-auth wrapper + hermetic inner sshd** | Full (cert+ext)   | All v1 + v2 extensions          | Three variants in `wrapper/`: `python/` (PoC), `go/` (production), `alpine/` (minimal C, Alpine-only). See [detailed-wrapper.md](ssh-rt-auth-detailed-wrapper.md). |
| 2    | **Library-based SSH servers** (AsyncSSH today; Go, libssh, MINA, Russh planned) | Full (cert+ext) | All v1 + v2 extensions, in-app | AsyncSSH integration shipped in PoC. Other libraries are v2+ work. |
| 3    | **OpenSSH compatibility mode** (AKC + small upstream patches) | Yes/no via AKC    | **None** in-session             | Two small upstream patches (0002 + 0003) shipped with the PoC. |

**Tier 1 is the wrap-and-proxy architecture**: an mTLS-terminating
wrapper daemon that authenticates the user via the CA, mints a
short-lived OpenSSH user cert with policy critical-options, and proxies
the inner SSH session to a hermetic localhost-bound sshd that the
wrapper owns. The operator never sees or edits the inner sshd config.
This avoids the SSH-protocol CVE-response burden that comes with
owning an SSH server, hides OpenSSH's 120-directive config surface
behind a small wrapper YAML, and matches the industry consensus
established by Smallstep, Teleport's agentless mode, and Boundary.

**Tier 1 ships in three language variants** under `wrapper/`:

- **`python/src/sshrt/msshd/`** — PoC implementation. Fast iteration, easy to
  vet against the existing PoC test suite. Performance is acceptable
  for non-busy hosts.
- **`go/`** — production port of the vetted Python design.
  Balances throughput with memory safety. The default production
  target.
- **`c/`** — minimal C+Mbed TLS or C+wolfSSL
  implementation for constrained Alpine-only deployments. Smallest
  footprint, hardest to audit; opt-in.

The three variants share the wire protocol, config schema, and CA
contract, so a single test suite verifies all three.

The earlier "C/Mbed TLS greenfield server" idea is **fully dropped**.
`c/` covers the constrained-deployment use case without
us having to own the SSH protocol.

**OpenSSH's full constraint-enforcement patches (the original 0004–0007
plan) are dropped from active work.** They are kept as design notes in
[../../ssh-rt-auth-openssh/NOTES.md](../../ssh-rt-auth-openssh/NOTES.md)
for historical context only; not on the critical path.

## 2. Rationale

**Why we dropped the OpenSSH heavy-patch plan:** the patch series had
grown to ~1000+ LOC across multiple files, with parallel Dropbear work
implied, plus a forever-rebase burden across upstream releases.

**Why Tier 1 is now wrap-and-proxy (not greenfield):** the SSH protocol
CVE-burden falls on anyone who owns SSH-server code, in both
memory-unsafe (C) and memory-safe (Go, Rust) implementations. Concrete
evidence: Teleport's own SSH cert validation shipped CVE-2025-49825
(CVSS 9.8 auth bypass, June 2025), plus inherits `x/crypto/ssh` CVEs
(CVE-2024-45337 / CVE-2025-22869 / CVE-2025-58181). A custom C SSH
server would have a strictly worse CVE record. Wrap-and-proxy keeps the
protocol implementation in OpenSSH (mature, audited, focused security
response) and reduces our scope to ~2-5 kLOC of glue. Industry pattern
matches: Smallstep, Teleport-agentless, and Boundary all wrap rather
than reimplement. Full analysis in
[ssh-rt-auth-wrapper-research.md](ssh-rt-auth-wrapper-research.md).

**Why wrap-and-proxy doesn't import OpenSSH's config mess:** the wrapper
*owns* the inner sshd config. Operators never edit it. The wrapper's
operator-facing surface is a small YAML (a dozen knobs) from which the
hermetic inner sshd config is derived at startup. Hash-validated against
an embedded known-good. See
[wrapper-research § 5](ssh-rt-auth-wrapper-research.md).

**Why Tier 2 (library integrations) is still worth investing in:** the
library-callback SSH servers don't require patching at all — they expose
a `validate_public_key`-style callback that's exactly where our shim
wants to live. Those integrations are tens to low hundreds of lines
each, one-shot, and many production SSH deployments worth caring about
already live in this category (Gerrit, Gitea, large numbers of cloud
bastions, libssh-based appliances).

OpenSSH's role for Tier 3 is honestly described: it's where the deployed
fleet lives, it's the lowest common denominator, and it can do
*authentication* and *yes/no authorization* well via AKC + our shim. It
cannot do cert-bound *constraint enforcement* through AKC alone, and
we're choosing not to pay for the heavy patches that would change that —
the wrapper solves the same problem in a less invasive place.

## 3. Tier 3 (OpenSSH) feature degradation, in detail

This is the deliberately-degraded path. Document it plainly so users
choose Tier 1 / Tier 2 when their threat model demands more.

| Capability                                            | Tier 1 / Tier 2 | Tier 3 (OpenSSH + AKC)        |
|-------------------------------------------------------|-----------------|-------------------------------|
| Yes/no per (user, server) authorization               | ✓               | ✓                             |
| Source-CIDR policy                                    | ✓               | ✓ (via patch 0002, `%R`)      |
| Split-domain / per-interface policy (multi-homed hosts) | ✓             | ✓ (via patch 0002, `%L` / `%I`) |
| Rich connection context to CA (kex, cipher, banner…)  | ✓               | ✗ (was 0002b; dropped 2026-05-14 in favour of Tier 1 wrapper) |
| Pre-auth attack surface mitigation                    | ✓ (no pre-auth CA query) | Partial — shim-side rate limit + fingerprint pre-filter + patch 0003 (SSH_AKC_PHASE) |
| `sshrtauth-channel-policy` enforcement                | ✓               | ✗                             |
| `sshrtauth-force-command` enforcement                 | ✓               | Partial (via `command="…"` in AKC stdout) |
| `sshrtauth-environment` enforcement                   | ✓               | Partial (via `environment="…"` in AKC stdout) |
| `sshrtauth-max-session` enforcement                   | ✓               | ✗                             |
| Cert `notAfter` mid-session enforcement / refresh     | ✓               | ✗                             |
| v2 `sshrtauth-session-bind` (cross-session replay)    | ✓               | ✗                             |
| v2 `sshrtauth-host-key-pin`                           | ✓               | ✗                             |
| v2 `sshrtauth-crypto-floor` (centrally enforced)      | ✓               | Advisory only (CA decides; sshd doesn't re-check) |

Tier 3 users are getting roughly "OpenSSH with AKC + a smarter
backend." That is genuinely useful — a stolen client key is still
useless without CA reachability, source-CIDR policy still works, audit
is centralized — but it is *not* the full security model. The CA's
audit log surfaces `sshd_attestation.classification == "unpatched"` so
this state is visible at glance ([v2-enhancements § 5.6](ssh-rt-auth-v2-enhancements.md)).

## 4. Supported SSH servers matrix

This table is the single authority for "is X supported by ssh-rt-auth?"
Each row links to its integration doc (forthcoming).

| Server / library                | Category    | Tier  | Notes                                              |
|---------------------------------|-------------|-------|----------------------------------------------------|
| ssh-rt-auth wrapper (`python/src/sshrt/msshd/`) | Daemon | 1 — PoC | Python implementation; inner sshd is unmodified OpenSSH; full feature set; see [detailed-wrapper.md](ssh-rt-auth-detailed-wrapper.md) |
| ssh-rt-auth wrapper (`go/`)     | Daemon | 1 — production | Go port of the vetted Python design; production default |
| ssh-rt-auth wrapper (`c/`) | Daemon | 1 — Alpine minimal | C+Mbed TLS or C+wolfSSL; smallest footprint; Alpine-only |
| AsyncSSH (Python)               | Library     | 2     | Already integrated in `server/ssh_server.py`       |
| golang.org/x/crypto/ssh         | Library     | 2     | Planned — large cloud-bastion footprint            |
| libssh (server mode, C)         | Library     | 2     | Planned — appliances, embedded                     |
| Apache MINA SSHD (Java)         | Library     | 2     | Planned — Java git servers, Gerrit                 |
| Russh (Rust)                    | Library     | 2     | Planned — younger ecosystem                        |
| OpenSSH-portable                | Daemon      | 3     | Compatibility mode only; patches 0002 + 0003 (0002b dropped) |
| OpenSSH (OpenBSD upstream)      | Daemon      | 3     | Same patches as portable                           |
| Dropbear                        | Daemon      | 3 / — | Compatibility via AKC only IF Dropbear gains AKC equivalent (it does not today). Realistically: **not supported** at production tier; replace with reference server on the target device. |
| wolfSSH server                  | Commercial  | —     | Out of scope                                       |
| Tectia                          | Commercial  | —     | Out of scope                                       |

## 5. Migration / messaging stance

Public-facing description of the deployment options should read
roughly:

> ssh-rt-auth ships an **mTLS-authenticating wrapper** that fronts a
> hermetic, locked-down OpenSSH instance for production deployments
> needing full cert-bound constraint enforcement. The wrapper does
> mTLS, authorization, and policy translation; OpenSSH does the SSH
> protocol — so we inherit OpenSSH's mature security response while
> hiding its messy configuration surface. For applications embedding
> an SSH server library (Go, Python, Rust, Java, libssh-based daemons)
> we provide **first-class integration libraries** that wire the CA
> into your existing auth callback. We also support **unmodified
> OpenSSH** in a compatibility mode that provides yes/no authorization
> and centralized audit, but does not enforce per-session constraints;
> users on this path are encouraged to migrate to the wrapper when
> their threat model warrants it.

The compatibility-mode framing is deliberate. We're not pretending
OpenSSH-with-AKC is a security-equivalent path — we're saying it's the
*compatible* path, with the expectation that the security gap is the
motivator to migrate.

## 6. TODO — future deployment topologies

### 6.1 Dual-mode listener on port 22

Speculative: a single listener on port 22 that protocol-sniffs the
opening bytes and routes:

- Legacy SSH client (`SSH-2.0-…` greeting) → forwards to / bridges to
  an unmodified OpenSSH backend running on a localhost port. Pander to
  existing clients, no upgrade required from them.
- Modern ssh-rt-auth client (`MSSH-1.0-…` or similar greeting) → handled
  natively by the reference server, full features, modern transport,
  pre-userauth attestation handshake possible.

This would let an organization deploy ssh-rt-auth on every host
without breaking existing clients, AND signal "you're talking to a
modern endpoint" to clients that know how to ask. It also opens room
for a richer pre-auth handshake on the modern path — for example,
client attestation, channel-binding ceremony, or stronger transport
crypto (e.g., MLS-style group keys for shared bastion sessions) —
without breaking the SSH-2.0 wire format for legacy clients.

Open questions to revisit when this becomes active work:

- Greeting-byte ambiguity: SSH's banner format is fairly rigid; can
  a new protocol greeting coexist without breaking RFC 4253 §4.2's
  version-string negotiation? Probably yes via a distinct prefix
  (`MSSH-`) that legacy parsers reject early.
- Bridge mode vs native mode: if we bridge legacy SSH to a localhost
  sshd, we're effectively a TLS-terminating proxy for SSH. That
  forfeits some of the cleanliness of "CA-mediated authorization at
  the actual SSH endpoint." Probably we just listen for both and
  serve from one process; no bridge.
- Migration story: clients gradually adopt `mssh` capability; servers
  serve both forever. Same shape as HTTP/1 vs HTTP/2.

**Status:** Not in PoC scope. Captured here so the idea isn't lost.

### 6.2 Wrapper design doc

Decision in [wrapper-research.md](ssh-rt-auth-wrapper-research.md) was
to adopt wrap-and-proxy as Tier 1. The next deliverable is a detailed
wrapper design doc (`ssh-rt-auth-detailed-wrapper.md`) covering the
open questions from wrapper-research § 11:

- Wrapper language (Go strongly favored)
- Inner SSH transport security (`Ciphers none` decision)
- OpenSSH version pinning policy
- Local user-CA key custody (provisioning, rotation, backup)
- Outer wire protocol shape (raw SSH-in-TLS vs custom RPC)
- Hermetic inner sshd_config template + per-version hash table
- Operator-facing YAML schema
- Per-connection cert-handoff flow + critical-option translation table

Should land before any wrapper code is written.

The earlier "C + Mbed TLS greenfield server" design has been fully
dropped — the `c/` variant (C + Mbed TLS or wolfSSL on top
of unmodified OpenSSH) covers the constrained-deployment use case
without us having to own the SSH protocol.

### 6.3 Per-language integration libraries

One repo per Tier 2 target:
- `ssh-rt-auth-go` — golang.org/x/crypto/ssh integration
- `ssh-rt-auth-libssh` — C library wrapping the shim for libssh-based daemons
- `ssh-rt-auth-rust` — Russh integration
- `ssh-rt-auth-java` — Apache MINA SSHD integration

Each is roughly: implement the host library's auth callback, populate
the v2 `connection` blob from whatever the library exposes, call the
existing shim (Python today, C eventually), enforce returned cert
extensions in the library's session-handling hooks.

## 7. What this changes in existing docs

- [../../ssh-rt-auth-openssh/NOTES.md](../../ssh-rt-auth-openssh/NOTES.md):
  patches 0004–0007 stay demoted to "design notes, not active work";
  **0002b dropped 2026-05-14** (subsumed by Tier 1 wrapper); **0002 and
  0003 remain active** as small upstream-friendly patches that close
  real security gaps in Tier 3 (broken source-CIDR + pre-auth attack
  surface) with independent upstream value for any AKC helper.
- [CLAUDE.md](../CLAUDE.md): "final implementation: C with Mbed TLS"
  is no longer the production target — wrap-and-proxy is, in three
  language variants under `wrapper/` (python PoC → go production →
  alpine minimal C).
- [ssh-rt-auth-v2-enhancements.md](ssh-rt-auth-v2-enhancements.md):
  v2 cert extensions (`.1.8` onward) are consumed by the wrapper
  (which translates them into OpenSSH cert critical-options where
  possible, and enforces the remainder itself) and by Tier 2
  integrations. Tier 3 still ignores them.

## 8. Cross-references

- Wrapper research and decision: [ssh-rt-auth-wrapper-research.md](ssh-rt-auth-wrapper-research.md)
- OpenSSH patch series: [../../ssh-rt-auth-openssh/NOTES.md](../../ssh-rt-auth-openssh/NOTES.md)
- v2 enhancements & cert OID arc: [ssh-rt-auth-v2-enhancements.md](ssh-rt-auth-v2-enhancements.md)
- AKC attack surface (motivates Tier 3's degradation): tests/issues.md § 9
- Project overview: [ssh-rt-auth-doc-00-overview.md](ssh-rt-auth-doc-00-overview.md)
