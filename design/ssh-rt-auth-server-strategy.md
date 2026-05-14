# ssh-rt-auth server strategy

**Status:** Decided 2026-05-14. Supersedes the implicit "patch OpenSSH
heavily" assumption that earlier patch-plan work was operating under.

**Author:** Kurt Godwin

---

## 1. Decision

ssh-rt-auth offers **three deployment tiers**, each with a clear
feature/effort trade-off. We invest fully in Tier 1 and Tier 2.
Tier 3 (OpenSSH) is treated as a **compatibility mode**, intentionally
degraded relative to Tier 1/2, and is meant to *motivate* migration to
a modern transport and attestation story — not to be the production
endpoint.

| Tier | Target                                | Authorization     | Constraints enforced            | Lift                                      |
|------|---------------------------------------|-------------------|---------------------------------|-------------------------------------------|
| 1    | **Reference C/Mbed TLS server**       | Full (cert+ext)   | All v1 + v2 extensions          | Greenfield build (already in CLAUDE.md as "final implementation") |
| 2    | **Library-based SSH servers** (AsyncSSH, Go, libssh, MINA, Russh) | Full (cert+ext) | All v1 + v2 extensions, in-app | ~100–200 LOC integration per language     |
| 3    | **OpenSSH compatibility mode** (AKC + small upstream patches) | Yes/no via AKC    | **None** in-session             | Two small upstream patches (0002 + 0002b) |

**OpenSSH's full constraint-enforcement patches (the original 0004–0007
plan) are dropped from active work.** They are kept as design notes in
[../../ssh-rt-auth-openssh/NOTES.md](../../ssh-rt-auth-openssh/NOTES.md)
in case the reference server (Tier 1) is descoped, but are not on the
critical path.

## 2. Rationale

The patch series against OpenSSH had grown to ~1000+ LOC across
multiple files, with parallel Dropbear work implied, plus a
forever-rebase burden across upstream releases. Engineering effort that
feeds a codebase we plan to leave behind (CLAUDE.md already says the
final implementation is C + Mbed TLS) is poor leverage.

The library-callback SSH servers in Tier 2 don't require patching at
all — they expose a `validate_public_key`-style callback that's exactly
where our shim wants to live. Those integrations are tens to low
hundreds of lines each, one-shot, and many of the production SSH
deployments worth caring about today already live in this category
(Teleport, Gerrit, Gitea, large numbers of cloud bastions, libssh-based
appliances).

OpenSSH's role is then honestly described: it's where the deployed
fleet lives, it's the lowest common denominator, and it can do
*authentication* and *yes/no authorization* well via AKC + our shim. It
cannot do cert-bound *constraint enforcement* without a deep patch, and
we're choosing not to pay for that.

## 3. Tier 3 (OpenSSH) feature degradation, in detail

This is the deliberately-degraded path. Document it plainly so users
choose Tier 1 / Tier 2 when their threat model demands more.

| Capability                                            | Tier 1 / Tier 2 | Tier 3 (OpenSSH + AKC)        |
|-------------------------------------------------------|-----------------|-------------------------------|
| Yes/no per (user, server) authorization               | ✓               | ✓                             |
| Source-CIDR policy                                    | ✓               | ✓ (via patch 0002, `%R`)      |
| Split-domain / per-interface policy (multi-homed hosts) | ✓             | ✓ (via patch 0002, `%L` / `%I`) |
| Rich connection context to CA (kex, cipher, banner…)  | ✓               | ✓ (via patch 0002b, JSON env) |
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
| ssh-rt-auth reference server    | Daemon      | 1     | C + Mbed TLS; greenfield, full feature set         |
| AsyncSSH (Python)               | Library     | 2     | Already integrated in `server/ssh_server.py`       |
| golang.org/x/crypto/ssh         | Library     | 2     | Planned — large cloud-bastion footprint            |
| libssh (server mode, C)         | Library     | 2     | Planned — appliances, embedded                     |
| Apache MINA SSHD (Java)         | Library     | 2     | Planned — Java git servers, Gerrit                 |
| Russh (Rust)                    | Library     | 2     | Planned — younger ecosystem                        |
| OpenSSH-portable                | Daemon      | 3     | Compatibility mode only; patches 0002 + 0002b + 0003 |
| OpenSSH (OpenBSD upstream)      | Daemon      | 3     | Same patches as portable                           |
| Dropbear                        | Daemon      | 3 / — | Compatibility via AKC only IF Dropbear gains AKC equivalent (it does not today). Realistically: **not supported** at production tier; replace with reference server on the target device. |
| wolfSSH server                  | Commercial  | —     | Out of scope                                       |
| Tectia                          | Commercial  | —     | Out of scope                                       |

## 5. Migration / messaging stance

Public-facing description of the deployment options should read
roughly:

> ssh-rt-auth ships a **reference server** for production deployments
> that need full cert-bound constraint enforcement. For applications
> embedding an SSH server library — including Go, Python, Rust, Java,
> and libssh-based daemons — we provide **first-class integration
> libraries** that wire the CA into your existing auth callback. We
> also support **unmodified OpenSSH** in a compatibility mode that
> provides yes/no authorization and centralized audit, but does not
> enforce per-session constraints; users on this path are encouraged to
> migrate to the reference server when their threat model warrants it.

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

### 6.2 Reference server design doc

Promote the CLAUDE.md "C + Mbed TLS" line to a proper design doc
(`ssh-rt-auth-detailed-reference-server.md`). Scope: SSH protocol
stack (Mbed TLS for transport crypto? or libsodium?), AuthorizationModule
hook called inline (no fork/exec subprocess), v2 cert extensions
enforced natively, channel constraints in the main I/O loop. Should
land before any code is written.

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
  patches 0004–0007 demoted to "design notes, not active work";
  0002 / 0002b / 0003 remain active and upstream-targeted.
- [CLAUDE.md](../CLAUDE.md): "final implementation: C with Mbed TLS"
  is now the v1-of-production target (the reference server), not a
  phase-5 nicety.
- [ssh-rt-auth-v2-enhancements.md](ssh-rt-auth-v2-enhancements.md):
  v2 cert extensions (`.1.8` onward) are enforced only by Tier 1 / Tier 2;
  add a note to that effect.

## 8. Cross-references

- OpenSSH patch series: [../../ssh-rt-auth-openssh/NOTES.md](../../ssh-rt-auth-openssh/NOTES.md)
- v2 enhancements & cert OID arc: [ssh-rt-auth-v2-enhancements.md](ssh-rt-auth-v2-enhancements.md)
- AKC attack surface (motivates Tier 3's degradation): tests/issues.md § 9
- Project overview: [ssh-rt-auth-doc-00-overview.md](ssh-rt-auth-doc-00-overview.md)
