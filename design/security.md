# mssh — security model + threat analysis

This document covers the security properties mssh is designed to
provide, the assumptions those properties rest on, and the
specific attacks each component is designed to stop.

For lower-level cryptographic detail on individual protocols see
[archive/design/ssh-rt-auth-security-analysis.md](../archive/design/ssh-rt-auth-security-analysis.md).

---

## The core property

> **A stolen client credential is useless if the attacker cannot
> reach the CA.**

Concretely: an attacker who exfiltrates `~/.mssh/key.pem` from
alice's laptop gets a credential that, by itself, authorizes
nothing. They must:

  1. Network-reach a server running msshd; AND
  2. Network-reach the CA from that server's perspective; AND
  3. Have the CA say "yes" — which it won't, if the request
     looks anomalous (wrong source CIDR, outside time window,
     key recently revoked, etc.).

If the CA is on a private network reachable only from your SSH
servers, requirement (2) means the attacker needs to also have
network position inside your fleet — at which point a stolen SSH
key was already not the worst problem.

This property is **the** reason this system exists. Every design
decision below either enables it or hardens it.

---

## Trust boundaries

```
            ┌──────────────────────────┐
            │  Operator workstation     │
            │  ──────────────────────   │
            │  • CA signing key (cold)  │
            │  • Admin mTLS cert        │
            └────────────┬──────────────┘
                         │  mssh-admin
                         │  (mTLS REST)
                         ▼
            ┌──────────────────────────┐  ← TRUSTED — never internet-routable
            │           CA              │
            │  ──────────────────────   │
            │  • signing key (online)   │
            │  • enrollment DB          │
            │  • audit log              │
            └────────────┬──────────────┘
                         │
                         │  authorize REST
                         │  (mTLS, server-initiated)
                         ▼
            ┌──────────────────────────┐  ← SEMI-TRUSTED
            │          msshd            │
            │  ──────────────────────   │
            │  • mTLS server cert       │
            │  • mTLS client cert (→CA) │
            │  • local user-CA          │
            │    (signs inner certs)    │
            └────────────┬──────────────┘
                         │
                         │  ephemeral OpenSSH cert
                         │  (localhost)
                         ▼
            ┌──────────────────────────┐  ← FULLY-CONSTRAINED
            │     hermetic inner sshd  │
            │  ──────────────────────   │
            │  • only the local user-CA │
            │    can mint trustable     │
            │    credentials            │
            └──────────────────────────┘

            ┌──────────────────────────┐  ← UNTRUSTED
            │         mssh client       │
            │  ──────────────────────   │
            │  • user mTLS cert + key   │
            │  • CA trust root          │
            └──────────────────────────┘
```

  - **CA** — fully trusted. If the CA is compromised, the
    attacker is the CA: nothing else matters. Custody of the CA
    host is the operator's primary security responsibility.
  - **msshd** — semi-trusted. msshd terminates mTLS and decides
    what bytes flow into the inner sshd. A compromised msshd
    can deny service or proxy the user's session to an attacker.
    It cannot mint forged authorization certs — those require
    the CA's signing key.
  - **inner sshd** — fully constrained. The hermetic config
    means even a compromised msshd cannot smuggle a different
    credential in: the inner sshd only trusts msshd's local
    user-CA, and the cert it accepts has lifetime measured in
    seconds.
  - **mssh client** — untrusted. The credential alone is
    insufficient (see "core property" above); the client is
    just an attacker-reachable artifact.

---

## Two separate cert hierarchies

mssh deliberately uses **two** root-of-trust hierarchies, kept
separate:

  - **CA signing hierarchy.** Issues the X.509 authorization
    certs that msshd consumes, plus the mTLS client certs for
    enrolled servers and admins. Lives on the CA host.
  - **User-facing hierarchy.** Issues mssh client mTLS certs and
    msshd's TLS server cert. Could be the same CA, could be a
    separate one (e.g. web-PKI). Operator's choice.

Why separate: the authorization decision (CA signing hierarchy)
and the network identity (user-facing hierarchy) answer different
questions. Authorization says *"is this user allowed here?"*;
identity says *"is this really alice's certificate?"* The CA
signing key is the high-value secret; the user-facing CA is
operationally rotatable.

A third, internal hierarchy lives inside msshd:

  - **msshd's local user-CA.** Mints ephemeral OpenSSH user
    certs for the hermetic inner sshd. Never leaves the msshd
    host. Rotation is free (mint a new pair, restart msshd,
    inner sshd re-loads `TrustedUserCAKeys`).

---

## Fail-closed defaults

Every error path denies:

  - CA unreachable → deny (unless the operator has provisioned an
    emergency cert; see below).
  - mTLS handshake fails → deny.
  - Authorization cert signature invalid → deny.
  - Policy returns no match → deny.
  - Source IP outside `source_cidrs` → deny.
  - Outside time window → deny.
  - Inner sshd refuses the ephemeral cert → connection closed.

There is no "default allow" path. Even at the YAML enrollment
layer, a user with no policy attached is denied access to
everything; the admin must explicitly grant.

### Emergency cert

For the CA-unreachable case, msshd can optionally hold an
**emergency cert** — a long-lived authorization cert minted offline
and provisioned manually onto the server. Disabled by default.
When present, msshd will fall back to it if the CA is
unreachable, log the fallback prominently, and rate-limit its use
(typically: minutes per use, not seconds, so a degraded mode is
obvious in the audit log).

The emergency cert is a deliberate accommodation for "what if our
network is on fire and we still need to fix it" scenarios. It
trades the core property locally for continuity — operators who
don't want it just don't provision it.

---

## What stops which attack

### Stolen mssh client credential (key + cert exfiltrated)

Stopped by **CA-unreachability**. The credential is necessary
but not sufficient; the attacker must also reach the CA from a
machine that the CA trusts. Source-CIDR policies further
constrain the geography of valid use.

Mitigation strength: depends on the operator's CA network design.
Private CA = strong. Internet-routable CA = weak (mostly down to
source-CIDR + revocation).

### Stolen msshd local user-CA key

Lets the attacker mint OpenSSH user certs the hermetic inner sshd
will accept — **on that specific server only**. The attacker still
needs to network-reach the inner sshd, which is localhost-only:
they need root on the msshd host already. If they have that, the
local user-CA key is a side concern.

Mitigation: ensure msshd runs as a non-root, dedicated user; the
key lives in a directory only that user can read.

### Stolen CA signing key

Catastrophic. The attacker can mint any authorization cert for
any user against any server. Equivalent to "the CA is the
attacker."

Mitigation: aggressive custody. The CA signing key should be
kept offline where operationally feasible (HSM, cold storage,
periodic re-bootstrap). Online CA deployments accept this risk
in exchange for operational simplicity.

### Compromised msshd binary or config

The attacker decides which authorize calls happen and which
get suppressed. They can deny service. They cannot mint authz
certs the CA didn't sign. They cannot accept a connection the
inner sshd won't accept (the hermetic config is pinned).

What they CAN do: man-in-the-middle the user's session bytes,
because msshd terminates mTLS and re-encrypts to the inner sshd.

Mitigation: msshd binary integrity (signed packages, secure
boot, file-system attestation) and config integrity (the
hermetic sshd_config hash is per-OpenSSH-version and validated
at startup).

### Compromised inner sshd binary or config

The attacker accepts arbitrary credentials. Mitigation: the
hermetic sshd_config is owned by msshd, regenerated at every
restart, hash-validated against an OpenSSH-version-specific
baseline. The inner sshd binary itself is a system file; OS
integrity tooling is the operator's defense.

### Replay of a captured authorize call

`request_id` is unique per call; the CA's audit log captures
every call. Replay against the CA would mint a new cert
identical to the original (same client, same context) — at
best a no-op. Replay against msshd to a target with a now-revoked
key fails at the inner sshd step (revoked key won't validate
against the new cert).

The authorization cert's `valid_to` is minute-scale, capping
the window in which a captured cert is useful at all.

### CA timing-side-channel against enrollment

The CA's response time to a "denied" decision should not leak
whether the user is enrolled (and was denied by policy) vs not
enrolled at all. The CA should perform constant-work denial
paths or, at minimum, batch responses to obscure timing.

This is an active concern, currently mitigated by enforcing
"do not include detail in the denied_reason" — detail goes to
audit, not the wire.

### Clock skew between client and CA

If the client's clock is far ahead, the `issued_at` it sends
looks like a future request and gets rejected. If far behind,
stale. The CA enforces a configurable drift window
(typically 10 minutes).

For deeper deployments, the CA can expose a `/v1/clock` endpoint
so msshd / mssh sync against the CA's clock rather than relying
on NTP. See [future-ideas.md](future-ideas.md) §clock-authority.

---

## What's explicitly NOT in the threat model

  - **Insider with operator-level CA access.** If the operator
    is malicious, mssh cannot help — they own the CA.
  - **Compromised OS or hypervisor under msshd.** Out of scope;
    OS integrity is a precondition.
  - **Compromised mssh client OS.** The credential is on that
    machine and the attacker has it. mssh's job is to reduce
    the value of the credential to "almost zero off-network";
    it cannot prevent the user typing on a compromised laptop.
  - **Side-channels in OpenSSH itself.** mssh inherits whatever
    surface OpenSSH presents. The hermetic config minimizes the
    surface; vulnerabilities in OpenSSH's transport layer would
    affect mssh deployments too.
  - **Quantum-capable adversaries.** Standard ed25519 + ECDH
    crypto; post-quantum migration is an open OpenSSH question
    that mssh will inherit when OpenSSH lands a PQ KEX.

---

## Auditability

Every authorization decision and every admin action lands in the
CA's audit log (JSON-Lines on disk; see [api.md](api.md) §audit).
For a security incident response, the log is the source of
truth for "who tried what when."

The audit log is append-only; rotation is operator-managed (typical
sustained rates are dozens to hundreds of events per second per
server). Tampering with the log requires CA-host access — at
which point the threat model is already broken.
