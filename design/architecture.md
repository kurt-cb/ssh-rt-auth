# mssh — architecture

mssh is a runtime, CA-mediated SSH authorization system. SSH client
identity and credentials don't change; **authorization** moves out
of the client and into a CA on a separate, restricted network. The
server contacts the CA at connection time and gets a short-lived
authorization decision back.

The defining property: **a stolen client credential is useless if
the attacker can't reach the CA.** Put the CA on a network reachable
only from your SSH servers; stolen keys can't trigger authorization
from anywhere else.

---

## Components

```
                       ┌──────────────────┐
                       │      CA           │
                       │  • policy engine  │
                       │  • cert minter    │
                       │  • enrollment DB  │
                       │  • audit log      │
                       └────────┬─────────┘
                                │  mTLS REST
                                │
   ┌─────────────────────────────┼─────────────────────────────┐
   │                             │                              │
   │  ┌────────────────────────┴──────────────────────────┐    │
   │  │                       msshd                        │    │
   │  │  • outer listener (mTLS to mssh clients)           │    │
   │  │  • per-connection CA call                          │    │
   │  │  • ephemeral OpenSSH cert mint (local user-CA)     │    │
   │  │  • hermetic inner sshd                             │    │
   │  └──────────────────────────────────────────────────┬─┘    │
   │                                                       │      │
   └──────── mTLS+JSON-frame outer protocol ──────────────┘      │
                                ▲                                 │
                                │                                 │
                          ┌─────┴────┐                            │
                          │   mssh    │                           │
                          │  client   │                           │
                          └──────────┘                            │
                                                                   │
                          ┌──────────────┐                         │
                          │  mssh-admin   │ mTLS REST              │
                          │  (CLI)        │────────────────────────┘
                          └──────────────┘
```

There are five distinct pieces. Two are user-facing, three are
infrastructure.

### CA

The central authorization service. mTLS-only REST API. Three
responsibilities:

  - **Authorize:** evaluate an authorization request against
    enrollment + policy, mint a short-lived X.509 cert if the
    answer is yes.
  - **Enroll:** maintain the inventory of servers, users, keys,
    policies via the admin API.
  - **Audit:** log every authorization decision and every admin
    action to an append-only JSON-Lines file.

The signing key never leaves the CA host. The CA is typically
deployed on a private network reachable only from your SSH servers
and your admin workstations.

### `mssh` (client)

Pure-Python TLS client. Reads an X.509 client cert + key + trust
root from `$HOME/.mssh/` (or env vars), opens a TLS connection to
msshd, presents an mTLS client cert, sends a JSON-framed
session-RPC header, and from there acts like a standard SSH client.

### `msshd` (server-side gateway)

The outer-facing server. Terminates the mTLS+JSON-frame outer
protocol from mssh clients, calls the CA to authorize the
connection, mints an ephemeral OpenSSH user cert with a local
user-CA, hands the cert to a **hermetic inner sshd** that it
owns, and proxies the byte stream end-to-end-encrypted.

The inner sshd is a stock unmodified OpenSSH instance launched by
msshd with a generated, locked-down `sshd_config` (see
[§ Hermetic inner sshd](#hermetic-inner-sshd)). msshd manages its
lifecycle; the operator never edits the inner config directly.

msshd supports three modes ([§ Operating modes](#operating-modes)).

### `mssh-admin` (CLI)

Operator CLI for the CA's admin API. Enrols servers, users, keys,
and policies; rotates certs; runs audits. mTLS-authenticated with
role-based access control (`superuser`, `admin`, `auditor`).

### `debug_sshd`

A standalone SSH server (AsyncSSH-based) that calls the CA inline
after pubkey auth. **Not a production deployment target** — kept as
the minimal CA-call surface for isolating CA / policy / cert-parsing
issues from msshd's gateway machinery. The adoption-time
helper for "is the CA actually deciding what I expect?"

---

## Operating modes

`msshd` supports three modes selected at config time. Two are
implemented today; one is a deferred design (see
[design/future-ideas.md](future-ideas.md) §gated).

| Mode | Outer auth (mssh→msshd) | Inner auth (msshd→sshd) | Whose policy wins | Status |
|---|---|---|---|---|
| **fallback** | none — TCP proxy | the operator's existing sshd_config | the operator | implemented |
| **gated** | mTLS + CA approval | the operator's existing sshd_config | the operator, gated by CA | deferred |
| **enforce** | mTLS + CA approval + ephemeral cert minted | hermetic minimal sshd_config (trusts only the mint key) | the CA | implemented |

The intended adoption journey is **fallback → gated → enforce**,
each step reversible by a single config flag. Operators can
preserve their existing sshd policy as long as they want and
flip to CA-mediated auth on their schedule. See
[docs/operations.md § adoption journey](../docs/operations.md#the-adoption-journey).

### Why three modes (not just enforce)

Operators have years of accumulated policy in `/etc/ssh/sshd_config`,
`authorized_keys`, PAM, AllowGroups. Flipping straight from "vanilla
sshd" to "CA does everything" on day one is the highest-risk
moment in any adoption. The three modes give the operator
intermediate states where they can verify the gateway is wired in
correctly (fallback), then introduce CA-gating without changing
auth (gated), then move full policy to the CA (enforce) on a
per-server schedule.

---

## Hermetic inner sshd

In **enforce** mode, msshd doesn't trust the operator's
`/etc/ssh/sshd_config`. It generates a **hermetic** config at
startup, hash-validates it against a per-OpenSSH-version baseline,
and launches a fresh sshd subprocess against that config. The
hermetic sshd:

  - listens only on localhost (msshd is the only client)
  - accepts only ed25519 + ecdsa-p256, AEAD ciphers only
  - accepts only pubkey auth, only via `TrustedUserCAKeys` pinned
    to msshd's local user-CA
  - has no PAM, no Include directives, no Match blocks
  - logs to msshd's stderr (no syslog, no separate log files)

The operator never edits the hermetic config. When OpenSSH releases
a new version, the hash baseline is updated together with whatever
config-surface changes that version introduces — making the auth
config a **versioned, audited artifact** rather than a moving
target.

This is the safety net: even if msshd has a bug in its
authorization decision, the hermetic sshd cannot accept any
credential msshd did not just mint. There is no other trust path
into the inner sshd.

---

## Trust model

Two distinct certificate hierarchies, intentionally separate:

  - **CA's signing key.** Lives only on the CA host. Mints the
    short-lived X.509 authorization certs that msshd reads. Also
    mints the mTLS client certs for each enrolled server and admin.
    Lost or compromised → re-enroll everything.
  - **msshd's local user-CA.** A separate keypair, one per msshd
    deployment. Used only to sign ephemeral OpenSSH user certs
    for the hermetic inner sshd. Never leaves the msshd host;
    rotation is cheap (mint a new pair, restart msshd, the inner
    sshd re-loads its `TrustedUserCAKeys`).

Two more certificates exist outside the CA's signing hierarchy:

  - **msshd's TLS server cert.** What msshd presents to mssh
    clients. Issued by a **user-facing CA** chosen by the
    operator (could be the mssh CA itself, could be a separate
    web-PKI CA — the choice is operational, not architectural).
  - **mssh client certs.** Issued by the same user-facing CA
    chosen above. mssh clients present these on TLS handshake;
    msshd verifies and forwards the certificate identity to the
    mssh CA for the authorization call.

Operators who want a fully self-contained deployment can use the
mssh CA for both the authorization hierarchy *and* the
user-facing hierarchy. Operators who want web-PKI for the
user-facing side can use a separate issuer. The mssh CA does not
care which.

---

## Wire protocols

  - **mssh ↔ msshd:** TLS 1.3 outer transport with mutual auth.
    Inside the TLS tunnel: a small JSON-framed session-RPC header
    (`{"version": 1, "user": "...", "command": [...]}`) followed
    by an encapsulated SSH transport stream. The JSON header lets
    msshd attribute the connection to a specific user identity
    without trusting an attacker-supplied SSH `user` field.

  - **msshd ↔ CA:** standard HTTPS with mutual TLS. `POST
    /v1/authorize` carries the connection context and identity
    blob; the response carries the X.509 authorization cert or
    a structured denial.

  - **mssh-admin ↔ CA:** same HTTPS + mTLS. Separate `/v1/admin/`
    URL prefix. Role-checked by the admin's certificate subject
    against the enrollment record.

  - **msshd ↔ inner sshd:** standard SSH transport. Localhost-only.

Concrete API: see [api.md](api.md).

---

## Failure model

Default behavior on every failure is **deny**:

  - CA unreachable: msshd denies the authorization. Optional
    emergency cert (long-lived, kept offline, restored manually)
    can override this for break-glass continuity.
  - Cert validation fails: deny.
  - Policy returns no match: deny.
  - Inner sshd refuses the ephemeral cert: connection closed.

mssh client never retries automatically against a different
endpoint with the same identity — the CA endpoint list in the
client config defines the failover order, and once all endpoints
are exhausted, the client fails.

---

## What's deliberately NOT in scope

  - **Password authentication.** Ever. Even as a fallback.
  - **Server-side per-user configuration.** Everything per-user is
    a CA enrollment, not a server-side file edit.
  - **mssh client agent forwarding by default.** The client cert
    binds to a specific session; forwarding it is a policy choice
    that must be explicitly enabled in the CA policy.
  - **Long-lived credentials.** Authorization certs are
    minute-scale. Identity certs (the user's mTLS cert) can be
    longer-lived but are still bounded.

See [security.md](security.md) for the threat model and
[future-ideas.md](future-ideas.md) for everything we've considered
adding later.
