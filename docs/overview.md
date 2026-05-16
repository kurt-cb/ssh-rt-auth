# mssh — overview

**mssh** is an SSH client + server-side gateway that moves
authorization out of the SSH protocol and into a separate, network-
restricted CA. Users keep their existing SSH workflow; operators
gain centralized, auditable authorization that can revoke access
in seconds and that **renders stolen client credentials useless if
the attacker can't reach the CA**.

This document is for operators evaluating mssh. For deeper
technical detail see [design/architecture.md](../design/architecture.md);
for install + day-to-day operation see [operations.md](operations.md).

---

## What problem does mssh solve?

Standard SSH puts the trust decision on the client side: whoever
has the private key authenticates as that user. Once a key is
stolen, the attacker has full access until you notice and
manually rotate everything.

OpenSSH user certs (and tools like Vault SSH) move the trust to a
signing authority, but the signed cert is still **carried by the
client**, so a captured cert is good until expiry.

mssh moves the trust decision **server-side** and **online**: the
server contacts a CA at every connection. The CA is what decides
"yes / no" and how long this authorization is valid for (minute-
scale). The client carries only their identity; the CA carries the
policy.

Net effect:

  - **Revoke access in seconds**, not after the next key rotation
    window.
  - **Audit every authorization** centrally — every connection
    attempt is an entry in one log.
  - **Stolen client credentials are useless** off the network
    where the CA is reachable.
  - **Existing SSH workflows are preserved** during migration —
    users still use SSH, operators flip CA-mediated auth on
    server-by-server.

---

## The pieces

```
  Your users (laptops, jump hosts)
                │
                │  mssh (client)
                ▼
  Each of your SSH servers
                │
                │  msshd (server-side gateway)
                │      • mTLS termination
                │      • calls the CA at every connection
                │      • mints an ephemeral OpenSSH cert
                │      • hands off to a hermetic inner sshd
                │
                ▼  (CA call, mTLS REST)
                │
  Your CA, on a restricted network
                ├─  Policy engine + enrollment DB
                ├─  Authorization cert minter
                └─  Audit log

  Your operators
                │
                │  mssh-admin (CLI)
                ▼  (mTLS REST to the CA)
```

  - **mssh** — drop-in SSH client. Same UX (`mssh alice@host`).
  - **msshd** — sits on each of your SSH servers. Receives mssh
    client connections, calls the CA, runs a hermetic inner sshd.
  - **mssh-ca** — the central authorization service. Lives on
    a network reachable only from your SSH servers and operator
    workstations.
  - **mssh-admin** — operator CLI for enrolling servers, users,
    and policies.

For full detail see [design/architecture.md](../design/architecture.md).

---

## When does mssh fit?

mssh is a good fit when:

  - **You have many SSH servers and want one place to manage
    access.** Today that means rotating `authorized_keys` across
    fleets; mssh centralizes it.
  - **You need fast revocation.** A leaked key disabled in seconds,
    not after the next rotation window.
  - **You need centralized auditing.** Every connection attempt
    logged in one place with full context.
  - **You can put the CA on a private network.** This is the
    feature that makes stolen credentials useless off-network.
  - **You want to migrate without disrupting users.** mssh's
    `msshd` gateway supports a **transparent-proxy** mode that
    drops it in front of your existing sshd without changing
    user auth at all — you flip to CA-mediated auth on your
    schedule, per-server.

mssh is **not** a good fit when:

  - **Your SSH servers are internet-only** with no separate
    operator network. The core "CA-unreachable = useless"
    property weakens significantly if the CA must be
    internet-routable.
  - **You need single-sign-on against an external IdP.** mssh
    is the policy engine; integrating with an IdP for identity
    is a separate (future) feature.
  - **You can't tolerate a per-connection CA call (~tens of ms).**
    mssh's caching helps but the design assumes the CA is in
    the auth path.

---

## What you get for adopting

  - A **single source of truth** for SSH authorization: the CA's
    enrollment + policy.
  - A **single audit trail**: every connection, every admin
    action, in one JSON-Lines file you can ship to your SIEM.
  - **Short-lived authorization**: minutes, not days. Even a
    completely compromised user laptop has a short window of
    abuse.
  - **Mediated channel policy**: msshd enforces "session-only,
    no port forwarding" etc. at the gateway, not at the inner
    sshd.
  - **Per-server transition modes**: keep your existing sshd
    policy on critical hosts while you migrate the easy ones
    first. See [operations.md § adoption journey](operations.md#the-adoption-journey).

---

## What you take on

  - **Operating the CA.** It's the highest-value asset in your
    auth path. Custody of the CA signing key, network isolation
    of the CA host, and audit-log retention are your
    responsibilities.
  - **Provisioning msshd on every server.** Today this is a
    Python package + a systemd unit. A clean `apt install mssh`
    distro package is on the [future-ideas list](../design/future-ideas.md);
    `install_mssh.sh` is the interim install path.
  - **Educating your users on mssh.** The UX is `mssh user@host`
    instead of `ssh user@host` — small change, but it's a change.
    During migration the transparent-proxy mode lets users keep
    using `ssh` unchanged until you're ready.

---

## Next steps

  - **Try the adhoc lab.** Five LXC containers; full
    Phase-0-to-Phase-2 migration in 2 minutes; flip between
    modes from the host. See
    [`python/tests/lxc/test_setup_only_msshd.py`](../python/tests/lxc/test_setup_only_msshd.py)
    or run `./setup_adhoc.sh` from the `python/` directory.
  - **Read [operations.md](operations.md)** for install, the
    adoption journey, and day-to-day operator tasks.
  - **Read [design/architecture.md](../design/architecture.md)**
    for the technical model in depth.
  - **Read [design/security.md](../design/security.md)** for
    the threat model and trust analysis.
