# mssh

**Runtime, CA-mediated SSH authorization.**

mssh moves SSH authorization out of the SSH protocol and into a
separate, network-restricted **CA**. Users keep their existing SSH
workflow; operators get centralized, auditable authorization that
can revoke access in seconds — and that **renders stolen client
credentials useless if the attacker can't reach the CA**.

```
   mssh client  ──TLS+mTLS──▶  msshd ──mTLS REST──▶  CA  (private network)
                                  │
                                  └─▶  hermetic inner sshd (localhost)
```

  - `mssh` — the client. Same UX as `ssh`.
  - `msshd` — the **gateway** that sits on each of your SSH servers.
    Terminates mTLS, calls the CA, runs a hermetic inner sshd.
  - `mssh-ca` — the central authorization service.
  - `mssh-admin` — operator CLI.
  - `debug_sshd` — debug-only AsyncSSH server that calls the CA inline;
    useful for isolating CA issues from gateway machinery.

---

## Quick start

```bash
git clone https://github.com/kurt-cb/ssh-rt-auth.git
cd ssh-rt-auth/python
pip install -e .

# Try the adhoc lab — 5 LXC containers, full Phase-0→Phase-2
# migration in 2 minutes, host-side workflow:
./setup_adhoc.sh
```

That puts you in an interactive shell with helper functions:

```bash
mssh_as alice acct whoami            # mssh through msshd (Phase 2)
ssh_as  alice acct whoami            # plain ssh (Phase 0, always works)
flip_to_fallback / flip_to_enforce   # operator workflow, no lxc exec
```

---

## Where to read next

  - **[docs/overview.md](docs/overview.md)** — what mssh is, what
    problem it solves, when it fits.
  - **[docs/operations.md](docs/operations.md)** — install, the
    three-phase adoption journey, day-to-day operator tasks,
    troubleshooting.
  - **[design/architecture.md](design/architecture.md)** — the
    technical model (components, modes, trust hierarchies, hermetic
    inner sshd).
  - **[design/api.md](design/api.md)** — REST + admin API contract.
  - **[design/security.md](design/security.md)** — threat model,
    fail-closed defaults, what stops which attack.
  - **[design/future-ideas.md](design/future-ideas.md)** — deferred
    features (gated mode, browser bastion, MCP, legacy capture, distro
    packaging, …).

Historical design docs that predate the clean-room rewrite are in
[archive/](archive/) for internal reference.

---

## Repo layout

```
mssh/
├── python/                 # current implementation (mssh + msshd + mssh-ca + mssh-admin)
│   ├── src/mssh/          # the mssh Python package
│   ├── tests/
│   └── setup_adhoc.sh      # spin up the adhoc lab
├── design/                 # technical design docs (clean-room)
├── docs/                   # operator-facing docs
├── archive/                # historical design + docs (internal reference)
├── config/                 # example operator configs (lang-neutral)
├── scripts/                # operator scripts
└── systemd/                # service unit files (lang-neutral)
```

Future language ports (`go/`, `c/`, `rust/`) are deferred; see
[design/future-ideas.md § distro packaging](design/future-ideas.md).

---

**Author:** Kurt Godwin (github.com/kurt-cb)
