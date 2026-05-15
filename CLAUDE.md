# ssh-rt-auth

Runtime, CA-mediated SSH authorization system.

## Project summary

This system moves SSH authorization from the client to the server. Instead of
clients holding authorization certs, the server queries a CA at connection time
to get a short-lived X.509 authorization cert based on the client's identity.
The client uses only their existing SSH key or OpenSSH cert — no changes needed.

The key architectural property: a stolen client credential is useless if the
attacker can't reach the CA. Place the CA on a private network; stolen keys
can't trigger authorization.

## Architecture

Three components:

1. **SSH server with shim** — An SSH server (AsyncSSH for PoC) calls the
   ssh-rt-auth shim after userauth succeeds. The shim queries the CA over mTLS,
   caches the response, and returns the authorization cert to the server.

2. **Authorization CA** — REST API over mTLS. Receives identity blobs and
   connection context from the shim, evaluates policy, mints X.509 authorization
   certs. All policy decisions live here.

3. **ssh-rt-admin CLI** — Management tool for enrolling servers, users, and
   admins. Authenticated via admin mTLS certs with role-based access control.

## Key design decisions

- Authorization cert format: X.509 with custom extensions (settled, do not change)
- Identity proof: bare SSH public key + OpenSSH cert (v1 scope, no X.509 client certs)
- Server identity: via mTLS cert, not hostname. CA identifies server from mTLS handshake.
- Raw blob forwarding: sshd/shim does not parse identity certs. CA does all parsing.
- PoC language: Python (AsyncSSH for SSH, Flask for CA, cryptography lib for X.509)
- PoC minimum target: **Alpine + Python**. CA stays Python in production —
  it runs on operator infrastructure, not constrained endpoints, so the
  earlier "C/Mbed TLS CA" plan was dropped.
- Production endpoint (Tier 1): **wrap-and-proxy** — mTLS-terminating wrapper
  in front of a hermetic, locked-down unmodified OpenSSH. Three planned
  variants in `wrapper/`:
  - `python/src/sshrt/msshd/` — PoC implementation, fast iteration, easy to vet
  - `wrapper/go/` — production port; balances performance with memory safety
  - `wrapper/alpine/` — minimal C+Mbed TLS or C+wolfSSL for constrained
    Alpine-only deployments
  See `design/ssh-rt-auth-detailed-wrapper.md`.
- No password auth, ever
- Fail-closed: if CA unreachable, deny (unless emergency cert)

## Design docs

Read these before implementing — they contain the detailed specifications:

- `docs/ssh-rt-auth-doc-00-overview.md` — High-level overview, component diagrams, trust model
- `docs/ssh-rt-auth-doc-02-ca-design.md` — CA design goals, API overview, enrollment model
- `docs/ssh-rt-auth-detailed-shim.md` — Shim interface, cache, failover, sshd integration
- `docs/ssh-rt-auth-detailed-rest-api.md` — Complete REST API spec (all endpoints, all fields)
- `design/ssh-rt-auth-server-strategy.md` — Three-tier deployment model; wrapper is Tier 1
- `design/ssh-rt-auth-wrapper-research.md` — Wrap-and-proxy vs greenfield decision; hermetic inner sshd design
- `design/ssh-rt-auth-detailed-wrapper.md` — Implementation blueprint for the Tier 1 wrapper (Python/Go/Alpine variants)
- `design/ssh-rt-auth-v2-enhancements.md` — v2 connection-context schema, reserved cert-extension OIDs, sshd-implementation policy
- `design/ssh-rt-auth-phase2-ideas.md` — Deferred ideas (per-connection sshd, smart cards, HTTPS proxy, passkeys, 2FA, …)
- `docs/ssh-rt-auth-detailed-ca-admin.md` — CA internals, enrollment DB schema, cert minting, admin CLI

## PoC implementation phases

### Phase 1: CA and admin tool
1. `ssh-rt-admin init` — generate CA signing key, bootstrap admin cert
2. Enrollment YAML read/write (servers, users, admins, policies)
3. `POST /v1/authorize` — identity parsing, policy evaluation, cert minting
4. Admin API endpoints (server add, user add, key add, policy add)
5. Admin authentication and role checking
6. Audit logging (JSON Lines)

### Phase 2: Shim (Python)
1. Python shim with mTLS client
2. Cache (in-memory dict)
3. Failover logic (try endpoints in order)
4. Response validation (verify cert signature before caching)

### Phase 3: SSH server integration
1. AsyncSSH server with public key auth
2. Hook into shim after userauth succeeds
3. Extract raw public key blob and connection context
4. Enforce cert constraints (channel policy, source bind)

### Phase 4: End-to-end test
1. ssh-rt-admin init → bootstrap
2. Enroll a server, enroll a user with a key, add a policy
3. Start CA, start SSH server
4. Connect with standard SSH client → authorized session
5. Connect with unauthorized key → denied
6. Connect outside time window → denied

## Project structure

Top-level dir = language. Within each language, full client + server + CA.
Operator-facing artifacts (configs, scripts, systemd, OpenSSH patches)
live at the repo root and are language-neutral.

```
ssh-rt-auth/
├── CLAUDE.md               # this file
├── README.md
├── INSTALLATION.md
├── design/                 # design docs
├── docs/                   # operator-facing docs (overview, REST API, ...)
├── python/                 # Python implementation (PoC + Tier 1 wrapper)
│   ├── setup.py            # legacy-compat shim for editable install
│   ├── pytest.ini
│   ├── requirements.txt
│   ├── src/sshrt/          # the package namespace
│   │   ├── __init__.py
│   │   ├── ca/             # CA server (Flask + mTLS)
│   │   │   ├── server.py            # mTLS listener
│   │   │   ├── authorize.py         # POST /v1/authorize handler
│   │   │   ├── admin.py             # admin API handlers
│   │   │   ├── policy.py            # policy evaluation engine
│   │   │   ├── enrollment.py        # enrollment DB (YAML backend)
│   │   │   ├── cert_minter.py       # X.509 cert generation
│   │   │   ├── identity_parser.py   # SSH key/cert blob parsing
│   │   │   ├── audit.py             # audit logging
│   │   │   └── config.py            # CA config loading
│   │   ├── admin/          # ssh-rt-admin CLI
│   │   │   ├── main.py              # click CLI entry point
│   │   │   ├── client.py            # mTLS HTTP client for admin API
│   │   │   ├── key_parser.py        # SSH key/cert file parsing
│   │   │   └── formatters.py
│   │   ├── shim/           # AKC-style authorization shim
│   │   │   ├── shim.py              # main shim logic
│   │   │   ├── cache.py             # in-memory cert cache
│   │   │   ├── sqlite_cache.py      # cross-process cert cache
│   │   │   ├── ca_client.py         # mTLS HTTP client with failover
│   │   │   └── config.py
│   │   ├── asyncssh_ref/   # Tier 2 reference SSH server (AsyncSSH)
│   │   │   └── ssh_server.py
│   │   ├── akc_shim/       # Tier 3 AuthorizedKeysCommand entry point
│   │   │   └── openssh_shim.py
│   │   ├── msshd/          # Tier 1 wrapper daemon
│   │   │   ├── msshd.py             # entry point
│   │   │   ├── listener.py          # fallback-mode TCP listener
│   │   │   ├── enforce_listener.py  # enforce-mode mTLS listener
│   │   │   ├── inner.py             # hermetic inner sshd lifecycle
│   │   │   ├── userca.py            # local user-CA key + OpenSSH cert mint
│   │   │   ├── policy.py            # X.509 ext → OpenSSH critical-options
│   │   │   ├── proxy.py             # fallback byte proxy
│   │   │   ├── ssh_proxy.py         # enforce-mode asyncssh proxy
│   │   │   ├── ca.py                # CA client (wraps shim.ca_client)
│   │   │   ├── config.py
│   │   │   └── admin.py             # ssh-rt-wrapper-admin CLI
│   │   └── mssh.py         # Tier 1 client CLI (single module)
│   └── tests/
│       ├── conftest.py
│       ├── test_*.py                # host unit tests
│       └── lxc/                     # LXC integration tests
├── go/                     # future — full Go impl across the trio (placeholder)
├── c/                      # future — minimal C for Alpine (placeholder)
├── openssh-patches/        # absorbed: upstream-targeted patches for AKC
│   ├── patches/                     # exported .patch files
│   ├── NOTES.md                     # patch-plan rationale
│   ├── README.md
│   └── build.sh                     # apply + build helper
├── config/                 # example operator configs (lang-neutral)
│   ├── wrapper.yaml.example
│   └── sshd_config.template
├── scripts/                # operator scripts
│   └── upgrade.sh                   # host upgrade / install / verify / rollback
└── systemd/                # service unit files (lang-neutral)
    ├── ssh-rt-wrapperd.service
    └── ssh-rt-inner-sshd.service
```

## Dependencies

```
asyncssh>=2.14
cryptography>=41.0
flask>=3.0
pyyaml>=6.0
click>=8.0
requests>=2.31
```

## Style

- Author: Kurt Godwin (github.com/kurt-cb)
- Keep code simple and readable
- No over-engineering — this is a PoC
- Comments explain why, not what
- Error messages should be specific and actionable
- All network errors fail-closed (deny access)
