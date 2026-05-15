# ssh-rt-auth

**Runtime, CA-mediated SSH authorization.**

Moves SSH authorization from the client to the server. Instead of
clients holding authorization certs, the server queries a CA at
connection time to get a short-lived X.509 authorization cert based on
the client's identity. The client uses only their existing SSH key — no
changes needed.

**The key architectural property:** a stolen client credential is
useless if the attacker can't reach the CA. Place the CA on a private
network; stolen keys can't trigger authorization.

---

## Quick map

```
ssh-rt-auth/
├── python/                      # Python implementation (PoC + Tier 1 wrapper)
│   ├── setup.py + pytest.ini
│   ├── src/sshrt/
│   │   ├── ca/                  # CA — issues short-lived X.509 authz certs
│   │   ├── admin/               # ssh-rt-admin CLI (enroll servers/users/policies)
│   │   ├── shim/                # authorization shim (server-side CA query over mTLS)
│   │   ├── asyncssh_ref/        # Tier 2 AsyncSSH reference SSH server
│   │   ├── akc_shim/            # Tier 3 AuthorizedKeysCommand entry point
│   │   ├── msshd/               # Tier 1 wrapper daemon
│   │   └── mssh.py              # Tier 1 client CLI
│   └── tests/                   # host + LXC integration tests
├── go/                          # future — full Go impl across the trio
├── c/                           # future — minimal C for Alpine
├── openssh-patches/             # OpenSSH upstream-targeted patches (Tier 3 only)
├── config/                      # operator-facing config examples (lang-neutral)
├── scripts/upgrade.sh           # host upgrade / install / verify / rollback
├── systemd/                     # service unit files (lang-neutral)
├── design/                      # design docs
└── docs/                        # operator-facing docs (overview, REST API, …)
```

**No language-mixing in production builds.** Each language directory
(`python/`, `go/`, `c/`) ships its own client/server/CA implementation.
Operator-facing artifacts (config, scripts, systemd, openssh-patches)
live at the repo root and are language-neutral.

---

## Three-tier deployment model

| Tier | What you run                                                        | Auth model                  | When to choose it |
|------|---------------------------------------------------------------------|-----------------------------|-------------------|
| **1** | **ssh-rt-auth wrapper** + hermetic localhost OpenSSH (`wrapper/`)  | Full cert-bound, all policy extensions enforced | **Production.** Currently designed; implementation in next phase. |
| **2** | Your own SSH server library (AsyncSSH, Go, libssh, etc.) with our integration | Full cert-bound, in-app    | You're embedding an SSH server in your app. AsyncSSH integration ships in this repo (`server/`); others planned. |
| **3** | Unmodified `sshd` + our AKC shim (`openssh/`)                       | Yes/no via AuthorizedKeysCommand. No in-session constraint enforcement. | Lowest deployment friction; orgs that can't deploy the wrapper. Documented limitations. |

See [design/ssh-rt-auth-server-strategy.md](design/ssh-rt-auth-server-strategy.md)
for the full strategy.

---

## What's in the PoC (this repo)

The Proof-of-Concept implements **Tiers 2 and 3 end-to-end**, with the
**CA, shim, admin CLI, and full test suite**.

- **`python/src/sshrt/ca/`** — CA server: Flask + mTLS, issues
  short-lived X.509 authz certs with policy extensions.
- **`python/src/sshrt/admin/`** — `ssh-rt-admin` CLI: enroll servers,
  users, admins, keys, policies. Role-based access control.
- **`python/src/sshrt/shim/`** — Authorization shim called by sshd or
  library-based servers. mTLS to CA, response validation, SQLite cache.
- **`python/src/sshrt/asyncssh_ref/`** — Reference Tier 2 SSH server
  (AsyncSSH). End-to-end working.
- **`python/src/sshrt/akc_shim/`** — Tier 3 entry point: stock
  `AuthorizedKeysCommand` helper that calls the shim.
- **`python/src/sshrt/msshd/`** — Tier 1 wrapper daemon: mTLS-terminating
  outer listener, CA call, OpenSSH cert minting, hermetic inner sshd.
- **`python/src/sshrt/mssh.py`** — Tier 1 client CLI (pure-Python TLS
  client, JSON-framed outer protocol).
- **`python/tests/`** — host + LXC integration tests.

---

## Running the PoC

```bash
# Install editable (older venvs may need: pip install --no-build-isolation -e ./python)
pip install -e ./python

# Bootstrap a CA
ssh-rt-admin init --ca-dir /tmp/myca

# Run host tests
cd python && pytest tests -m "not lxc"

# Run LXC integration tests (needs lxc/lxd)
cd python && pytest tests/lxc -m lxc

# Run the ad-hoc test environment (5 LXC containers, "real" lab setup)
cd python && pytest tests/lxc/test_setup_only.py -v -m setup_only
# Then read ADHOC_TEST_ENV.md for what to do with it.
```

---

## Design docs

Start here:

- **[design/ssh-rt-auth-server-strategy.md](design/ssh-rt-auth-server-strategy.md)**
  — three-tier model overall
- **[design/ssh-rt-auth-wrapper-research.md](design/ssh-rt-auth-wrapper-research.md)**
  — why Tier 1 is wrap-and-proxy, not greenfield (CVE-burden analysis)
- **[design/ssh-rt-auth-detailed-wrapper.md](design/ssh-rt-auth-detailed-wrapper.md)**
  — wrapper implementation blueprint
- **[design/ssh-rt-auth-v2-enhancements.md](design/ssh-rt-auth-v2-enhancements.md)**
  — connection-context schema, reserved cert-extension OIDs, sshd-implementation policy

Deeper:

- **[docs/ssh-rt-auth-doc-00-overview.md](docs/ssh-rt-auth-doc-00-overview.md)**
  — high-level overview, component diagrams, trust model
- **[docs/ssh-rt-auth-detailed-rest-api.md](docs/ssh-rt-auth-detailed-rest-api.md)**
  — CA REST API spec
- **[docs/ssh-rt-auth-detailed-ca-admin.md](docs/ssh-rt-auth-detailed-ca-admin.md)**
  — CA internals, cert minting, admin CLI
- **[docs/ssh-rt-auth-detailed-shim.md](docs/ssh-rt-auth-detailed-shim.md)**
  — shim interface, cache, failover, sshd integration
- **[design/ssh-rt-auth-security-analysis.md](design/ssh-rt-auth-security-analysis.md)**
  — threat model, attack surface analysis, standards conformance

Operational diary:

- **[python/tests/overview.md](python/tests/overview.md)** — what every test verifies
- **[python/tests/issues.md](python/tests/issues.md)** — running list of bugs hit during development and how each was fixed

---

## OpenSSH upstream patches

Two small patches (`%R %r %L %l` tokens + `SSH_AKC_PHASE` env var)
live at [openssh-patches/](openssh-patches/). Useful to any
`AuthorizedKeysCommand` helper (LDAP, Vault, IAM bridges, this
project's Tier 3 path). Independent of the Tier 1 wrapper.

---

## Project status

**PoC + Tier 1 Python wrapper: complete and tested end-to-end.**
Future language ports (`go/`, `c/`) are deferred until Phase 2
features stabilize.

**Author:** Kurt Godwin (github.com/kurt-cb)
