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
├── ca/                CA — issues short-lived X.509 authz certs
├── cli/               ssh-rt-admin — enroll servers, users, policies
├── shim/              authorization shim — server-side query to CA over mTLS
├── server/            AsyncSSH reference SSH server (Tier 2)
├── openssh/           AuthorizedKeysCommand entry point (Tier 3)
├── wrapper/           Tier 1 production endpoint (next phase)
│   ├── python/        PoC
│   ├── go/            production port
│   └── alpine/        minimal C+Mbed TLS / wolfSSL (Alpine-only)
├── tests/             host + LXC integration tests
└── design/            design docs
```

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

- **`ca/`** — CA server: Flask + mTLS, issues short-lived X.509 authz
  certs with policy extensions. Enrollment DB in YAML.
- **`cli/`** — `ssh-rt-admin` CLI: enroll servers, users, admins, keys,
  policies. Role-based access control.
- **`shim/`** — Authorization shim called by sshd or library-based
  servers. mTLS to CA, response validation, SQLite cache for
  short-lived AKC subprocesses.
- **`server/`** — Reference Tier 2 SSH server (AsyncSSH) that wires
  the shim into `validate_public_key`. End-to-end working today.
- **`openssh/`** — Tier 3 entry point: `AuthorizedKeysCommand`
  helper that calls the shim. Works against unmodified `sshd`.
- **`tests/`** — 79 host unit tests + 24 LXC integration tests. Covers
  matrix authorization, mTLS attacks on the CA, audit-log coverage,
  emergency-cert fallback, wildcard policies, and more.

**The wrapper (Tier 1) is designed but not yet implemented.** See
[wrapper/README.md](wrapper/README.md).

---

## Running the PoC

```bash
pip install -r requirements.txt

# Bootstrap a CA
python -m cli.main init --ca-dir /tmp/myca

# Run host tests
pytest tests -m "not lxc"

# Run LXC integration tests (needs lxc/lxd)
pytest tests/lxc -m lxc

# Run the ad-hoc test environment (5 LXC containers, "real" lab setup)
pytest tests/lxc/test_setup_only.py -v -m setup_only
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

- **[tests/overview.md](tests/overview.md)** — what every test verifies
- **[tests/issues.md](tests/issues.md)** — running list of bugs hit
  during development and how each was fixed

---

## Related repos

- **[../ssh-rt-auth-openssh/](../ssh-rt-auth-openssh/)** — small upstream
  OpenSSH patches for the Tier 3 compatibility path (`%R`/`%L`/etc.
  tokens; `SSH_AKC_PHASE` env var). Independent from the wrapper.

---

## Project status

**PoC: complete.** Tiers 2 and 3 are functionally implemented and
tested. The wrap-and-proxy Tier 1 wrapper is designed
([wrapper/](wrapper/)) and is the next phase of work.

**Author:** Kurt Godwin (github.com/kurt-cb)
