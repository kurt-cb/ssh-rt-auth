# mssh

Runtime, CA-mediated SSH authorization system.

## Project summary

mssh moves SSH authorization out of the SSH protocol and into a
separate, network-restricted CA. The server contacts the CA at
every connection and gets a short-lived authorization back. The
client uses only their existing SSH key — no client changes.

The defining property: **a stolen client credential is useless if
the attacker can't reach the CA.** Put the CA on a private
network; stolen keys can't authorize from outside that network.

## Component naming

Canonical names:

- **mssh** — the client (`python/src/mssh/client.py`); `import mssh.client`
- **msshd** — the server-side gateway daemon (`python/src/mssh/msshd/`)
- **mssh-ca** — the central CA service (`python/src/mssh/ca/`)
- **mssh-admin** — operator CLI (`python/src/mssh/admin/`)
- **debug_sshd** — debug-only AsyncSSH server (`python/src/mssh/debug_sshd/`)
  — not a production tier
- **shim** (library) — shared "call the CA" code (`python/src/mssh/shim/`)

Avoid the word "wrapper" — historical, ambiguous. Use "gateway"
for msshd. The previous "Tier 1 / 2 / 3" framing is also retired;
mssh has a single production server (msshd) plus the optional AKC
shim (`python/src/mssh/akc_shim/`) for unmodified-OpenSSH compat.

## Three operating modes

msshd selects between three modes via `wrapper.yaml`:

- `fallback` — pure TCP proxy to operator's existing sshd. No CA
  call. Implemented.
- `gated` — mTLS + CA approval, but forward to operator's existing
  sshd for auth. **Deferred** (see design/future-ideas.md).
- `enforce` — mTLS + CA call + ephemeral OpenSSH cert minted +
  hermetic inner sshd. Implemented.

Operator adoption journey: fallback → gated → enforce, reversible.

## Key design decisions

- Authorization cert format: X.509 with custom extensions (settled, do not change)
- Identity proof: bare SSH public key + OpenSSH cert; X.509 client
  cert from a separate user-facing CA
- Server identity: via mTLS cert (subject), not hostname
- Raw blob forwarding: msshd does NOT parse identity certs; the CA
  does all parsing
- Two distinct cert hierarchies, intentionally separate:
  - **CA signing key** — authz certs + server/admin mTLS certs
  - **User-facing CA** — mssh client mTLS certs + msshd's TLS server cert
- **msshd's local user-CA** — third, internal key, signs ephemeral
  OpenSSH user certs for the hermetic inner sshd. Never leaves the
  msshd host.
- No password auth, ever
- Fail-closed: if CA unreachable, deny (unless emergency cert)
- Implementation language: Python today. Go on Alpine is harder
  than expected (musl support); Rust is the cleanest cross-distro
  cross-language option. See design/future-ideas.md § distro packaging.

## Docs

### Operator-facing

- `docs/overview.md` — what mssh is, when it fits
- `docs/operations.md` — install, adopt, run, troubleshoot

### Design

- `design/architecture.md` — components, modes, hermetic inner sshd
- `design/api.md` — REST + admin API contract + enrollment YAML
- `design/security.md` — trust model + threat analysis
- `design/future-ideas.md` — deferred features (read this before
  proposing new ones — many ideas are captured here already)

### Historical (don't write new content here; reference only)

- `archive/design/` — original 12 design docs that pre-date the
  clean-room rewrite. Use older naming ("ssh-rt-auth", "Tier 1/2/3",
  "Phase 1/2", "PoC"). Frequently more detailed than the new docs.
- `archive/docs/` — original operator docs.

## Project structure

Top-level dir = language. Within each language, full client + server + CA.
Operator-facing artifacts (configs, scripts, systemd, OpenSSH patches)
live at the repo root and are language-neutral.

```
mssh/
├── CLAUDE.md               # this file
├── README.md
├── INSTALLATION.md
├── design/                 # clean-room design docs
├── docs/                   # operator-facing docs
├── archive/                # historical design + docs (internal reference)
├── python/                 # current Python implementation
│   ├── setup.py            # legacy-compat shim for editable install
│   ├── pytest.ini
│   ├── requirements.txt
│   ├── src/mssh/          # the mssh Python package
│   │   ├── ca/             # CA server (Flask + mTLS)
│   │   ├── admin/          # mssh-admin CLI
│   │   ├── shim/           # shared "call the CA" library
│   │   ├── debug_sshd/     # debug-only AsyncSSH server (not a tier)
│   │   ├── akc_shim/       # OpenSSH AKC entry point (Tier-3 compat)
│   │   ├── msshd/          # the gateway daemon
│   │   └── client.py       # the mssh client (single module)
│   └── tests/
├── go/                     # future — Go port (placeholder)
├── c/                      # future — C for Alpine (placeholder)
├── openssh-patches/        # upstream-targeted OpenSSH patches (AKC support)
├── config/                 # example operator configs
├── scripts/                # operator scripts
└── systemd/                # service unit files
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
- Comments explain why, not what
- Error messages should be specific and actionable
- All network errors fail-closed (deny access)
- Avoid the word "wrapper" — use "gateway" for msshd
- Avoid Phase / Tier / PoC framing in new docs — those were
  intermediate; reference architecture.md for the canonical view
