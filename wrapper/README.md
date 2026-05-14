# wrapper — Tier 1 production endpoint

The ssh-rt-auth wrapper is the production endpoint for the Tier 1
deployment model: an mTLS-terminating daemon that authenticates the
user via the CA, mints a short-lived OpenSSH user cert with the
authorization policy translated into critical-options, and proxies the
inner SSH session to a **hermetic** localhost-bound `sshd` that the
wrapper owns.

The operator never sees or edits the inner `sshd_config`. The wrapper
hides OpenSSH's 120-directive config surface behind a small opinionated
YAML (see `config/wrapper.yaml.example`).

## Three language variants, same wire protocol

| Variant            | Role                  | Status        |
|--------------------|-----------------------|---------------|
| `python/`          | PoC implementation    | Next phase    |
| `go/`              | Production port       | After Python is vetted |
| `alpine/`          | Minimal C + Mbed TLS / wolfSSL (Alpine-only, constrained deployments) | After Go ships |

All three share:

- **Wire protocol:** SSH over TLS 1.3 with mTLS (client cert auth).
- **Config schema:** `config/wrapper.yaml.example`.
- **CA contract:** the existing `POST /v1/authorize` endpoint
  (`design/ssh-rt-auth-detailed-rest-api.md`), reusing the shim's mTLS
  client.
- **Hermetic inner sshd config template:** `config/sshd_config.template`.
- **systemd integration:** unit files in `systemd/`.

So a single integration test suite verifies all three.

## Design references

Implementation should follow:

- [Detailed wrapper design](../design/ssh-rt-auth-detailed-wrapper.md)
  — implementation-blueprint level. Critical-option translation table,
  per-connection flow, key custody, phasing.
- [Wrapper research and decision](../design/ssh-rt-auth-wrapper-research.md)
  — prior-art analysis (Teleport, Smallstep, Tailscale, Boundary,
  BastionZero), CVE-burden evidence, hermetic-inner-sshd argument.
- [Server strategy](../design/ssh-rt-auth-server-strategy.md) — three-tier
  deployment model overall.

## Implementation order

1. **`python/`** first — fast iteration; reuses the PoC's `shim/`
   and `ca/` Python machinery directly; easy to vet against the
   existing LXC test suite.
2. **`go/`** once Python is vetted — port the design to a memory-safe
   production language with better long-running-daemon ergonomics.
3. **`alpine/`** if/when a constrained deployment target asks for it —
   C + Mbed TLS or C + wolfSSL minimal implementation.

The three are deliberately structurally parallel so the wire/config
contract stays a single source of truth.

## Safe-rollout flow

The wrapper deploys in **fallback mode by default** — a transparent
proxy to the existing system sshd that doesn't change the auth surface
at all. The operator graduates to CA-enforced mode through explicit
phases, with verification gates between each. See
[../design/ssh-rt-auth-detailed-wrapper.md § 6.5](../design/ssh-rt-auth-detailed-wrapper.md).

The companion script [`scripts/upgrade.sh`](scripts/upgrade.sh) walks
through it:

```
upgrade.sh install   → fallback wrapper alongside system sshd
upgrade.sh verify-1  → confirm SSH still works
upgrade.sh enforce   → switch wrapper to CA-mediated auth
upgrade.sh verify-2  → confirm CA-mediated auth works
upgrade.sh cutover   → move wrapper to port 22, stop system sshd
upgrade.sh verify-3  → confirm port 22 still works
upgrade.sh rollback  → at any phase, restore system sshd
```

It's POSIX sh (ash/bash compatible) and intended to be SCP'd to a
target host and run as root. Includes systemd + OpenRC detection.

## Not yet implemented

The Python / Go / C wrapper implementations are skeletons only. The
upgrade script and config schema are real and reviewable. Implementation
work begins in the next phase, separately from the PoC tag.
