# c/ — Alpine-targeted C implementation (placeholder)

**Status:** not yet implemented. Phase 2+ work after Python features
stabilize. Operator preference: this comes **before** the Go port.

Constrained-deployment target (Alpine, embedded, single-board hardware).

```
c/
├── mssh/                    # Tier 1 client (C + Mbed TLS or wolfSSL)
├── msshd/                   # Tier 1 wrapper daemon (C + Mbed TLS or wolfSSL)
├── micro-ca/                # pre-configured tiny CA — one or two users
│                            # plus an admin/root, hard-coded enrollment.
│                            # Users wanting more deploy a python/ or go/ CA elsewhere.
└── common/                  # shared C utilities (mTLS, cert helpers, ...)
```

Design constraints:

- **Minimal feature surface.** Whatever Python ships first that
  exceeds C's footprint budget stays Python-only.
- **All-C for client + server.** No Python or Go in the runtime.
- **micro-CA is the fallback for single-machine deployments.** If the
  operator needs full policy DSL, multiple admins, audit retention,
  etc., they run a full Python or Go CA on a separate (beefier) host
  and point the Alpine box's msshd at it via the standard CA config.
- **TLS lib choice deferred.** Both Mbed TLS and wolfSSL ship on
  Alpine; both are embedded-friendly. wolfSSL has commercial support,
  Mbed TLS has broader open-source adoption. Decide at implementation
  start.

See [../design/ssh-rt-auth-phase2-ideas.md](../design/ssh-rt-auth-phase2-ideas.md)
for sequencing context and
[../design/ssh-rt-auth-detailed-wrapper.md](../design/ssh-rt-auth-detailed-wrapper.md)
for the protocol contract that this implementation must honor.
