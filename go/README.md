# go/ — Go implementation (placeholder)

**Status:** not yet implemented. Phase 2+ work after Python features
stabilize.

When implemented this tree will hold a **full Go port** of the
project — CA + admin CLI + shim + Tier 1 wrapper (msshd) + Tier 1
client (mssh). No mixing with the Python implementation: a Go
deployment uses only this tree's binaries.

Planned layout:

```
go/
├── go.mod
├── cmd/
│   ├── mssh/                # Tier 1 client
│   ├── msshd/               # Tier 1 wrapper daemon
│   ├── ca/                  # CA server
│   └── admin/               # ssh-rt-admin
├── internal/
│   ├── protocol/            # JSON outer-protocol-v1
│   ├── ca/                  # CA-side packages
│   ├── shim/
│   ├── msshd/
│   ├── mssh/
│   └── common/              # cert helpers, mTLS, etc.
└── tests/
```

The Go and Python implementations share **wire protocol, config
schema, and CA contract** — they must remain interoperable. A single
integration test suite (LXC) should drive both via the same external
interfaces.

See [../design/ssh-rt-auth-detailed-wrapper.md](../design/ssh-rt-auth-detailed-wrapper.md)
for the implementation blueprint and
[../design/ssh-rt-auth-phase2-ideas.md](../design/ssh-rt-auth-phase2-ideas.md)
for the sequencing decision (Python features first, then Go port).
