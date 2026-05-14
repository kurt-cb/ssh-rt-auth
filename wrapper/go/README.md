# wrapper/go — production port of the Tier 1 wrapper

**Status:** Not yet implemented. Future phase, after `wrapper/python/`
is vetted.

The Go port of the wrap-and-proxy Tier 1 endpoint. This is the default
production target — balances performance with memory safety.

## Why Go

- `golang.org/x/crypto/ssh` is the de-facto SSH client/server library;
  Teleport's agentless-OpenSSH integration is a working reference for
  the inner SSH leg.
- `crypto/tls` provides mature, well-audited TLS 1.3 with client-cert
  support; mTLS plumbing is one struct.
- Memory-safe, single static binary, easy cross-compile (amd64/arm64).
- Standard library covers everything else needed.

## Layout (planned, see [detailed-wrapper.md § 2.2](../../design/ssh-rt-auth-detailed-wrapper.md))

```
wrapper/go/
├── go.mod
├── cmd/
│   ├── ssh-rt-wrapperd/           # the daemon
│   └── ssh-rt-wrapper-admin/      # init / lint / rotate-ca
└── internal/
    ├── config/                    # YAML + render hermetic sshd_config
    ├── ca/                        # mTLS client to the CA
    ├── userca/                    # local user-CA key custody + cert minting
    ├── policy/                    # X.509 → OpenSSH critical-option translation
    ├── inner/                     # inner sshd lifecycle
    ├── proxy/                     # byte-shuffler; channel parser
    ├── audit/                     # connection log
    └── listener/                  # outer mTLS listener
```

The Python and Go variants are deliberately structurally parallel.

## When to start this

Only after `wrapper/python/` is functionally complete and has passed
the LXC integration test suite. The Python PoC defines the
behavior contract; the Go port faithfully reproduces it.
