# wrapper/alpine — minimal C variant for constrained Alpine deployments

**Status:** Not yet implemented. Last phase, after `wrapper/go/` ships.

A minimal C implementation of the wrap-and-proxy Tier 1 endpoint, built
on either **Mbed TLS** or **wolfSSL**, targeted at constrained
Alpine-only deployments where Go's runtime is unwanted.

## Why this exists

Originally we planned a greenfield C+Mbed TLS SSH server as a fallback
to the wrap-and-proxy approach (see
[wrapper-research.md](../../design/ssh-rt-auth-wrapper-research.md)).
That fallback was dropped once we settled on wrap-and-proxy: there's
no need to own the SSH protocol in C.

But "wrap-and-proxy, with the wrapper itself written in minimal C"
is a different proposition entirely. The wrapper is small (~2–5 kLOC
in Go); a faithful C port is in the 3–6 kLOC range. The SSH protocol
implementation stays in unmodified OpenSSH (the inner sshd). All the
CVE-burden arguments that motivated wrap-and-proxy still apply here.

## Scope

- mTLS termination via Mbed TLS or wolfSSL.
- HTTP client for the CA call (one of the two TLS libs again; or a
  minimal hand-rolled HTTP/1.1 over the existing TLS connection).
- OpenSSH user cert minting — write an Ed25519 OpenSSH cert blob in
  plain C. The OpenSSH cert format is well-documented; ~200 LOC.
- Inner sshd lifecycle via fork/exec + signal handling.
- Byte-proxy (Variant A) initially; Variant B channel parsing
  optional.

## When to start this

Only if there's a real demand from a constrained-deployment customer.
Wait until `wrapper/go/` is in production and has been operating in
the field for at least one release cycle. The C variant is a footgun
unless we know exactly what we're optimizing for.

## Choice of TLS library

To be decided. Both Mbed TLS and wolfSSL ship on Alpine; both are
embedded-friendly. wolfSSL has stronger commercial support; Mbed TLS
has broader adoption in the open-source embedded world. Defer the
choice until implementation starts.
