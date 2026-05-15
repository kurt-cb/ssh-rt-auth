# Wrap-and-proxy vs greenfield server: research and recommendation

**Status:** Decision proposal, 2026-05-14. Pending final approval.

**Decides:** Whether ssh-rt-auth's production endpoint (currently
"reference C/Mbed TLS server" in
[ssh-rt-auth-server-strategy.md](ssh-rt-auth-server-strategy.md)) should
be built greenfield or implemented as an mTLS wrapper around unmodified
OpenSSH.

**Recommendation:** Adopt **wrap-and-proxy** as Tier 1. Greenfield
server fully dropped. (Revised 2026-05-14 after the decision to also
ship a `wrapper/alpine/` minimal C variant, which covers the
constrained-deployment use case that originally motivated the
greenfield fallback.)

---

## 1. Summary

The wrap-and-proxy architecture — an mTLS-terminating wrapper that
proxies authenticated sessions to a hermetic localhost-bound OpenSSH
instance — is the right home for ssh-rt-auth's production endpoint.
Three findings drive this:

1. **CVE burden is severe for anyone who owns SSH protocol code**, in
   both memory-unsafe (C) and memory-safe (Go, Rust) implementations.
   The industry consensus, based on five major bastion products
   surveyed, is to wrap rather than reimplement.
2. **OpenSSH configuration is a known operator hazard.** A hermetic
   inner sshd — owned by the wrapper, never edited by operators —
   *hides* the messy 120-directive `sshd_config` surface behind a
   small, opinionated wrapper config. This is a stronger position
   than greenfield, which would force us to design that surface from
   scratch.
3. **Engineering scope drops from "20k+ LOC greenfield server with
   perpetual CVE pager" to "2–5 kLOC of glue."** OpenSSH does the SSH
   protocol; we do mTLS, authorization, cert handoff, and (optionally)
   a thin channel-layer policy filter.

---

## 2. Prior art

Survey of five established bastion / SSH-zero-trust products:

| Product            | Server side                            | Wire protocol                       | Owns SSH protocol code? | CVE-burden evidence |
|--------------------|----------------------------------------|--------------------------------------|--------------------------|---------------------|
| **Teleport**       | Go reimplementation (`x/crypto/ssh`) + agentless OpenSSH mode | TLS-wrapped SSH, ALPN routed on 443 | Yes (own + upstream)     | **CVE-2025-49825** (CVSS 9.8 auth bypass in their own cert validation, June 2025); plus inherits `x/crypto/ssh` CVEs (CVE-2024-45337, CVE-2025-22869, CVE-2025-58181) |
| **Smallstep**      | Unmodified OpenSSH, `TrustedUserCAKeys` pinning step-ca's pubkey | Standard SSH; no proxy | No (cert minter only)    | No SSH protocol exposure                          |
| **Tailscale SSH**  | Greenfield Go server (`tailssh/`, vendored fork of `gliderlabs/ssh`) inside `tailscaled` | SSH "none" auth inside WireGuard tunnel | Yes (own + upstream) | Inherits x/crypto SSH CVEs                                       |
| **Boundary**       | Unmodified sshd; netcat-in-ProxyCommand from client; mTLS leg to worker | mTLS tunnel; SSH on inside | No (proxy only)        | No SSH protocol exposure                          |
| **BastionZero**    | Agent on target; MrZAP proto over WebSocket/TLS | SSH-over-WebSocket-over-TLS, custom auth | Partial (custom auth proto) | Custom proto = own bug surface                                |

**Pattern A — wrap-and-defer (Smallstep, Boundary, Teleport's agentless mode):** Issue
short-lived OpenSSH certs and let unmodified sshd do the work. Minimal LOC, no
SSH-protocol CVE burden. Limited to what OpenSSH cert critical-options express.

**Pattern B — greenfield (Teleport agent, Tailscale, sshpiper, Warpgate):** Own the SSH protocol in Go/Rust. Full control over the auth/policy model. Carries inherited *plus* original CVE burden.

**Nobody re-implements SSH in a memory-unsafe language.** All modern entrants are
Go or Rust. A C+Mbed TLS implementation would be unique in this space, and
historically custom C SSH implementations (Dropbear, libssh) ship CVEs at a
higher rate than OpenSSH itself.

Source citations are inline in the research-agent transcript that produced this
section.

---

## 3. CVE-burden reality check

The reason "Go is memory-safe so reimplementation is fine" doesn't hold up:

- **Teleport CVE-2025-49825 (CVSS 9.8).** Remote auth bypass in
  Teleport's own SSH cert-handling code. Nested `ssh.Certificate`
  unwrap + `KeyId`-as-RBAC-username trust bug. 100% Teleport code, not
  upstream. Patched June 2025.
- **CVE-2024-45337** in `golang.org/x/crypto/ssh`: PublicKeyCallback
  misuse → auth bypass. Affected every Go SSH server.
- **CVE-2025-22869** in `x/crypto/ssh`: server-side DoS via slow KEX.
- **CVE-2025-58181** in `x/crypto/ssh`: GSSAPI memory exhaustion.

By contrast OpenSSH ships ~6 advisories per year through a mature,
focused response process. Wrapping it lets that response process
remain upstream's responsibility.

**The takeaway:** building *or even embedding* an SSH protocol
implementation makes you responsible for that surface. Even a
well-funded Go-based vendor with a security team shipped a critical
auth bypass in 2025.

---

## 4. Proposed architecture

```
                              ┌─────────────────────────────────┐
                              │   ssh-rt-auth host              │
mssh client ──mTLS (TLS 1.3)──┼─►  ssh-rt-wrapper (~2–5 kLOC)   │
   (presents user cert        │      │                          │
   or pubkey ceremony)        │      │  (1) authorize via CA    │
                              │      │      over mTLS           │
                              │      │  (2) mint 30s OpenSSH    │
                              │      │      user-cert (local    │
                              │      │      user-CA, in mem)    │
                              │      │  (3) proxy bytes (raw    │
                              │      │      or channel-aware)   │
                              │      ▼                          │
                              │  inner sshd  ──── localhost only│
                              │   (hermetic config, our owned)  │
                              │   (TrustedUserCAKeys = local CA)│
                              └─────────────────────────────────┘
```

### 4.1 Components

- **Wrapper.** Long-lived daemon. Owns:
  - mTLS listener (port 22 by default; protocol-detected dual-mode optional, per [strategy.md § 6.1](ssh-rt-auth-server-strategy.md))
  - Outbound mTLS to the CA (re-using the existing shim machinery)
  - Local user-CA key (in-memory; loaded from disk at startup, never re-read)
  - Inner sshd process lifecycle (systemd unit)
  - Per-connection cert minting (30s validity, principals from the CA's
    response, critical-options derived from the X.509 cert's extensions)
  - Optional: channel-layer policy filter (see § 6)

- **Inner sshd.** Vanilla unmodified OpenSSH, bound to 127.0.0.1 on a
  wrapper-allocated port. Trusts only the local user-CA. **No other auth
  paths are accepted.** Configuration is hermetic (§ 5).

- **Local user-CA.** A separate OpenSSH user CA key per host, generated
  on first install. The wrapper holds the private key (in memory only;
  not on disk after load). The public key is in the inner sshd's
  `TrustedUserCAKeys`.

### 4.2 Per-connection flow

1. Client opens TLS to wrapper:443 (or :22), presents user cert in mTLS.
2. Wrapper extracts user identity + connection context.
3. Wrapper calls CA via existing shim path (reusing all current PoC code).
4. CA returns X.509 authz cert with extensions (channel-policy, force-command, etc.) or deny.
5. Wrapper translates X.509 extensions → OpenSSH cert critical-options:
   - `sshrtauth-force-command` → cert's `force-command` critical option
   - `sshrtauth-source-bind` → `source-address` critical option
   - `sshrtauth-environment` → `permit-environment` extension + sshd_config restrictions
   - `sshrtauth-channel-policy` → enforced *at the wrapper* (cert can't express it)
   - `sshrtauth-max-session` → enforced by wrapper-side timer
   - cert `notAfter` → cert's `valid_before`
6. Wrapper signs the OpenSSH user cert (30s validity) for the principal.
7. Wrapper opens a localhost SSH session to inner sshd, presenting the cert.
8. Inner sshd validates against `TrustedUserCAKeys`, accepts, spawns the shell.
9. Wrapper pipes bytes between client (TLS) and inner sshd (SSH), optionally
   parsing channel-open frames if Variant B (§ 6).

### 4.3 Cert handoff is well-established

Teleport's agentless-OpenSSH mode and Smallstep both use exactly this pattern in
production. Documented playbooks exist for the `TrustedUserCAKeys` + short-lived
cert flow. **The handoff is not novel work** — only the wrapper's pre-handoff
authorization (calling our CA, translating extensions) is.

---

## 5. Hermetic inner sshd configuration

**The single biggest concern raised against wrap-and-proxy is that we're
inheriting OpenSSH's notoriously messy config surface.** This section
addresses it head-on.

### 5.1 The problem

`sshd_config` has ~120 directives, complex `Match` precedence,
non-obvious value semantics (`PermitRootLogin prohibit-password` vs
`forced-commands-only` vs `without-password`), distro-divergent defaults
(Ubuntu / RHEL / Alpine ship different files), an `Include` mechanism
that pulls in `/etc/ssh/sshd_config.d/*.conf` (which various distro
packages populate without operator knowledge), and three overlapping
auth-method directives. CIS / NIST / DISA STIG hardening guides run to
dozens of pages each. Audits regularly find production hosts violating
them.

If we say "wrap unmodified OpenSSH" without addressing this, we've
imported the operator's existing problem.

### 5.2 Resolution: wrapper owns inner sshd config; operator never sees it

The wrapper treats the inner sshd as a **hermetic artifact** that the
operator does not configure directly. Concretely:

**a. Wrapper ships an embedded, opinionated `sshd_config` template:**

```
ListenAddress 127.0.0.1
Port <wrapper-allocated>
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
AllowStreamLocalForwarding no
GatewayPorts no
UsePAM no
TrustedUserCAKeys /var/lib/ssh-rt-auth/wrapper-user-ca.pub
AuthorizedKeysFile /dev/null
AuthorizedKeysCommand none
KexAlgorithms sntrup761x25519-sha512,curve25519-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com
LogLevel VERBOSE
```

Explicitly **no** `Include` directives, **no** `Match` blocks (the
wrapper does any per-connection dispatch, not sshd), **no**
`/etc/ssh/sshd_config.d/`-style fragment merging.

**b. Wrapper owns the sshd process lifecycle.** Its own systemd unit
(`ssh-rt-auth-inner-sshd.service`), its own runtime dir
(`/var/lib/ssh-rt-auth/inner-sshd/`), its own host keys. The operator's
*system* sshd (if present) is untouched, unrelated, and on a different
port.

**c. Wrapper exposes a small operator-facing config.** A YAML file with
maybe a dozen knobs: which external addresses to listen on, which Unix
users are allowed, log destinations, optional SFTP enablement, allowed
crypto suites (with sane defaults). The wrapper *derives* the inner
sshd config from this. Operators do not edit `sshd_config` directly.

**d. Startup integrity check.** The wrapper computes a hash of the
rendered inner `sshd_config` and compares against an embedded known-good
hash bound to the OpenSSH version it's running against. Mismatch =
refuse to start, log loudly. Catches: accidental drift, package-update
surprises, anyone editing the file by hand, supply-chain tampering.

**e. `ssh-rt-admin lint` command.** Validates: inner sshd_config matches
expected hash; no rogue `sshd_config.d/` fragments; no other sshd
listening on a conflicting port; the local user-CA pubkey is correctly
installed and writeable only by root. Optionally audits the *operator's
legacy sshd* (if running) and emits advisory warnings on common
misconfigurations.

### 5.3 Why this strengthens the wrap-and-proxy case

The pattern mirrors how Kubernetes manages kubelet (operators write a
Kubelet ConfigMap; kubelet reads it; operators don't tweak kubelet
flags directly) and how systemd-resolved manages `/etc/resolv.conf`
(owned, regenerated). It hides a messy underlying configuration behind
a small, opinionated, auditable surface.

Versus the alternatives:

- **Greenfield server:** we design our own config surface from scratch
  *and* we own all SSH protocol bugs. We'd have to design a config
  surface anyway. We're paying twice.
- **Wrap-and-proxy with hermetic inner sshd:** we design the
  *operator-facing* config surface from scratch (small, tight), and we
  get OpenSSH's protocol implementation for free. The inner sshd config
  is our *implementation detail*, not an operator artifact.

So the "OpenSSH config is a mess" concern actually **flips** in
wrap-and-proxy's favor. Greenfield doesn't hide the config-design
problem; it forces us to solve it without the benefit of OpenSSH's
proven protocol stack.

### 5.4 Risks worth naming

- **Distro package updates** can drop files into
  `/etc/ssh/sshd_config.d/`. Mitigated by isolating the inner sshd
  config dir entirely; it doesn't share state with system sshd.
- **Operators wanting customization** (SFTP enabled, X11 for a specific
  role, etc.) need an extension mechanism. The wrapper exposes a narrow
  whitelist of safe toggles via the operator YAML; everything else
  requires editing the wrapper's source.
  - **Phase 2 candidate:** if this whitelist proves too constraining,
    consider per-connection ephemeral sshd ([phase2-ideas.md § 1](ssh-rt-auth-phase2-ideas.md))
    so that the authorization cert's policy extensions render
    directly into a per-session sshd_config. Removes the need for a
    static whitelist entirely; sshd does native enforcement of
    whatever the cert says.
- **OpenSSH version drift** — new directives appear, defaults change.
  Mitigated by version-pinning the OpenSSH binary used as the inner
  sshd, regenerating the config template per supported version, and
  validating the hash at startup.
- **The operator's *other* sshd** (legacy, port 22, ops-managed) is
  still as messy as it was. We can't fix that; we can lint it and emit
  warnings.

---

## 6. Channel-policy enforcement: variant A vs B

Two implementation choices for `sshrtauth-channel-policy` enforcement:

### Variant A — pure proxy, no SSH parsing

Wrapper terminates outer mTLS, mints inner cert, opens inner SSH session,
pipes bytes. Force-command, source-address, environment, max-session
are enforced via cert critical-options (OpenSSH does the enforcement
natively). Channel-policy is **not** enforced — clients can open any
channel type the inner sshd allows (the hermetic config disables
agent / tcp / X11 / tunnel / stream-local forwarding at the sshd level,
so the only thing left is `session`; arguably sufficient).

- **LOC budget:** ~2 kLOC total.
- **Coverage gap:** can't express "allow `session` but not `direct-tcpip`"
  per-policy beyond the static hermetic-config defaults.
- **For the PoC: probably sufficient.** The hermetic config already
  bans the dangerous channel types globally.

### Variant B — channel-aware proxy

Wrapper parses SSH `SSH_MSG_CHANNEL_OPEN` / `SSH_MSG_CHANNEL_REQUEST`
frames as they pass through, enforces channel-policy from the X.509
cert per-connection. Rejects unwanted opens with
`SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`. Everything else is unchanged.

- **LOC budget:** ~2 kLOC (Variant A) + ~500 LOC for the channel parser. Still 2–3 kLOC total.
- **Coverage:** full per-policy channel-policy enforcement.
- **Risk:** parsing SSH wire format = we own a small slice of SSH protocol
  code. Restricted to channel-open and channel-request frames; substantially
  less surface than a full SSH server, but non-zero.

### Recommendation

Start with **Variant A.** Validates the architecture and ships the PoC
faster. Add Variant B once we have at least one customer asking for
fine-grained per-channel policy that the hermetic-config defaults can't
provide. The wrapper's design should leave room for the channel parser
to be added without disrupting the proxy core.

---

## 7. Coexistence with the operator's legacy sshd

Most production hosts already run a system sshd on port 22. Two options:

1. **Wrapper takes port 22; legacy sshd moves to a different port.** Clean
   for new deployments. Disruptive for retrofits. Requires an admin
   change to existing hosts.
2. **Wrapper takes a separate port (e.g., 2200) initially.** Operators
   migrate clients to the new port. Legacy sshd remains untouched on
   :22 for backward compatibility. **Recommended default** — gradual
   adoption story.
3. **Future: dual-mode listener on :22** (strategy.md § 6.1). Wrapper
   sniffs the opening bytes; if the client speaks our mTLS-wrapped
   protocol, handle natively; if it speaks raw SSH, transparently
   forward to the legacy sshd. Single port, both protocols. Captured
   as future work; not v1.

Regardless of which option is chosen, the inner sshd is *never* on a
public port and is *never* what the operator's existing sshd is. The
inner sshd is implementation detail.

---

## 8. Trade-offs: wrap-and-proxy vs greenfield

| Dimension                              | Greenfield C+Mbed TLS server | Wrap-and-proxy + hermetic inner sshd |
|----------------------------------------|------------------------------|--------------------------------------|
| LOC scope (new code)                   | ~10–20 kLOC                  | ~2–5 kLOC                            |
| SSH protocol CVE response burden       | Ours forever                  | Upstream's (`apt-get upgrade`)       |
| sshd_config surface exposed to operators | We design from scratch     | Hidden behind small wrapper YAML     |
| sftp / scp / X11 / agent forwarding feature parity | Reimplementation gaps | Inherited from OpenSSH (free, but disabled by default in hermetic config) |
| Force-command / source-bind / env enforcement | Native                | Native (via OpenSSH cert critical-options) |
| Channel-policy enforcement             | Native                       | Variant B: parse channel-open frames at the wrapper |
| Cert mid-session refresh / termination | Native                       | Wrapper holds the TCP socket; drop it = session ends |
| v2 session-binding to outer transport  | SSH H                        | Outer mTLS session ID (different binding, equivalent strength) |
| Audit story                            | "trust our new SSH server"  | "trust mTLS + OpenSSH (auditor already trusts both)" |
| Memory safety of the SSH protocol code | We write C against Mbed TLS — historically poor track record for custom C SSH | OpenSSH (mature C, well-audited, focused security response) |
| Industry precedent                     | None (no major bastion is a custom C SSH server) | Strong — Smallstep, Boundary, Teleport-agentless |

Greenfield wins on one axis only: theoretical ceiling on what we could
build if engineering time were unbounded. Wrap-and-proxy wins on every
other axis that matters in practice.

---

## 9. Recommendation

**Adopt wrap-and-proxy as Tier 1.** Greenfield server fully dropped.

Updated [strategy.md](ssh-rt-auth-server-strategy.md) tier model:

| Tier | Target                                                       | Status                                                     |
|------|--------------------------------------------------------------|------------------------------------------------------------|
| 1    | ssh-rt-auth wrapper + hermetic inner sshd, three variants in `wrapper/`: `python/` (PoC) → `go/` (production) → `alpine/` (minimal C, Alpine-only) | **Primary production target.** |
| 2    | Library-based SSH server integrations (AsyncSSH shipped; Go, libssh, MINA, Russh planned v2+) | **Still supported.** |
| 3    | OpenSSH compatibility mode (AKC + patches 0002 / 0003)       | **Still supported**, for orgs that can't deploy the wrapper. (0002b dropped post-decision — subsumed by wrapper.) |

The `wrapper/alpine/` C variant covers the constrained-deployment use
case that originally motivated holding a greenfield-server fallback.
Greenfield is no longer reserved.

The currently active OpenSSH patches (0002 and 0003) remain valuable
because they harden Tier 3, which serves orgs that can't run the
wrapper.

---

## 10. What this changes in existing docs

- [ssh-rt-auth-server-strategy.md](ssh-rt-auth-server-strategy.md): tier
  table revised per § 9; "reference C/Mbed TLS server" demoted to
  fallback. Add forward-reference to this doc.
- [CLAUDE.md](../CLAUDE.md): "final implementation: C with Mbed TLS" is
  no longer the production target. Update to reflect wrap-and-proxy as
  the production endpoint.
- [ssh-rt-auth-v2-enhancements.md](ssh-rt-auth-v2-enhancements.md): § 4
  reserved OIDs are now consumed by the **wrapper** (which translates
  them into OpenSSH cert critical-options) and by Tier 2 integrations.
  v2 features like session-binding bind to the *outer mTLS session*,
  not SSH H.

---

## 11. Open questions / next research

These don't block the decision but should be settled before
implementation starts:

1. **Wrapper language.** Go (huge std lib, mature crypto, easy mTLS,
   easy SSH client via `x/crypto/ssh` for the inner leg) vs Rust
   (memory safety, smaller runtime, harder integration story) vs Python
   (PoC reuses existing shim code instantly, slower, larger runtime).
   Strongly prefer **Go** — Teleport's agentless-mode code is a working
   reference, and `x/crypto/ssh` is exactly what we need for the inner
   leg.
2. **Inner SSH transport security.** Double-encryption (TLS-wrapped
   SSH-wrapped payload). Is `Ciphers none` on the inner SSH acceptable,
   given the outer mTLS already provides confidentiality? OpenSSH
   supports it but flags it heavily. Decision affects performance for
   high-throughput SCP/SFTP workloads.
3. **OpenSSH version pinning policy.** Use distro package, bundle our
   own build, or both? Hash-validation of inner config requires we
   know exactly which OpenSSH version we're targeting.
4. **Cert handoff key custody.** The local user-CA private key lives in
   wrapper memory. How is it provisioned initially? Generated on
   `ssh-rt-admin init` per host? Rotated how? Backed up how (if at
   all)?
5. **mTLS-tunneled SSH wire protocol.** The outer connection from
   client to wrapper: do we use raw SSH-over-TLS (run an SSH session
   directly inside the TLS tunnel — same as Teleport), or define a
   slim RPC wrapping (SSH frames as JSON, simpler to debug, novel)?
   Probably raw SSH-in-TLS for compatibility — clients can use any SSH
   client with a TLS-wrapping ProxyCommand.

---

## 12. Cross-references

- Industry research summary (5 products): captured in the conversation
  transcript that produced § 2; URLs cited inline by the research agent.
- Strategy doc (predecessor to this one): [ssh-rt-auth-server-strategy.md](ssh-rt-auth-server-strategy.md)
- v2 enhancements: [ssh-rt-auth-v2-enhancements.md](ssh-rt-auth-v2-enhancements.md)
- OpenSSH patch series (Tier 3 only): [../../ssh-rt-auth-openssh/NOTES.md](../../ssh-rt-auth-openssh/NOTES.md)
- Project overview: [ssh-rt-auth-doc-00-overview.md](ssh-rt-auth-doc-00-overview.md)
