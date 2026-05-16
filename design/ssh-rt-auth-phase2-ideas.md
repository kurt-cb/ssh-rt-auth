# ssh-rt-auth — Phase 2+ ideas

**Status:** Capture-only. Not on the Phase 1 critical path.

This doc collects design ideas surfaced during Phase 1 that are
deferred to later phases. Each entry has a rough sense of scope and
risk; none are committed work yet. They get promoted to formal design
docs (`design/ssh-rt-auth-detailed-*.md`) when a decision is made to
build them.

---

## 1. Per-connection ephemeral inner sshd

**Status:** Worth pursuing in Phase 2. Genuinely cleaner architecture.

### Idea

Today the wrapper runs **one** long-lived inner sshd whose config is
hermetic and identical for every session. Policy that OpenSSH config
could natively express (force-command, environment, channel-allow,
etc.) is either disabled globally in the hermetic config or
re-enforced by the wrapper at the application layer.

Per-connection sshd inverts this: spawn a **fresh sshd-on-pipes per
session**, with a config rendered from the CA's authorization cert.
Each cert extension becomes a directive in that session's sshd_config.

```
Outer mTLS accept
  │
  ├── CA call → authz cert with policy extensions
  ├── Mint inner OpenSSH user cert (unchanged)
  ├── Render per-session sshd_config from the cert's policy:
  │     sshrtauth-force-command       → ForceCommand
  │     sshrtauth-environment         → SetEnv (multiple)
  │     sshrtauth-channel-policy      → AllowTcpForwarding / X11Forwarding / etc.
  │     sshrtauth-max-session         → ClientAliveCountMax + ClientAliveInterval
  │   …plus the hermetic-config bones (crypto floor, no PAM, etc.)
  ├── Open pipe pair (or socketpair)
  ├── Spawn  sshd -i -f /tmp/session-XXX.conf  with pipes as stdin/stdout
  └── Proxy bytes between outer TLS and the pipe
       Connection close → sshd exits.
```

OpenSSH's `-i` (inetd) mode is the key: sshd handles a single
connection on stdin/stdout and exits. No port allocation, no listener
thread, no monitor process for us to manage.

### Wins

- **Native enforcement of every policy extension OpenSSH can express.**
  `sshrt.msshd.policy.translate_to_inner_cert_kwargs()` shrinks to
  one line (or disappears). The "what does the wrapper enforce vs
  what does OpenSSH enforce" boundary moves entirely into OpenSSH.
- **Per-session resource isolation.** A bug in one ForceCommand, a
  buggy sftp-server, a leaked file descriptor — none of it affects
  other sessions.
- **No port management.** Pipe pair instead of `49152-65535`.
- **Mental model is clean.** "sshd is the session-implementation
  engine the wrapper hands a config and a connection to."

### Cons / open questions

| Concern | Estimate | Mitigation                               |
|---|---|---|
| Memory per session | ~5–7 MB (sshd + sshd-session) | Fine for servers, costly for embedded. Document the cap as ops guidance; expose a `max_concurrent_sessions` limit. |
| Startup latency | ~50–100 ms | Imperceptible for interactive shells; could matter for burst exec / sftp-of-many-small-files workloads. Acceptable for v1 of the change. |
| Process tracking | Medium | `asyncio.create_subprocess_exec` + a registry of children + reap-on-exit. ~50 LOC. |
| `/run/sshd` & host keys | Shared across all instances | No change needed beyond what we already do. |
| Config file lifecycle | Tempfile per session | Render, spawn, unlink after sshd's open. ~10 LOC. |
| Per-version sshd_config validity | Same as today — hermetic template must work for the running OpenSSH version | Per-version hash table in [detailed-wrapper.md §5.3](ssh-rt-auth-detailed-wrapper.md) becomes "validate the TEMPLATE against an embedded known-good; the rendered output varies per-session and isn't hash-verifiable directly." |

### What this does NOT solve

- **CVE-response responsibility is unchanged.** Per-connection still
  uses the distro's sshd binary. The wrapper picks up CVE fixes
  faster (next *connection* rather than next wrapper *restart*), but
  it's still the distro's responsibility, not ours.
- **Version drift across the fleet** is the same as today — each
  wrapper host runs whatever sshd the distro installed.

### Migration plan when this gets built

1. Add `inner.mode: long-lived | per-connection` to `wrapper.yaml`.
   Default keeps the current model.
2. Phase 1 of the change: implement `per-connection` mode; existing
   `long-lived` keeps working. Test both side-by-side.
3. After at least one release cycle of stable `per-connection` use,
   default it on for new installs (existing installs keep the long-
   lived default until explicit migration).
4. Eventually deprecate `long-lived` mode? Possibly never — it has a
   legitimate place for high-frequency-connection workloads where
   the 50–100 ms startup is unacceptable.

### LOC estimate

~300 LOC in the wrapper: pipe handoff, per-session config renderer,
process registry, lifecycle hooks. Reuses everything we have today
for cert minting / outer protocol / CA call.

---

## 2. Smart-card (PIV / PKCS#11) support

**Status:** Probably trivial. Investigate in a focused half-day.

### Idea

Three roles where smart-card backing materially improves the security
story:

1. **CA admins.** The bootstrap-admin cert (and any subsequent
   superuser admins) are highest-value targets. Backing them with a
   YubiKey / PIV card eliminates exfiltration-by-file-system-access.
2. **Wrapper's mTLS-to-CA key.** Today the wrapper holds this on disk
   (mode 0600). A PIV card means a compromised wrapper host can use
   the key WHILE compromised but can't exfiltrate it to use later.
3. **mssh client.** The user's mTLS cert is the most lateral-
   movement-relevant key in the system. PIV-backing it raises the
   bar significantly with near-zero UX cost on modern OSes.

### Approach

- Python's `cryptography` library doesn't speak PKCS#11 directly.
  Use `python-pkcs11` (10kLOC mature lib) OR shell out to `openssl`
  with a PKCS#11 engine for cert ops. Either is well-understood.
- mssh: add `--pkcs11-uri` flag and use `ssl.SSLContext`'s engine
  support to load the private key from the card. Browser-style.
- Wrapper: same approach for its mTLS-to-CA leg.
- CA admin CLI: same approach for admin certs.

### Cons

- Operator complexity. A PIV card lost is a key lost.
- The wrapper as a daemon can't prompt for a PIN; the card must be
  pre-unlocked or use a slot configured for no-PIN-required.

### Out of scope

Storing the wrapper's **local user-CA** signing key on a card —
that key signs ~30s-lived OpenSSH user certs at high volume. PIV
signing throughput (~10-50 ops/sec on commodity cards) might
bottleneck at burst-login time. Worth measuring before committing.

---

## 3. Client / server split — **mostly done; common-protocol piece remains**

**Status:** Substantially superseded by the 2026-05-15 project reorg.
The top-level language directories (`python/`, `go/`, `c/`) replaced
the original `wrapper/<lang>/` shape. Each language tree now owns the
full client+server+CA implementation. The remaining piece is the
**shared protocol module** described below.

### What's done

The reorg established:

- `python/src/sshrt/msshd/` — wrapper server (Python).
- `python/src/sshrt/mssh.py` — wrapper client (Python).
- `python/src/sshrt/ca/`, `admin/`, `shim/` — supporting Python pieces.
- `go/` and `c/` skeleton directories with READMEs documenting the
  same layout per language.

Operators can already package and update client and server independently
within Python (the client is a single module, the server is a
sub-package). The client doesn't pull in server dependencies at
runtime because `mssh` doesn't import from `msshd/`.

### What still remains: a shared protocol module

The v1 outer-protocol frame format (JSON header + raw bytes) is
implemented twice today:

- `python/src/sshrt/mssh.py:build_header()` / `parse_ack()`
- `python/src/sshrt/msshd/ssh_proxy.py:_read_header_line()` / `_write_ack()`

These two implementations have to stay byte-for-byte compatible
forever. A drift-detection bug between them would silently break
authentication. Today the test suite catches it because both are
exercised end-to-end, but with more variants (Go client + Python
server, C client + Go server, etc.) the combinatorics get ugly.

**Proposed:** consolidate the frame definitions into a per-language
`common/` module:

```
python/src/sshrt/common/
├── __init__.py
└── protocol.py     # PROTOCOL_VERSION, build_header, parse_header,
                    # build_ack, parse_ack
```

Both `mssh.py` and `msshd/ssh_proxy.py` import from
`sshrt.common.protocol`. Drift becomes impossible because there's
one implementation.

Mirror for `go/` and `c/` when they exist:

- `go/internal/protocol/` — Go package, same frame format.
- `c/common/protocol.c` — C functions, same frame format.

Cross-language wire compatibility comes from **a single source of
truth in a spec doc** ([detailed-wrapper.md §3](ssh-rt-auth-detailed-wrapper.md))
plus per-language unit tests that round-trip canonical encodings.
Consider adding a `protocol/conformance.json` with golden vectors
that every language's tests must produce identical output for.

### LOC estimate

~half a day for Python (extract two ~30-LOC helpers into a shared
module, update two import sites, add a unit test). Negligible for
future language ports — they just import from their own
`common/protocol`.

### Why this isn't urgent

Today there are only two implementations (both Python) and they're
small. The drift risk is real but the cost is also real. Wait until
either (a) the Go port starts, or (b) the protocol gains a new
revision that has to land in both sides.

---

## 4. Wrapper supports protocols beyond SSH — HTTPS / TCP proxy

**Status:** Genuinely interesting; needs analysis.

### Idea

The wrapper's authentication path (mTLS client cert → CA call →
policy decision) is **protocol-agnostic**. Today it dispatches to an
inner SSH session, but it could just as easily dispatch to an inner
HTTP proxy, TCP forward, or anything else.

User-side experience: instead of `mssh alice@host -- whoami`, the
user opens a browser. The browser already speaks mTLS and already
stores the user's PIV-backed (or passkey-backed) cert. The wrapper
authenticates the browser session, calls the CA, gets a policy decision
for "access internal-tool.example.com", and proxies HTTPS to the
internal target.

Result: narrow-scoped, per-request-authorized access to internal
HTTPS services. No VPN tunnel ("everything I can route to from
this machine"), no broad SSH-based port forward — just "alice is
authorized to reach internal-tool today, from these IPs, in this
time window."

### Comparable products

- Cloudflare Access — same shape but cloud-hosted.
- Pomerium, Teleport's Application Access — open-source equivalents.
- BeyondCorp — Google's internal reference architecture.

We'd be cloning a pattern that has multiple production proofs of
concept. The differentiator: tight coupling with our existing
runtime-CA-mediated authorization model.

### Open design questions

- **Outer protocol.** Browsers don't speak our v1 JSON-framed thing
  — they speak HTTPS. The wrapper would need a separate listen path
  for HTTPS (port 443) where the outer protocol is HTTP/2, the
  client cert is presented in mTLS, and the wrapper's policy decision
  results in a proxied HTTP request to the inner target.
- **Per-request vs per-session authorization.** SSH gets a single
  authz at connection time. HTTP could authorize per-request (every
  call hits the CA) or per-session (one CA call, cached for N
  minutes). Per-request is more expensive but tighter; per-session
  matches the SSH model better.
- **Service discovery.** Where does "internal-tool.example.com" map
  to "the wrapper should proxy to https://10.0.0.42:8443"? Static
  config? Consul-style discovery? Out-of-scope-for-PoC.

### LOC estimate

Hard to say without design work. Likely 1-2k LOC for v1 — HTTPS
listener, request-level policy hooks, configurable backend routing,
session cookie handling.

---

## 5. The CA could mint certs for other applications (step-ca parallel)

**Status:** Architecturally trivial; worth doing once a real consumer asks.

### Idea

The CA already:
- Holds two signing keys (auth-signing for X.509 authz, mTLS-root for
  client-cert issuance).
- Has an enrollment DB with users / policies / RBAC.
- Has an audit log.
- Has an admin CLI.

This is **most of what step-ca offers** (https://smallstep.com/docs/step-ca/).
With modest additions it could mint:

- **TLS server certs for internal services.** "Issue a 30-day cert
  for grafana.internal.example.com" — same enrollment model, same
  policy DSL, same audit.
- **Code-signing certs.** Sign binaries with a cert traceable to a
  particular admin / build agent.
- **SSH user certs.** Today the CA mints X.509 authz certs for the
  shim/wrapper. It could also mint OpenSSH user certs directly,
  bypassing the wrapper for shops that just want better SSH
  certificate management.
- **mTLS certs for service-to-service.** Each microservice gets a
  cert from the CA; the CA's enrollment policy decides who's allowed
  to issue / renew.

### What we'd need to add

- New admin endpoints: `cert mint --type=tls-server`, `cert mint
  --type=code-sign`, etc.
- Per-cert-type policy DSL extensions (validity windows, allowed
  SANs, allowed signature algorithms).
- ACME endpoint compatibility (so existing ACME clients can use us).
  Optional but high adoption-value.

### LOC estimate

~1500 LOC. Mostly endpoint plumbing, since the core minting
machinery is already in [ca/cert_minter.py](../ca/cert_minter.py).

---

## 6. Require 2FA for high-privilege roles (with air-gap fallback)

**Status:** Design needed; implementation isn't trivial.

### Idea

Some roles should require a second factor beyond "the user holds the
mTLS cert." Examples:

- `superuser` admins on the CA.
- A `root-prod` role that grants production SSH as root.
- Anything with `force-command: /bin/db-shell` on the user's primary
  identity store.

Second-factor options:

- **TOTP** (Google Authenticator / Authy / 1Password / etc.). Cheap,
  ubiquitous, works offline.
- **Push to phone** (Duo / Okta Verify / etc.). Better UX, requires
  internet on the user side.
- **Hardware key tap** (YubiKey, FIDO2). Highest assurance.
- **WebAuthn / passkey** challenge from the wrapper or mssh. Modern.

### The air-gap angle

> "eliminate if auth was air-gapped" — the user

If the CA is reachable only from a private network, **and** the
attacker's path also requires reaching the CA, then the 2FA layer's
value drops: the attacker who can't reach the CA can't drive
authorization anyway. In an air-gapped deployment, 2FA mostly defends
against insider-with-credentials, not external attackers.

That's a legitimate position for an air-gapped deployment to take.
The 2FA mechanism should be **policy-driven**, not hardcoded:
operator decides per-role whether to require it.

### Mechanism sketch

CA-side policy DSL gains:

```yaml
- name: root-admin
  servers: ['*']
  channels: ['session']
  require_2fa: totp     # totp | push | hardware | webauthn | none
  2fa_within_seconds: 60   # how recently the user authenticated 2FA
```

The wrapper's `POST /v1/authorize` request body grows a
`2fa_evidence` field (already on the cert-extension side at OID
`.1.7`, just not produced by clients today). mssh CLI grows a
`--totp` flag (or auto-prompts).

### Cons

- Adds runtime dependency on a TOTP / push / WebAuthn endpoint.
- Adds operator friction for what may be low-frequency operations
  anyway — diminishing returns.
- Doesn't help the air-gapped case (per above).

### LOC estimate

~500 LOC for TOTP only (which is the easiest factor). WebAuthn adds
significantly more (browser-style challenge protocol).

---

## 7. Passkey / WebAuthn support

**Status:** Investigate. Likely complements (2) and (5) rather than
standing alone.

### Idea

Passkeys are the WebAuthn-based credential format that browsers and
OS keychains now natively support. Where smart cards (item 2)
require an extra piece of hardware, passkeys are zero-extra-hardware
for users on modern Mac / Windows / Android / iOS.

Two paths:

1. **Passkey-backed mssh client cert.** Same shape as PIV
   (item 2) — the mssh client's private key lives in the OS
   keychain, accessed via platform credential APIs. Lower friction
   than PIV cards.
2. **Passkey as the 2FA second factor.** The mssh client (or a
   helper website the CA hosts) presents a WebAuthn challenge; the
   user's passkey signs it; signature goes to the CA as
   `2fa_evidence`.

Path 2 is the more natural fit — passkeys are best understood as
"unlock the next step" rather than "be the long-lived identity."

### Cons

- WebAuthn protocol is browser-centric; CLI usage requires platform
  helpers (`secretive`, `pinentry`-style daemons, or shelling out to
  a browser).
- Server-side requires a WebAuthn library (Python: `webauthn` PyPI
  package).

### Composes with

- Item 2 (smart-card) as an alternate factor.
- Item 5 (2FA for high-privilege roles) as one of the supported
  mechanisms.
- Item 4 (HTTPS proxy in the wrapper) — browser passkey flows are
  natural when the wrapper is already speaking HTTPS to browsers.

---

## 8. Centralized client config — `~/.mssh/` replaces `~/.ssh/`

**Status:** Strong idea. Worth doing once the Tier 1 wrapper has
production users.

### Idea

Today an SSH-using laptop is a snowflake. `~/.ssh/config` accumulates
per-host stanzas, `~/.ssh/known_hosts` accumulates fingerprints,
`~/.ssh/authorized_keys` (on the server side) accumulates per-user
public keys, plus there's per-user / per-host config drift in
`/etc/ssh/`. Operators describe the result as "a maintenance
nightmare of separate client and server configs spread over the
network."

The CA already knows:
- Which servers exist (`server add`).
- Which users are enrolled (`user add`).
- Which (user, server) pairs are allowed by policy.
- The wrapper's server cert and the user-mTLS root.

So the CA can **mint a per-user client config** that mssh consumes:

```
~/.mssh/
├── cert.pem                  # user's mTLS cert (PIV-backed in v2)
├── key.pem                   # user's mTLS key (or PIV slot URI)
├── ca.pem                    # trust root for wrapper server certs
├── config                    # CA-rendered: alias → wrapper-host:port
└── known-wrappers            # CA-rendered: list of allowed wrapper hosts
```

`~/.mssh/config` is generated server-side and pulled by `mssh --sync`
(or auto-refreshed every login). It contains *only* the hosts the
user is currently authorized to reach. Operators don't maintain it
by hand; the CA's enrollment DB IS the config.

### Wins

- **One source of truth** for which servers a user can reach: the
  CA's enrollment DB. No drift between client config and server-side
  policy.
- **Removing a user from a policy auto-removes the host from their
  `mssh config`** on next sync. Today the user keeps the old
  `~/.ssh/config` entry forever; the SERVER denies them but the
  client doesn't know that until it tries.
- **No `known_hosts` mystery.** The wrapper's TLS server cert is
  signed by a CA the user already trusts. No "host key has changed"
  prompts ever again.
- **Restricts client behaviour.** `~/.mssh/` has only what mssh
  needs — no agents, no socks proxies, no random key files getting
  loaded by accident. Smaller surface than `~/.ssh/`.

### Incremental migration story

```
Day 1:  Install mssh alongside ssh. Tell users:
        "for the new bastions, use mssh instead of ssh."

Day 7:  Each user has done a few mssh sessions; they verify access
        works as expected.

Day 30: Operator pushes a config that disables ssh access on the
        wrapper hosts. mssh keeps working.

Day 31: User notices ssh no longer works; rm -rf ~/.ssh/.
        That stuff was bit-rotting anyway.
```

The point: **existing SSH stays operational the entire time.** No
flag day. mssh runs side-by-side until the user is comfortable.

This aligns with [scripts/upgrade.sh](../scripts/upgrade.sh)'s
server-side phased upgrade — both ends do incremental, verify-as-you-go
migration.

### Open questions

- **Sync mechanism.** Push (`mssh --sync` against the CA's admin
  API)? Pull (CA exposes a per-user-cert-authenticated endpoint)?
  Probably pull, scoped to the user's own cert.
- **Where does sync happen.** First connection of the day? Every
  connection? On a schedule? Probably first-of-day or explicit
  `mssh --sync`.
- **What about non-CA-enrolled servers?** If a user wants to mssh
  to a host that isn't in the CA's enrollment (e.g., a brand-new
  test box), they need a way to bypass the CA-managed config.
  `--no-sync` + explicit host:port flag works as a v1 escape hatch.
- **Privacy.** The CA's enrollment DB now knows everywhere every
  user can reach. Was always true server-side; now also true on the
  client. Worth surfacing in the security analysis doc.

### LOC estimate

~200 LOC. New CA endpoint (`GET /v1/clients/<cert-fingerprint>/config`,
mTLS-authenticated with the user's own cert), `mssh --sync` flag,
renderer for the config file.

---

## 9. Incremental SSH→mssh migration story (operational doc)

**Status:** Documentation / operator-facing, not a code task.

### Idea

The technical pieces for incremental migration already exist:

- Server side: [scripts/upgrade.sh](../scripts/upgrade.sh)
  runs the wrapper in fallback mode alongside system sshd, then
  graduates to enforce mode, then cuts over port 22.
- Client side: item 8 above puts the new config in `~/.mssh/`
  without touching `~/.ssh/`. Users keep `ssh` working until they
  flip.

What's missing is a **single operator-facing runbook** that ties both
sides together:

```
Day 0:  Install wrapper on the server. wrapper.yaml = fallback mode.
        ssh keeps working as before.

Day 1:  Enrol the test user at the CA. Install mssh on the test
        user's laptop. Verify mssh access works.

Day 7:  Enrol more users. Flip wrapper to enforce mode for one role.
        ssh still works for non-enforced roles via fallback.

Day 30: All users have validated mssh access. Cut wrapper port to
        22. Stop system sshd. Notify users to retire ~/.ssh/.

Day 60: Validate; cleanup any holdouts.
```

### What this doc would contain

- Pre-flight checklist (CA running, wrapper installed, etc.).
- Per-user onboarding script: enroll, mint their mTLS cert, push
  `~/.mssh/` material, smoke-test their access.
- Per-server upgrade script (already exists as upgrade.sh).
- Per-role enforce-toggling: flip one role at a time, validate, move
  on. Roll back per-role if a problem surfaces.
- Final cleanup: stopping system sshd, advising users to rm
  `~/.ssh/`, retention policy on old SSH server logs.

### LOC estimate

Zero code, ~1500 lines of operator-facing markdown. Should live as
`docs/MIGRATION.md` (peer to `INSTALLATION.md`) when it's written.

---

## 10. Browser-based SSH terminal (xterm.js over HTTPS, mTLS-authenticated)

### Idea

Add an HTTPS entry point to `msshd` that serves a browser-side SSH
terminal (xterm.js + WebSocket). The browser authenticates with the
user's existing mssh X.509 client cert (presented as a TLS client cert
during the HTTPS handshake). Server-side, msshd treats the browser
session exactly like a regular `mssh` session: same CA call, same
ephemeral inner-sshd cert mint, same policy enforcement.

Net effect: a single internet-facing `msshd` becomes a **web-based
bastion** that can proxy-jump to any backend SSH server the user is
authorized to reach — no local SSH client install required, no
client-side mssh binary required. Just a browser and the user's mTLS
cert.

### Composition

  ```
  browser (with user mTLS cert in keystore)
      │ HTTPS + mTLS (cert authenticates the user)
      ▼
  msshd HTTPS listener  ─►  CA  ─►  inner sshd cert
      │
      ▼
  msshd opens an outbound SSH session to target host (proxy-jump)
      │
      ▼
  xterm.js  ◄── WebSocket stream ──── PTY in the target session
  ```

### Wins

  - Zero-install client: any browser becomes an SSH client.
  - The mTLS cert workflow already exists; the browser just presents
    the cert during the TLS handshake (same machinery used by
    enterprise SSO over client certs).
  - Single chokepoint for auditing, recording, and policy: the
    bastion sees every keystroke if you want it to.
  - Works from networks where outbound SSH (port 22) is blocked but
    HTTPS (443) is open.

### Cons / open questions

  - **Browser support for client mTLS certs is uneven** — works in
    most desktop browsers but is awkward on mobile, often needs
    OS-level keychain integration, and some browsers (Safari, mobile
    Chrome) handle cert prompts poorly. Real test: can a Firefox user
    on Ubuntu and a Safari user on iOS both authenticate cleanly?
  - **Cert distribution to the browser keystore** is the rough edge.
    The mssh CLI knows how to read PEM files; the browser needs the
    cert imported (PKCS#12 + passphrase). Tooling and docs would be
    needed.
  - **Recording / session replay** raises privacy + compliance
    questions distinct from regular SSH — every keystroke transits
    the bastion, where regular SSH end-to-end-encrypts past it.
  - **WebSocket framing** is straightforward but adds a new wire
    format alongside the existing JSON-frame outer protocol — two
    things to keep in sync.
  - **Proxy-jump target list** — does the browser UI list the user's
    allowed servers (queried from the CA via the bastion), or does
    the user type a hostname? CA-driven would be cleaner but couples
    the UI to the CA's enrollment view.

### Composes with

  - Item 4 (HTTPS / TCP proxy) — same HTTPS listener can host both
    the terminal UI and protocol-proxy targets.
  - Item 7 (WebAuthn / passkeys) — passkeys could replace mTLS for
    browser auth where cert handling is painful (e.g. mobile).
  - Item 8 (centralized `~/.mssh/` client config) — server-side
    inventory of allowed targets feeds the terminal UI's target picker.

### LOC estimate

  - HTTPS+WebSocket listener inside msshd: ~300 lines.
  - Browser-side xterm.js + WebSocket glue: ~500 lines JS.
  - PTY + outbound-SSH plumbing on the bastion: ~200 lines.
  - Cert-import docs + Firefox/Chrome/Safari verification: weeks of
    real testing, not LOC.

Total order-of-magnitude: ~1k lines of code + meaningful UX work,
plus the recording / compliance design conversation.

---

## How items relate

```
                    ┌────────────────────────────────────┐
                    │ 4. HTTPS / browser entry to wrapper │
                    └─────────────┬──────────────────────┘
                                  │
                  ┌───────────────┼─────────────────┐
                  ▼               ▼                 ▼
   ┌──────────────────┐ ┌──────────────────┐ ┌─────────────────┐
   │ 2. PIV/PKCS#11   │ │ 7. WebAuthn/     │ │ 5. CA mints     │
   │    smart cards   │ │    passkeys      │ │    other certs  │
   └────────┬─────────┘ └────────┬─────────┘ └─────────────────┘
            │                    │
            └────────┬───────────┘
                     ▼
         ┌─────────────────────────┐
         │ 6. 2FA for high-priv    │
         │    roles                │
         └─────────────────────────┘

   ┌──────────────────────┐   ┌──────────────────────┐
   │ 1. Per-connection    │   │ 3. Shared protocol   │
   │    ephemeral sshd    │   │    module (drift     │
   │  (Phase 2 priority)  │   │    prevention)       │
   └──────────────────────┘   └──────────────────────┘

   ┌──────────────────────┐   ┌──────────────────────┐
   │ 8. ~/.mssh/ replaces │   │ 9. Migration runbook │
   │    ~/.ssh/ (CA-       │──▶│   (operator-facing  │
   │    managed client    │   │    doc, ties both    │
   │    config)           │   │    ends together)    │
   └──────────────────────┘   └──────────────────────┘
```

Items 1 and 3 are **wrapper internal architecture** — independent of
each other, both worth doing in Phase 2.

Items 2, 5, 6, 7 are **identity / authentication enhancements** —
they compose; the right pattern is to design 2 + 7 + 6 together as
a coherent identity layer, not piecemeal.

Item 4 is a **scope expansion** — the wrapper becomes a multi-protocol
authorization proxy, not just an SSH gateway. Decide before it whether
that's the project's direction.

Item 10 (browser-based xterm.js terminal) is a **client-side
expansion** that builds on item 4's HTTPS listener: the bastion
serves a web SSH client to anyone with the right mTLS cert in their
browser. Composes naturally with item 7 (passkeys, where browser
cert handling is painful) and item 8 (centralized client config, to
feed the terminal UI's target picker).

---

## When this doc gets cleaned up

When an item is promoted to active work, move it to a dedicated design
doc (`design/ssh-rt-auth-detailed-<feature>.md`) and replace its
section here with a one-line "→ moved to <file>" pointer.
