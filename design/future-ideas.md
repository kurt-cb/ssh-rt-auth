# mssh — future ideas

**Status:** Capture-only. Not on any current critical path.

Design ideas considered but deferred. Each entry has a rough sense
of scope and risk; none are committed work yet. They get promoted
to formal design docs (or merged into existing ones) when a
decision is made to build them.

See [architecture.md](architecture.md) for what's implemented today;
see [api.md](api.md) for the API contract; see [security.md](security.md)
for the trust model. Items below extend or compose with those.

---

## 1. Per-connection ephemeral inner sshd

**Status:** Worth pursuing in Phase 2. Genuinely cleaner architecture.

### Idea

Today msshd runs **one** long-lived inner sshd whose config is
hermetic and identical for every session. Policy that OpenSSH config
could natively express (force-command, environment, channel-allow,
etc.) is either disabled globally in the hermetic config or
re-enforced by msshd at the application layer.

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
  one line (or disappears). The "what does msshd enforce vs
  what does OpenSSH enforce" boundary moves entirely into OpenSSH.
- **Per-session resource isolation.** A bug in one ForceCommand, a
  buggy sftp-server, a leaked file descriptor — none of it affects
  other sessions.
- **No port management.** Pipe pair instead of `49152-65535`.
- **Mental model is clean.** "sshd is the session-implementation
  engine msshd hands a config and a connection to."

### Cons / open questions

| Concern | Estimate | Mitigation                               |
|---|---|---|
| Memory per session | ~5–7 MB (sshd + sshd-session) | Fine for servers, costly for embedded. Document the cap as ops guidance; expose a `max_concurrent_sessions` limit. |
| Startup latency | ~50–100 ms | Imperceptible for interactive shells; could matter for burst exec / sftp-of-many-small-files workloads. Acceptable for v1 of the change. |
| Process tracking | Medium | `asyncio.create_subprocess_exec` + a registry of children + reap-on-exit. ~50 LOC. |
| `/run/sshd` & host keys | Shared across all instances | No change needed beyond what we already do. |
| Config file lifecycle | Tempfile per session | Render, spawn, unlink after sshd's open. ~10 LOC. |
| Per-version sshd_config validity | Same as today — hermetic template must work for the running OpenSSH version | Per-version hash table in [detailed-wrapper.md §5.3](architecture.md) becomes "validate the TEMPLATE against an embedded known-good; the rendered output varies per-session and isn't hash-verifiable directly." |

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

~300 LOC in msshd: pipe handoff, per-session config renderer,
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
2. **Wrapper's mTLS-to-CA key.** Today msshd holds this on disk
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

Storing msshd's **local user-CA** signing key on a card —
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
truth in a spec doc** ([detailed-wrapper.md §3](architecture.md))
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
  client cert is presented in mTLS, and msshd's policy decision
  results in a proxied HTTP request to the inner target.
- **Per-request vs per-session authorization.** SSH gets a single
  authz at connection time. HTTP could authorize per-request (every
  call hits the CA) or per-session (one CA call, cached for N
  minutes). Per-request is more expensive but tighter; per-session
  matches the SSH model better.
- **Service discovery.** Where does "internal-tool.example.com" map
  to "msshd should proxy to https://10.0.0.42:8443"? Static
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
  bypassing msshd for shops that just want better SSH
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
- **WebAuthn / passkey** challenge from msshd or mssh. Modern.

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
- Item 4 (HTTPS proxy in msshd) — browser passkey flows are
  natural when msshd is already speaking HTTPS to browsers.

---

## 8. Centralized client config — `~/.mssh/` replaces `~/.ssh/`

**Status:** Strong idea. Worth doing once the msshd has
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
  runs msshd in fallback mode alongside system sshd, then
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

## 11. In-situ `debug_sshd` swap-in for troubleshooting (sideband CA audit)

### Idea

Promote `debug_sshd` (the Python AsyncSSH server that already calls
the shim) from "debug-only utility" to **a hot-swappable inner SSH
server you can stand up next to the production sshd for in-situ
diagnosis**. An admin facing a "why is my mssh session failing on
this one server" mystery would:

1. SSH to the troubled server (break-glass path).
2. Run `msshd-admin enable-debug-sshd` — msshd starts spawning
   `debug_sshd` instead of the hermetic OpenSSH for new connections
   (existing connections unaffected).
3. Trigger the failing mssh from the client side.
4. Read structured debug output (per-stage shim call, cert validation,
   policy match) — either locally or streamed to the CA as a
   **sideband audit channel**.
5. `msshd-admin disable-debug-sshd` — back to production.

The sideband audit is the interesting part. `debug_sshd` already
parses the X.509 extensions inline (because it's a library-style
integration of the shim, not a delegating proxy). It can emit a
detailed per-event log alongside the regular CA audit, giving the
operator forensic-grade visibility into *exactly* what the inner
sshd saw and decided — without having to interpret strace or
sshd's terse DEBUG output.

### Composition with the adoption journey

  - In **fallback** mode, debug_sshd has no role (msshd is just a
    proxy).
  - In **gated** mode (§6.5.1 of wrapper detailed design),
    debug_sshd could be enabled as an alternative inner server
    that calls the shim, so the operator can see CA decisions
    even before flipping to enforce.
  - In **enforce** mode, debug_sshd replaces the hermetic OpenSSH
    on demand for troubleshooting. The hermetic config can't be
    instrumented at runtime; debug_sshd can.

### Wins

  - Single tool for "is the CA actually returning what I expect for
    this user?" without rebuilding/redeploying.
  - Sideband audit gives the CA visibility into per-decision detail
    that the production sshd path doesn't emit.
  - Re-uses code that already exists (debug_sshd has been kept
    explicitly for this kind of purpose).
  - Useful in the adhoc lab too: an operator running the tutorial
    can flip a knob and see CA decisions live.

### Cons / open questions

  - Hot-swap of the inner server while msshd is running implies
    msshd accepts a runtime config-change signal (graceful drain
    + restart the inner). That's a small-but-real piece of
    plumbing — not zero.
  - Sideband audit channel: ship logs to the CA over the existing
    mTLS connection, or open a separate one? Volume / format /
    retention questions.
  - Production deployments probably want this **gated by an admin
    role** at the CA — turning on debug_sshd on a sensitive host
    is itself an auditable action.
  - debug_sshd performance vs hermetic sshd: AsyncSSH is fine for
    debug, but you wouldn't want to leave it on as the steady-state
    inner server. Need a "this is temporary, expire after N hours"
    safety.

### LOC estimate

  - msshd: ~150 lines for inner-server swap + signal handling.
  - debug_sshd: ~200 lines for structured sideband-audit emitter.
  - CA: ~100 lines for receiving + storing the sideband stream
    alongside regular audit entries.

---

## 12. MCP interface to the CA — natural-language diagnostics + config

### Idea

Expose the CA over an [MCP](https://modelcontextprotocol.io)
(Model Context Protocol) server so that an AI assistant (Claude,
or any other MCP-compatible agent) can:

  - **Read-only diagnostics:** "why was alice denied last Tuesday?",
    "show me every policy that grants access to srv-acct",
    "what's the most-recently-rotated server cert", "summarize the
    audit log for the last hour" — answered in natural language by
    querying the CA's enrollment + audit data through MCP tools.
  - **Trusted-AI configuration:** with an admin-grade mTLS cert and
    explicit grant from the operator, the assistant can also enroll
    users, attach policies, or rotate certs — every change goes
    through the same admin API + audit log as a human admin's
    actions.

The CA already has the structured data (enrollment YAML + JSON-Lines
audit). MCP just exposes it as typed tools an LLM can call.

### Composition

Two MCP server modes, served from the same daemon:

  - `read_only`: enrollment-list, policy-explain, audit-search,
    cert-info. Available to any admin cert with `auditor` role.
  - `trusted_write`: above + server-add, user-add, policy-add,
    key-rotate. Requires admin cert with explicit `mcp_writable: yes`
    flag in enrollment. Every call audit-logged as
    `actor: mcp:<admin_subject>`.

### Wins

  - The CA's data model is the source of truth for "who can do what
    where." A natural-language interface to that data lowers the
    operational ceiling significantly.
  - Forensic queries on the audit log become trivial.
  - Bootstrapping a new CA / re-enrolling after a disaster becomes
    "describe the policy in English, AI translates and applies"
    rather than YAML-by-hand.

### Cons / open questions

  - Trusted-AI writes are a meaningful trust-delegation step.
    Probably opt-in per-admin and per-CA, never on by default.
    Should the operator be able to require an interactive approval
    step (CA prompts the admin's terminal for each `apply`?)
  - Audit-log volume going through MCP could be large; want pagination
    + query primitives, not just dump-everything.
  - Read-only mode is the obvious starting point. Write mode is a
    second milestone.

### LOC estimate

  - MCP server skeleton + tool definitions: ~400 lines.
  - Read-only adapters over enrollment/audit: ~200 lines.
  - Write adapters + role gating: ~300 lines.
  - Operator docs + per-tool descriptions for the LLM: small markdown
    investment.

---

## 13. Legacy-config migration with dual-enforce / shadow mode

### Idea

When an organization adopts ssh-rt-auth, their existing servers carry
*years* of accumulated policy: `authorized_keys` files, sshd_config
`AllowGroups`/`AllowUsers`, PAM rules, AKC plugins, `/etc/security/`
limits, etc. Manually translating that into CA enrollments is
high-effort and the highest-risk part of the migration ("did I
remember to grant alice the same access she had before?"). It is
also where most adoptions stall.

Propose two things that compose:

1. **Capture-and-translate tool.** A new `mssh-admin import` mode
   scrapes the existing server config and produces a draft
   enrollment YAML:
   - `authorized_keys` entries → per-user `keys` enrollment
   - `AllowGroups` / `AllowUsers` → server `groups` + user policies
   - Existing AKC plugin output → pass-through allow rules
   - PAM-restricted users → annotate (won't translate; operator
     reviews)
   The output is a starting point, not final policy — the operator
   reviews and edits before applying. Adhoc-mode lab runs this on
   the Phase-0 vanilla sshd state so the lab visibly demonstrates
   "drop-in migration with no manual rewriting."

2. **CA-side dual-enforce / shadow mode.** A per-server CA policy
   flag enables a transitional state where every authorization
   decision is evaluated **twice**:
   - against the **legacy ruleset** (the imported authorized_keys
     / AllowGroups / etc.)
   - against the **new CA policy** (the operator's hand-curated
     enrollments)

   The CA returns the union (or chosen primary; configurable),
   and **emits a divergence audit entry** for every case where
   the two disagree:
   - `legacy_allow_only`: legacy said yes, CA said no — operator
     is more restrictive in the new policy (potentially desired,
     or might be missed access that needs re-granting)
   - `ca_allow_only`: CA said yes, legacy said no — operator
     intentionally widened access (probably fine, but worth flagging)
   - `both_deny`, `both_allow`: agreement (no event needed)

   The operator runs in dual-enforce mode for as long as it takes
   to see zero `legacy_allow_only` events for any user they still
   want to support. Then they flip a config flag and the legacy
   ruleset is dropped — single-source-of-truth enforcement going
   forward.

### Wins

  - Removes the biggest adoption blocker: "I don't trust myself to
    have translated 10 years of sshd config correctly into CA
    policies."
  - Users see **no disruption** during migration — they continue to
    have exactly the access they had before, plus whatever the new
    CA policy adds. Operators can iterate on the CA policy
    asynchronously.
  - Audit log becomes a discovery tool: "show me every user whose
    legacy access we haven't replicated" → punch list.
  - In the adhoc lab, the workflow is the most compelling demo
    we can ship: "your existing servers worked at Phase 0; flip
    on capture-and-translate; Phase 2 enforce works with the same
    access patterns; admin tightens policy with zero user impact."

### Cons / open questions

  - Translation is heuristic, not lossless. PAM rules in particular
    don't have a clean equivalent in CA policy. Need a clear
    "couldn't translate; please review" output stream.
  - Dual-enforce slows every auth decision (~2x evaluation per call).
    Acceptable transitionally, not in steady state. Need a hard
    deadline (e.g. dual-enforce auto-expires after 30 days unless
    re-armed).
  - The legacy-allow-only vs ca-allow-only labels are slightly
    misleading when a user's legacy access is "all systems" and
    the new policy intentionally narrows that. The audit needs to
    distinguish "policy gap" from "policy tightening."
  - Storing the legacy ruleset at the CA means the CA now has a
    direct copy of every server's `authorized_keys`. Custody +
    cleanup matter.

### Composes with

  - §6.5.1 of msshd detailed design (gated mode) — gated mode
    leaves the operator's sshd policy in place at run-time. Legacy
    capture-and-translate goes a step further: it lifts that policy
    into the CA so the operator can eventually retire the original.
    Gated mode is "preserve the policy where it lives"; this is
    "move the policy into the CA."
  - §9 (migration runbook) — capture-and-translate is the missing
    automation that runbook would otherwise have to walk operators
    through by hand.
  - §11 (debug_sshd sideband audit) — sideband logs make divergence
    cases inspectable in detail when the operator can't tell why
    legacy said yes and CA said no.

### LOC estimate

  - `mssh-admin import` parsers (authorized_keys, sshd_config,
    AllowGroups, PAM-summary): ~500 lines.
  - CA-side dual-enforce evaluator + divergence audit: ~300 lines.
  - Adhoc-lab integration (a `Phase 0.5` step that runs import,
    shows the operator the draft, applies it): ~200 lines.

---

## 14. Tutorial / walkthrough doc for the adhoc lab

### Idea

The adhoc msshd lab already provisions Phase 0 → 1 → 2 with operator
flip scripts and a per-user README. Promote it to a **published
walkthrough** that demonstrates every mssh feature: the CA call, the
ephemeral inner cert, channel policy, source-CIDR, audit, the flip
scripts, debug_sshd swap-in (once §11 lands), the gated mode (once
§6.5.1 lands), the legacy-capture+dual-enforce (once §13 lands).

This is mostly an **operational doc effort**, not new code:
`docs/TUTORIAL.md` (or similar), walking the reader through running
the lab, observing each behavior, and explaining what the operator
would do at the equivalent step in a real adoption. Cross-link from
the README so newcomers have a guided entry point.

The tutorial reuses the adhoc lab as its sandbox — no separate
infrastructure needed. The lab's `ADHOC_TEST_ENV.md` is the seed
content for the tutorial's "Setup" section; the rest is per-feature
exercises.

### LOC estimate

  - ~2000 lines of operator-facing markdown.
  - Zero code, **assuming** the features it demonstrates (gated,
    legacy capture, sideband audit, MCP) are already implemented.
    Otherwise the tutorial's scope shrinks to whatever's available.

---

## 15. `install_mssh` — distro-style installer + BYO-container adhoc lab

### Idea

Replace the adhoc lab's LXC-specific source-push with a portable
**install script** that simulates `apt install mssh msshd` as if it
were a real distro package. The script does:

  - Install Python + venv on the target machine
  - Install the mssh + msshd packages (from a pre-built tarball)
  - Lay down systemd units for `msshd` (and the CA, where relevant)
  - **Does NOT enable** anything — leaves the operator to configure
    `wrapper.yaml`, enroll at the CA, and `systemctl enable msshd`
    when they're ready.

The adhoc lab becomes provisioner-agnostic. The test author spins
up containers however they want (LXC, Docker, VirtualBox, k8s, a
fleet of bare VMs, an SBC cluster on the desk), runs `install_mssh`
on each, and the rest of the lab (enroll, configure, flip modes)
proceeds over ssh exactly as it would in production.

### Composition

  - Single tarball: `mssh-<version>.tar.gz` containing the Python
    source, install script, systemd units, default config templates.
  - `install_mssh.sh <tarball>`: idempotent. Verifies prereqs
    (python3, openssl, openssh-server), creates a system user
    (`msshd`), installs into `/opt/mssh/`, drops systemd units in
    `/etc/systemd/system/` (disabled). Outputs the post-install
    checklist (enroll at CA, edit wrapper.yaml, enable).
  - Per-distro shims for `apt-get install` vs `apk add` of system
    deps (openssh-server, python3, openssl) wrapped behind a small
    detection step at the top of `install_mssh.sh`.

### Wins

  - **Adhoc lab is no longer LXC-specific.** Bring any container or
    VM; run the install script; join it to the CA.
  - **Documents the production install path.** The install script
    IS what `apt install mssh msshd` will eventually run. Operators
    who don't want a package can run it directly.
  - **Tutorial story improves.** "Here's a clean Ubuntu VM. Run
    `install_mssh`. Now enroll it at the CA. Now ssh as alice."
  - **Test surface contracts.** The lab's setup code stops being
    100+ lines of LXC-specific provisioning + `lxc file push` and
    becomes "spin up containers (your choice), then run the install
    script over ssh."

### Cons / open questions

  - The install script needs to handle distro variation gracefully.
    Ubuntu/Debian (`apt`), Alpine (`apk`), RHEL/Fedora (`dnf`),
    Arch (`pacman`). Start with Ubuntu + Alpine since those are the
    PoC's targets; extend later.
  - Versioning: the tarball needs a clear semver and the install
    script needs to refuse downgrades or warn on cross-version
    mismatch with the CA.
  - In the adhoc lab, who builds the tarball? Probably a small
    `make tarball` step at lab-startup time so the lab uses the
    in-tree source.

### Composes with

  - §11 (debug_sshd swap-in) — the install script lays down
    `debug_sshd` alongside the hermetic OpenSSH; the admin
    enables either as needed.
  - §13 (legacy capture + dual-enforce) — `install_mssh.sh`
    optionally runs `mssh-admin import` on the target before
    enrollment, so the CA starts with a migrated copy of the
    existing sshd policy.
  - §14 (tutorial doc) — the install script is the tutorial's
    onboarding step; the rest of the tutorial demonstrates what
    you do after `install_mssh` finishes.

### LOC estimate

  - `install_mssh.sh`: ~300 lines of bash with distro-detection.
  - Tarball assembly: ~50-line `make tarball` rule.
  - Adhoc-lab refactor to use the install script over ssh instead
    of `lxc file push`: ~200 lines net (mostly deletions).

---

## 16. Distro packaging path (`.deb` / `.rpm` / `.apk`)

### Idea

Long-term: ship native distro packages so the operator install
becomes literally `apt install mssh msshd` (Ubuntu/Debian),
`dnf install` (RHEL/Fedora), `apk add` (Alpine), instead of running
[§15](#15-install_mssh--distro-style-installer--byo-container-adhoc-lab)'s
shell installer.

### Three tiers of effort

  - **Quick win (~1 day): [`fpm`](https://github.com/jordansissel/fpm).**
    Eats a tarball or wheel, spits out `.deb` + `.rpm` + `.apk` from
    one command. No proper changelogs, no signing, no infrastructure;
    good enough for "users can `apt install ./mssh_0.1_amd64.deb`."
    Right call for the first release.

  - **Proper per-distro packaging (~1-2 weeks).** `dh-virtualenv`
    for Debian (packages the venv into a `.deb` — the standard
    Python-on-Debian story), proper `.spec` for RPM, `APKBUILD` for
    Alpine. Cleaner integration with apt/dnf/apk; more recipes to
    maintain over time.

  - **[openSUSE Build Service (OBS)](https://build.opensuse.org/).**
    Free for FOSS, used by KDE/Mozilla. Builds `.deb` / `.rpm` /
    `.apk` from a single source spec, for every distro you care
    about, automatically on push. Setup is half a day; after that
    it's a build-and-distribute pipeline you don't maintain.

### Why the underlying language matters

apt/dnf/apk were built around C's "one binary + shared libs in
known paths" model. Python (and to some extent Go) violate that
assumption — Python needs an interpreter + venv; Go static binaries
solve the interpreter problem but bring their own platform issues.

  - **Python** packaging: `dh-virtualenv` is the least-bad answer —
    you ship the entire venv (~30MB), distro-managed. `fpm` does
    the same thing with less ceremony.
  - **Go** packaging is *normally* trivial — a 15MB static binary
    that drops in `/usr/bin/`. **BUT Go does not target musl
    cleanly** (Alpine's libc). With `CGO_ENABLED=1` the binary
    depends on glibc; with `CGO_ENABLED=0` you lose cgo-dependent
    functionality (system DNS resolver, some crypto, system
    libraries). There are workarounds (alpine-go images, gccgo,
    cross-compile to musl with special toolchains) but they're
    not "just run `go build`."
  - **C / C++** packaging is what distro tooling was designed for;
    smallest binaries, cleanest integration, but biggest engineering
    investment to write.
  - **Rust** packaging is increasingly first-class via cargo-deb /
    cargo-rpm, with musl support that actually works (`x86_64-unknown-linux-musl`
    target builds cleanly for Alpine). If "small static binary that
    also runs on Alpine" matters, Rust is currently the cleanest
    answer of the cross-language options.

### Implications for the language strategy

If Alpine support stays a goal (it does — Alpine + Python is the PoC
target), the Go port's distro-packaging story is harder than initially
hoped. Options:

  1. Accept the constraint: ship Python on Alpine via the venv
     packaging path; Go on glibc-only distros.
  2. Bite the bullet on the C port for Alpine specifically (clean
     `.apk` story, smallest footprint, hardest to write).
  3. Consider Rust as the third language slot instead of Go for
     the Alpine target — single-binary `.apk` works out of the
     box, identity-management ecosystem (rustls, x509-cert, ssh-key)
     is mature enough.

This isn't a near-term decision, but worth knowing before committing
to a Go port whose primary value-prop (clean static binary
distribution) doesn't apply to half the deployment targets.

### Out of scope

The user noted this is "probably out of scope" — captured here so
we don't lose the constraint. No action implied; revisit when
shipping a real release becomes a priority.

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

Item 4 is a **scope expansion** — msshd becomes a multi-protocol
authorization proxy, not just an SSH gateway. Decide before it whether
that's the project's direction.

Item 10 (browser-based xterm.js terminal) is a **client-side
expansion** that builds on item 4's HTTPS listener: the bastion
serves a web SSH client to anyone with the right mTLS cert in their
browser. Composes naturally with item 7 (passkeys, where browser
cert handling is painful) and item 8 (centralized client config, to
feed the terminal UI's target picker).

Items 11, 13, 14 are the **operator-adoption block** — each tackles
a different obstacle to "we'd like to deploy this but the migration
looks scary":
  - **11 (debug_sshd swap-in + sideband audit)** gives the operator
    a "what is the CA actually deciding?" inspection tool when
    something looks wrong in production.
  - **13 (legacy capture + dual-enforce)** removes the
    re-translate-everything-from-scratch tax and makes the migration
    auditably non-disruptive.
  - **14 (tutorial)** is the operator-facing doc that ties the
    adhoc lab to a guided walkthrough of every feature.

Item 12 (MCP interface to the CA) is **orthogonal** to all of the
above — a different surface (LLM-driven) onto the same CA data
model. Mostly read-only diagnostics are the obvious starting point;
trusted-AI writes are a second milestone with their own trust
discussion.

---

## When this doc gets cleaned up

When an item is promoted to active work, move it to a dedicated design
doc (`design/mssh-detailed-<feature>.md`) and replace its
section here with a one-line "→ moved to <file>" pointer.
