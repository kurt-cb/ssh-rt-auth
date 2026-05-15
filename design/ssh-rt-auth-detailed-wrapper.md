# ssh-rt-auth wrapper — detailed design

**Status:** Design v1, 2026-05-14. Implementation-blueprint level.

**Predecessor:** [ssh-rt-auth-wrapper-research.md](ssh-rt-auth-wrapper-research.md) (decision).

**Audience:** anyone about to start writing the wrapper. Resolves the
open questions from wrapper-research § 11 and specifies enough to begin
implementation.

---

## 1. Scope

The wrapper is the Tier 1 production endpoint of ssh-rt-auth. It:

1. Listens on an externally-reachable port (default 22 or 2200).
2. Terminates an mTLS connection from a modern `mssh` client (TLS 1.3
   with client certificate authentication).
3. Calls the CA (over its own mTLS leg) to obtain an X.509
   authorization cert with policy extensions.
4. Translates the authorization cert into a short-lived OpenSSH user
   cert with appropriate critical options.
5. Hands off to a hermetic, localhost-bound, unmodified OpenSSH daemon
   that the wrapper owns.
6. Proxies bytes between the outer mTLS leg and the inner SSH leg,
   optionally inspecting the channel layer for policies the inner
   sshd can't enforce.
7. Drops the connection on cert expiry, policy revocation, or
   operator-initiated termination.

What the wrapper does **not** do: parse SSH protocol beyond the
channel-open layer (Variant B, deferred), implement the SSH protocol
from scratch (out of scope — see § 2 on why greenfield was dropped), or manage the
operator's *other* sshd (legacy system sshd on a different port stays
the operator's problem).

---

## 2. Language and layout

**Decision: three language variants, one wire protocol, one config
schema.** Each variant lives in its own subfolder under `wrapper/`:

| Variant            | Role            | Why                                                                                  |
|--------------------|------------------|--------------------------------------------------------------------------------------|
| `wrapper/python/`  | PoC              | Fast iteration; reuses the PoC's shim/CA machinery directly; easy to vet against the existing test suite. Performance acceptable for non-busy hosts. |
| `wrapper/go/`      | Production       | Memory-safe, single static binary, easy cross-compile. The default production target after the Python PoC is vetted. `golang.org/x/crypto/ssh` is the SSH client/server library; Teleport's agentless-OpenSSH integration is a working reference. |
| `wrapper/alpine/`  | Constrained / minimal | C + Mbed TLS or C + wolfSSL. Smallest footprint; Alpine-only; opt-in for embedded / appliance use cases where Go's runtime is unwanted. |

**Implementation order:** Python first → vet against PoC tests → Go
port → C-minimal port. The three share wire protocol, config schema,
and CA contract so the same integration test suite verifies all three.

The earlier "greenfield C/Mbed TLS server" plan is dropped —
`wrapper/alpine/` covers the constrained-deployment use case without
us having to own the SSH protocol.

### 2.1 Layout within the main repo

```
ssh-rt-auth/                       # this repo
├── ca/                            # CA (unchanged)
├── shim/                          # AKC shim (unchanged)
├── server/                        # AsyncSSH Tier 2 reference (unchanged)
├── openssh/                       # OpenSSH AKC entry point (unchanged)
├── wrapper/                       # ←── new
│   ├── python/                    # PoC implementation
│   │   ├── __init__.py
│   │   ├── wrapperd.py            # daemon entry point
│   │   ├── listener.py            # outer mTLS listener
│   │   ├── inner.py               # inner sshd lifecycle
│   │   ├── userca.py              # local user-CA key custody + cert minting
│   │   ├── policy.py              # X.509 ext → OpenSSH critical-option translation
│   │   ├── proxy.py               # byte-shuffler; channel parser (Variant B, later)
│   │   ├── audit.py               # connection log (separate from CA audit)
│   │   ├── config.py              # wrapper.yaml loader
│   │   └── admin.py               # ssh-rt-wrapper-admin CLI (init / lint / rotate-ca)
│   ├── go/                        # production port (next phase)
│   │   └── (cmd/ + internal/ layout — see § 2.2)
│   ├── alpine/                    # minimal C variant (future phase)
│   │   └── (Mbed TLS or wolfSSL)
│   ├── config/
│   │   ├── wrapper.yaml.example   # operator-facing config template
│   │   └── sshd_config.template   # hermetic inner sshd_config template
│   ├── systemd/
│   │   ├── ssh-rt-wrapperd.service
│   │   └── ssh-rt-inner-sshd.service
│   └── README.md                  # variant chooser + quick start
├── tests/
│   └── lxc/
│       └── test_wrapper_*.py      # one test file per variant
└── ...
```

### 2.2 Go variant layout (for reference)

When `wrapper/go/` is implemented:

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

---

## 3. Outer wire protocol: JSON-framed session-RPC over mTLS

**Decision (revised 2026-05-14): custom session-RPC framing inside a
TLS 1.3 + mTLS tunnel. NOT raw SSH.**

Earlier drafts assumed the outer protocol could be "raw SSH inside a
TLS tunnel," which would let any stock SSH client work through the
wrapper. That doesn't actually work end-to-end: the outer SSH session
and the inner (wrapper → hermetic sshd) session can't share an
authenticated principal because they use different keys. Stock `ssh`
would need to be MITMed (sshpiper-style) to bridge the two — feasible
but a much larger implementation surface than makes sense for v1.

**v1 outer protocol** is a small line-delimited JSON handshake
followed by raw bytes:

```
< TLS 1.3 + mTLS handshake >

Client → Server   (single line, newline-terminated, ≤ 4 KB):
  {"v": 1, "command": "<cmd>" | null, "interactive": bool,
   "term": "xterm-256color" | null,
   "rows": int | null, "cols": int | null,
   "env": {"K":"V", ...} | null}

Server → Client   (single line, newline-terminated):
  {"v": 1, "ok": true} | {"v": 1, "ok": false, "reason": "..."}

After ack: bidirectional raw byte stream.
  Client → Server : stdin (raw bytes).
  Server → Client : stdout + stderr (merged stream).

TCP close = session end.
```

Fields:

- `command` — the remote command. `null` or absent means "interactive
  shell".
- `interactive` — request a PTY. Defaults to `false` for exec, `true`
  for shell.
- `term`, `rows`, `cols` — used only when `interactive == true`.
- `env` — environment overrides; ssh-rt-auth's `sshrtauth-environment`
  cert extension may override these.

What's intentionally NOT v1:

- Multiplexed channels (sftp, port forwarding, X11). v1 is
  one-session-per-connection.
- Separate stdout / stderr streams. Merged for simplicity. v2 adds
  framing or a side-channel.
- Exit code propagation. The connection close signals "done"; mssh
  exits 0 if the remote shell closed cleanly, non-zero if the TLS
  tunnel was reset. v2 adds an end-of-stream frame with the real
  exit code.
- Window-resize messages mid-session.
- Reconnect / session resumption.

### 3.1 Why the JSON header

A line of JSON gives us:

- A version byte (`"v": 1`) for future protocol revisions.
- Forward-compatible structure — adding new fields doesn't break
  older clients that ignore them.
- Easy debugging — operators can `tcpdump` + inspect the cleartext
  payload (after TLS termination) and read it.

The cost is a few microseconds of `json.dumps` / `json.loads` per
connection — negligible.

### 3.2 Client

A small `mssh` CLI ships with the wrapper package. It does the TLS
handshake itself (Python's `ssl.SSLContext`), emits the JSON header,
acks, then byte-pumps stdin/stdout. **It does NOT spawn `ssh` or
`openssl`** — those external dependencies were tempting for v1 but
brought the protocol-bridge problem above. mssh is a pure-Python
client; `openssh-client` is no longer a runtime requirement.

```
mssh alice@server-01                  # interactive shell, default port
mssh alice@server-01 -- uname -a      # exec
mssh -p 2222 alice@server-01:2222
mssh --identity ~/.mssh/alt-cert alice@server-01
```

Configuration: `~/.mssh/config` (key=value), env vars (`MSSH_CERT`,
`MSSH_KEY`, `MSSH_CA`), or CLI flags.

### 3.3 Server (wrapper)

The wrapper's `enforce_listener.py` reads the header line, dispatches:

- **Exec mode** (`command != null`): wrapper opens an asyncssh
  client to inner sshd, calls `conn.run(command, ...)`, pipes
  result back.
- **Interactive mode** (`command == null`, `interactive == true`):
  wrapper opens an asyncssh session with PTY (`term`, `rows`,
  `cols`), pumps stdin/stdout both ways.

Both paths apply `sshrtauth-force-command` (overrides client's
command if set), `sshrtauth-environment` (overrides `env`), and the
wrapper-side `max_session_seconds` timer.

### 3.1 mTLS handshake details

- **TLS version:** 1.3 minimum. No TLS 1.2 fallback.
- **Cipher suites:** `TLS_AES_256_GCM_SHA384`,
  `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`.
- **Client cert verification:** verify against the ssh-rt-auth user-CA
  trust root (separate from the server-mTLS trust root used between
  wrapper and CA). Subject must contain a `sshrtauth-user` field; the
  wrapper extracts the user identity from there.
- **Server cert:** the wrapper presents a cert signed by the
  ssh-rt-auth server-mTLS CA, same as today's PoC `ca.crt` trust root.
- **SNI:** unused by us; we accept any. (Future: ALPN routing if we
  ever need to multiplex other protocols on the same port.)
- **Session ID:** TLS exchange hash is captured as the binding token
  for the v2 `sshrtauth-session-bind` extension (replaces SSH H from
  the original v2 design — see § 8).

### 3.2 Legacy SSH coexistence

The wrapper does not protocol-sniff (deferred to
[strategy.md § 6.1](ssh-rt-auth-server-strategy.md)). For v1 the
operator runs the wrapper on a non-22 port (default: 2200) and leaves
the system sshd on 22. Migration shape: clients adopt `mssh` over
time; the operator decides when to move ports.

---

## 4. Inner SSH transport: keep encrypted

**Decision: use a normal OpenSSH cipher on the inner leg.**

OpenSSH supports `Ciphers none` but flags it heavily as a foot-gun.
The performance win for skipping inner encryption is real only for
high-throughput (~Gb/s) workloads; for the interactive-shell and
small-file-transfer cases that dominate SSH usage, the cost is
negligible (~5 % on a modern CPU). Defaulting to a normal cipher
matches operator expectations and avoids a "this looks misconfigured"
moment in an audit.

If a future operator needs the throughput, we can add a
`performance.inner_cipher_none: true` opt-in to the wrapper YAML.
Out of scope for v1.

---

## 5. Hermetic inner sshd

### 5.1 Process lifecycle

- **Spawned by:** `ssh-rt-wrapperd` at startup. Runs as a child
  process under `systemd` via `ssh-rt-inner-sshd.service`, declared
  `BindsTo=ssh-rt-wrapperd.service` so they live and die together.
- **User:** dedicated system user `_sshrtinner` (similar to OpenSSH's
  `sshd` user). No shell, no home dir worth speaking of.
- **Runtime dir:** `/var/lib/ssh-rt-auth/inner-sshd/`. Contains:
  - `sshd_config` — rendered hermetic config (hash-checked)
  - `ssh_host_ed25519_key`, `ssh_host_ed25519_key.pub` — host keys,
    separate from system sshd's
  - `wrapper-user-ca.pub` — local user-CA pubkey, written by wrapper
    at startup, mode 0644
  - `*.pid` — pidfile
- **Listening:** `ListenAddress 127.0.0.1` on a wrapper-allocated
  port in the 49152-65535 ephemeral range. Allocation is dynamic at
  startup; wrapper passes the chosen port to its own SSH client.
- **OpenSSH binary:** the distro's `/usr/sbin/sshd` by default; an
  override `inner.sshd_binary: /opt/openssh-9.9/sbin/sshd` is
  available for sites that pin a specific version.

### 5.2 The hermetic sshd_config template

This is the embedded template the wrapper renders at startup.
Operators do not edit it. The wrapper hashes the rendered output and
refuses to start if it doesn't match the embedded known-good hash
for the OpenSSH version in use.

```
# Hermetic inner sshd_config — generated by ssh-rt-wrapperd.
# DO NOT EDIT. Edit /etc/ssh-rt-auth/wrapper.yaml and restart.

ListenAddress 127.0.0.1
Port {{INNER_PORT}}
HostKey /var/lib/ssh-rt-auth/inner-sshd/ssh_host_ed25519_key

# Auth: cert-only, via local user-CA pinned in TrustedUserCAKeys.
AuthenticationMethods publickey
PubkeyAuthentication yes
TrustedUserCAKeys /var/lib/ssh-rt-auth/inner-sshd/wrapper-user-ca.pub
AuthorizedKeysFile /dev/null
AuthorizedKeysCommand none
AuthorizedPrincipalsFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
PermitRootLogin no
PermitEmptyPasswords no

# No forwarding / tunneling at the SSH layer; channel-policy
# is enforced at the wrapper (or hardcoded off here).
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
AllowStreamLocalForwarding no
GatewayPorts no

# No PAM. PAM is a config-surface multiplier we don't want.
UsePAM no

# Crypto floor — opinionated allowlist, modern only.
KexAlgorithms sntrup761x25519-sha512,curve25519-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519
PubkeyAcceptedAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Explicitly NO Include directive.
# Explicitly NO Match blocks.
# Explicitly NO sshd_config.d/.
```

Variables (`{{INNER_PORT}}`, the host-key path) are the only things
that vary between deployments — the rest is byte-identical across
hosts of the same OpenSSH version.

### 5.3 Per-version hash table

The wrapper embeds a table:

```go
var hermeticConfigHashes = map[string]string{
    "OpenSSH_9.9p1":  "sha256:b3...e9",
    "OpenSSH_9.9p2":  "sha256:c2...0a",
    "OpenSSH_9.10p1": "sha256:...",
    // populated for every supported OpenSSH version
}
```

At startup the wrapper runs `sshd -V`, parses the version, renders
the template, hashes the result, and compares against the table.
Mismatch = log loudly and refuse to start. Catches: distro updates
that introduce new defaults, accidental in-flight edits, supply-chain
tampering of the wrapper binary.

Adding a new OpenSSH version means: (1) verify the template still
makes sense for that version (some directives may rename), (2)
compute the new hash, (3) add a row, (4) ship a wrapper update.
Tedious but cheap, and `ssh-rt-wrapper-admin verify` can do step 2
for the operator who wants to fast-track a version we haven't
shipped support for yet.

### 5.4 Host keys

Inner sshd has its own host keys, generated by `ssh-rt-wrapper-admin
init` at install time. Operators don't see them. The outer mTLS
provides the actual cryptographic identity of the host (server cert);
the inner host key only matters between wrapper and inner sshd, both
on localhost. We could even regenerate them on every wrapper restart
without functional impact; for now we persist so log lines have
stable fingerprints.

---

## 6. Local user-CA key custody

The wrapper holds an OpenSSH user-CA private key that signs the
short-lived inner certs handed off to inner sshd. Custody:

### 6.1 Provisioning

`ssh-rt-wrapper-admin init` (run once at install):

1. Generates a fresh Ed25519 keypair.
2. Writes the **private** key to `/var/lib/ssh-rt-auth/wrapper-user-ca`
   mode 0600, owned by `_sshrtwrapper:_sshrtwrapper`.
3. Writes the **public** key to
   `/var/lib/ssh-rt-auth/inner-sshd/wrapper-user-ca.pub` mode 0644,
   owned `root:_sshrtinner`.
4. Records the key fingerprint in
   `/var/lib/ssh-rt-auth/wrapper-user-ca.fingerprint` for audit.

### 6.2 Runtime custody

- Wrapper reads the private key into memory at startup. **The key is
  not re-read from disk** during normal operation; SIGHUP triggers a
  re-read for rotation.
- The on-disk file remains readable only by the wrapper user. A
  startup check verifies permissions and refuses to start if
  group/other have any bits set.
- Memory protection: best-effort. Go does not give us mlock for
  arbitrary slices; we don't attempt to do anything beyond keeping the
  key off disk. (A full HSM/TPM integration is reserved for later;
  see § 13.)

### 6.3 Rotation

`ssh-rt-wrapper-admin rotate-ca`:

1. Generates a fresh keypair.
2. Writes both keys atomically (new private key, new public key in
   `wrapper-user-ca.pub`).
3. Sends SIGHUP to the wrapper, which re-reads both files.
4. Restarts the inner sshd (so it picks up the new
   `TrustedUserCAKeys` pubkey).
5. Logs the old fingerprint as retired and the new fingerprint as
   active.

During rotation, in-flight connections complete with the old cert
(certs are 30-second lived; the worst-case interruption is one cert
window). New connections after the SIGHUP use the new key.

### 6.4 No backup

The user-CA private key is **not backed up**. If it's lost, run
`init` again — the only consequence is that the inner sshd gets a new
`TrustedUserCAKeys` pubkey, which is a no-op for end users (they
never see this key) and self-heals on next connection. Backing it up
would broaden the key's footprint without functional benefit.

---

## 6.5 Fallback / shadow mode (safe-rollout default)

The wrapper supports a **fallback mode** that is the **default at first
install**. In fallback mode the wrapper:

- Accepts incoming TLS connections on its configured port.
- Does **not** call the CA.
- Does **not** mint any inner cert.
- **Transparently forwards** the connection's bytes to a pre-existing
  sshd (typically the system sshd on port 22), letting that sshd's
  existing auth — `authorized_keys`, passwords, whatever — handle
  everything.

The wrapper is therefore a **no-op security-wise** in this mode, but
proves that:

- It can accept TLS connections on the configured port.
- Its bytes-through-proxy machinery works.
- Its systemd unit + lifecycle management is sane.
- The operator's existing SSH workflow is **unbroken**.

The operator graduates to CA-enforced mode by flipping a single config
flag in `wrapper.yaml`:

```yaml
mode: fallback   # default; transparent proxy to system sshd
# mode: enforce  # flip to this once verified
```

In `enforce` mode the wrapper does the full CA call + inner cert mint
+ inner sshd handoff described in §7.

### Why this matters

Cutover from "unmodified OpenSSH" to "ssh-rt-auth CA-mediated
authorization" is the highest-risk moment in a deployment. A wrong
config flag or a missing CA endpoint reachability check can lock the
operator out of the host. The fallback-default mode means:

1. Operator installs the wrapper. Existing SSH access is unaffected.
2. Operator restarts SSH service. Existing SSH access is unaffected
   (wrapper is transparently forwarding).
3. Operator runs `ssh-rt-wrapper-admin verify` to confirm CA
   reachability, cert validity, and inner-sshd config hash.
4. Operator flips `mode: enforce` and restarts.
5. Operator tests CA-mediated auth from a SECOND terminal (keeping
   the first one open as a rollback escape).
6. Operator commits if verification succeeds, or `mode: fallback`
   again if not.

The companion `wrapper/scripts/upgrade.sh` walks the operator through
exactly this sequence with explicit verify/rollback prompts.

---

## 6.6 Clock and time authority

**Status:** Designed 2026-05-14, not yet implemented.

### 6.6.1 The problem clock skew creates

Authorization certs have tight validity windows (~1h default). The
CA enforces `timestamp_drift_seconds` (default 600s) against the
`timestamp` field of every `POST /v1/authorize` request. A wrapper
host whose local clock disagrees with the CA's by more than that
window gets **every authorization request denied** with
`clock_drift_too_large`. This is silent fleet-wide DOS — particularly
nasty because:

- The operator's first symptom is "all my users got logged out at
  once", not "the clock drifted".
- NTP misconfiguration is common on freshly provisioned hosts.
- A single ill-timed VM clock-skew event (e.g., live migration on
  some hypervisors) can produce a multi-second jump that pushes a
  previously-healthy host out of the window.

There is no purely-passive defense — if the wrapper's `timestamp`
field is wrong, the CA can't tell whether the request is a replay,
a clock-skewed honest call, or an attack. The CA's only safe
posture is to deny.

### 6.6.2 Design: the CA is the authoritative clock

The wrapper synchronises its perception of "now" to the CA at
startup, then uses **CA-derived time** in:

- `timestamp` field of every CA request body (the load-bearing
  case — prevents denials).
- `valid_before` / `valid_after` of minted inner OpenSSH user
  certs (so the wrapper-to-inner-sshd handoff agrees with the
  CA's view).
- Audit log timestamps emitted by the wrapper (so wrapper logs
  cross-correlate with the CA's audit log on a single timeline).

The wrapper's *system clock* is still used in places where the CA's
perspective is irrelevant or unhelpful:

- Outer mTLS handshake — Python's `ssl` module validates cert dates
  against `time.time()`. We don't fix this at the application layer
  because mTLS client/server certs are long-lived (30+ days), so a
  few hours of host skew is harmless.
- `time.monotonic()` for elapsed-time measurements (timers, etc.) —
  not affected by wall-clock skew.

### 6.6.3 The `Clock` module

`wrapper/python/clock.py` (forthcoming):

```python
@dataclass
class Clock:
    offset_seconds: float = 0.0
    last_sync_local_monotonic: float = 0.0   # time.monotonic() at last sync
    last_sync_local_wall: datetime | None = None
    last_sync_ca_wall: datetime | None = None
    sync_failures_in_a_row: int = 0

    def now(self) -> datetime:
        """CA-perspective UTC datetime."""
        return _dt.datetime.now(_dt.UTC) + timedelta(seconds=self.offset_seconds)

    async def sync(self, ca_client) -> None:
        """Hit /v1/clock, compute new offset with round-trip correction."""
        t_send = time.monotonic()
        ca_time = await ca_client.get_clock()
        t_recv = time.monotonic()
        rtt = t_recv - t_send
        # Estimate CA time at the moment we received it as midway through
        # the round-trip; offset that against our local wall clock.
        local_now = _dt.datetime.now(_dt.UTC)
        self.offset_seconds = (ca_time - local_now).total_seconds() - rtt / 2
        self.last_sync_local_monotonic = t_recv
        self.last_sync_local_wall = local_now
        self.last_sync_ca_wall = ca_time
        self.sync_failures_in_a_row = 0

    def staleness_seconds(self) -> float:
        return time.monotonic() - self.last_sync_local_monotonic

    def is_degraded(self, max_staleness: float = 3600) -> bool:
        return self.staleness_seconds() > max_staleness
```

### 6.6.4 Lifecycle

| Event                          | Behaviour                                                                                       |
|--------------------------------|--------------------------------------------------------------------------------------------------|
| Wrapper startup                | Sync with CA. **Refuse to start if unreachable** — silently broken offset = silent denials.    |
| Every CA request (`/v1/authorize`) | Wrapper uses `Clock.now()` for the request timestamp. CA includes its current time in the response; wrapper updates its offset opportunistically. |
| Background task               | Re-sync every 5 minutes via `/v1/clock`. On failure, log and keep last-known offset.            |
| Staleness > 1 hour            | Wrapper transitions to "degraded" — emits a metric, surfaces in `admin status`, and (configurable) refuses to mint new inner certs. Existing connections survive. |
| SIGHUP                        | Force-resync.                                                                                    |
| `admin verify`                | Reports local time, CA time, offset, last-sync age, staleness state.                            |

### 6.6.5 CA-side requirements

- New endpoint **`GET /v1/clock`** — unauthenticated (no mTLS needed,
  no policy decisions exposed); returns `{"time": "ISO-8601 UTC",
  "version": "ssh-rt-auth-ca/x.y"}`. Maximum cache-control:
  no-store.
- Every `/v1/authorize` response (grant or deny) carries a `"time"`
  field as well. Wrappers update their offset on every call,
  reducing the need for explicit `/v1/clock` traffic.
- **The CA host's own NTP is now load-bearing.** Operator obligation:
  multi-source `chronyd`, monitored, alerted on drift.

### 6.6.6 mssh client side

The client tool (separate from the wrapper) makes an unauthenticated
call to the wrapper's pass-through clock endpoint at startup and
errors out loudly if local skew exceeds a safe threshold:

```
$ mssh alice@server-01
mssh: your local clock is 17h22m off from the CA. Run `chronyc -a
makestep` (or equivalent) and retry. Authentication can't proceed
without working local time.
```

This is **not auto-bypass** — the client's clock must be right for
mTLS handshake validation of the wrapper's server cert. But the
clear early-fail is much better operator-experience than
`Permission denied (publickey)` with no further detail.

### 6.6.7 Failure modes recap

| Bad clock on…                       | Behaviour                                                                  |
|-------------------------------------|----------------------------------------------------------------------------|
| CA host                             | Whole fleet sees denials. The single point of clock truth — operator must monitor it. |
| Wrapper host                        | Mitigated by `Clock` offset; transparent to users.                          |
| Tier 2/3 shim host                  | Same mechanism (when Phase 1B+ Tier 2/3 picks it up — not in scope today). |
| Client laptop                       | mssh CLI hard-fails at startup with a clear message.                       |
| Inner sshd (same host as wrapper)   | Irrelevant; shares the wrapper's clock; CA never enters this loop.         |

### 6.6.8 Why not just "fix everyone's NTP"

Tempting but wrong:

- Hundreds of wrapper hosts is hundreds of NTP configs to keep right.
  One ill-provisioned host produces silent denials.
- End-user laptops are the worst case — operators have zero control.
- VM migrations, sleeping containers, time-jumping after suspend —
  all routine, all create transient skew that the CA's static window
  punishes.
- Making the CA authoritative reduces the operational surface from
  N hosts to 1 host. Much easier to alert on, much easier to root-cause.

### 6.6.9 What this section explicitly defers

- Wrapper-side application-layer mTLS cert date validation against
  CA-derived time. Doable (custom verify callback + manual chain
  validation via `cryptography.x509`) but adds complexity for a
  rare failure mode (client/server cert lifetimes are long enough
  that day-scale skew rarely matters here). Open question for v2.
- Cryptographically authenticated `/v1/clock` responses. Currently
  unauthenticated; an attacker on-path could poison the wrapper's
  offset. Mitigation: the wrapper's CA mTLS leg is the actual trust
  boundary; the wrapper's `/v1/clock` call goes through the same
  mTLS pipe in practice. Document the threat model when
  implementing.
- Time-monotonicity guarantees during clock jumps. Use
  `time.monotonic()` for elapsed timers; don't rely on
  `Clock.now()` to be monotonic.

---

## 7. Per-connection flow

Sequence for one successful connection (deny paths abbreviated to "→ close"):

```
1. Client opens TCP to wrapper:2200.
2. mTLS handshake.
   - Wrapper verifies client cert chain against user-mTLS root.
   - Wrapper extracts user identity from cert subject.
   → on failure: close.
3. Wrapper opens (or reuses, with pooling) mTLS to CA.
4. Wrapper sends POST /v1/authorize with:
   - identity (user cert pubkey or OpenSSH cert blob)
   - v2 connection context (source IP/port, local IP/port, TLS
     session ID, negotiated ciphers, sshd_attestation flagged
     "tier=wrapper")
5. CA returns authz cert (X.509 with extensions) or deny.
   → on deny: close with reason logged.
6. Wrapper translates extensions to OpenSSH cert critical-options
   (see § 8 translation table).
7. Wrapper mints OpenSSH user cert:
   - Principal: <validated unix user>
   - Valid: now+0, expires in min(authz_cert.notAfter, +30s)
   - Critical options: from translation
   - Signed by local user-CA key
8. Wrapper dials its own SSH client to 127.0.0.1:{inner_port}
   presenting the just-minted cert.
9. Inner sshd validates cert against TrustedUserCAKeys, accepts,
   spawns the user shell.
10. Wrapper pipes bytes between outer TLS and inner SSH leg.
    Optionally: Variant B parses channel-open frames here (§ 9).
11. Wrapper holds the connection. When the authz cert's notAfter
    arrives, wrapper terminates the inner SSH session and closes the
    outer TLS connection (refresh path: § 10).
```

The TLS session ID captured at step 2 is what the v2
`sshrtauth-session-bind` extension binds to (§ 8).

---

## 8. Critical-option translation table

How each X.509 extension on the authz cert (from the CA) is enforced.

| X.509 extension OID | Name                          | Translates to                                              | Enforced by         |
|---------------------|-------------------------------|------------------------------------------------------------|---------------------|
| `.1.1`              | `sshrtauth-source-bind`        | OpenSSH cert `source-address` critical option              | **Inner sshd** (native) |
| `.1.2`              | `sshrtauth-server-bind`        | Verified by wrapper before minting; rejects mismatched server | **Wrapper** (pre-mint) |
| `.1.3`              | `sshrtauth-channel-policy`     | Variant A: hermetic config bans non-`session` channels globally. Variant B: per-conn enforcement in proxy. | **Wrapper** (Variant B) |
| `.1.4`              | `sshrtauth-force-command`      | OpenSSH cert `force-command` critical option               | **Inner sshd** (native) |
| `.1.5`              | `sshrtauth-environment`        | OpenSSH cert `permit-environment` extension + per-var pre-set | **Inner sshd** (native) |
| `.1.6`              | `sshrtauth-max-session`        | Wrapper-side timer; force-close at deadline                | **Wrapper** |
| `.1.7`              | `sshrtauth-2fa-evidence`       | Recorded in audit; not enforced (informational)            | n/a |
| `.1.8`              | v2 `sshrtauth-session-bind`    | Validated against outer mTLS session ID before mint        | **Wrapper** (pre-mint) |
| `.1.9`              | v2 `sshrtauth-crypto-floor`    | Validated against negotiated mTLS ciphers before mint      | **Wrapper** (pre-mint) |
| `.1.10`             | v2 `sshrtauth-client-version-allow` | Validated against client SSH version string             | **Wrapper** (pre-mint) |
| `.1.11`             | v2 `sshrtauth-host-key-pin`    | Validated against wrapper's outer-mTLS host key fingerprint | **Wrapper** (pre-mint) |
| `.1.12`             | v2 `sshrtauth-auth-method-allow` | Validated against actual mTLS userauth method            | **Wrapper** (pre-mint) |
| `.1.13`             | v2 `sshrtauth-issuer-ca-pin`   | Validated against client-cert's issuer chain               | **Wrapper** (pre-mint) |
| `.1.14`             | v2 `sshrtauth-local-bind`      | Validated against listening interface                      | **Wrapper** (pre-mint) |
| `.1.15`             | v2 `sshrtauth-step-up-required` | CA-side concern; wrapper passes through                    | **CA** (pre-grant) |

Note: most v2 enforcement happens **before** the OpenSSH cert is
minted. The wrapper is the security boundary, not the inner sshd.
Inner sshd is a commodity that enforces what the (locally-minted) cert
tells it to enforce; nothing more.

---

## 9. Channel-policy enforcement: phased

### Phase 1 (v1): Variant A — pure proxy, hardcoded allowlist

Hermetic config bans `direct-tcpip`, `forwarded-tcpip`,
`session-streamlocal`, etc. globally. Only `session` channels are
allowed by inner sshd. This covers ~95 % of what
`sshrtauth-channel-policy` wants to express.

### Phase 2 (post-v1): Variant B — channel-open parser

Add a small SSH wire-format parser in `internal/proxy/` that intercepts:

- `SSH_MSG_CHANNEL_OPEN` (RFC 4254 §5.1)
- `SSH_MSG_CHANNEL_REQUEST` (RFC 4254 §5.4) — for `subsystem`, `exec`,
  `shell`, etc. Lets us enforce e.g. "shell allowed, exec denied" per
  policy.

Parser scope is intentionally narrow: ~500 LOC. We don't parse data
channels, key-exchange, userauth — those go through unchanged.

---

## 10. Cert expiry, refresh, termination

### 10.1 Expiry

Wrapper tracks the authz cert's `notAfter` per connection. At
`notAfter`, wrapper sends `SSH_MSG_DISCONNECT` (reason
`SSH_DISCONNECT_BY_APPLICATION`, message "cert expired") on the
inner leg, then closes the outer TLS connection.

### 10.2 Refresh (optional, v1.1)

Before `notAfter`, wrapper can attempt to re-call the CA for a
renewed authz cert. On success, the wrapper mints a new inner
OpenSSH cert — but the inner sshd doesn't support mid-session cert
rotation, so the new cert only takes effect on the **next**
connection. Practical implication: long-running sessions need to
either accept the disconnect at expiry or use very long-lived authz
certs (defeats the point).

A future enhancement: wrapper signals expiry to a smart `mssh`
client, which reconnects (over TLS) and resumes via SSH multiplexing.
Deferred.

### 10.3 External termination

`ssh-rt-wrapper-admin kill --session <id>` and CA-driven revocation
(future) both work by signaling the wrapper, which closes the
relevant connection.

---

## 11. Operator-facing YAML schema

Single file: `/etc/ssh-rt-auth/wrapper.yaml`.

```yaml
listen:
  external_address: 0.0.0.0          # what the wrapper binds for client traffic
  external_port: 2200                # change to 22 after migrating clients
  # Optional: restrict to specific interfaces for split-domain hosts
  interfaces: []                     # empty = all

tls:
  server_cert: /etc/ssh-rt-auth/wrapper-server.crt
  server_key:  /etc/ssh-rt-auth/wrapper-server.key
  user_ca_pubkey: /etc/ssh-rt-auth/user-ca.pub
  # Versions and ciphers are hardcoded (TLS 1.3 only); not tunable
  # to avoid the OpenSSH-config-mess problem.

ca:
  endpoints:
    - https://ca-1.internal:8443
    - https://ca-2.internal:8443
  client_cert: /etc/ssh-rt-auth/wrapper-mtls.crt
  client_key:  /etc/ssh-rt-auth/wrapper-mtls.key
  ca_pubkey:   /etc/ssh-rt-auth/server-mtls-ca.pub
  timeout_seconds: 5
  emergency_cert: /etc/ssh-rt-auth/emergency.cert    # optional

inner:
  sshd_binary: /usr/sbin/sshd       # version-pinned override allowed
  port_range: [49152, 65535]         # ephemeral allocation
  # No sshd_config knob — the template is hermetic.

users:
  # Which Unix users the wrapper is allowed to drop into.
  # Connections requesting a user not in this list are denied.
  # Use ["*"] to allow any (NOT recommended).
  allowed:
    - alice
    - bob
    - svc-deploy

logging:
  level: info                        # debug | info | warn | error
  destination: syslog                # syslog | stderr | file:/path
  audit_destination: file:/var/log/ssh-rt-auth/wrapper-audit.jsonl

# Optional: per-Unix-user overrides (rare; most config should be
# expressed in CA policy, not here)
user_overrides: {}

# Performance knobs (rare)
performance:
  inner_cipher_none: false           # see § 4
  max_concurrent_sessions: 200
```

`ssh-rt-wrapper-admin lint` validates this file plus the inner-sshd
hermetic config hash plus on-disk permissions plus that the
configured CA is reachable.

---

## 12. systemd integration

### 12.1 ssh-rt-wrapperd.service

```ini
[Unit]
Description=ssh-rt-auth wrapper (mTLS-authenticated SSH frontend)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=_sshrtwrapper
Group=_sshrtwrapper
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/sbin/ssh-rt-wrapperd --config /etc/ssh-rt-auth/wrapper.yaml
Restart=on-failure
RestartSec=5

# Sandboxing
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/log/ssh-rt-auth /var/lib/ssh-rt-auth
ProtectHome=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

### 12.2 ssh-rt-inner-sshd.service

```ini
[Unit]
Description=ssh-rt-auth inner sshd (hermetic, localhost-only)
BindsTo=ssh-rt-wrapperd.service
After=ssh-rt-wrapperd.service

[Service]
Type=forking
ExecStart=/usr/sbin/sshd -f /var/lib/ssh-rt-auth/inner-sshd/sshd_config
PIDFile=/var/lib/ssh-rt-auth/inner-sshd/sshd.pid
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`BindsTo` ensures the inner sshd dies if the wrapper dies. The
wrapper renders the inner sshd config + writes the pubkey before
starting the unit; uses systemd's notify socket to know when the
wrapper is ready.

---

## 13. Phasing

### Phase 1: minimum-viable wrapper

- Outer mTLS listener with user-cert auth
- CA call via reused shim machinery
- OpenSSH cert minting with Source-bind, Force-command, Environment,
  Max-session translation (the v1 extensions)
- Inner sshd lifecycle
- Pure byte-proxy (no channel parsing)
- Basic operator YAML + lint command

Goal: feature parity with what the LXC e2e test currently exercises
via AsyncSSH, but on Tier 1 architecture.

### Phase 2: v2 extension enforcement

- Add OID parsing for `.1.8` through `.1.14`
- Implement the pre-mint wrapper-side validations
- v2 audit attestation populated

### Phase 3: Variant B channel parsing

- Wire-format parser for channel-open / channel-request
- Per-connection enforcement of `sshrtauth-channel-policy`

### Phase 4: HSM/TPM key custody

- Local user-CA key in TPM2 or PKCS#11
- Per-cert sign requests via the HSM

---

## 14. Testing

- **Unit tests** for each `internal/` package, especially the
  critical-option translator (table-driven).
- **Integration tests** mirror the existing LXC suite shape:
  spin up LXC containers, deploy wrapper + CA, run scenarios
  (granted / denied / source-CIDR / force-command / max-session /
  refresh / external-termination).
- **Hermetic-config drift detector**: a test that re-renders the
  template against every supported OpenSSH version and confirms the
  embedded hash matches. Runs on every CI build.
- **Fuzzing** (Phase 3+): channel-open parser, with go-fuzz.

---

## 15. Open questions deferred

These don't block Phase 1 but should be revisited:

1. **mssh client tooling.** Do we ship a CLI (`mssh user@host`) that
   hides the ProxyCommand+TLS incantation, or document the raw
   ProxyCommand for v1? Probably the former — DX matters.
2. **Long-running sessions.** Cert refresh story (§ 10.2) is weak.
   Either accept "long sessions get disconnected at notAfter and
   the client reconnects" or design a session-resume mechanism.
   Probably the former for v1.
3. **Wrapper HA.** Multiple wrappers on different hosts fronting the
   same fleet. Mostly an operational concern; the wrapper is
   stateless (per-connection) so HA = load-balance + heartbeat.
4. **Dropbear / Tier 3-on-steroids.** If an org runs Dropbear and
   wants Tier 1, can the wrapper proxy to Dropbear instead of
   OpenSSH? In principle yes — Dropbear also supports
   `TrustedUserCAKeys`-equivalent (via authorized_keys options).
   Out of scope for v1.
5. **Reverse-tunnel mode.** Like Teleport's reverse-tunnel agents —
   wrapper dials *out* to a central proxy on a private port, lets
   clients reach behind-NAT hosts. Out of scope for v1.

---

## 16. Cross-references

- Decision and rationale: [ssh-rt-auth-wrapper-research.md](ssh-rt-auth-wrapper-research.md)
- Tier model: [ssh-rt-auth-server-strategy.md](ssh-rt-auth-server-strategy.md)
- v2 extension OID arc: [ssh-rt-auth-v2-enhancements.md](ssh-rt-auth-v2-enhancements.md)
- REST API (CA, called by wrapper): [ssh-rt-auth-detailed-rest-api.md](ssh-rt-auth-detailed-rest-api.md)
- Shim (reused by wrapper for CA call): [ssh-rt-auth-detailed-shim.md](ssh-rt-auth-detailed-shim.md)
- PoC overview: [ssh-rt-auth-doc-00-overview.md](ssh-rt-auth-doc-00-overview.md)
