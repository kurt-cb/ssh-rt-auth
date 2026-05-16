# Patch plan — design notes

Detailed rationale + file-and-line targets for each patch in the series.

> **Scope update (2026-05-14, revised):** per
> [../ssh-rt-auth/design/ssh-rt-auth-server-strategy.md](../ssh-rt-auth/design/ssh-rt-auth-server-strategy.md)
> and [../ssh-rt-auth/design/ssh-rt-auth-wrapper-research.md](../ssh-rt-auth/design/ssh-rt-auth-wrapper-research.md),
> Tier 1 is now wrap-and-proxy (mTLS wrapper + hermetic inner OpenSSH),
> not a greenfield server. OpenSSH stays **Tier 3 — compatibility
> mode**, supported with documented limitations. Active patches are
> now **0002** and **0003** only — both close real security gaps in
> Tier 3 and have independent upstream value for any AKC helper. The
> previously-active **0002b** (rich JSON env var) is **dropped** —
> subsumed by the wrapper, not worth the maintenance cost given the
> Tier 3 cohort is small. The larger 0004–0007 series stays demoted to
> design notes.

The line numbers are placeholders — they refer to upstream `V_9_9_P1`
and may drift in newer tags. The `dev-loop.sh` script will tell you when
a patch fails to apply.

## Active patches (upstream-targeted)

| # | Patch | Status | LOC | Purpose |
|---|-------|--------|-----|---------|
| 0002 | Connection-endpoint tokens for AKC (`%R %r %L %l %I`) | active | ~30 | Source-CIDR policy + split-domain identification (which interface / subnet accepted the connection) |
| 0003 | `SSH_AKC_PHASE` env var | active | ~10 | **Security patch.** Lets the shim skip CA query during the unauthenticated SSH publickey `query` phase, so the CA is hit only after sshd has verified a signature. Closes the "attacker without credentials drives CA queries" attack surface. |

## Dropped / design-note patches (not on the critical path)

| # | Patch | Status | LOC |
|---|-------|--------|-----|
| 0001 | Instrumentation | obsoleted | ~20 |
| 0002b | `SSH_CONNECTION_CONTEXT` JSON env | **dropped (2026-05-14)** — subsumed by Tier 1 wrapper; small Tier 3 cohort doesn't justify maintenance cost | ~80 |
| 0004 | `AuthorizationModule` directive | deferred | ~500–800 |
| 0005 | `mssh-channel-policy` enforcement | deferred | ~80 |
| 0006 | `mssh-force-command` enforcement | deferred | ~50 |
| 0006b | `mssh-environment` enforcement | deferred | ~30 |
| 0007 | `CheckExpireCommand` + session timer | deferred | ~200 |
| 0007b | `AuthorizationAuditCommand` | deferred | ~50 |
| 0009–0012 | v2 OID enforcement (session-bind, host-key-pin, crypto-floor, auth-method) | deferred | ~30 each |

---

## 0001 — instrument AuthorizedKeysCommand calls (investigation only)

**Status: largely obsoleted by static analysis** — the double-call
mystery is the SSH publickey-auth protocol, not a sshd implementation
quirk. See below. Keep this patch around only if you want runtime
counters for the env-var patch (0003) to confirm both phases route
through `SSH_AKC_PHASE` correctly.

### Where the call actually originates (V_9_9_P1)

There is **one** call site, in `auth2-pubkey.c`:

```
auth2-pubkey.c:617  user_key_command_allowed2(...)        # the helper
auth2-pubkey.c:712          subprocess("AuthorizedKeysCommand", ...)
auth2-pubkey.c:800  ... = user_key_command_allowed2(...)  # only caller
auth2-pubkey.c: 89  userauth_pubkey(struct ssh *ssh, ...)
```

`user_key_command_allowed2()` is invoked exactly once per call to
`userauth_pubkey()`. The reason we see TWO calls per accepted
connection is that **`userauth_pubkey()` itself is called twice** —
once for "querying" the key, once for "attempting" with a signature:

```c
/* auth2-pubkey.c:130 */
debug2_f("%s user %s %s public key %s %s",
    authctxt->valid ? "valid" : "invalid", authctxt->user,
    have_sig ? "attempting" : "querying", pkalg, keystring);
```

The `have_sig` flag (parsed from the wire 12 lines earlier) is the
discriminator:

- `have_sig == 0` → client is asking "would you accept this key?"
  sshd runs the auth check, replies `SSH_MSG_USERAUTH_PK_OK` to
  mean "yes, send me a signature".
- `have_sig == 1` → client has signed a challenge with the key.
  sshd runs the auth check again, also verifies the signature.

This is RFC 4252 §7 — the protocol can't accept on the first message
because the client hasn't proved it holds the private key. Trying to
"fix" this by deduplicating sshd-side would either weaken security
(skipping the verify-phase auth check is wrong) or break protocol
compliance.

### Implication for the patch series

Patch 0003 (`SSH_AKC_PHASE` env var) is exactly the right fix.

- In `userauth_pubkey()` we already know which phase we're in — it's
  `have_sig`. Pass `have_sig` down to `user_key_command_allowed2()`.
- In `user_key_command_allowed2()`, just before the `subprocess()`
  call, set the env var so the child inherits it:

  ```c
  setenv("SSH_AKC_PHASE", have_sig ? "verify" : "query", 1);
  ```

  (Or extend `subprocess()` to take an env-var list; cleaner but
  bigger patch surface.)
- Drop or skip the investigation patch — we don't need empirical
  confirmation any more.

---

## 0002 — connection-endpoint tokens for AuthorizedKeysCommand

**Goal:** plumb both ends of the TCP connection through to the helper
so the CA can enforce source-CIDR policy AND distinguish which
interface / subnet accepted the connection (split-domain hosts).
Today the only way to know any of this is fragile `/proc` scraping.

Tokens added (letters subject to upstream review — these are intent
descriptions, not committed slot assignments):

| Token | Substitutes to                          | Source in sshd          | Use case                                       |
|-------|-----------------------------------------|-------------------------|------------------------------------------------|
| `%R`  | Remote client IP address                | `remote_ipaddr_string()`| Source-CIDR policy (issues.md § 9.1)           |
| `%r`  | Remote client port                      | `remote_port()`         | Audit; correlate with conntrack / proxy logs   |
| `%L`  | Local IP that accepted the connection   | listen socket `getsockname()` | **Split-domain identification.** Lets the CA say "admin role authorizable only when sshd accepted the connection on the mgmt VLAN's IP." Server already knows this; not sensitive. |
| `%l`  | Local port that accepted the connection | listen socket `getsockname()` | Multi-port sshd (e.g., port 22 for general, port 2222 for admin); audit/policy can distinguish. |
| `%I`  | Interface name (`eth1`, …)              | `SO_BINDTODEVICE` / route lookup | Where the OS exposes it cheaply. Optional — fall back to empty string if not determinable. |

**Why no subnet token:** the subnet → zone mapping is a CA-side concern
(the enrollment DB already knows which IPs / interfaces map to which
security zones). Pushing CIDR arithmetic into sshd is the wrong place
for that decision — sshd just exposes the local endpoint and lets the
CA classify it.

**Why this matters and isn't a security risk:** the server's own
network topology (which IPs / interfaces it has, which port accepted a
connection) is information the server already has and that any local
process can already determine via `ss` / `netstat`. Exposing it to the
authorization helper through stable tokens is strictly safer than the
status quo (scraping `/proc/net/tcp`) and unlocks split-domain policy
that's otherwise unstateable.

**Targets:**

- `servconf.c` — the token table for `AuthorizedKeysCommand`. Look for
  `expand_path_args` or similar. Add the new tokens to the substitution
  list.
- `auth-options.c` — pass the remote IP, remote port, local IP, local
  port, and interface name through to the substitution context.
- `sshd.c` / `serverloop.c` — the listen socket has `getsockname()`
  data available at accept-time; surface it on the per-connection
  struct so it's reachable from the AKC code path.

**Verify:**

```
AuthorizedKeysCommand /usr/bin/env %R %r %L %l %I
```

ssh in from a known source, see all five values in the env output.
Multi-home the host, ssh in from clients reaching different interfaces,
confirm `%L` / `%I` reflect which leg accepted the connection.

**~30 lines** (was ~10 for `%R` alone; the local-side additions are
~5 LOC each — most of the diff is the new fields on the connection
struct + the substitution-table entries).

**Strong candidate for upstream submission first** — self-contained,
strictly additive, useful to every AKC helper (LDAP, Vault, IAM
bridges, ours). The split-domain story is independently compelling
enough that this should land cleanly on its own.

**Relationship to 0002b:** these same five fields also land in
`SSH_CONNECTION_CONTEXT` as `source_ip`, `source_port`, `local_ip`,
`local_port`, `interface` (v2-enhancements § 2). 0002 is "easy
incremental win using existing extension mechanism"; 0002b is "richer
context for helpers willing to parse JSON". Helpers can use either.

---

## 0002b — `SSH_CONNECTION_CONTEXT` env var (rich JSON blob) — DROPPED

**Status: DROPPED 2026-05-14.** After the Tier 1 → wrap-and-proxy
decision, this patch's value collapsed: the wrapper provides
everything 0002b would have (richer connection context, kex/cipher
visibility, etc.), and the Tier 3 cohort that would benefit from
0002b in isolation is small. ~80 LOC + ongoing upstream-rebase
maintenance isn't justified for a forensics-only improvement on a
deliberately-degraded tier. Section preserved below as design notes
in case someone wants to revive the upstream contribution
independently of ssh-rt-auth (it's still useful to any AKC helper
wanting rich context — LDAP, Vault, IAM bridges).

**Goal:** complement `%R` with a comprehensive, forward-compatible
connection-context JSON document delivered to `AuthorizedKeysCommand`
via environment variable. Fields the helper doesn't read are ignored;
fields a future helper adds need no further sshd change. The full
schema is the v2 spec in
[../ssh-rt-auth/design/ssh-rt-auth-v2-enhancements.md](../ssh-rt-auth/design/ssh-rt-auth-v2-enhancements.md)
§ 2.

**Why a JSON env var rather than more `%`-tokens:**

- **Open-ended.** Token slots are scarce and one-per-letter; the schema
  evolves. Env-var JSON is unbounded.
- **No `ps` exposure.** Same locality argument as `SSH_AKC_PHASE`
  (issue 0003 above): env vars stay in the child's address space.
- **Backward compatible.** Helpers that ignore the env var see no
  behaviour change.
- **Useful beyond ssh-rt-auth.** Any AKC helper (LDAP, Vault, IAM
  bridges) benefits from richer context — strong upstream-submission
  pitch.

**Wire format:**

```bash
SSH_CONNECTION_CONTEXT='{"source_ip":"10.0.1.42",…}'
```

JSON document matching the `connection` object in v2-enhancements § 2.
Schema versioning via a `"_schema": "ssh-rt-auth-v2.0"` key at the
root. Compact encoding (no whitespace) to keep env size small.

**Targets:** `auth2-pubkey.c` near the existing `subprocess()` call.
Build the JSON document from the same data sshd already has on hand
when expanding `%`-tokens (`ssh->kex`, `authctxt`, the listening
socket, etc.).

**Size budget:** typical context is ~600–900 bytes. `ARG_MAX` /
`ENV_MAX` is at least 128 KB on Linux — comfortably in budget.

**~80 lines** including the JSON builder. Self-contained patch.

**Verify:** `AuthorizedKeysCommand /usr/bin/env`, grep
`SSH_CONNECTION_CONTEXT`, jq the value.

---

## 0003 — set `SSH_AKC_PHASE` env var on AuthorizedKeysCommand calls

**Status: REINSTATED as a security patch.** The earlier skip-rationale
treated this as a perf optimization that the SQLite cache already
covered. That missed the real value: with this patch the shim can
**decline to contact the CA during the unauthenticated SSH publickey
`query` phase**, so the CA is only queried after sshd has verified a
client signature. Closes the "attacker without credentials drives CA
queries" attack surface
([../ssh-rt-auth/design/ssh-rt-auth-server-strategy.md](../ssh-rt-auth/design/ssh-rt-auth-server-strategy.md)
§ 3, [../ssh-rt-auth/tests/issues.md § 9.1–9.3](../ssh-rt-auth/tests/issues.md)).
This is the most important hardening available for the Tier 3 path.

UX trade-off: clients with multiple keys in their agent get prompted
to sign each one before being told "no", instead of being told "no"
immediately. Acceptable cost for the security win.

**Goal:** sshd calls the helper twice per accepted connection — first to
enumerate candidate keys (`SSH_AKC_PHASE=search`), second to verify a
specific key+signature pair (`SSH_AKC_PHASE=verify`). The verify call
is the one that matters; the search call is redundant for any helper
that returns a stable yes/no per (user, key) tuple.

Letting the helper know which phase it's in means new helpers can skip
the search-phase work entirely (return empty), forcing sshd into the
verify phase. The CA only sees the call that matters, the audit log
goes back to one entry per login, and the security properties are
identical.

**Why an env var rather than a new `%`-token or new directive:**

- **Strict backward compatibility.** Existing helpers never read
  `SSH_AKC_PHASE`; their behaviour is unchanged. No config update, no
  syntax change. The kernel of the change is one `setenv()` call.
- **No new attack surface in `ps`.** Tokens get substituted into the
  helper's `argv` (visible in `ps -ef`). Env vars stay in the child's
  address space — same locality as the key material itself.
- **Trivial patch.** ~10 lines in `auth-options.c` (or wherever the
  spawn happens — pin via 0001 first).

**Helper-side usage (in our PoC):**

```python
# openssh_shim.py
if os.environ.get('SSH_AKC_PHASE') == 'search':
    sys.exit(0)            # empty stdout → sshd moves on to verify
# else: full CA call
```

**Targets (confirmed against V_9_9_P1):**

- `auth2-pubkey.c:617`-ish — function signature of
  `user_key_command_allowed2`. Add an `int have_sig` parameter.
- `auth2-pubkey.c:800` — single call site of
  `user_key_command_allowed2`; pass through the `have_sig` from
  `userauth_pubkey`'s wire-parsed packet.
- `auth2-pubkey.c:712` — just before the existing `subprocess(…)`
  call, do `setenv("SSH_AKC_PHASE", have_sig ? "verify" : "query", 1)`
  in the parent. `subprocess()` is fork+exec'd so the child inherits
  the env.

**~10 lines.** Strong upstream-submission candidate — self-contained,
zero behaviour change for existing users, useful for any helper that
wants to be smarter about double-calls.

**Alternative (rejected):** drop the first call entirely. That's a
behaviour change for existing AuthorizedKeysCommand consumers (some
of which rely on the enumeration call to refresh server-side state).
Backward-incompatible. Skip.

---

## 0004 — `AuthorizationModule` sshd_config directive (the big one)

**Goal:** add the post-userauth authorization hook that the design
doc 01 specifies. After sshd has verified the client's signature, it
calls `AuthorizationModule` (an arbitrary binary) with the
**full v2 connection context** (see
[../ssh-rt-auth/design/ssh-rt-auth-v2-enhancements.md](../ssh-rt-auth/design/ssh-rt-auth-v2-enhancements.md)
§ 2) and the raw identity proof blob.

…and receives back an X.509 authorization cert (DER) + serial. sshd
parses the cert's critical extensions and stores them on the session
struct (`Authctxt`?) so the channel-open / force-command code can read
them.

**Targets:**

- `servconf.c` + `servconf.h` — directive parsing.
- `auth.c` — call the module after `userauth_finish`.
- `auth.h` — add fields to `Authctxt`: `auth_cert`, `auth_cert_len`,
  `auth_cert_serial`, `auth_channel_policy`, …
- `serverloop.c` / `channels.c` — consult the stored fields in
  `session_input_channel_req` / channel-open paths.

**Wire format:**

- **STDIN:** single JSON document, newline-terminated, matching the
  v2 `connection` schema. The identity blob (pubkey or OpenSSH cert)
  is included as a base64-encoded field, NOT as a separate raw input —
  one wire format end-to-end avoids the "two inputs, two failure
  modes" headache.
- **STDOUT:** the X.509 authorization cert (DER, base64-encoded on
  one line). Empty stdout means "deny but without a reason"; reasons
  belong on stderr.
- **Exit code:** 0 = grant, non-zero = deny. STDERR is forwarded to
  sshd's log channel for diagnostics.
- **Schema versioning:** the inbound JSON has a `"_schema":
  "ssh-rt-auth-v2.0"` key so module implementations can fail-fast on
  unknown versions; the cert is the response carrier, so it carries
  its own version via the OID arc reservation
  (v2-enhancements § 4).

Picking JSON over a binary framing is a deliberate v2 choice: every
field that lands in this blob also lands in the CA's audit log (see
v2-enhancements § 3), so being able to grep/jq it is a operational
multiplier. The dependency cost is one libjson — every modern distro
ships one; sshd already links against several heavier libs.

**~500–800 lines** depending on how much of the cert parsing lives in
sshd vs in a helper library. Most of it is plumbing fields through
the session struct.

**Submission strategy:** likely needs an RFC-style discussion on
openssh-unix-dev before sending the patch. Could land as
"AuthenticationModule" framework with our extensions as the first
consumer.

---

## 0005 — enforce `mssh-channel-policy` on channel-open

**Goal:** when the session has a stored channel-policy extension,
every `channel_input_open_request` checks the channel type against
the allowed list. Reject (with `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`)
if not present.

**Targets:**

- `channels.c` — the channel-type dispatch table. Wrap or replace.
- `serverloop.c` — for global request channel opens.

**Depends on 0004** (needs the policy fields on the session).

**~80 lines.**

---

## 0006 — enforce `mssh-force-command`

**Goal:** when the cert carries a force-command extension, override
the client's exec / shell request with the specified command. Mirrors
the existing `ForceCommand` config directive but driven per-connection
by the cert, not statically.

**Targets:** `session.c`, specifically `do_exec` / `do_exec_pty` /
`do_exec_no_pty`.

**Depends on 0004.**

**~50 lines.**

---

## 0007 — `CheckExpireCommand` + session-side timer

**Goal:** enforce the cert's `notAfter` during the live session. Add
a directive `CheckExpireCommand` and an internal timer that fires at
`notAfter - 60s`. sshd calls the command with the cert serial + the
session's connection context. Possible responses:

- `refresh\n` + a new cert (DER on stdout) → sshd swaps in the new
  cert and resets the timer.
- `terminate\n` → sshd sends `SSH_MSG_DISCONNECT` with reason
  "expired" and closes the session.

**Targets:** `serverloop.c` — add the timer to the select() loop;
`session.c` — the disconnect path; `servconf.c` for the directive.

**Depends on 0004.** Also implies a new code path for "rotate
authorization cert mid-session" which doesn't exist today.

**~200 lines.**

---

## 0008 — REMOVED

Previously: "drop AuthorizedKeysCommand fallback". Removed because it
contradicts [v2-enhancements § 5.7](../ssh-rt-auth/design/ssh-rt-auth-v2-enhancements.md)
and the project principle that **unpatched sshd MUST keep working**.
The legacy `AuthorizedKeysCommand` path stays operational forever; it
is the bedrock that lets an org deploy ssh-rt-auth without waiting on
a distro update.

---

## Open questions

1. **Cert format.** Upstream OpenSSH already uses its own (non-X.509)
   certificate format for SSH user certs. Plumbing X.509 in as the
   "authorization" cert may meet resistance from upstream. The
   `AuthorizationModule` interface is cert-format-agnostic (binary on
   stdout) — that should be enough framing for upstream review even if
   they don't want to ship cert-parsing code.
2. **Audit hook.** The PoC sends every grant/deny to the CA's audit
   log. sshd already has its own logging via `LogLevel`. We may want a
   `AuthorizationAuditCommand` directive too. Stretch goal.
3. **Multi-process sshd.** sshd's privsep architecture forks for each
   connection. The `AuthorizationModule` call should happen in the
   monitor process (which has access to private keys for signature
   verification anyway), then the result is passed to the privsep
   child. Care needed around when the timer for 0007 fires —
   probably in the privsep child since that's where the session
   lives.
