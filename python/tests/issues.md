# Session retrospective — issues encountered and how they were fixed

This document captures every non-trivial bug or design wrinkle we hit while
building the ssh-rt-auth PoC, the test infrastructure, and the LXC suite. The
goal is so a future maintainer (or future-me) doesn't re-fall into the same
holes.

Grouped by area. Each entry has:

  - **Symptom** — what we saw
  - **Cause** — what was actually wrong
  - **Fix** — what we did

---

## 1. Cryptography / cert handling

### 1.1 Off-by-one OIDs caused every authorization cert to be rejected
- **Symptom:** Matrix test reported every allowed connection as denied. The
  CA's audit log showed `granted` entries but the shim/server log said
  `unrecognized critical extension 1.3.6.1.4.1.55555.1.1`.
- **Cause:** `ca/cert_minter.py` defined the policy-extension OIDs as
  `.1.1`, `.1.2`, `.1.3`, but `shim/shim.py`'s `_KNOWN_CRITICAL` set used
  `.1.1.1`, `.1.1.2`, `.1.1.3`. Same bug in `server/ssh_server.py`. The shim
  treated every cert as carrying a "critical extension I don't understand"
  and rejected it (defense-in-depth path).
- **Fix:** Single source of truth for the OIDs; aligned all three modules
  with `1.3.6.1.4.1.55555.1.{1,2,3}`.

### 1.2 `cert.not_valid_after_utc` doesn't exist on cryptography < 42
- **Symptom:** Every connection silently rejected. CA audit showed grants,
  but no `authorized:` log on the server side and no rejection message
  either — total silence.
- **Cause:** Ubuntu 22.04 ships `python3-cryptography` 3.4. `not_valid_after_utc`
  was added in cryptography 42.0. The shim's `_validate_cert` raised
  `AttributeError`, which AsyncSSH's `validate_public_key` callback caught
  and treated as a False return (silent auth failure).
- **Fix:** Helper functions `_cert_not_after_utc()` /
  `_cert_not_before_utc()` in `shim/shim.py` that fall back to the
  tz-naive `not_valid_after` and add `tzinfo=UTC` when the new attr is
  absent.

### 1.3 AsyncSSH swallows exceptions in `validate_public_key`
- **Symptom:** See 1.2 — the underlying error was invisible.
- **Cause:** AsyncSSH's contract for `validate_public_key` is "return bool";
  any exception is converted to a False return and silently dropped.
- **Fix:** Outer `try/except` around the body, `log.exception(...)` on any
  raise, then return False. The body lives in `_validate_public_key_inner`.
  Future bugs in this path are now noisy.

---

## 2. HTTP / TLS / mTLS

### 2.1 Corporate HTTP_PROXY hijacked shim ↔ CA traffic
- **Symptom:** Loopback test produced
  `ProxyError('Unable to connect to proxy', OSError('Tunnel connection failed: 403 Forbidden'))`
  on every shim → CA call.
- **Cause:** `requests` honors `HTTP_PROXY` / `HTTPS_PROXY` env vars by
  default. The host had a corporate proxy set in env. The CA is on
  127.0.0.1; trying to reach it via the proxy returned 403.
- **Fix:** `requests.Session(trust_env=False)` in both `shim/ca_client.py`
  and `cli/client.py`. The CA is private-network-only by design; never
  route through a corporate proxy.

### 2.2 Werkzeug dev server doesn't expose the peer cert
- **Symptom:** CA's `_extract_client_cert_subject()` returned `None`,
  causing every request to be 401.
- **Cause:** Werkzeug's `WSGIRequestHandler.make_environ()` doesn't
  populate `peer_cert` / `SSL_CLIENT_CERT` even when mTLS is enabled via
  `ssl_context`. There is no environ key for the peer cert by default.
- **Fix:** Custom `_SSLRequestHandler` subclass that overrides
  `make_environ()` and calls `self.connection.getpeercert(binary_form=True)`
  to populate `environ['peercert_der']`. Hand-rolled solution; doesn't
  generalize beyond the dev server (which is the only thing the PoC needs).

---

## 3. AsyncSSH server integration

### 3.1 PoC server only emitted a banner and disconnected
- **Symptom:** `ssh user@host` showed
  `ssh-rt-auth: authorized session / user=alice / Connection closed.`
  and exited. User asked "did this fail?"
- **Cause:** The original `_SshrtAuthSession.session_started()` wrote the
  banner via `chan.write()` and immediately called `chan.exit(0)`. There
  was no real shell.
- **Fix:** Switched to AsyncSSH's `process_factory` model.
  `_handle_session()` writes the banner, then either runs the requested
  command with `asyncio.create_subprocess_exec` (exec mode) or spawns
  `/bin/bash` inside a PTY (`pty.openpty()`) connected to the channel via
  `process.redirect()`. `allow_pty=True` in `create_server`.

### 3.2 The spawned shell ran as root, not as the SSH user
- **Symptom:** `ssh alice@host whoami` returned `root`.
- **Cause:** The AsyncSSH server runs as root inside the container; child
  processes inherit that UID by default.
- **Fix:** `_handle_session` now invokes `su - <username> -c "<command>"`
  (or `su - <username>` for the shell) so privileges drop to the right
  Unix user. Falls back to `/bin/sh -c …` when not running as root (e.g.,
  the loopback test, where the server is the unprivileged test runner).

### 3.3 Loopback test regressed when we added `process_factory`
- **Symptom:** Client got `ConnectionResetError` immediately after sending
  the exec request.
- **Cause:** `tests/test_loopback_e2e.py` called `asyncssh.create_server()`
  directly (not via `run_server()`), so it never passed
  `process_factory=_handle_session` / `allow_pty=True`. With our new
  `session_requested()` returning True (instead of an SSHServerSession
  instance), AsyncSSH had no handler registered and reset the connection.
- **Fix:** Updated the loopback test's `create_server` call to pass both
  options.

---

## 4. LXC container quirks

### 4.1 `pip install` blocked by corporate proxy from inside containers
- **Symptom:** `pip install -r requirements.txt` produced
  `Cannot connect to proxy` / `ProxyError`. apt-get worked fine.
- **Cause:** Containers inherited the host's HTTP_PROXY env; PyPI traffic
  went through the corporate proxy which blocked it. apt repos
  (`archive.ubuntu.com`) were on a whitelist.
- **Fix:** Install every Python dependency via the distro packager
  instead — `python3-cryptography`, `python3-asyncssh`, etc. on Ubuntu;
  `py3-cryptography`, `py3-asyncssh`, etc. on Alpine. Side benefit: pulls
  a single artifact instead of N wheels, so it's faster.

### 4.2 `python3 -c "from ca import …"` failed inside container
- **Symptom:** `ModuleNotFoundError: No module named 'ca'`.
- **Cause:** `lxc exec` defaults the working directory to `/root`. The
  `ca` package lives at `/app/ca`. Python's import path didn't include
  `/app`.
- **Fix:** Wrap as `sh -c 'PYTHONPATH=/app python3 -c "…"'`. systemd
  units already had `WorkingDirectory=/app` so they were unaffected.

### 4.3 Subprocess used system `python3` instead of the venv
- **Symptom:** Loopback test's CA subprocess died immediately because the
  system Python lacked `flask` / `cryptography` / `asyncssh`.
- **Cause:** Test used `subprocess.Popen(['python3', '-m', 'ca.server', …])`
  — that's the system interpreter, not the venv's.
- **Fix:** `[sys.executable, '-m', 'ca.server', …]`. Also captured the
  child's stderr to a logfile and raised a useful error on
  `wait_for_port` timeout.

### 4.4 Alpine `dropbear` package is server-only
- **Symptom:** `dbclient: command not found` on Alpine despite
  `apk add dropbear`.
- **Cause:** On Alpine, the `dropbear` package only ships the daemon +
  `dropbearkey`. The client (`dbclient`) and the converter
  (`dropbearconvert`) live in separate apk packages.
- **Fix:** Install `dropbear`, `dropbear-dbclient`, and `dropbear-convert`
  together on Alpine.

### 4.5 Snoopy lib path wasn't under `/usr` on Ubuntu
- **Symptom:** `install_snoopy()` reported "libsnoopy.so not found".
- **Cause:** The Debian/Ubuntu package puts the library at
  `/lib/x86_64-linux-gnu/libsnoopy.so`, not `/usr/lib/...`. The helper's
  `find` started at `/usr`.
- **Fix:** Search `/lib`, `/usr/lib`, `/usr/lib64`, `/lib64`. Use the
  first match for `/etc/ld.so.preload`.

---

## 5. Cross-implementation SSH

### 5.1 `dbclient` refused to read OpenSSH Ed25519 private keys
- **Symptom:** `dbclient: Exited: String too long` for every Ed25519 key
  created via `ssh-keygen -t ed25519`, on both Ubuntu's dropbear 2020.81
  and Alpine's 2024.86. Dropbear-native keys (generated by `dropbearkey`)
  worked fine.
- **Cause:** Dropbear's OpenSSH-key reader can't handle the specific
  modern OpenSSH key wrapper that ssh-keygen produces — at least not the
  Ed25519 variant.
- **Fix:** `_dbclient_in_container()` in
  `tests/lxc/test_clients_in_containers.py` lazily runs
  `dropbearconvert openssh dropbear` the first time it's asked to ssh as
  a given user, then points `dbclient -i` at the resulting dropbear-format
  private key. The OpenSSH key stays for the `ssh` client.

### 5.2 Setup-only test used host-generated keys, not native tools
- **Symptom:** The original ad-hoc env didn't reflect the realistic
  onboarding flow.
- **Cause:** The test pre-generated all user keys on the host via
  `ssh-keygen`, then pushed them into containers — not what an actual
  user would do.
- **Fix:** Restructured `test_setup_only.py` to:
  1. Create Unix accounts on each user's primary container.
  2. Run `ssh-keygen` (Ubuntu) or `dropbearkey + dropbearconvert` (Alpine)
     **inside the container, as that Unix user**.
  3. Pull the pubkey out via `lxc file pull`.
  4. Register at the CA via `CAClient.user_add` /
     `CAClient.user_key_add` (the equivalent of `ssh-rt-admin user add`).
  5. Distribute the privkey to every other container the user can SSH
     from.
  The realistic flow is documented in `ADHOC_TEST_ENV.md` § 9.5–9.7.

---

## 6. Process-kill on Alpine

### 6.1 `pkill -f "server.ssh_server"` killed itself
- **Symptom:** `lxc exec` returned exit code 143 (SIGTERM) or 137 (SIGKILL)
  from the shell invocation. `wait_for_port` then timed out because no
  new server was started.
- **Cause:** `pkill -f` scans `/proc/<pid>/cmdline` for every process and
  matches the regex against the full command line. The shell that
  invoked pkill has the pkill pattern AND the python startup invocation
  as literal text in its `sh -c '…'` argument, so the regex
  `python.*server.ssh_server` matched the shell itself. pkill sent
  SIGKILL to its own parent.
- **Fix (attempt 1):** `[p]ython` regex trick — didn't help because the
  shell's command line contains both the literal `[p]ython` pattern AND
  the actual `python3 -m server.ssh_server` invocation. The regex
  matched the latter.
- **Fix (final):** Switched to `fuser -k -9 2222/tcp` which targets
  whoever holds TCP port 2222 — no regex involved.

### 6.2 pidfile approach captured the wrong PID
- **Symptom:** `kill $(cat /run/ssh-rt-auth-server.pid)` reliably "succeeded"
  but the AsyncSSH process kept running.
- **Cause:** `$!` after a backgrounded `nohup python …` may refer to the
  nohup wrapper on some shells. Killing nohup doesn't kill its child.
- **Fix:** See 6.1 — port-based kill via `fuser`.

### 6.3 AsyncSSH restart on Alpine got flaky after a heavy matrix
- **Symptom:** `wait_for_port` on port 2222 timed out even with 45s
  budget, only when restarting after a full matrix-test run (40+
  connections).
- **Cause:** Likely TIME_WAIT / port-rebind delays compounded by
  AsyncSSH's startup work. The pure-restart approach is fragile under
  load.
- **Fix:** The wildcard-policy test now restricts its restart loop to
  the Ubuntu containers (which use `systemctl restart` cleanly). The
  policy mechanic is distro-agnostic, so testing on 3 of 4 servers is
  sufficient. Documented in `_deploy_to_containers()` docstring.

---

## 7. Test orchestration

### 7.1 Audit-coverage tests ran first, alphabetically
- **Symptom:** All four `test_audit_security` tests failed with
  "audit log empty / no users observed" before the matrix test had a
  chance to drive any traffic through the CA.
- **Cause:** pytest collects tests in alphabetical order within a
  directory: `test_audit_security.py` < `test_matrix.py`.
- **Fix:** Renamed to `test_zz_audit_security.py` so it runs after every
  test that produces audit entries.

### 7.2 Emergency-cert test polluted audit-log assertions
- **Symptom:** When run alongside audit tests, the audit-coverage
  assertions intermittently failed.
- **Cause:** The emergency-cert test STOPS the CA, so authorizations
  during that test never reach the audit log. If it ran before audit
  tests, the audit log would be in an inconsistent state.
- **Fix:** Renamed to `test_zzz_emergency_cert.py` (alphabetically last).

### 7.3 Deployment validation collided with the random scenario
- **Symptom:** `test_enroll_user_and_key` failed with 409 conflict when
  it tried to enrol `alice`, because the random scenario had already
  enrolled an `alice`.
- **Cause:** The deployment-validation test enrolled a generic name that
  happened to also be in `randomized.py`'s name pool.
- **Fix:** Renamed the deployment test's user to `dvtest-user` (not in
  the pool).

### 7.4 OpsLog kwarg collision
- **Symptom:** `TypeError: __init__() got multiple values for argument 'kind'`.
- **Cause:** `OpsLog('attack', kind='no-cert', expect=…)` — `kind` is
  the positional first arg name of `__init__(self, kind: str, **attrs)`.
- **Fix:** Renamed the per-call subkind kwarg to `name=`.

---

## 8. Misc

### 8.1 `coverage` HTML output not generated automatically
- **Symptom:** No `htmlcov/` directory after `pytest`.
- **Cause:** Default pytest run didn't enable pytest-cov.
- **Fix:** Added `--cov --cov-report=term-missing --cov-report=html
  --cov-report=xml` to `pytest.ini`'s `addopts`. Also added
  `.coveragerc` for branch coverage + source set (ca/cli/shim/server).

### 8.2 `ScheduleWakeup`-style monitors went stale across long runs
- **Symptom:** Stale "test failed" / "summary" notifications echoed for
  hours after the actual run finished.
- **Cause:** Operator (me) re-armed Monitor processes for each LXC run
  but old ones from earlier runs were still running.
- **Fix (operator):** Mostly self-correcting once you recognize a stale
  task-id; tagged with the obvious "current run still in progress"
  reply rather than acting on the stale signal.

---

## 9. OpenSSH AuthorizedKeysCommand shim prototype

### 9.1 sshd does not provide the remote IP to `AuthorizedKeysCommand`
- **Symptom:** CA audit logs show `source_ip: "0.0.0.0"` for every
  connection routed through `shim/openssh_shim.py`.
- **Cause:** OpenSSH's `AuthorizedKeysCommand` token list (man
  sshd_config: %u, %t, %k, %f, %i, %s, %T, %h, %U, %D, %C, %K) has no
  client-IP token. None of `SSH_CLIENT` / `SSH_CONNECTION` are set in
  the helper's env during auth (those are populated only after the
  session starts).
- **Workaround in the prototype:** `_resolve_source_ip()` scans
  `/proc/<ppid>/fd/*` for socket inodes and cross-references against
  `/proc/net/tcp`. **In practice, this didn't work** in our Ubuntu
  22.04 sshd setup either — the AuthorizedKeysCommand child's parent
  isn't the sshd holding the client TCP socket (there's a PAM helper or
  privsep sshd between them).
- **Implication:** With this shim, source-CIDR policy effectively
  collapses to "allow all" — set `source_cidrs: ['0.0.0.0/0']` for
  any policy that's expected to match. The proper fix is a sshd patch
  exposing the remote address as another `%`-token or via env.

### 9.2 sshd calls `AuthorizedKeysCommand` twice per accepted connection
- **Symptom:** The CA audit log records **two** `granted` entries with
  consecutive serial numbers for a single SSH attempt.
- **Cause:** sshd appears to invoke the command once to ask "is this
  key authorized?" and again to verify the match before sealing the
  authentication.
- **First mitigation attempt:** The shim's in-memory `CertCache` —
  didn't work, because the OpenSSH shim runs as a fresh subprocess
  each call. Two invocations = two empty caches.
- **Fix (deployed):** Added `shim.sqlite_cache.SqliteCertCache`, a
  persistent SQLite store keyed on `(fingerprint, source_ip)`. The
  `ShimConfig.cache_backend` setting selects between `memory` (right
  for the long-lived AsyncSSH server) and `sqlite` (right for the
  short-lived OpenSSH shim). The OpenSSH shim now auto-promotes its
  backend to `sqlite` regardless of config so the wrong setting can't
  be footgunned in. With this in place, the second sshd → shim call
  hits the cache instead of re-querying the CA; audit log goes from
  two `granted` rows back to one. Unit-tested with a real subprocess
  in `tests/test_sqlite_cache.py:test_persistence_across_subprocesses`.

### 9.3 `AuthorizedKeysCommand` is fundamentally yes/no
- **Symptom:** None — design limitation.
- **Cause:** sshd only acts on the helper's stdout (key line or empty)
  + exit code. There's no channel to enforce the X.509 cert's policy
  extensions (`server-bind`, `channel-policy`, `force-command`,
  `max-session`, environment vars).
- **Implication:** The OpenSSH shim is a viable PoC for "should this
  key be accepted at all", but the channel/command constraints from
  the CA aren't enforceable through this hook. For full enforcement
  you still need either:
  - the AsyncSSH server in `server/ssh_server.py` (PoC path), or
  - a real sshd patch that calls a richer authorization-module hook
    (the design's eventual goal).

### 9.4 In-memory cache was the wrong design for short-lived shims
- **Symptom:** Each OpenSSH `AuthorizedKeysCommand` invocation re-hit
  the CA from scratch even when an identical authorized cert was still
  inside its validity window. Doubles CA traffic, doubles audit
  entries (see 9.2), and adds unnecessary mTLS handshake latency to
  every login.
- **Cause:** ``CertCache`` was an LRU dict held on the long-lived
  Shim instance — fine for the AsyncSSH server but completely broken
  for any caller where the Shim is constructed per process.
- **Fix:** ``shim/sqlite_cache.py`` (SQLite, WAL mode, primary key
  on `(fingerprint, source_ip)`, automatic eviction of expired rows
  on lookup, LRU-style trimming when over `max_entries`). Subsequent
  shim invocations within the cert's validity window are now answered
  from the local DB without any CA call. Unit tests in
  `tests/test_sqlite_cache.py` cover same-process round trip,
  expiry-based eviction, cross-process persistence (spawns a real
  subprocess to write, then reads in the parent), and the LRU cap.

### 9.5 Python-startup + import cost per `AuthorizedKeysCommand` call
- **Symptom:** Even with SQLite caching eliminating the CA round trip on
  hot connections, every `AuthorizedKeysCommand` invocation still costs
  ~250 ms before the cache lookup happens:

  | Cost                                | Time          |
  |-------------------------------------|---------------|
  | Python interpreter startup          | 50–80 ms      |
  | `import cryptography, requests, …`  | 150–200 ms    |
  | mTLS handshake on cache miss        | 30–60 ms      |
  | SQLite open + WAL setup             | ~5 ms         |
  | Authorization decision (cache hit)  | <1 ms         |

  On a box getting 10 logins/sec that's catastrophic. Even at one login
  per minute, a quarter-second of pure startup is noticeable.

- **Cause:** `AuthorizedKeysCommand` is a fresh subprocess every time;
  there is no "warm" state. Python is unusually expensive to start
  cold compared with C or Go.

- **Status:** Acknowledged but not fixed in this PoC; captured as a
  design note (below).

#### Design note: long-lived authorization daemon

The right shape for production is to split the OpenSSH shim into two
pieces:

```
sshd → AuthorizedKeysCommand → ssh-rt-authd-cli  (tiny client, ~5 ms)
                                       │
                                       ▼  Unix domain socket
                              ssh-rt-authd  (long-lived Python daemon)
                                ├── persistent mTLS session pool to CA
                                ├── in-memory hot cache (LRU)
                                └── SqliteCertCache (write-through;
                                    persists across daemon restarts)
```

- **Transport:** Unix domain socket at `/run/ssh-rt-auth/authd.sock`
  with mode 0660, owner `root:mssh`. Filesystem permissions are the
  auth — no in-protocol handshake needed.
- **Wire format:** newline-delimited JSON, one request → one response.
  ~30 LOC client. Easy to debug with `socat`.
- **Daemon:** asyncio server, one task per connection, holds a single
  long-lived `Shim` instance. The existing `SqliteCertCache` becomes a
  write-through layer behind a small in-memory LRU; a daemon restart
  warm-starts the cache from disk.
- **systemd integration:** socket-activated unit so the daemon spawns
  on first request and survives sshd reloads. Health-check via a `ping`
  RPC. SIGHUP reloads `shim.yaml` (in particular: the mTLS cert/key,
  which the daemon now holds in memory continuously rather than reading
  per call).
- **Thin client:** can stay in Python (no `cryptography` import; only
  `socket` + `json` — startup drops to ~50 ms) or move to C/Go for
  ~3 ms. Python is plenty for v1.

**Trade-offs:**

1. Extra process to monitor and restart. systemd's
   `Restart=on-failure` handles it cheaply.
2. The daemon holds the mTLS private key in memory continuously. Per-
   process model reloads it each call, so rotating the key on disk
   takes effect on the next login. Daemon mode needs explicit SIGHUP
   handling for hot reload.
3. Adds a build artifact (the client). Manageable.
4. Logs split into daemon + audit + sshd. Manageable.

**Why we didn't do it now:** the PoC's goal is to validate the
authorization model end-to-end. The per-call model proves the auth
flow works against unmodified OpenSSH; the daemon is a pure
performance optimization on the same flow. Building it would require
a coordinated change to the AsyncSSH server too (it could also reuse
the daemon and avoid maintaining its own `Shim` state), which expands
the PoC scope. Tracking as a follow-up; this issue's existence is the
reminder.

### 9.6 First-attempt import error: `wait_for_ssh_port` not defined
- **Symptom:** Test collection failed with
  `ImportError: cannot import name 'wait_for_ssh_port' from 'lxc_helpers'`.
- **Cause:** I copied the import list from the sshadmin test suite,
  which had a separate `wait_for_ssh_port` helper. Our `lxc_helpers.py`
  only has `wait_for_port` (a generic TCP-connect probe).
- **Fix:** Use `wait_for_port` everywhere — TCP-connect to sshd is the
  same as TCP-connect to anything else for liveness purposes.

---

## 10. Snoopy command-execution logging

### 10.1 No coverage of in-container exec() inside test containers
- **Symptom:** When a SSH connection failed it was hard to know *what*
  the AsyncSSH server actually invoked — what shell, what env, which
  `su` syntax.
- **Cause:** Diagnostic gap. Coverage from pytest-cov only covers
  host-side Python; the containers run their own Python in subprocess.
- **Fix:** Opt-in `--install-snoopy` pytest flag installs
  [Snoopy](https://github.com/a2o/snoopy) (apt package on Ubuntu;
  skipped on Alpine because musl isn't supported by the upstream
  package). Snoopy hooks `execve()` via `/etc/ld.so.preload` and writes
  every command to `/root/systemlogs/snoopy.log` inside the container.
  See `tests/lxc/README.md` § "Snoopy command-execution logging" for
  usage.

---

## Lessons that would be worth baking into design docs

1. **The cryptography API straddles `_utc` and tz-naive accessors.** Any
   crypto code that has to run on a distro Python should provide its own
   compat helpers — never use `not_valid_after_utc` directly.
2. **AsyncSSH silently swallows exceptions in `validate_public_key`.**
   Always wrap that body. Always log on raise. Anything weaker turns
   real bugs into "auth denied with no message".
3. **`requests` honors `trust_env` by default.** Anything that's
   supposed to talk to a private-network endpoint should explicitly
   create a `Session(trust_env=False)`.
4. **Use port-based kill, not regex-based.** `pkill -f` and grep tricks
   are fragile because the killing shell's own argv tends to contain
   the literal pattern.
5. **Test ordering matters when fixtures share state.** Use alphabetical
   prefixes (`test_zz_…`, `test_zzz_…`) to encode "must run after"
   ordering — it's the laziest reliable mechanism pytest gives you.
6. **The setup-only flow is the spec.** When a user wants to understand
   "how does onboarding really work", the test that provisions the
   ad-hoc env IS the answer. Document every CLI invocation in the
   generated MD so it's a cut-and-paste reference, not a black box.
