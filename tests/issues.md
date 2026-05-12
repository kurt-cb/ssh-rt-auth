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

## 9. Snoopy command-execution logging

### 9.1 No coverage of in-container exec() inside test containers
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
