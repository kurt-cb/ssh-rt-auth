# Handoff — picking up the mssh work

State as of commit `4ef9818` (post-rename). This file exists so a
fresh session — Claude or human — can resume quickly without
re-reading the conversation history.

If you're an LLM picking this up: read **this file first**, then
`CLAUDE.md`, then the current `design/` and `docs/`. The
`archive/` directory is historical reference only; don't write
into it.

## Recent commits (most recent → older)

| Hash | Title |
|---|---|
| `4ef9818` | rename Python package sshrt → mssh; entry-point binaries → mssh-* |
| `3055256` | Updated fixtures (msshd_env + test_msshd_matrix.py) |
| `b5c56e9` | msshd: serve a pre-auth Banner via the hermetic inner sshd |
| `a641693` | phase2-ideas §16: distro packaging path (.deb/.rpm/.apk) + Go+musl caveat |
| `17a92cf` | doc reorg: clean-room mssh rewrite; archive old design + docs |
| `4f41ec2` | adhoc lab: host-side workflow, hide lxc from the tester |
| `bc07738` | adhoc lab: flip scripts run on CA, model real operator workflow |
| `b8317ed` | adhoc lab: Tier-1 msshd Phase 0→1→2 journey + gated-mode design |
| `c1c645a` | rename asyncssh_ref → debug_sshd; document terminology; capture xterm.js idea |
| `ca767d6` | tests/lxc: fix post-reorg paths, disable apt automation, save container disk |

## What this project is

mssh — runtime, CA-mediated SSH authorization. SSH client identity
unchanged; **authorization** moves out of the client and into a
network-restricted CA that the server contacts at every connection.
The defining property: stolen client credentials are useless if the
attacker can't reach the CA.

Read `design/architecture.md` for the technical model.
Read `docs/overview.md` for the elevator pitch.

## Component map (post-rename)

| Component | Path | What it is |
|---|---|---|
| **mssh** | `python/src/mssh/client.py` | The client (was `mssh.py`, renamed to avoid `mssh.mssh` import path) |
| **msshd** | `python/src/mssh/msshd/` | Server-side gateway daemon |
| **mssh-ca** | `python/src/mssh/ca/` | CA service |
| **mssh-admin** | `python/src/mssh/admin/` | Operator CLI |
| **shim** | `python/src/mssh/shim/` | Shared "call the CA" library |
| **debug_sshd** | `python/src/mssh/debug_sshd/` | Debug-only AsyncSSH server (not a tier) |
| **akc_shim** | `python/src/mssh/akc_shim/` | OpenSSH AuthorizedKeysCommand entry point |

Console-script entry points (in `python/setup.py`):

```
mssh, mssh-ca, mssh-admin, msshd, msshd-admin, mssh-debug-sshd
```

## Three msshd operating modes

In `wrapper.yaml`, `mode:` selects one of:

| Mode | Status | Outer auth | Inner auth |
|---|---|---|---|
| `fallback` | Implemented | none — TCP proxy | operator's existing sshd |
| `gated` | Deferred — see `design/future-ideas.md` | mTLS + CA approval | operator's existing sshd |
| `enforce` | Implemented | mTLS + CA + ephemeral cert | hermetic minimal sshd |

The adoption journey is fallback → gated → enforce, reversible.

## Things explicitly NOT done yet — pick up here

### High-priority deferred (NEAR-TERM)

1. **Runtime filesystem paths still use `ssh-rt-auth`.** The package
   rename is done but these paths weren't touched:
   - `/etc/ssh-rt-auth/` (config dir)
   - `/var/lib/ssh-rt-auth/` (state dir)
   - `/var/log/ssh-rt-auth/` (logs)
   - `/run/ssh-rt-auth/` (pidfiles)

   Should become `/etc/mssh/`, `/var/lib/mssh/`, etc. Touches:
   - `python/src/mssh/msshd/*.py` (defaults)
   - `python/src/mssh/debug_sshd/ssh_server.py`
   - `python/tests/lxc/conftest.py`
   - `python/tests/lxc/test_setup_only_msshd.py`
   - `python/tests/lxc/msshd_helpers.py`
   - `python/tests/lxc/test_wrapper_enforce.py`
   - `python/tests/lxc/test_zzz_emergency_cert.py`
   - Several other test files
   - `systemd/msshd.service`
   - `scripts/install_mssh.sh` (already uses `/etc/mssh/` — good)

2. **`SSH_RT_AUTH_WRAPPER_STATE_DIR` env var.** Used by
   `python/src/mssh/msshd/msshd.py` to locate state dir. Rename to
   `MSSHD_STATE_DIR` for consistency. Touches the test fixtures
   that set it.

3. **debug_sshd banner string.** `'ssh-rt-auth: authorized session'`
   in `python/src/mssh/debug_sshd/ssh_server.py:300`. Update to
   `'mssh: authorized session'`. Two test assertions also check
   for the old string:
   - `python/tests/test_loopback_e2e.py:247`
   - `python/tests/lxc/test_clients_in_containers.py:172, 232`

After all three: run full LXC suite to validate. Should be
straightforward — same kind of bulk-sed approach worked for the
package rename.

### Captured-but-deferred design ideas (in `design/future-ideas.md`)

These have full design sections; pick one up when ready to implement:

1. Per-connection ephemeral inner sshd
2. Smart-card (PIV / PKCS#11) support
3. Shared protocol module across language ports
4. msshd supports protocols beyond SSH (HTTPS / TCP proxy)
5. CA mints certs for other applications (step-ca parallel)
6. Require 2FA for high-privilege roles (with air-gap fallback)
7. Passkey / WebAuthn support
8. Centralized client config — `~/.mssh/` replaces `~/.ssh/`
9. Incremental SSH→mssh migration runbook (operator doc)
10. Browser-based SSH terminal (xterm.js over HTTPS, mTLS-auth)
11. In-situ debug_sshd swap-in + sideband CA audit channel
12. MCP interface to the CA (NL diagnostics + trusted-AI config)
13. Legacy-config migration with dual-enforce / shadow mode
14. Tutorial walkthrough doc for the adhoc lab
15. `install_mssh.sh` — distro-style installer (MVP at `scripts/install_mssh.sh`)
16. Distro packaging path (.deb/.rpm/.apk) + Go+musl caveat
17. Per-session banner with variable substitution

Section 6.5.1 of `archive/design/ssh-rt-auth-detailed-wrapper.md`
also captures **gated mode** (the missing third operating mode);
the canonical pointer for that is now `design/architecture.md` +
`design/future-ideas.md`.

### Open style/naming questions

- **Word "wrapper" is retired** in favor of "gateway" for msshd.
  If you see "wrapper" outside archive/, fix it.
- **Phase / Tier / PoC framing is retired** in the clean-room docs.
  Reference architecture.md for the canonical view.
- **GitHub repo URL is still `kurt-cb/ssh-rt-auth`.** Don't rename
  in URLs even when doing path cleanups.

## How to validate changes

- **Fast (unit tests only, ~2s):** `cd python && pytest tests --no-cov -m 'not lxc'`
- **Slow (full LXC suite, ~5 min):** `cd python && pytest tests --no-cov`
- **Adhoc lab from the host:** `cd python && ./setup_adhoc.sh`
  Then source `./adhoc-env.sh`; run `mssh_as alice acct whoami`,
  `flip_to_fallback`, `flip_to_enforce`, etc. See
  `python/tests/lxc/test_setup_only_msshd.py` for what it provisions.

## Tooling quirks worth knowing

- **pip pep517 builds fail in the venv.** `pip install -e ./python`
  errors with "No matching distribution found for setuptools>=40.8.0".
  Doesn't matter for the editable install (it picks up source via
  a .pth file). But it means changes to entry-points in setup.py
  don't refresh the `mssh`, `mssh-ca` etc. binaries in
  `.venv/bin/`. Workaround in tests + adhoc-env: invoke
  `PYTHONPATH=/app/src python3 -m mssh.client ...` directly,
  bypassing the entry-point shim.
- **LXC `adduser -D` (Alpine) and `useradd -m` (Ubuntu) both
  leave accounts locked.** debug_sshd is tolerant; the hermetic
  msshd inner sshd refuses. The msshd_env fixture unlocks
  with `sed -i 's|^USER:!:|USER:*:|' /etc/shadow` before starting
  msshd. Same fix is in `test_setup_only_msshd.py`. Watch for
  this pattern any time you add a new test that uses msshd-enforce.
- **`ssh` from a container needs `-o IdentitiesOnly=yes`.**
  Otherwise it offers every key in the agent, hits MaxAuthTries,
  and disconnects before our `-i` key gets a chance. Helpers
  in `adhoc-env.sh` already include this; new code should too.
- **`ssh -n` for in-loop ssh calls.** ssh reads stdin and will
  swallow a `while read` loop's pipe. The flip scripts
  (`python/tests/lxc/test_setup_only_msshd.py:_flip_script`)
  use `-n` for every ssh that doesn't consume stdin, and
  `</dev/null` for the loop iteration as belt-and-suspenders.

## Things I noticed but didn't touch

- `python/.swp`, `python/1`, `python/t` are stray editor/scratch
  files that got committed in 4ef9818. Probably want to delete
  and add to .gitignore.
- `archive/design/ssh-rt-auth-detailed-wrapper.md §6.5.1` (gated
  mode) is the most-detailed deferred design and probably the
  highest-value near-term implementation. Worth promoting to
  `design/gated-mode.md` if the project commits to building it.

## Bookmark for next session

The work that was queued and is NOT done:
- The 3 path/banner/env-var cleanups in "High-priority deferred"
  above. ~1-2 hours to do all three with a bulk-sed + LXC suite
  re-run.
- After that: pick the next thing from `design/future-ideas.md`
  based on operator priority. My read: **§13 (legacy-config
  capture + dual-enforce)** is the single biggest unlock for
  real adoption, but it's also the largest piece of work (~1000
  LOC + design discussion).

The lab is currently torn down (user finished with it). Re-run
`./setup_adhoc.sh` to provision fresh.
