# ssh-rt-auth — things we covered and dropped

**Purpose:** historical record of ideas, names, and structures that
were seriously considered (and sometimes implemented partially) before
being superseded. Captured here so a future reader can see "we did
think about that — here's why we don't do it this way today" without
having to git-archaeology the answer.

Organized by category. Each entry has:
- **What it was** — the original idea / name / structure.
- **Why it was dropped** — the decision rationale.
- **When** — rough date so the trail is dateable.
- **Where the live design now lives** — pointer to the current source
  of truth.

---

## Naming

### `ssh-rt-wrapperd` (daemon name)

- **What:** The Tier 1 wrapper daemon's binary was originally
  `ssh-rt-wrapperd` and was referenced that way in scripts, systemd
  units, log channels, and design docs.
- **Why dropped:** Too long; doesn't match the project's
  client/server pair (`mssh` / `msshd`); operator preference
  expressed during 2026-05 planning.
- **When:** 2026-05-15.
- **Current name:** `msshd` (binary), `msshd.service` (systemd unit),
  `sshrt.msshd` (Python package).
- **Where:** [python/setup.py](../python/setup.py),
  [systemd/](../systemd/).

### `wrapper/` (top-level subtree)

- **What:** Initial structure put the Tier 1 wrapper at
  `wrapper/python/`, `wrapper/go/`, `wrapper/alpine/` — wrapper as a
  subsystem-level concept, with language as a subdirectory.
- **Why dropped:** Language mixing makes packaging messy (Python
  package shouldn't contain Go source it'll never compile). The user
  established the principle "language at top-level, each language
  ships its own full client+server+CA" during the reorg discussion.
- **When:** 2026-05-15 reorg.
- **Current structure:** Top-level `python/`, `go/`, `c/`. Wrapper
  client = `python/src/sshrt/mssh.py`; wrapper server =
  `python/src/sshrt/msshd/`.
- **Where:** [CLAUDE.md § Project structure](../CLAUDE.md).

### `ssh-rt-auth-openssh` (sibling repo)

- **What:** OpenSSH upstream patches lived in a sibling repository
  (`../ssh-rt-auth-openssh/`) with its own git history, submodule
  for `openssh-portable`, and patch series.
- **Why dropped:** Patches are small enough that a sibling repo is
  overhead. Easier discoverability and CI integration with them in
  the main repo.
- **When:** 2026-05-15 reorg.
- **Current location:** [openssh-patches/](../openssh-patches/) in
  the main repo. The `openssh-portable` submodule itself was
  **not** absorbed — operators clone it themselves or use the
  sibling repo if they already have it (controlled via the
  `SSHRT_OPENSSH_PORTABLE` env var read by the LXC test).
- **Where:** [openssh-patches/README.md](../openssh-patches/README.md).

---

## Architecture

### Greenfield C+Mbed TLS SSH server

- **What:** Tier 1 production endpoint was originally going to be a
  ground-up SSH server implementation in C + Mbed TLS, called out in
  [CLAUDE.md](../CLAUDE.md)'s original "Key design decisions" section
  as "Final implementation: C with Mbed TLS (not part of PoC)."
- **Why dropped:** Empirical CVE record across the SSH-server-impl
  industry (Teleport, Tailscale, sshpiper, Warpgate — all Go or
  Rust — and historical C SSH impls like Dropbear, libssh) shows that
  *owning* an SSH protocol implementation means owning a steady CVE
  pager. Even Go-based Teleport with a full-time security team
  shipped a CVSS 9.8 auth bypass in 2025 (CVE-2025-49825). A
  greenfield C impl would have strictly worse CVE odds.
- **When:** 2026-05-14, after the wrapper-research analysis.
- **Replaced by:** **Wrap-and-proxy** — mTLS-terminating wrapper in
  front of unmodified upstream OpenSSH. CVE response stays with
  upstream OpenSSH (mature, focused security response).
- **Where:** [design/ssh-rt-auth-wrapper-research.md](ssh-rt-auth-wrapper-research.md),
  [design/ssh-rt-auth-detailed-wrapper.md](ssh-rt-auth-detailed-wrapper.md).
- **Note:** The constrained-deployment niche that motivated the
  greenfield idea is now covered by the `c/` variant in the tier
  table — a minimal C **wrapper** around unmodified OpenSSH, NOT a
  greenfield SSH server.

### MITM SSH outer protocol ("stock ssh client + openssl s_client ProxyCommand")

- **What:** Original plan for Tier 1 client: users run stock `ssh`
  with `ProxyCommand="openssl s_client -connect host:port -cert ..."`.
  Inside the TLS tunnel the wire protocol would be raw SSH, with the
  wrapper acting as a transparent byte-pipe to inner sshd.
- **Why dropped:** The outer SSH session and the inner (wrapper →
  hermetic sshd) session can't share an authenticated principal —
  they use different keys. The wrapper would have to MITM the SSH
  protocol (sshpiper-style: terminate outer SSH, re-establish inner
  SSH with the wrapper-minted cert) — a much larger implementation
  surface than v1 warranted.
- **When:** 2026-05-14 in Phase 1B.
- **Replaced by:** **JSON-frame outer protocol over mTLS.** The
  client tool (`mssh`) speaks a tiny line-delimited JSON header
  followed by raw bytes; no stock SSH client involved.
- **Where:** [design/ssh-rt-auth-detailed-wrapper.md § 3](ssh-rt-auth-detailed-wrapper.md).

### `wrapper/<lang>/` (subdir-per-language under wrapper/)

See "Naming" → "`wrapper/` (top-level subtree)" above. Same drop.

### `wrapper/client/<lang>` + `wrapper/server/<lang>` split

- **What:** [phase2-ideas.md § 3](ssh-rt-auth-phase2-ideas.md) proposed
  splitting `wrapper/<lang>/` into `wrapper/client/<lang>` and
  `wrapper/server/<lang>` so that client and server could be packaged
  / shipped independently.
- **Why dropped:** Substantially superseded by the 2026-05-15 reorg.
  Top-level language directories already give each variant its own
  shipping pipeline. Within a language, client and server are
  already organisationally separate (`sshrt.mssh` is a single module;
  `sshrt.msshd` is a sub-package).
- **When:** 2026-05-15 reorg.
- **What remains:** The "shared protocol module to prevent
  client/server frame-format drift" piece. See
  [phase2-ideas.md § 3](ssh-rt-auth-phase2-ideas.md).

---

## OpenSSH patch series

### Patches 0004–0007 — `AuthorizationModule` directive + cert-ext enforcement

- **What:** Originally planned series:
  - **0004** — new `AuthorizationModule` sshd_config directive
    (~500–800 LOC). Post-userauth hook that receives the full
    connection context + identity blob and returns an X.509 authz
    cert. sshd parses critical extensions and stores them on the
    session struct.
  - **0005** — enforce `sshrtauth-channel-policy` on channel-open
    (~80 LOC, depends on 0004).
  - **0006** — enforce `sshrtauth-force-command` (~50 LOC, depends
    on 0004).
  - **0006b** — enforce `sshrtauth-environment` (~30 LOC).
  - **0007** — `CheckExpireCommand` + session-side timer for cert
    refresh/terminate (~200 LOC).
  - **0007b** — `AuthorizationAuditCommand` (~50 LOC).
- **Why dropped:** With the wrap-and-proxy architecture as Tier 1,
  none of these patches are needed. The wrapper enforces cert
  constraints itself (or translates them into OpenSSH cert critical
  options for the hermetic inner sshd). Maintaining ~1000+ LOC of
  upstream-divergence across OpenSSH releases isn't worth it when
  the project no longer needs the framework.
- **When:** 2026-05-14 in the strategy-doc revision.
- **Replaced by:** Wrapper-side enforcement +
  [v2 cert extensions](ssh-rt-auth-v2-enhancements.md).
- **Where:** Historical NOTES at [openssh-patches/NOTES.md](../openssh-patches/NOTES.md).

### Patch 0002b — `SSH_CONNECTION_CONTEXT` JSON env var

- **What:** Patch to `AuthorizedKeysCommand` that would set an env
  var `SSH_CONNECTION_CONTEXT` containing a rich JSON document
  (source IP/port, local IP/port, kex, cipher, banner, etc.) for the
  AKC helper to consume.
- **Why dropped:** Subsumed by the wrapper — operators wanting rich
  connection context can deploy the wrapper instead. The smaller
  community of Tier 3 users doesn't justify the maintenance burden.
- **When:** 2026-05-14.
- **Where:** [openssh-patches/NOTES.md](../openssh-patches/NOTES.md)
  has the section marked DROPPED with the rationale.

### Patch 0008 — drop the legacy `AuthorizedKeysCommand` fallback

- **What:** Optional patch to remove the legacy AKC code path once
  the `AuthorizationModule` framework was in place.
- **Why dropped:** Contradicts the "unpatched sshd must keep working"
  principle established for v2. The legacy AKC path is the basis
  of Tier 3 compatibility mode and must remain operational.
- **When:** 2026-05-14.
- **Where:** [openssh-patches/NOTES.md](../openssh-patches/NOTES.md)
  has the section marked REMOVED with the rationale.

### Patch 0003 SKIP reversal

- **What:** Patch 0003 (`SSH_AKC_PHASE` env var) was originally
  marked SKIPPED on the basis that the SQLite cache (issue 9.2)
  already deduplicates the AKC double-call functionally.
- **Why reinstated:** The skip-rationale missed that the patch
  closes a real *security* surface (the CA being queried for
  unauthenticated probes during the publickey-auth `query` phase),
  not just a performance issue. With the patch the shim can
  decline to contact the CA during query phase entirely.
- **When:** Reinstated 2026-05-14.
- **Where:** Patch lives at
  [openssh-patches/patches/0001-Set-SSH_AKC_PHASE-env-var-on-AuthorizedKeysCommand-c.patch](../openssh-patches/patches/0001-Set-SSH_AKC_PHASE-env-var-on-AuthorizedKeysCommand-c.patch).

---

## Tooling / packaging

### `pyproject.toml` with `[project]` table

- **What:** Modern Python package metadata in `pyproject.toml` only,
  with `[build-system]` pointing at setuptools-build-meta.
- **Why dropped:** The CI / dev venvs ship `setuptools 53` (Ubuntu
  22.04 / RHEL 9 era), which doesn't implement PEP 660
  (`build_editable` hook). `pip install -e ./python` fails. Upgrading
  setuptools through the corporate proxy is blocked.
- **When:** 2026-05-15 during the reorg.
- **Current state:** Package metadata + entry points live in
  `python/setup.py` (legacy). `python/pyproject.toml` carries only
  pytest configuration. Tests are run via the conftest.py sys.path
  shim, not pip-installed.
- **Where:** [python/setup.py](../python/setup.py),
  [python/pyproject.toml](../python/pyproject.toml).
- **Note:** When the supported-venv floor moves to setuptools >= 64,
  promote `pyproject.toml` to a full `[project]` table and delete
  the `setup.py` shim.

### `pip install -e ./python` editable install

- **What:** Standard pattern for Python development.
- **Why partially dropped:** Same PEP 660 / setuptools issue as
  above. Editable installs work on newer venvs but not on the
  current dev environment.
- **Current state:** Tests work via `conftest.py`'s `sys.path.insert(
  parent / 'src')`. Console scripts (`mssh`, `msshd`, etc.) are
  available when a recent-enough setuptools is installed; otherwise
  use `PYTHONPATH=python/src python -m sshrt.msshd ...`.

### Console-script alias `ssh-rt-wrapperd`

- **What:** Earlier name for the wrapper daemon console-script entry.
- **Why dropped:** Renamed to `msshd` (see Naming).
- **When:** 2026-05-15 cleanup.
- **Note:** Old scripts/systemd units / docs that still reference
  `ssh-rt-wrapperd` are being updated in the same cleanup pass.

---

## Other operational concepts

### "Use stock SSH client + openssl s_client ProxyCommand"

See Architecture → "MITM SSH outer protocol" above.

### Systemd-managed inner sshd (`ssh-rt-inner-sshd.service`)

- **What:** The original Phase 1 design ([detailed-wrapper.md §12.2](ssh-rt-auth-detailed-wrapper.md))
  had **systemd managing the inner sshd as a separate unit** with
  `BindsTo=msshd.service`. The wrapper would render the sshd config
  + write the host key + drop the user-CA pubkey, then signal systemd
  to start `ssh-rt-inner-sshd.service`. Systemd would handle the
  lifecycle, restarts, journaling, etc.
- **Why dropped:** The wrapper's port allocation for the inner sshd
  is **dynamic** (random pick from `49152-65535` at every startup),
  which doesn't fit a static `Port` directive in a systemd unit.
  Letting systemd own the lifecycle would have meant pre-allocating
  the port at unit-install time, contradicting the wrapper's runtime
  allocation. The simpler path: wrapper spawns sshd as a subprocess
  via `asyncio.create_subprocess_exec`, owns its lifecycle directly.
- **When:** Phase 1B implementation, 2026-05-14.
- **Current implementation:** [inner.py](../python/src/sshrt/msshd/inner.py)
  `InnerSshd.start()` runs `sshd -D -f <config>` as a subprocess.
  Wrapper supervises (start, wait-for-port, stop with SIGTERM+SIGKILL
  escalation). No systemd unit involved.
- **Where the file was:** `systemd/ssh-rt-inner-sshd.service` —
  **deleted 2026-05-15**. Recoverable from git history if anyone
  ever wants to switch architectures.
- **What this lets future architectures do (if desired):**
  pre-allocate the inner sshd port, run it as a long-lived
  systemd-managed service, have the wrapper proxy to a fixed
  localhost:port. Would simplify the wrapper at the cost of losing
  the per-startup port flexibility. Documented here so the trade-off
  is visible.

### "OpenSSH-portable submodule absorbed into main repo"

- **What:** Option considered during the reorg: pull the OpenSSH
  source tree into `openssh-patches/openssh-portable/` as a git
  submodule of the main repo.
- **Why dropped:** Complicates the main-repo's submodule machinery
  for marginal benefit. The patches themselves are small files;
  the submodule (50MB of OpenSSH source) is heavy.
- **When:** 2026-05-15 reorg.
- **Current state:** Operators init `openssh-portable` themselves
  per the instructions in
  [openssh-patches/README.md](../openssh-patches/README.md), or use
  an existing checkout (e.g., the original sibling repo) via the
  `SSHRT_OPENSSH_PORTABLE` env var that the LXC test honors.

---

## When this doc gets updated

Add an entry every time something gets renamed, dropped, or
substantially reshaped. The bar for inclusion: "would a future reader
benefit from knowing this *isn't* the answer?"

When a Phase 2 idea gets *promoted* to active work (from
[phase2-ideas.md](ssh-rt-auth-phase2-ideas.md)), it doesn't go here —
it gets a fresh `design/ssh-rt-auth-detailed-<feature>.md` and the
phase2-ideas entry becomes a one-line "→ moved to <file>" pointer.

Only **dropped** or **superseded** ideas land here. Things kept and
implemented don't.
