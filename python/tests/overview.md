# ssh-rt-auth test suite overview

This document is a map of every test category that ships with the PoC:
where it lives, what it verifies, how to run it. It's the single place to
look when you ask "is this code path tested?" or "where would I add a
regression test for X?".

For the diary of bugs we hit while building the suite, see
[issues.md](issues.md).

---

## Layout

```
tests/
├── conftest.py                       # shared fixtures (Ed25519 keys,
│                                     #   bootstrap CA dir, CA config path)
├── test_identity_parser.py           # 7 tests
├── test_enrollment.py                # 13 tests
├── test_policy.py                    # 14 tests (incl. wildcards)
├── test_cert_minter.py               # 4 tests
├── test_authorize.py                 # 7 tests
├── test_admin.py                     # 7 tests
├── test_shim.py                      # 7 tests
├── test_shim_config.py               # 3 tests
├── test_sqlite_cache.py              # 9 tests (persistence,
│                                     #   cross-process, LRU, expiry)
├── test_audit.py                     # 3 tests
├── test_key_parser.py                # 4 tests
├── test_loopback_e2e.py              # 1 test  (3-process loopback)
├── lxc/
│   ├── conftest.py                   # provisioned_env, scenario,
│   │                                 #   --keep-containers, --install-snoopy,
│   │                                 #   --seed pytest options
│   ├── lxc_helpers.py                # subprocess wrappers, snoopy installer
│   ├── log_helpers.py                # OpsLog, banner, render_table
│   ├── randomized.py                 # seed-reproducible scenario builder
│   ├── test_deployment_validation.py # 4 tests (Phase 1 smoke)
│   ├── test_matrix.py                # 2 tests (user × server matrix)
│   ├── test_clients_in_containers.py # 2 tests (ssh + dbclient cross-distro)
│   ├── test_mtls_security.py         # 7 tests (mTLS attacks on the CA)
│   ├── test_rogue_host.py            # 3 tests (unauthorized host scenarios)
│   ├── test_wildcard_policy.py       # 1 test  (servers: ['srv-*'])
│   ├── test_zz_audit_security.py     # 4 tests (audit-log coverage)
│   ├── test_zzz_emergency_cert.py    # 1 test  (CA-offline break-glass)
│   ├── test_setup_only.py            # 1 test, opt-in (-m setup_only)
│   └── test_openssh_shim.py          # 1 test, opt-in (-m openssh_shim)
├── issues.md                         # session retrospective
└── overview.md                       # this file
```

---

## What each category covers

### Host-side unit tests (run on every `pytest` invocation)

| File | Code under test | What it verifies |
|------|-----------------|------------------|
| `test_identity_parser.py` | `ca/identity_parser.py` | SSH wire-format pubkey + OpenSSH-cert parsing; SHA-256 fingerprint matches `ssh-keygen -l`; rejects mis-typed blobs; handles real `ssh-keygen`-minted certs end-to-end. |
| `test_enrollment.py` | `ca/enrollment.py` | YAML round-trip; CRUD on servers/users/admins/policies; last-superuser protection; wildcard server names are allowed in policies but plain names must already exist. |
| `test_policy.py` | `ca/policy.py` | Server match by name OR group OR `fnmatch` wildcard; source-CIDR check; time-window check (incl. timezone + day-of-week); channel intersection; multi-policy merging (channels unioned, validity min'd, env merged, force-command preserved). |
| `test_cert_minter.py` | `ca/cert_minter.py` | `bootstrap_ca()` writes all eight key/cert artifacts; admin/server cert chain validates against the mTLS root; minted authz cert has the right custom extensions, is signed by the auth root, has the right subject. |
| `test_authorize.py` | `ca/authorize.py` | Full `/v1/authorize` decision path: unknown server → 401; unknown identity → 403; granted path mints a real cert; audit log entry written for both grant + deny; source-CIDR deny path; clock-drift deny path. |
| `test_admin.py` | `ca/admin.py` | Role-based access control — auditor can't add a server, server-admin can't add a policy, only superuser can add/remove admins; can't remove the last superuser; key add rejects bad base64. |
| `test_shim.py` | `shim/shim.py` + `shim/cache.py` | In-memory cache hit / expiry / LRU; shim granted-passthrough path (mints + validates a real cert with the actual signing key); deny passthrough; failover-all-down → STATUS_ERROR; invalid-cert-from-CA → STATUS_ERROR (defense in depth). |
| `test_shim_config.py` | `shim/config.py` | Minimal YAML loads with defaults; validate() rejects missing endpoints; validate() rejects missing files. |
| `test_sqlite_cache.py` | `shim/sqlite_cache.py` | Same-process put → get; miss for different `source_ip`; expired entries evicted on get; LRU cap honored; clear; `vacuum_expired()` count; **cross-process persistence** (spawns a real subprocess to write, then reads from the parent — the actual scenario the OpenSSH shim hits). |
| `test_audit.py` | `ca/audit.py` | JSONL append + read round-trip; concurrent writers from 4 threads don't corrupt the file. |
| `test_key_parser.py` | `cli/key_parser.py` | Bare pubkey line; `authorized_keys`-style line with options prefix; reads from disk; rejects empty input. |
| `test_loopback_e2e.py` | `ca.server` + `shim.shim` + `server.ssh_server` end-to-end | A real CA subprocess on 127.0.0.1, AsyncSSH server on 127.0.0.3, ssh client binding `local_addr=127.0.0.2` — the whole authorization flow through Python without containers. |

**Run them all:**

```bash
pytest tests -m "not lxc"
# 79 tests / ~3s
```

### LXC integration tests

Marked `pytest.mark.lxc`. Auto-skipped when `lxc` isn't on PATH.

| File | What it verifies |
|------|------------------|
| `test_deployment_validation.py` | Phase-1 smoke: CA boots, admin API mTLS reachable, two SSH servers enrollable via the CLI, user+key+policy CRUD through the API. |
| `test_matrix.py` | For every (user, server) in the random scenario, ssh from `mssh-lxc-u1` to that server and verify the outcome matches `user.allowed_hosts`. Plus a "from a different source container" pass to confirm the decision is independent of which box you're sshing from. |
| `test_clients_in_containers.py` | Same matrix as above but driven by BOTH the OpenSSH `ssh` AND Dropbear's `dbclient` from inside each container. Lazy converts the user's OpenSSH-format key to dropbear format on first use because Ubuntu 22.04's dbclient 2020.81 / Alpine's 2024.86 can't read OpenSSH Ed25519 directly. |
| `test_mtls_security.py` | 7 attacks on the CA: no client cert → TLS handshake rejection; self-signed client cert → TLS handshake rejection; valid mTLS cert with unenrolled subject → 401 on admin AND on `/v1/authorize`; bootstrap admin cert on `/v1/authorize` → 401 (admin ≠ server); server cert on `/v1/admin/server/list` → 401 (server ≠ admin); auditor role attempting `server.add` → 403 (forbidden). |
| `test_rogue_host.py` | Raw TLS handshake from outside the enrollment fails: with no cert, with a self-signed cert. Models the design's central property: a stolen user key is useless if you can't reach the CA through a valid server mTLS cert. |
| `test_wildcard_policy.py` | Enrols a user with policy `servers: ['srv-*']` and confirms they reach every `srv-*` server; enrols a sibling with `servers: ['nomatch-*']` and confirms they're denied. Restricted to Ubuntu hosts (restarting the Alpine AsyncSSH server mid-suite is flaky — see issues.md § 6.3). |
| `test_zz_audit_security.py` | After the matrix + security tests have run, the audit log contains: admin entries for every server/user/policy created; an authorization entry for every user in the scenario; structured `reason` on denials; the central deny reasons (`unknown_server`, `no_matching_policy`, `unknown_identity`, etc.) are observable. Named `zz_` to run alphabetically last so the matrix has populated the log first. |
| `test_zzz_emergency_cert.py` | Mints a long-lived emergency cert pinned to (user, server, source-IP); installs it as `emergency_cert` on the shim of one SSH host; stops the CA via `systemctl`; ssh's from u1 to that host — expects the shim to detect "all CA endpoints unreachable", fall back to the emergency cert, and let the connection through. Verifies the server log shows `using emergency cert`. Named `zzz_` to run after the audit tests since it deliberately runs without leaving any audit trail. |

**Run them all:**

```bash
pytest tests/lxc -v -m lxc
# 24 tests / ~3 min (incl. container provisioning)
```

### Opt-in tests

These have their own marker and are silently skipped on every normal run.
Pass the marker explicitly to enable.

| File | Marker | Purpose |
|------|--------|---------|
| `test_setup_only.py` | `setup_only` | Provisions an ad-hoc lab with department-style roles (`accounting` / `sales` / `hr` / `engineering` + a `root-admin` superuser). Each user generates their own keypair **inside** their primary container using the native tool (ssh-keygen for Ubuntu, dropbearkey + dropbearconvert for Alpine), the admin enrolls them with `ssh-rt-admin user add`, and the test leaves everything running. Writes `ADHOC_TEST_ENV.md`, `adhoc-env.sh`, and `cleanup_containers.sh` into the invocation cwd. No teardown. |
| `test_openssh_shim.py` | `openssh_shim` | Wires `openssh/openssh_shim.py` into a stock OpenSSH `sshd` via `AuthorizedKeysCommand`. Three SSH attempts: enrolled+policy → granted, enrolled+no-policy → denied, not-enrolled → denied. Also asserts the SQLite cache de-duplicates sshd's double `AuthorizedKeysCommand` call (audit log has exactly 1 granted row for alice, not 2). |

**Run:**

```bash
pytest tests/lxc/test_setup_only.py -v -m setup_only
pytest tests/lxc/test_openssh_shim.py -v -m openssh_shim
```

---

## Useful flags

| Flag | What it does |
|------|--------------|
| `--seed=N` | Replay a specific LXC scenario. The seed prints at session start; pass it back here to reproduce. |
| `--keep-containers` | Leave LXC containers running after the test for live inspection. Use `cleanup_containers.sh` (or `lxc delete --force …`) when done. |
| `--install-snoopy` | Install [Snoopy](https://github.com/a2o/snoopy) on every Ubuntu LXC container so every `execve()` is logged to `/root/systemlogs/snoopy.log` inside that container. Invaluable for diagnosing "what did the shim actually invoke?". Alpine is skipped (musl). |
| `--cov…` | Enabled in `pytest.ini`; every run writes `htmlcov/index.html` + `coverage.xml`. Open the HTML report in a browser to drill down. |

---

## Running everything

```bash
# Host unit tests (fast)
pytest tests -m "not lxc"

# LXC integration (slow, needs lxc/lxd)
pytest tests/lxc -v -m lxc

# Both, with combined coverage
pytest tests -m "not lxc"
pytest tests/lxc -m lxc --cov-append
coverage html

# The opt-in suites
pytest tests/lxc/test_setup_only.py -v -m setup_only
pytest tests/lxc/test_openssh_shim.py -v -m openssh_shim
```

---

## Coverage snapshot (host-only run)

Host-side coverage hovers around **55–60 %** with the unit tests. The
remaining uncovered code is in modules that only exercise via integration:

- `ca/server.py` (Flask app entry, mTLS listener) — covered when LXC runs
- `cli/main.py` (click CLI) — exercised by hand or via LXC's CAClient
- `server/ssh_server.py` (AsyncSSH server) — covered by loopback + LXC
- `openssh/openssh_shim.py` — covered by `test_openssh_shim.py`

Run LXC and `--cov-append` to lift the totals into the high 70s.

---

## What's *not* tested (deliberate gaps)

- The actual SSH protocol parser inside AsyncSSH (3rd-party, not our code).
- X.509 OCSP / CRL revocation (out of PoC scope; cert TTL handles it).
- HA / multi-CA replication (PoC has one CA; failover is tested by stopping
  the CA in the emergency-cert test).
- C / Mbed TLS reference shim (final implementation phase; current shim is
  Python).
- Real-world load (no stress tests; one connection at a time in matrix).
- A long-lived authorization **daemon**. The current OpenSSH shim is a
  fresh subprocess per call, costing ~250 ms of Python startup +
  imports before the SQLite cache even gets consulted. The daemon
  design (Unix domain socket + JSON RPC, persistent mTLS to the CA,
  in-memory hot cache backed by the existing SQLite layer) is sketched
  in [issues.md § 9.5](issues.md). Tracked as a follow-up; the PoC
  prioritises correctness over latency.

See [issues.md](issues.md) for the running list of bugs encountered while
building this and how each was fixed.
