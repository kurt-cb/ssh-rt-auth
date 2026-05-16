# LXC Integration Tests

Modeled on the sshadmin LXC suite. Spins up real LXC containers and exercises
the ssh-rt-auth flow end-to-end.

## Topology

```
mssh-lxc-ca       Ubuntu 22.04   Flask CA + ssh-rt-admin
mssh-lxc-u1       Ubuntu 22.04   sshd + Python shim
mssh-lxc-u2       Ubuntu 22.04   sshd + Python shim
mssh-lxc-u3       Ubuntu 22.04   sshd + Python shim
mssh-lxc-alpine   Alpine 3       sshd + Python shim   (cross-distro coverage)
```

All four SSH hosts host the same Unix-user matrix (8 regular users + 2
superusers), generated deterministically from a per-run seed by
`tests/lxc/randomized.py`. Each run can be replayed exactly by passing
`--seed=<N>` to pytest.

## Prerequisites

- `lxc version` works (LXD 6+ recommended)
- `images:ubuntu/22.04` and `images:alpine/3.21` reachable
- Python 3.9+ with pytest and the dependencies in `requirements.txt`

## Running

```bash
cd /home/kgodwin/ssh-rt-auth
# Phase 1 — deployment validation only
pytest tests/lxc/test_deployment_validation.py -v

# Replay a previous run by seed
pytest tests/lxc -v --seed=1234567890

# Leave containers running after the test for inspection
pytest tests/lxc -v --keep-containers
```

## Phases

| Phase | Goal | File |
|-------|------|------|
| 1 | Environment validation: CA up, admin API reachable, register 2 hosts, enroll a user. | `test_deployment_validation.py` |
| 2 | Randomized full matrix: 10 users x 4 hosts under seed-generated policies; verify all allow/deny outcomes match the policy. | _Future_ |
| 3 | Failover, emergency cert, cache TTL, source-bind enforcement, time-window enforcement. | _Future_ |

Phase 1 is the "is the environment sound" smoke test and is the only
LXC-required test in the initial PoC drop. Phase 2 and 3 ride on the same
`lxc_env` fixture.

## Snoopy command-execution logging (opt-in diagnostics)

Add `--install-snoopy` to any pytest invocation to install
[Snoopy](https://github.com/a2o/snoopy) on every Ubuntu test container. Snoopy
hooks `execve()` via `/etc/ld.so.preload` and writes every command — with
`uid`, `pid`, `tty`, `cwd`, and full argv — to
`/root/systemlogs/snoopy.log` inside that container.

```bash
pytest tests/lxc -v -m lxc --install-snoopy --keep-containers
```

While the containers are still up:

```bash
# Tail snoopy on the CA host
lxc exec mssh-lxc-ca -- tail -f /root/systemlogs/snoopy.log

# Or on an SSH server while you reproduce an issue
lxc exec mssh-lxc-u1 -- tail -f /root/systemlogs/snoopy.log
```

Useful for:

- diagnosing **what** the shim actually invoked when an SSH connection failed
- watching the AsyncSSH server's `su - <user> -c "..."` calls during exec mode
- confirming the `ssh-keygen` / `dropbearkey` flows in the setup-only test
  ran exactly the commands documented in `ADHOC_TEST_ENV.md` § 9

### Alpine caveat

Alpine uses musl libc; the Alpine `dropbear` repos don't carry snoopy and
upstream snoopy requires a custom musl build. The `--install-snoopy` flag
silently skips the Alpine container with a notice on stderr. If you need
exec-level logging on Alpine, the closest alternative is `ltrace -f -e execve*`
attached to the dropbear / AsyncSSH server processes.
