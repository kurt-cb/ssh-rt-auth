# ssh-rt-auth-openssh

OpenSSH patches that turn unmodified `sshd` into a first-class ssh-rt-auth
authorization point. Companion to the
[ssh-rt-auth](../ssh-rt-auth) PoC.

The PoC's `openssh/openssh_shim.py` integration via
`AuthorizedKeysCommand` proved the authorization model works against
stock OpenSSH, but exposed three structural limits:

- the command is called **twice** per accepted connection (search +
  verify); we have to dedupe via a SQLite cache.
- there is **no remote-IP token** for `AuthorizedKeysCommand`, so the CA's
  source-CIDR policy is effectively unenforceable.
- the hook is fundamentally **yes/no**; there is no way to enforce the
  X.509 authorization cert's critical extensions (`server-bind`,
  `channel-policy`, `force-command`) or its `notAfter` timestamp.

This repo carries the patch series that fixes all three by adding new
sshd hooks. Targets upstream OpenSSH-portable; intended for eventual
upstream submission.

## Layout

```
.
├── README.md                     ← this file
├── NOTES.md                      ← the patch plan (rationale, file targets)
├── .gitignore
├── build.sh                      ← apply patches + configure + make
├── dev-loop.sh                   ← hack-patch-export workflow helper
├── openssh-portable/             ← git submodule (see "Quick start")
├── patches/
│   ├── series                    ← quilt-style ordered patch list
│   ├── 0001-…  0002-…  …         ← patch series, one per logical change
│   └── README.md                 ← patch-style conventions
├── investigation/
│   └── 0000-instrument-AuthorizedKeysCommand-fprintf.patch
│                                 ← landing-pad patch that adds stderr
│                                   markers so we can confirm "called
│                                   twice" before fixing it
└── test/
    └── integration_with_ssh_rt_auth.sh
                                  ← runs our patched sshd against the
                                    ssh-rt-auth LXC test suite
```

## Quick start

```bash
# Initialise the repo and add OpenSSH-portable as a submodule.
git init
git submodule add https://github.com/openssh/openssh-portable.git openssh-portable
git -C openssh-portable checkout V_9_9_P1

# Build with our patches applied.
./build.sh

# Run the investigation patch (just markers, no behaviour change):
./build.sh --apply-investigation
sudo install -m 755 openssh-portable/sshd /usr/local/sbin/sshd-patched
# … point your test sshd at /usr/local/sbin/sshd-patched and watch stderr.
```

## Patch series goals (in submission order)

| # | Patch | What it does | Lines (est.) |
|---|-------|--------------|--------------|
| 1 | `instrument-AuthorizedKeysCommand-calls.patch` | Adds stderr markers around each invocation so the "called twice" story can be confirmed empirically. **Investigation only — never submitted upstream.** | ~20 |
| 2 | `add-remote-addr-token-to-AuthorizedKeysCommand.patch` | New `%R` token expands to the remote client's IP. Trivial change in `servconf.c` + `auth-options.c`. Fixes the PoC's `source_ip = 0.0.0.0` issue. | ~10 |
| 3 | `set-SSH_AKC_PHASE-env-on-AuthorizedKeysCommand.patch` | Set `SSH_AKC_PHASE={search,verify}` in the helper's env so new helpers can skip the redundant search-phase call. **Fully backward-compatible** — existing helpers ignore the env var. Sidesteps the call-twice dedup hack. | ~10 |
| 4 | `add-AuthorizationModule-sshd-config.patch` | The big one. New `AuthorizationModule` directive points at a binary that gets called AFTER userauth with the raw identity blob + full connection context + intended channels; returns an X.509 authz cert; sshd parses the critical extensions and stores them on the session struct for downstream enforcement. Maps 1:1 to design doc 01. | ~500–800 |
| 5 | `enforce-AuthorizationCert-channel-policy.patch` | Walks the session's stored channel-policy extension on every channel-open request; rejects non-listed types. | ~80 |
| 6 | `enforce-AuthorizationCert-force-command.patch` | Override exec / shell request to the cert's `sshrtauth-force-command` extension when present. Similar shape to `ForceCommand` but cert-driven, not config-driven. | ~50 |
| 7 | `add-CheckExpireCommand-and-session-timer.patch` | Adds a session-side timer that fires at `cert.notAfter - 60s`; sshd calls `CheckExpireCommand` with the current cert serial + connection state; result is `refresh` (with a new cert) or `terminate` (`SSH_MSG_DISCONNECT`). | ~200 |
| 8 | `remove-AuthorizedKeysCommand-fallback.patch` | Drop the legacy path now that everything routes through `AuthorizationModule`. **Optional / project preference — DO NOT submit upstream.** | ~30 |

### Backward compatibility

Every patch in this series is designed to leave existing behaviour
untouched:

- **AuthorizedKeysCommand** keeps the same contract. Patch 0002 adds
  a new optional `%R` token; patch 0003 adds a new env var. Existing
  helpers that don't reference either keep working byte-for-byte.
- **AuthorizationModule** is a brand-new directive added in parallel.
  Configs that don't set it see no change.
- During migration you can run **both**: AuthorizedKeysCommand
  answers "is this key allowed at all", AuthorizationModule returns
  the cert with extensions. sshd consults both; either denying is a
  hard deny.
- The optional 0008 patch (drop legacy path) is local-only — do not
  submit upstream; upstream OpenSSH must keep the legacy directive
  working forever for compatibility with deployed helpers.

## Development workflow

We use a quilt-style patch series so each logical change is a single
upstream-submittable patch. Workflow:

```bash
# 1. Start from a clean upstream + all patches applied
./build.sh

# 2. Hack inside the submodule
cd openssh-portable
$EDITOR auth2-pubkey.c

# 3. Commit your work to the submodule's branch
git add -u
git commit -m "WIP: enforce channel-policy extension"

# 4. Export back to the series in this repo
cd ..
./dev-loop.sh --export   # runs `git -C openssh-portable format-patch -o patches/ …`

# 5. Verify it still applies clean against pristine upstream
./build.sh --clean --apply-all
```

## Submission upstream

Each numbered patch is intended to land independently if at all possible.
After local validation:

```bash
git -C openssh-portable format-patch --thread=shallow --to=openssh-unix-dev@mindrot.org \
    --cover-letter -o ../upstream/v1/
```

Then edit the cover letter to summarise the series, and send via
`git send-email`.

## Relationship to the parent PoC

This repo is intentionally separate from the
[ssh-rt-auth](../ssh-rt-auth) PoC because:

- **Cadence** — OpenSSH ships every ~6 months; we want to track upstream
  with `git submodule update --remote` and re-validate patch applicability
  per tag in CI.
- **Scope** — the PoC is the spec + reference impl. This is "downstream
  changes to one specific SSH implementation". A sibling
  `ssh-rt-auth-dropbear` is anticipated; same structure, different
  submodule.
- **Submission** — keeping the patches in their own repo makes
  `git format-patch` + send-email cleaner than fishing through a
  larger codebase.

The PoC stays Python and runs against unmodified upstream. Once the
patches here land (in a fork or upstream), the PoC switches its
integration mode from `AuthorizedKeysCommand` to `AuthorizationModule`
and gains real cert-constraint enforcement.

## License

Apache-2.0 for our own contents. The submoduled `openssh-portable/` is
the upstream BSD-style license; patches we contribute upstream follow
the same.
