# Patch conventions

Each patch is a single `git format-patch` output file with a real commit
message. The first line must be a short, present-tense summary
(`Add SSH_AKC_PHASE env var on AuthorizedKeysCommand calls`), the body
explains rationale.

Apply order is the `series` file (quilt-style). `build.sh` reads it.

## Style rules (so upstream submission is easy)

- Match the surrounding code style. Upstream is K&R-ish with 8-space tabs.
- No new external dependencies.
- New `sshd_config` directives default to "off" so existing configs are
  bit-identical.
- Behaviour changes go in `NEWS` (sshd's release notes file).
- Each commit should compile + pass `make tests` on its own.

## Workflow

1. `./build.sh` — applies the series to a clean openssh-portable checkout.
2. `cd openssh-portable && $EDITOR …` — hack.
3. `git -C openssh-portable add -u && git -C openssh-portable commit`
4. `git -C openssh-portable format-patch -1 -o ../patches/` — export.
5. Append the new file's basename to `series`.
6. `./build.sh --clean` — verify the patch still applies cleanly from a
   pristine upstream tree.

## Investigation patches

`investigation/` holds patches that add `fprintf` markers, log lines, or
other ad-hoc instrumentation. They are **never** part of the upstream
series — apply them with `./build.sh --apply-investigation` only when
debugging.
