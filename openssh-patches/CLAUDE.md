# CLAUDE context — OpenSSH upstream submission management

**Purpose:** future Claude sessions should read this before touching
anything in this directory, so they can pick up the submission
lifecycle without re-deriving context.

This directory contains:

- `patches/*.patch` — the actual patches, exported from
  `../../ssh-rt-auth-openssh/openssh-portable` (sibling repo with the
  openssh-portable submodule).
- `openssh_submission_email_1.md` — draft submission email for the
  connection-endpoint-tokens patch (recommended first).
- `openssh_submission_email_2.md` — draft submission email for the
  `SSH_AKC_PHASE` env-var patch (recommended second; needs authorship
  fix before sending).
- `NOTES.md` — historical patch-plan rationale (not for upstream
  consumption; internal design notes).
- `README.md` — public-facing readme for this subtree.
- `build.sh`, `dev-loop.sh` — helpers to apply patches to a fresh
  `openssh-portable` checkout and re-export after editing.

---

## 1. Submission state machine

Each email goes through these states. Update the "Status" line in
the email file as state changes, and append to the relevant
"Submission log" section below.

```
  DRAFT
    │ (user sends the email)
    ▼
  SENT
    │ (no response after N days, with N>21)
    ├──────► PINGED (one polite reply-to-self ping; never more than once)
    │            │
    │            ▼
    │         SILENCE (no response after additional 21 days → treat as soft-rejected)
    │
    │ (any maintainer responds)
    ▼
  IN_REVIEW
    │
    ├──────► REJECTED — outcome final. Document the reason; consider
    │                   whether the design lesson informs anything else.
    │
    ├──────► CHANGES_REQUESTED — maintainer asked for specific edits.
    │            │
    │            ▼
    │         ITERATING — Claude (or operator) prepares revised patch
    │            │         + revised email; re-send as v2.
    │            │
    │            ▼
    │         (back to IN_REVIEW after re-send)
    │
    └──────► ACCEPTED — committed to OpenBSD tree. Track when it flows
                        into openssh-portable's master via the sync.
                        After it lands in portable, REMOVE the patch
                        from this directory (it'll be redundant) and
                        update strategy.md / NOTES.md to reflect
                        upstream presence.
```

---

## 2. Where to look when state changes

- **Mailing list archive:** the openssh-unix-dev archive at
  https://lists.mindrot.org/pipermail/openssh-unix-dev/ — searchable.
  Track our thread there.
- **Bugzilla:** https://bugzilla.mindrot.org — sometimes maintainers
  ask for a bugzilla entry instead of (or in addition to) the email
  thread. If they do, file one and link it from both directions.
- **OpenBSD CVS:** if accepted, the change shows up in
  https://github.com/openbsd/src/tree/master/usr.bin/ssh first, then
  flows downstream to openssh-portable within a few weeks.

---

## 3. Maintainers and their styles

(For context — not a directory; addresses are public on the list
archive.)

- **Damien Miller (`djm@`)** — primary committer. Direct, decisive
  feedback. Conservative on adding surface; appreciates patches that
  cite a concrete downstream use case. Sometimes silent for weeks,
  then responds with the final word.
- **Darren Tucker (`dtucker@`)** — portable-version maintainer.
  Detail-oriented, often catches portability issues. Good ally if a
  patch is portability-sensitive.
- **Theo de Raadt (`deraadt@`)** — OpenBSD lead. Rarely engages on
  AKC-class patches directly; if he does, his feedback is
  authoritative.
- **Style:** when a maintainer says "no" they generally mean it.
  Don't push back twice on the same point in the same thread.

---

## 4. Future-Claude playbook

When a future Claude session is invoked in this directory:

### If a new response arrived from openssh-unix-dev

1. Read the response in full. Capture the maintainer's name, the
   message archive URL, and the verbatim feedback into the
   "Submission log" section below for the relevant email.
2. Categorize: ACCEPTED, REJECTED, CHANGES_REQUESTED, or
   QUESTION_ONLY (no ask yet, just discussion).
3. If CHANGES_REQUESTED:
   - Re-read the relevant patch file in `patches/`.
   - Re-read the related design docs:
     `../design/ssh-rt-auth-detailed-wrapper.md`,
     `../INSTALLATION.md`, this file.
   - Propose the patch revision to the user before editing.
   - Once the user approves, edit the source in
     `../../ssh-rt-auth-openssh/openssh-portable/`, re-export via
     `git format-patch`, update the email body with a "v2" note + diff
     summary of the changes since v1, and present the revised email
     for the user to send.
4. If REJECTED:
   - Document the reason. Update `NOTES.md` to mark the patch as
     "rejected upstream — see CLAUDE.md submission log for reason."
   - Update `../design/ssh-rt-auth-server-strategy.md` Tier 3 section
     to reflect that the workaround is the canonical answer now.
   - Don't propose re-submission unless the user explicitly asks.
5. If ACCEPTED:
   - Wait for the change to flow into `openssh-portable` master
     (check the upstream commit log).
   - Once landed in portable, remove the patch from this directory.
   - Update `../README.md` "OpenSSH upstream patches" section to
     reflect the cert is now in distro builds (note which OpenSSH
     version first ships it).

### If no response in 21+ days

1. Verify the email actually reached the list (check the archive).
2. If it did and there's been silence: send one polite reply-to-self
   ping. Use the template in
   `openssh_submission_email_*.md` "Notes for the sender" section.
3. Update Status: from SENT to PINGED.
4. If another 21 days pass after PINGED: update Status to SILENCE.
   Don't ping again. Patch is effectively rejected by silence.

### If the user asks to revise an as-yet-unsent draft

1. Re-read both submission emails before editing one.
2. If the user's feedback contradicts the realistic-outcomes
   assessment at the bottom of each email, push back gently — the
   assessment was based on actual upstream history.
3. Keep the emails tight. OpenSSH's list culture rewards brevity.

---

## 5. Submission log — Email 1 (connection-endpoint tokens)

**Patch:** `patches/0002-Add-connection-endpoint-tokens-to-AuthorizedKeysComm.patch`

**Status:** DRAFT

**Submitted:** _(not yet)_

**Archive URL:** _(fill in after sending — the openssh-unix-dev archive
generates a permalink for each message)_

**Message-ID:** _(fill in after sending; visible in the sent email's
headers)_

**Iteration history:**

- v1: drafted 2026-05-15 by Claude session. See
  `openssh_submission_email_1.md`.

**Maintainer responses:** _(none yet)_

---

## 6. Submission log — Email 2 (SSH_AKC_PHASE env var)

**Patch:** `patches/0001-Set-SSH_AKC_PHASE-env-var-on-AuthorizedKeysCommand-c.patch`

**Status:** DRAFT — **blocked on authorship fix before sending.** See
`openssh_submission_email_2.md` "CRITICAL pre-send step" section.

**Submitted:** _(not yet)_

**Archive URL:** _(not yet)_

**Message-ID:** _(not yet)_

**Iteration history:**

- v1: drafted 2026-05-15 by Claude session. See
  `openssh_submission_email_2.md`.

**Maintainer responses:** _(none yet)_

---

## 7. Quick-reference: regenerating patches

If the source in `../../ssh-rt-auth-openssh/openssh-portable/` is
ever changed (e.g., to incorporate maintainer feedback), regenerate
the .patch files in this directory:

```bash
cd ../../ssh-rt-auth-openssh
git -C openssh-portable format-patch V_9_9_P1..HEAD \
    -o "$(pwd)/../ssh-rt-auth/openssh-patches/patches" \
    -- auth2-pubkey.c misc.c
```

The `-- auth2-pubkey.c misc.c` filter is important — without it, the
exported patches will include autogenerated files (ChangeLog, configure,
manpages, etc.) and balloon to 45,000+ lines.

Verify the patch sizes are sane (~100-200 lines each):

```bash
wc -l openssh-patches/patches/*.patch
```

And that they apply cleanly to a pristine V_9_9_P1 checkout:

```bash
cd ../ssh-rt-auth-openssh/openssh-portable
git stash push -u
git checkout V_9_9_P1
git apply --check ../ssh-rt-auth/openssh-patches/patches/0001-*.patch
git apply --check ../ssh-rt-auth/openssh-patches/patches/0002-*.patch
# (don't apply, just check)
git checkout ssh-rt-auth-v1
git stash pop
```

---

## 8. What's deliberately NOT in this submission

For completeness, these design ideas were considered but **NOT**
proposed upstream:

- **0004 `AuthorizationModule` directive** — full post-userauth
  authorization hook returning an X.509 cert that sshd parses and
  enforces. ~500-800 LOC. Architecturally bigger; would have needed
  RFC-style discussion first, and the parent ssh-rt-auth project no
  longer needs it (the wrapper does this work). Kept as historical
  design in `NOTES.md` only.
- **0005-0007 cert-extension enforcement patches** — channel-policy,
  force-command, CheckExpireCommand. All depend on 0004; deprecated
  with it.

If anyone in the upstream review thread asks "why don't you propose a
real authorization framework instead of these small AKC patches?"
the honest answer is: "The downstream project that motivated these
patches has moved to wrap-and-proxy and no longer needs the big
framework. The small patches are independently useful to any
AKC-helper consumer." That answer is the actual truth and is fine
to share.

---

## 9. License note

OpenSSH is BSD-2-clause licensed. Our patches contributed upstream
become BSD-2-clause by submission. The local ssh-rt-auth project is
Apache-2.0; the patches' upstream-bound copies effectively change
license on submission. This is normal and well-understood by
contributors; no special handling needed beyond not asserting Apache
copyright in the patch headers (which we don't).
