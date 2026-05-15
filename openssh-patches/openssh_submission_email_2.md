# OpenSSH upstream submission email #2

**Patch:** `patches/0001-Set-SSH_AKC_PHASE-env-var-on-AuthorizedKeysCommand-c.patch`
**Recommended submission order:** **SECOND** (more contentious; submit
*after* Email #1 has at least had a first round of feedback).

**Status:** DRAFT — not yet sent. See `CLAUDE.md` in this directory for
the submission state machine and follow-up workflow.

---

## CRITICAL pre-send step — fix the commit authorship

The exported patch file currently has:

```
From: Damien Miller <djm@mindrot.org>
```

This is **wrong**. It's an artifact of how the change was originally
committed in this repo (the commit hash was copied from an unrelated
upstream djm@ commit, and `git format-patch` preserved that authorship).
Sending it to openssh-unix-dev with djm's name on it will be confusing
at best and look like impersonation at worst — djm@ IS the OpenSSH
maintainer.

**Fix before sending:**

```bash
cd ../ssh-rt-auth-openssh/openssh-portable
git checkout ssh-rt-auth-v1
# Find the SSH_AKC_PHASE commit (the older of the two custom commits)
git log --format='%H %an' V_9_9_P1..HEAD
# It'll be the one authored by Damien Miller. Rebase to amend:
git rebase -i V_9_9_P1
# Mark the SSH_AKC_PHASE commit as 'edit' (it's the FIRST one chronologically).
# After rebase pauses on it:
git commit --amend --author="Kurt Godwin <kurtgo@hotmail.com>" --no-edit
git rebase --continue
# Re-export the patches:
cd ../../ssh-rt-auth/openssh-patches
git -C ../../../ssh-rt-auth-openssh/openssh-portable \
    format-patch V_9_9_P1..HEAD -o "$(pwd)/patches" -- auth2-pubkey.c misc.c
# Verify the new authorship in the .patch file:
head -3 patches/0001-Set-SSH_AKC_PHASE-env-var-on-AuthorizedKeysCommand-c.patch
# Expect: From: Kurt Godwin <kurtgo@hotmail.com>
```

**Do NOT send Email #2 until this is fixed.** Mark this step
complete by setting the checkbox below.

- [ ] Authorship amended to Kurt Godwin, patch re-exported.

---

## Pre-send checklist

- [ ] **Authorship fix above completed.**
- [ ] Confirm the patch still applies cleanly to current `master` of
      `openssh-portable` (`git apply --check patches/0001-*.patch`).
- [ ] **Email #1 has been submitted and received at least one round of
      feedback** (so this isn't the maintainers' first impression of you).
- [ ] Send as plain text. Inline the patch. Same mechanics as Email #1.

---

## Email

**To:** `openssh-unix-dev@mindrot.org`

**Subject:** `[PATCH] sshd: set SSH_AKC_PHASE env var on AuthorizedKeysCommand spawns`

**Body:**

---

Hi,

Following up on my earlier patch for connection-endpoint tokens (see
[link to first email's archive URL once available]), here's a smaller
companion proposal for the AuthorizedKeysCommand path.

sshd invokes the helper **twice** per accepted publickey connection
— once during the RFC 4252 §7 "querying" phase (`have_sig=0`, client
asks "would you accept this key?") and once during the "attempting"
phase (`have_sig=1`, client has signed a challenge). This is correct
protocol behaviour, not a sshd bug. It does, however, mean that helpers
which do expensive work per invocation pay the cost twice.

Concrete examples of "expensive work":

- LDAP / remote-directory lookups (the LDAP-AKC family of helpers).
- mTLS RPCs to authorization services.
- Anything involving an HSM signing operation.

There's no way for the helper to distinguish the two phases from any
signal sshd provides today. The patch sets an environment variable
`SSH_AKC_PHASE={query,verify}` on each spawn, derived from the
`have_sig` flag that sshd already parses from the userauth packet.

Helpers that opt-in can short-circuit the query phase (exit 0 with no
output, asking sshd to ask the client for a signature) and only do real
work on verify. Helpers that don't read the env var see byte-for-byte
identical behaviour: existing AKC consumers are unaffected.

The patch is small (~20 lines across `auth2-pubkey.c` and `misc.c`).
The misc.c portion ensures the env var passes through `subprocess()`'s
deliberately-minimal child environment.

Why an env var and not a `%`-token:

- Tokens get expanded into the helper's `argv`, which is visible in
  `ps`. Env vars stay in the child's address space — same locality
  as the key material itself.
- Existing helpers ignore unknown env vars more reliably than they
  ignore unknown `%`-tokens. The opt-in pattern is cleaner.

I considered making this a new `AuthorizedKeysCommandPhase yes|no`
sshd_config directive instead, but that adds config surface and
doesn't compose as cleanly with existing helpers that just want
to gate on `os.environ`. The env var seems lighter-touch.

Patch follows. Happy to take this any direction the list prefers —
including dropping the proposal if there's a better way to surface
the phase information.

Thanks,
Kurt Godwin

---

```
[PASTE patches/0001-Set-SSH_AKC_PHASE-env-var-on-AuthorizedKeysCommand-c.patch HERE,
 AFTER fixing the authorship per the section above.

 Same mechanics as Email #1: plain text, inline, do not let your mail
 client rewrap the diff.]
```

---

## Notes for the sender

- **Reference Email #1** in the body (replace the bracketed
  "[link to first email's archive URL once available]" with the actual
  mailing-list archive URL of your first submission). Linking
  acknowledges this isn't your first contact and helps maintainers
  remember the context.
- After sending, paste the message-ID into `CLAUDE.md` under
  "Submission log — Email 2".
- Be especially open to "rework as a token" or "rework as a directive"
  feedback. Env-var injection is the most contentious shape of the
  three; the maintainers may prefer something else.

---

## Realistic outcomes

Per my earlier analysis:

- **20-40% chance accepted** as-is. Env-var-injection patches face
  more resistance than token additions.
- **Most likely review comments:**
  - "Make this a `%P` token instead." — easy fix; minor restructure.
  - "Add a `AuthorizedKeysCommandPhase` directive." — slightly bigger
    fix, but doable.
  - "Why not just have helpers cache their decision per (user, key)?"
    — defend with examples where caching isn't appropriate (HSM
    operations, real-time policy that must be re-checked).
- **Most likely outright rejection reason:** "Not enough demonstrated
  demand." Counter by linking concrete helpers that would benefit;
  ideally have a real downstream user (LDAP-AKC maintainer, Vault
  team, etc.) chime in on the thread.

---

## Why this one might fail and that's OK

The AKC double-call has been there forever. Many helpers work around
it (caching, SQLite-backed dedup like ours, etc.). The upstream
position might reasonably be "you've already solved this; we don't
need to add API surface for it."

If this patch is rejected, the rejection is informative — it tells
ssh-rt-auth (and the AKC-helper community more broadly) that the
canonical workaround is "deduplicate downstream," not "ask sshd."
That's a fine outcome too.
