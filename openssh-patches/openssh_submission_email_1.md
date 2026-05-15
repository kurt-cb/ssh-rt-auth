# OpenSSH upstream submission email #1

**Patch:** `patches/0002-Add-connection-endpoint-tokens-to-AuthorizedKeysComm.patch`
**Recommended submission order:** **FIRST** (smaller, more upstream-friendly, builds credibility before submitting #2).

**Status:** DRAFT — not yet sent. See `CLAUDE.md` in this directory for
the submission state machine and follow-up workflow.

---

## Pre-send checklist

- [ ] Confirm the patch still applies cleanly to current `master` of
      `openssh-portable` (`git apply --check patches/0002-*.patch` against
      a fresh checkout).
- [ ] Subscribe to the openssh-unix-dev mailing list:
      https://lists.mindrot.org/mailman/listinfo/openssh-unix-dev
- [ ] Lurk for ~3-5 days to absorb the list's tone before posting.
- [ ] Send as **plain text** (no HTML formatting). Most modern mail
      clients can do this; in Gmail it's "Plain text mode" under the
      compose-window overflow menu.
- [ ] Inline the patch (do **not** attach). The diff is included
      below in copy-paste-ready form.
- [ ] Check that line wrap is set to ~72-80 chars and that the patch
      itself is NOT auto-wrapped by your mail client (Gmail and some
      others will silently rewrap, breaking the diff).

---

## Email

**To:** `openssh-unix-dev@mindrot.org`

**Subject:** `[PATCH] sshd: expose connection-endpoint tokens to AuthorizedKeysCommand`

**Body (everything below this line, including the patch):**

---

Hi,

`AuthorizedKeysCommand` helpers today have no first-class way to learn
the connection's source IP, source port, local IP, or local port. The
existing tokens (`%C`, `%D`, `%U`, `%u`, `%h`, `%t`, `%f`, `%k`, `%i`,
`%s`, `%T`) cover identity and the user but not the network endpoints.

Helpers that need this information today fall back to scraping
`/proc/<ppid>/fd/*` and cross-referencing `/proc/net/tcp`. That works
on simple sshd configurations but is brittle: with privsep there are
multiple sshd processes between the AKC child and the actual TCP
socket, the mapping isn't reliable, and IPv6 / rdomain cases are
poorly handled. In practice helpers like LDAP-backed AKC, Vault's
ssh-host-certs flow, and our own runtime-authorization service have
all hit this.

The attached patch adds four new substitution tokens to
AuthorizedKeysCommand's `%`-expansion table:

  %R  remote client IP address
  %r  remote client TCP port
  %L  local IP that accepted the connection
  %l  local TCP port that accepted the connection

All four values are already available to sshd at AKC-spawn time — the
patch sources them from `ssh_remote_ipaddr()`, `ssh_remote_port()`,
`ssh_local_ipaddr()`, and `ssh_local_port()`, which are already used
elsewhere in `user_key_command_allowed2()` to build the `%C`
connection-ID hash. Net cost is plumbing `remote_port`, `local_ip`,
and `local_port` through one more function signature and adding the
table entries.

The patch is strictly additive: helpers that don't reference the new
tokens see byte-for-byte identical behaviour, and the new tokens follow
existing naming conventions (uppercase for addresses, lowercase for
ports, consistent with `%C` / `%T` etc.).

Two concrete deployment scenarios this unlocks:

1. **Source-CIDR policy without `/proc` scraping.** Helpers can match
   the actual client IP against allowed-source networks deterministically
   per call.

2. **Per-interface policy on multi-homed hosts.** A bastion with
   separate mgmt-VLAN and DMZ interfaces can now express "this user
   role is only authorizable when the connection arrived on the mgmt
   VLAN," via `%L` matched against a known interface IP.

Interface-name (`%I`) is out of scope here — that needs `getifaddrs()`
plumbing and isn't always determinable. Happy to send as a separate
patch later if there's interest.

Patch follows. I'm happy to rework style or function-signature shape to
fit OpenSSH's conventions.

Thanks,
Kurt Godwin

---

```
[PASTE patches/0002-Add-connection-endpoint-tokens-to-AuthorizedKeysComm.patch HERE,
 INLINE, starting from the `From ` line.

 Practical: open the .patch file in your editor, copy from the first
 `From ...` line through the trailing `--` separator line + `2.x.x`
 version line. Paste below this line, as plain text. Do not let your
 mail client touch the formatting.]
```

---

## Notes for the sender

- **Authorship is correct** on this patch (Kurt Godwin
  `<kurtgo@hotmail.com>`). Verify with:
  `git -C ../ssh-rt-auth-openssh/openssh-portable log --format='%an %ae' -1 ssh-rt-auth-v1` — output should be `Kurt Godwin kurtgo@hotmail.com`.
- After sending, paste the message-ID into `CLAUDE.md` in this
  directory under the "Submission log — Email 1" section so future
  Claude sessions can find the thread.
- If you get **no response after 3 weeks**, send one polite ping
  (reply-all to your own message with "Friendly ping — any feedback
  on this?"). Don't ping more than once.
- If you get feedback asking for changes, drop the response email's
  full text into `CLAUDE.md` under the "Submission log" so the next
  Claude session has the full context to draft a revised patch.

---

## Realistic outcomes

Per my earlier analysis (in `design/...` and our chat):

- **40-60% chance accepted** as-is or with minor wording changes. Token
  additions following existing conventions are OpenSSH's most welcoming
  patch-class.
- **Most likely review comments:**
  - "Why not also add `%I` (interface)?" — pre-empted above.
  - "Use `getsockname()` directly instead of `ssh_local_*()`" — easy fix.
  - "Add documentation in `sshd_config.5`." — easy fix; would be a
    follow-up commit.
- **Hardest possible feedback:** "We don't think these tokens are
  needed; helpers can introspect `/proc`." Respond by linking concrete
  helper projects that have hit this (LDAP-AKC, Vault, ours).
