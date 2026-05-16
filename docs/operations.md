# mssh — operations

This document covers the day-to-day operator workflow: install the
pieces, bootstrap a CA, enrol servers and users, drive the
adoption journey, manage policy, troubleshoot.

For evaluation and high-level overview see
[overview.md](overview.md). For the API contract see
[design/api.md](../design/api.md). For the architecture see
[design/architecture.md](../design/architecture.md).

---

## Quick install (current state)

The packaging story is interim — a proper `apt install mssh msshd`
distro package is on the [future-ideas list](../design/future-ideas.md).
Today the install is:

```bash
# On every machine that runs any mssh component:
git clone https://github.com/kurt-cb/ssh-rt-auth.git
cd ssh-rt-auth/python
pip install -e .
```

This installs the `mssh`, `mssh-admin`, `mssh-ca`, and `msshd`
binaries into your active Python environment.

Future install path (see
[future-ideas §install_mssh](../design/future-ideas.md)):

```bash
install_mssh.sh /path/to/mssh-<version>.tar.gz
# … lays down the venv + binaries + systemd units, disabled.
```

---

## Bootstrap a CA

The CA holds the signing key, so it bootstraps itself:

```bash
mssh-admin init --ca-dir /etc/mssh-ca
# Generates: signing-key.pem, signing-cert.pem (root),
# bootstrap-admin-{cert,key}.pem, tls-{server,ca}-cert.pem.
```

The `bootstrap-admin-{cert,key}.pem` pair is your initial admin
identity. Move them to your operator workstation; subsequent
`mssh-admin` commands will reference them.

Start the CA service:

```bash
mssh-ca --config /etc/mssh-ca/ca-config.yaml
# or via the shipped systemd unit:
systemctl enable --now mssh-ca
```

The CA listens on TLS (port 8443 by default) with mTLS-only
client auth.

---

## Enrol a server

On your operator workstation, with the bootstrap admin creds:

```bash
mssh-admin server add srv-acct-01 --groups accounting,production
# → prints the mTLS cert + key (printed once, not retained by CA)
```

Capture the printed cert + key. SSH to the target server (or pipe
through `install_mssh.sh`) and provision them:

```
/etc/mssh/server-mtls.crt   (cert)
/etc/mssh/server-mtls.key   (key, mode 600)
/etc/mssh/ca-tls-root.pem   (the CA's TLS root, for verifying CA replies)
```

Drop a `wrapper.yaml` and start msshd:

```yaml
# /etc/mssh/wrapper.yaml (starting in fallback mode — Phase 1
# of the adoption journey, see below)
mode: fallback
fallback:
  host: 127.0.0.1
  port: 22
listen:
  external_address: 0.0.0.0
  external_port: 2200
```

```bash
systemctl enable --now msshd
```

At this point msshd is in front of your existing sshd in
transparent-proxy mode. Users `ssh -p 2200 user@srv-acct-01`
exactly as they would `ssh -p 22 user@srv-acct-01`; the auth
is the operator's existing sshd policy. Verify the wiring is
good before moving on.

---

## Enrol a user

```bash
mssh-admin user add alice
mssh-admin user key add alice --kind ssh-pubkey --blob "$(ssh-keygen -y -f ~alice/.ssh/id_ed25519)"
mssh-admin policy add alice --server-groups accounting --channels session
```

Each `policy add` attaches one rule to the user. Multiple rules
union. See [design/api.md § policy management](../design/api.md#policy-management)
for the full schema (source CIDRs, time windows, max cert validity,
…).

---

## The adoption journey

mssh deliberately supports three operating modes so the cutover from
"vanilla sshd" to "CA-mediated auth" can be done **per-server, on
your schedule, reversibly**. Each mode is a single line in
`wrapper.yaml`; restart msshd to flip.

### Phase 0 — no mssh

Before adoption. Your fleet runs unmodified sshd on port 22.
Users `ssh user@host`. Auth is your existing sshd config.

### Phase 1 — `mode: fallback`

msshd in front, transparent TCP proxy. Users `ssh -p 2200 user@host`.
Your existing sshd policy is still doing all the auth; msshd just
proves it's wired into the connection path.

```yaml
mode: fallback
fallback: { host: 127.0.0.1, port: 22 }
listen: { external_address: 0.0.0.0, external_port: 2200 }
```

What this validates: msshd accepts connections, can bind the new
port, has a sane systemd lifecycle. **No security change yet.**

### Phase 2 — `mode: gated` (deferred)

Not yet implemented. See [future-ideas.md § gated mode](../design/future-ideas.md)
and [archive/design/ssh-rt-auth-detailed-wrapper.md §6.5.1](../archive/design/ssh-rt-auth-detailed-wrapper.md).

When available: msshd does the full mTLS + CA call (so unauthorized
clients can't even attempt auth) but forwards to your existing
sshd for the actual auth. Bridges Phase 1 and Phase 3 without
forcing operators to retranslate their existing sshd policy on
day one.

### Phase 3 — `mode: enforce`

msshd terminates mTLS, calls the CA, mints an ephemeral OpenSSH
user cert, and hands the connection to a **hermetic inner sshd**
that only trusts msshd's mint key. CA policy is now the source of
truth.

```yaml
mode: enforce
listen:
  external_address: 0.0.0.0
  external_port: 2200
tls:
  server_cert: /etc/mssh/wrapper-server.crt
  server_key:  /etc/mssh/wrapper-server.key
  user_ca_pubkey: /etc/mssh/user-ca.pub
ca:
  endpoints: [https://mssh-ca.internal:8443]
  client_cert: /etc/mssh/server-mtls.crt
  client_key:  /etc/mssh/server-mtls.key
  ca_pubkey:   /etc/mssh/ca-tls-root.pem
  timeout_seconds: 5
inner:
  sshd_binary: /usr/sbin/sshd
  port_range: [49152, 65535]
users:
  allowed: ["*"]
```

Users `mssh user@host:2200`. mssh-admin's enrollment + policy is
the auth oracle. Your existing `/etc/ssh/sshd_config` is bypassed.

### Rolling back

Every step is reversible by flipping `mode:` and restarting msshd.
Operators with `flip-to-enforce.sh` / `flip-to-fallback.sh`
helpers (the adhoc lab ships these) can A/B between modes during
debugging.

---

## Common operator tasks

### Add a user, give them access

```bash
mssh-admin user add alice
mssh-admin user key add alice --kind ssh-pubkey --blob <pubkey>
mssh-admin policy add alice --server-groups accounting
```

### Revoke a user immediately

```bash
mssh-admin user del alice
# Any in-flight session is unaffected (already authorized) but all
# future authorize calls deny within the CA's cache TTL (default 1 minute).
```

### Add a server to a group

```bash
mssh-admin server groups srv-new --add accounting
```

### Rotate an admin's mTLS cert

```bash
mssh-admin admin add bob-2026     # mint new creds
mssh-admin admin del bob          # revoke old (do this AFTER bob switches)
```

### Search the audit log

```bash
mssh-admin audit --since "1 hour ago" --result denied
# JSON-Lines on stdout. Filter with jq.
```

### Bounce the CA without dropping sessions

The CA can be restarted at will. In-flight authorize calls fail
with `result: error` and msshd retries against the next endpoint
in its endpoint list. Existing established SSH sessions are
**unaffected** — they're already authorized.

For zero-downtime CA work, run two CA instances behind your DNS
and rolling-restart them.

---

## Troubleshooting

### "msshd won't start"

Check the systemd journal: `journalctl -u msshd -n 100`.
Common causes:

  - `wrapper.yaml` syntax error → msshd refuses to start, logs
    the parse failure.
  - mTLS cert files missing or wrong permissions (`server-mtls.key`
    must be mode 600).
  - In enforce mode: CA endpoint unreachable at startup. msshd
    will retry; check connectivity from the server to the CA.

### "Client gets denied, but should be allowed"

  - Check the CA audit log for the denied entry's
    `denied_reason`. The enum tells you which check failed
    (policy_no_match, policy_source_cidr, etc.).
  - Look up the user's policies:
    `mssh-admin user show alice`.
  - Verify the server's group membership matches the policy:
    `mssh-admin server show srv-acct-01`.

### "Client gets allowed, but inner sshd then refuses"

Means the ephemeral OpenSSH cert msshd minted failed to load
into the hermetic inner sshd. Check msshd's stderr for the cert
mint output and the inner sshd's complaint. Usually a clock-skew
issue (the cert is not yet valid) or a mismatch between msshd's
local user-CA pubkey and the inner sshd's `TrustedUserCAKeys`
pin.

### "I want to switch a server to debug mode"

(Future feature; see [future-ideas.md § debug_sshd swap-in](../design/future-ideas.md).)
Today: stop msshd and run `debug_sshd` directly to inspect what
the CA returns for each request.

### "I think my CA signing key is compromised"

Worst case. Procedure:

  1. Stop the CA. Every server fails closed.
  2. Generate a fresh CA signing key + new root cert.
  3. Re-enrol every server (their old mTLS creds were signed by
     the old root and are now invalid).
  4. Re-enrol every admin.
  5. Re-issue every authorization cert (they were signed by the
     old root too).

The audit log on the old CA host is invaluable here for "what
did the attacker touch."

If you've enabled emergency certs on servers, those continue to
work until manually revoked — handy for break-glass continuity
during the re-bootstrap, dangerous if the attacker has access
to those certs.

---

## Future operator features

These aren't here yet but are on the roadmap:

  - **`gated` mode** — Phase 2 of the journey (above).
  - **`install_mssh.sh`** — distro-agnostic installer that
    simulates `apt install mssh msshd`.
  - **Legacy config import** — `mssh-admin import` scrapes
    existing `authorized_keys` + `sshd_config` into a draft
    CA enrollment.
  - **Dual-enforce mode** — CA evaluates both the imported
    legacy ruleset AND the new policy, logs divergence cases
    so the operator can tighten without disruption.
  - **MCP interface to the CA** — natural-language diagnostics
    ("why was alice denied yesterday?") + trusted-AI config.
  - **Browser-based bastion** — xterm.js terminal over HTTPS
    with mTLS auth; zero-install client.
  - **Native distro packages** (`.deb`, `.rpm`, `.apk`).

See [design/future-ideas.md](../design/future-ideas.md) for the
full list with scope estimates.
