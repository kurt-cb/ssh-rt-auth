#!/bin/sh
# ssh-rt-auth wrapper — host upgrade / install / verify / rollback.
#
# POSIX sh (works under ash, busybox sh, bash). Run as root on the
# target host:
#
#   scp upgrade.sh root@target-host:/root/
#   ssh root@target-host
#   chmod +x upgrade.sh
#   ./upgrade.sh install     # phase 1 — fallback-mode wrapper alongside sshd
#   ./upgrade.sh verify-1    # confirm SSH still works through the wrapper
#   ./upgrade.sh enforce     # phase 2 — switch wrapper to CA-enforced
#   ./upgrade.sh verify-2    # confirm CA-mediated auth works
#   ./upgrade.sh cutover     # phase 3 — move wrapper to port 22
#   ./upgrade.sh verify-3    # confirm port 22 still works
#   ./upgrade.sh rollback    # at any point: restore original sshd state
#
# DESIGN PRINCIPLES
# - **Never lock out the operator.** Each phase keeps the previous
#   path open until the operator explicitly cuts over. The original
#   system sshd on port 22 is untouched in phases 1 and 2.
# - **Fallback-by-default.** The wrapper installs in transparent-proxy
#   mode (no CA call, no cert mint — just byte-forward to system sshd).
#   This proves the wrapper is wired up without changing auth behavior.
# - **Operator verifies every phase from a SECOND terminal.** The
#   script prompts; the operator confirms before the next phase. If a
#   phase breaks something, the operator's current SSH session (in the
#   first terminal) is the rollback escape.
# - **Idempotent where possible.** Re-running a completed phase should
#   be a no-op or a clean re-install.
#
# This script is **provisioning glue**, not a full installer. It assumes
# the ssh-rt-auth wrapper package has been delivered to the host (e.g.,
# distro package, tarball under /opt, or a binary copied alongside this
# script). The actual binary names / paths are configurable below.

set -eu

# ---------------------------------------------------------------------------
# Configuration — operator may override these via env vars before running.
# ---------------------------------------------------------------------------

WRAPPER_BIN="${WRAPPER_BIN:-/usr/sbin/ssh-rt-wrapperd}"
WRAPPER_ADMIN_BIN="${WRAPPER_ADMIN_BIN:-/usr/sbin/ssh-rt-wrapper-admin}"
WRAPPER_PKG="${WRAPPER_PKG:-/root/ssh-rt-auth-wrapper.tar.gz}"
                # tarball or .deb/.rpm path; install logic below picks
                # the right tool based on what's present.

WRAPPER_CONFIG_DIR="${WRAPPER_CONFIG_DIR:-/etc/ssh-rt-auth}"
WRAPPER_STATE_DIR="${WRAPPER_STATE_DIR:-/var/lib/ssh-rt-auth}"
WRAPPER_CONFIG="${WRAPPER_CONFIG:-${WRAPPER_CONFIG_DIR}/wrapper.yaml}"

# Phase 1 port: wrapper lives here in fallback mode, doesn't disrupt
# the system sshd on 22.
WRAPPER_PORT_INITIAL="${WRAPPER_PORT_INITIAL:-2200}"

# Phase 3 cutover port (typically 22; can be overridden if the operator
# wants to keep system sshd on a non-22 port permanently).
WRAPPER_PORT_FINAL="${WRAPPER_PORT_FINAL:-22}"

# CA endpoint — required for phase 2 (enforce). Will be prompted for
# if not pre-set in env or in wrapper.yaml already.
CA_ENDPOINTS="${CA_ENDPOINTS:-}"

# Backup directory for files we change; restored by rollback.
BACKUP_DIR="${BACKUP_DIR:-/var/backups/ssh-rt-auth-upgrade}"

# State file tracks which phase we're at — rollback uses it to know what
# to undo.
STATE_FILE="${STATE_FILE:-${BACKUP_DIR}/phase.state}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { printf '[%s] WARNING: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '[%s] ERROR: %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

confirm() {
    # $1 = prompt; returns 0 if user says yes, 1 otherwise.
    printf '%s [y/N]: ' "$1" >&2
    read -r ans || return 1
    case "$ans" in
        y|Y|yes|YES) return 0 ;;
        *)           return 1 ;;
    esac
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "must be run as root"
}

backup() {
    # $1 = absolute path to back up. Idempotent — won't overwrite an
    # existing backup if one already exists for this path.
    src="$1"
    [ -e "$src" ] || return 0
    mkdir -p "$BACKUP_DIR"
    # Replace / with __ in the backup filename so we can flatten the tree.
    dst="${BACKUP_DIR}/$(printf '%s' "$src" | sed 's|/|__|g').orig"
    if [ ! -e "$dst" ]; then
        cp -p "$src" "$dst"
        log "backed up $src → $dst"
    else
        log "backup of $src already exists at $dst (skipping)"
    fi
}

restore() {
    # $1 = absolute path to restore from the backup dir.
    src="$1"
    dst="${BACKUP_DIR}/$(printf '%s' "$src" | sed 's|/|__|g').orig"
    if [ -e "$dst" ]; then
        cp -p "$dst" "$src"
        log "restored $src from $dst"
    fi
}

set_phase() {
    mkdir -p "$BACKUP_DIR"
    printf '%s\n' "$1" > "$STATE_FILE"
}

get_phase() {
    if [ -r "$STATE_FILE" ]; then cat "$STATE_FILE"; else echo "none"; fi
}

is_systemd() {
    [ -d /run/systemd/system ]
}

service_running() {
    # Returns 0 if a service is active. Tries systemd first, then
    # falls back to rc-service (OpenRC) and finally to a process check.
    name="$1"
    if is_systemd; then
        systemctl is-active --quiet "$name" 2>/dev/null && return 0
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "$name" status >/dev/null 2>&1 && return 0
    else
        pgrep -x "$name" >/dev/null 2>&1 && return 0
    fi
    return 1
}

service_action() {
    # $1 = action (start/stop/restart/enable/disable)
    # $2 = service name
    action="$1"; name="$2"
    if is_systemd; then
        systemctl "$action" "$name"
    elif command -v rc-service >/dev/null 2>&1; then
        case "$action" in
            enable)  rc-update add "$name" default ;;
            disable) rc-update del "$name" default ;;
            *)       rc-service "$name" "$action" ;;
        esac
    else
        warn "no service manager detected — '$action $name' must be done manually"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

cmd_install() {
    require_root
    log "Phase 1: installing wrapper in FALLBACK mode (system sshd untouched)"

    # 1. Sanity: ensure system sshd is up and reachable. We're about to
    #    install something that will forward to it.
    if ! service_running sshd && ! service_running ssh; then
        die "system sshd not running — refusing to proceed. The wrapper " \
            "in fallback mode forwards to the system sshd; if it's down, " \
            "you'd lock yourself out."
    fi

    # 2. Install the wrapper package if not present.
    if [ ! -x "$WRAPPER_BIN" ]; then
        log "wrapper binary not at $WRAPPER_BIN; attempting install"
        if [ -e "$WRAPPER_PKG" ]; then
            case "$WRAPPER_PKG" in
                *.deb) dpkg -i "$WRAPPER_PKG" || apt-get install -f -y ;;
                *.rpm) rpm -i --replacepkgs "$WRAPPER_PKG" || \
                       (command -v dnf >/dev/null && dnf install -y "$WRAPPER_PKG") || \
                       (command -v yum >/dev/null && yum install -y "$WRAPPER_PKG") ;;
                *.tar.gz|*.tgz)
                       tar -C / -xzf "$WRAPPER_PKG" ;;
                *.apk) apk add --allow-untrusted "$WRAPPER_PKG" ;;
                *)     die "unknown package format: $WRAPPER_PKG" ;;
            esac
        else
            die "wrapper not installed and no package at $WRAPPER_PKG. " \
                "Set WRAPPER_PKG=... or install ssh-rt-auth-wrapper package first."
        fi
    fi
    [ -x "$WRAPPER_BIN" ] || die "wrapper still not installed at $WRAPPER_BIN"

    # 3. Create config + state dirs.
    mkdir -p "$WRAPPER_CONFIG_DIR" "$WRAPPER_STATE_DIR"
    chmod 0750 "$WRAPPER_CONFIG_DIR" "$WRAPPER_STATE_DIR"

    # 4. Write a minimal fallback-mode config.
    backup "$WRAPPER_CONFIG"
    cat > "$WRAPPER_CONFIG" <<EOF
# Generated by upgrade.sh — phase 1 (fallback mode).
# Edit /etc/ssh-rt-auth/wrapper.yaml to customise.
mode: fallback
fallback:
  host: 127.0.0.1
  port: 22
listen:
  external_address: 0.0.0.0
  external_port: ${WRAPPER_PORT_INITIAL}
  interfaces: []
# Other sections (tls, ca, users, ...) populated in phase 2 (enforce).
EOF
    chmod 0640 "$WRAPPER_CONFIG"
    log "wrote $WRAPPER_CONFIG (fallback mode, port $WRAPPER_PORT_INITIAL)"

    # 5. Enable + start the wrapper service.
    if is_systemd; then
        service_action enable ssh-rt-wrapperd
        service_action start  ssh-rt-wrapperd
    elif command -v rc-service >/dev/null 2>&1; then
        service_action enable ssh-rt-wrapperd
        service_action start  ssh-rt-wrapperd
    else
        warn "no service manager detected — please start the wrapper manually:"
        warn "  $WRAPPER_BIN --config $WRAPPER_CONFIG &"
    fi

    set_phase 'installed-fallback'

    cat <<EOF

================================================================
Phase 1 complete. Wrapper is running in FALLBACK mode on port
${WRAPPER_PORT_INITIAL}, transparently proxying to system sshd on
127.0.0.1:22. System sshd remains the actual auth surface.

NEXT STEP — verify from a SECOND terminal (keep this one open):

  ssh -p ${WRAPPER_PORT_INITIAL} <your-user>@<this-host>

You should land in a normal shell, authenticated by the system sshd
exactly as before. If that works, run:

  ./upgrade.sh verify-1

If it doesn't, run:

  ./upgrade.sh rollback

================================================================
EOF
}

cmd_verify_1() {
    require_root
    [ "$(get_phase)" = 'installed-fallback' ] || \
        warn "current phase is '$(get_phase)', expected 'installed-fallback'"

    log "verify-1: wrapper health-checks (fallback mode)"

    if ! service_running ssh-rt-wrapperd; then
        die "ssh-rt-wrapperd is not running"
    fi

    if ! ss -ltn 2>/dev/null | grep -q ":${WRAPPER_PORT_INITIAL}\b" && \
       ! netstat -ltn 2>/dev/null | grep -q ":${WRAPPER_PORT_INITIAL}\b"; then
        die "nothing listening on port $WRAPPER_PORT_INITIAL"
    fi

    log "ssh-rt-wrapperd is running and bound to port $WRAPPER_PORT_INITIAL"
    log "verify access via:  ssh -p $WRAPPER_PORT_INITIAL <user>@<this-host>"

    set_phase 'verified-fallback'
    cat <<EOF

Phase 1 verification complete. Next step (when ready):

  ./upgrade.sh enforce

EOF
}

cmd_enforce() {
    require_root

    # Require phase 1 verified — defensive, not absolute.
    case "$(get_phase)" in
        verified-fallback|installed-fallback) ;;
        *) warn "unexpected current phase '$(get_phase)' — proceeding anyway" ;;
    esac

    log "Phase 2: switching wrapper to ENFORCE mode (CA-mediated auth)"

    # Need CA endpoint + mTLS material.
    if [ -z "$CA_ENDPOINTS" ]; then
        printf 'CA endpoint URL (e.g. https://ca.internal:8443): ' >&2
        read -r CA_ENDPOINTS
        [ -n "$CA_ENDPOINTS" ] || die "CA endpoint required for enforce mode"
    fi

    for f in "$WRAPPER_CONFIG_DIR/wrapper-server.crt" \
             "$WRAPPER_CONFIG_DIR/wrapper-server.key" \
             "$WRAPPER_CONFIG_DIR/user-ca.pub" \
             "$WRAPPER_CONFIG_DIR/wrapper-mtls.crt" \
             "$WRAPPER_CONFIG_DIR/wrapper-mtls.key" \
             "$WRAPPER_CONFIG_DIR/server-mtls-ca.pub"; do
        [ -r "$f" ] || die "missing required cert/key file: $f " \
                          "(provision via ssh-rt-admin server add + copy)"
    done

    # Rewrite config with enforce mode.
    backup "$WRAPPER_CONFIG"
    cat > "$WRAPPER_CONFIG" <<EOF
# Generated by upgrade.sh — phase 2 (enforce mode).
mode: enforce

listen:
  external_address: 0.0.0.0
  external_port: ${WRAPPER_PORT_INITIAL}
  interfaces: []

tls:
  server_cert: ${WRAPPER_CONFIG_DIR}/wrapper-server.crt
  server_key:  ${WRAPPER_CONFIG_DIR}/wrapper-server.key
  user_ca_pubkey: ${WRAPPER_CONFIG_DIR}/user-ca.pub

ca:
  endpoints:
    - ${CA_ENDPOINTS}
  client_cert: ${WRAPPER_CONFIG_DIR}/wrapper-mtls.crt
  client_key:  ${WRAPPER_CONFIG_DIR}/wrapper-mtls.key
  ca_pubkey:   ${WRAPPER_CONFIG_DIR}/server-mtls-ca.pub
  timeout_seconds: 5

inner:
  sshd_binary: /usr/sbin/sshd
  port_range: [49152, 65535]

users:
  # POPULATE THIS — wrapper will deny connections for usernames not listed.
  allowed: []

logging:
  level: info
  destination: syslog
  audit_destination: file:/var/log/ssh-rt-auth/wrapper-audit.jsonl
EOF
    chmod 0640 "$WRAPPER_CONFIG"

    # Initialise the local user-CA if it doesn't exist yet.
    if [ -x "$WRAPPER_ADMIN_BIN" ] && \
       [ ! -e "${WRAPPER_STATE_DIR}/wrapper-user-ca" ]; then
        log "initialising local user-CA via $WRAPPER_ADMIN_BIN init"
        "$WRAPPER_ADMIN_BIN" init
    fi

    # Pre-flight: lint the config + check CA reachability.
    if [ -x "$WRAPPER_ADMIN_BIN" ]; then
        log "running $WRAPPER_ADMIN_BIN lint"
        if ! "$WRAPPER_ADMIN_BIN" lint; then
            die "wrapper lint failed — refusing to restart. Fix issues and re-run."
        fi
    else
        warn "$WRAPPER_ADMIN_BIN not present; skipping pre-flight lint"
    fi

    service_action restart ssh-rt-wrapperd

    set_phase 'enforced'

    cat <<EOF

================================================================
Phase 2 complete. Wrapper is now in ENFORCE mode on port
${WRAPPER_PORT_INITIAL}. System sshd on port 22 is STILL RUNNING
as the rollback escape.

NEXT STEP — verify CA-mediated auth from a SECOND terminal:

  mssh -p ${WRAPPER_PORT_INITIAL} <enrolled-user>@<this-host>

The user must be enrolled at the CA with a policy granting access.
If verification succeeds, run:

  ./upgrade.sh verify-2

If it fails:

  ./upgrade.sh rollback

(rollback returns the wrapper to fallback mode; system sshd was
never touched, so port 22 still works regardless.)

================================================================
EOF
}

cmd_verify_2() {
    require_root
    [ "$(get_phase)" = 'enforced' ] || \
        warn "current phase is '$(get_phase)', expected 'enforced'"

    log "verify-2: confirming CA-enforced wrapper is healthy"
    if ! service_running ssh-rt-wrapperd; then
        die "ssh-rt-wrapperd is not running"
    fi
    if [ -x "$WRAPPER_ADMIN_BIN" ]; then
        "$WRAPPER_ADMIN_BIN" lint || die "lint failed in enforce mode"
    fi
    log "OK — wrapper is enforcing"

    set_phase 'verified-enforced'
    cat <<EOF

Phase 2 verification complete. Next step (when ready):

  ./upgrade.sh cutover

This moves the wrapper to port ${WRAPPER_PORT_FINAL} and stops the
system sshd. AFTER cutover, your only SSH entry point is the wrapper —
make sure you have a working enrollment and a way back in.
EOF
}

cmd_cutover() {
    require_root

    log "Phase 3: cutover — moving wrapper to port $WRAPPER_PORT_FINAL"

    case "$(get_phase)" in
        verified-enforced) ;;
        *) confirm "Current phase is '$(get_phase)', not 'verified-enforced'. Cut over anyway?" || \
               die "aborting cutover" ;;
    esac

    confirm "FINAL CONFIRMATION. After cutover, port $WRAPPER_PORT_FINAL is the wrapper, system sshd is stopped. Continue?" || \
        die "aborting cutover"

    # 1. Stop the system sshd. (Note: this disconnects no existing sessions —
    #    they survive sshd restarts.)
    if service_running sshd; then
        service_action stop sshd
    elif service_running ssh; then
        service_action stop ssh
    fi

    # 2. Rewrite wrapper.yaml with port $WRAPPER_PORT_FINAL.
    sed -i.bak \
        "s|external_port: ${WRAPPER_PORT_INITIAL}|external_port: ${WRAPPER_PORT_FINAL}|" \
        "$WRAPPER_CONFIG"

    # 3. Restart wrapper.
    service_action restart ssh-rt-wrapperd

    # 4. Disable system sshd from autostart.
    if service_running sshd 2>/dev/null; then service_action disable sshd || true; fi
    if service_running ssh  2>/dev/null; then service_action disable ssh  || true; fi

    set_phase 'cutover'

    cat <<EOF

================================================================
Phase 3 (cutover) complete. The wrapper is now on port
${WRAPPER_PORT_FINAL}. System sshd is stopped and disabled.

NEXT STEP — verify from a SECOND terminal:

  mssh <enrolled-user>@<this-host>

If this works, you're done — run:

  ./upgrade.sh verify-3

If it doesn't:

  ./upgrade.sh rollback

(rollback re-enables and starts system sshd, returns wrapper to
fallback mode on port ${WRAPPER_PORT_INITIAL}.)

================================================================
EOF
}

cmd_verify_3() {
    require_root
    [ "$(get_phase)" = 'cutover' ] || \
        warn "current phase is '$(get_phase)', expected 'cutover'"

    log "verify-3: confirming wrapper is healthy on port $WRAPPER_PORT_FINAL"
    if ! service_running ssh-rt-wrapperd; then
        die "ssh-rt-wrapperd is not running"
    fi
    if ! ss -ltn 2>/dev/null | grep -q ":${WRAPPER_PORT_FINAL}\b" && \
       ! netstat -ltn 2>/dev/null | grep -q ":${WRAPPER_PORT_FINAL}\b"; then
        die "wrapper not listening on $WRAPPER_PORT_FINAL"
    fi
    log "OK — wrapper is on port $WRAPPER_PORT_FINAL"

    set_phase 'verified-cutover'
    cat <<EOF

================================================================
Upgrade complete. ssh-rt-auth wrapper is the SSH entry point for
this host. System sshd is stopped and disabled.

Periodic verification (e.g. via cron, monitoring):

  $WRAPPER_ADMIN_BIN lint
  systemctl is-active ssh-rt-wrapperd

To roll back at any time: ./upgrade.sh rollback

================================================================
EOF
}

cmd_rollback() {
    require_root
    phase="$(get_phase)"
    log "Rolling back from phase '$phase'"

    # 1. Make sure system sshd is up first — it's the safety net.
    if ! service_running sshd && ! service_running ssh; then
        # Re-enable + start.
        if is_systemd; then
            systemctl enable sshd 2>/dev/null || systemctl enable ssh 2>/dev/null || true
            systemctl start  sshd 2>/dev/null || systemctl start  ssh 2>/dev/null || true
        elif command -v rc-service >/dev/null 2>&1; then
            rc-update add sshd default 2>/dev/null || \
                rc-update add ssh default 2>/dev/null || true
            rc-service sshd start 2>/dev/null || rc-service ssh start 2>/dev/null || true
        fi
    fi

    # 2. Stop the wrapper.
    if service_running ssh-rt-wrapperd; then
        service_action stop ssh-rt-wrapperd
    fi

    # 3. If we're past phase 1, restore the original wrapper config (the
    #    one we backed up). If we're at phase 1, just remove ours.
    case "$phase" in
        installed-fallback|verified-fallback)
            # We installed the wrapper but never went to enforce.
            # Disable the service; leave the config behind for inspection.
            service_action disable ssh-rt-wrapperd || true
            ;;
        enforced|verified-enforced|cutover|verified-cutover)
            # Restore the fallback-mode wrapper config from backup, or
            # just rewrite it.
            restore "$WRAPPER_CONFIG"
            # Make sure mode is fallback.
            if [ -e "$WRAPPER_CONFIG" ]; then
                sed -i.bak 's|^mode:.*|mode: fallback|' "$WRAPPER_CONFIG"
            fi
            service_action disable ssh-rt-wrapperd || true
            ;;
        *)
            log "no wrapper state to roll back from phase '$phase'"
            ;;
    esac

    log "rollback complete. System sshd should be operational on its " \
        "original port. Verify by SSHing in normally."
    set_phase 'rolled-back'
}

cmd_uninstall() {
    require_root
    log "Uninstalling wrapper entirely"

    cmd_rollback || true

    # Remove config / state.
    if [ -d "$WRAPPER_CONFIG_DIR" ]; then
        confirm "Remove $WRAPPER_CONFIG_DIR (config + keys)?" && \
            rm -rf "$WRAPPER_CONFIG_DIR"
    fi
    if [ -d "$WRAPPER_STATE_DIR" ]; then
        confirm "Remove $WRAPPER_STATE_DIR (state, user-CA key)?" && \
            rm -rf "$WRAPPER_STATE_DIR"
    fi
    log "uninstall complete. System sshd untouched."
}

cmd_status() {
    require_root
    cat <<EOF
upgrade.sh status
  current phase:       $(get_phase)
  wrapper binary:      $WRAPPER_BIN $([ -x "$WRAPPER_BIN" ] && echo '(present)' || echo '(MISSING)')
  wrapper service:     $(service_running ssh-rt-wrapperd && echo 'running' || echo 'not running')
  system sshd:         $(service_running sshd && echo 'running' || service_running ssh && echo 'running' || echo 'not running')
  wrapper config:      $WRAPPER_CONFIG
  backup dir:          $BACKUP_DIR
EOF
}

cmd_help() {
    cat <<'EOF'
ssh-rt-auth wrapper — host upgrade tool

Usage:
  upgrade.sh install     Phase 1: install wrapper in FALLBACK mode
  upgrade.sh verify-1    Phase 1 health check
  upgrade.sh enforce     Phase 2: switch to CA-mediated auth (still on alt port)
  upgrade.sh verify-2    Phase 2 health check
  upgrade.sh cutover     Phase 3: move wrapper to port 22; stop system sshd
  upgrade.sh verify-3    Phase 3 health check
  upgrade.sh rollback    Restore system sshd; disable wrapper (works from any phase)
  upgrade.sh uninstall   Remove wrapper entirely
  upgrade.sh status      Show current phase + service status

Environment overrides (run with `VAR=value ./upgrade.sh ...`):
  WRAPPER_BIN, WRAPPER_PKG, WRAPPER_CONFIG_DIR, WRAPPER_STATE_DIR,
  WRAPPER_PORT_INITIAL (default 2200), WRAPPER_PORT_FINAL (default 22),
  CA_ENDPOINTS

Phase summary:
  install → verify-1 → enforce → verify-2 → cutover → verify-3
                                  ↑                        ↓
                                  rollback ←——————— rollback
EOF
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

cmd="${1:-help}"
case "$cmd" in
    install)    cmd_install ;;
    verify-1)   cmd_verify_1 ;;
    enforce)    cmd_enforce ;;
    verify-2)   cmd_verify_2 ;;
    cutover)    cmd_cutover ;;
    verify-3)   cmd_verify_3 ;;
    rollback)   cmd_rollback ;;
    uninstall)  cmd_uninstall ;;
    status)     cmd_status ;;
    help|-h|--help) cmd_help ;;
    *) die "unknown command: $cmd (try './upgrade.sh help')" ;;
esac
