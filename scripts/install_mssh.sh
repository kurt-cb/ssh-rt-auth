#!/bin/sh
# install_mssh.sh — install mssh + msshd from a tarball on a clean
# Linux host. Simulates `apt install mssh msshd` until a real distro
# package exists. See design/future-ideas.md §15.
#
# Usage:
#   install_mssh.sh <tarball-path>           [--install-dir /opt/mssh]
#                                            [--no-systemd]
#                                            [--user mssh]
#
# Assumes:
#   - Run as root (we touch /opt, /etc, systemd).
#   - Network access for the package manager (apt/dnf/apk).
#
# Does:
#   1. Detects distro family (apt | dnf | apk).
#   2. Installs system deps: python3, openssh-server, openssh-client.
#   3. Extracts the tarball to <install-dir>.
#   4. Creates a Python venv at <install-dir>/venv.
#   5. `pip install -e` the mssh source into that venv.
#   6. Drops symlinks for mssh/msshd/mssh-ca/mssh-admin into /usr/local/bin.
#   7. Installs systemd units (DISABLED) for msshd and mssh-ca, if systemd
#      is present and --no-systemd was not passed.
#   8. Lays down default config templates in /etc/mssh/ (operator edits these).
#   9. Prints next-step instructions.
#
# Does NOT:
#   - Enroll the server at a CA.
#   - Generate keys.
#   - Enable or start any service.
#   The operator does those steps explicitly (see docs/operations.md).
#
# Tarball layout expected: a directory containing python/, config/,
# systemd/ — produced by `make tarball` (or the equivalent here in CI).

set -eu

TARBALL=""
INSTALL_DIR="/opt/mssh"
NO_SYSTEMD=0
RUN_USER="mssh"

usage() {
    sed -n '2,/^$/p' "$0" | sed 's|^# \?||'
    exit "$1"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        --no-systemd)  NO_SYSTEMD=1; shift ;;
        --user)        RUN_USER="$2"; shift 2 ;;
        -h|--help)     usage 0 ;;
        -*)            echo "unknown flag: $1" >&2; usage 2 ;;
        *)
            if [ -z "$TARBALL" ]; then
                TARBALL="$1"; shift
            else
                echo "unexpected arg: $1" >&2; usage 2
            fi
            ;;
    esac
done

if [ -z "$TARBALL" ] || [ ! -f "$TARBALL" ]; then
    echo "tarball path required (got: ${TARBALL:-<empty>})" >&2
    exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "install_mssh.sh must run as root (need to write /opt, /etc, systemd)" >&2
    exit 2
fi

# ---- 1. Detect distro family ----------------------------------------------
if   command -v apt-get >/dev/null 2>&1; then PKG=apt
elif command -v dnf     >/dev/null 2>&1; then PKG=dnf
elif command -v apk     >/dev/null 2>&1; then PKG=apk
else
    echo "no supported package manager (need apt-get|dnf|apk)" >&2
    exit 3
fi
echo "==> distro family: $PKG"

# ---- 2. Install system deps -----------------------------------------------
echo "==> installing system deps"
case "$PKG" in
    apt)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q
        apt-get install -y -q --no-install-recommends \
            python3 python3-venv python3-pip \
            python3-cryptography python3-flask python3-yaml \
            python3-click python3-requests python3-asyncssh \
            openssh-server openssh-client
        ;;
    dnf)
        dnf install -y -q \
            python3 python3-pip \
            python3-cryptography python3-flask python3-pyyaml \
            python3-click python3-requests \
            openssh-server openssh-clients
        # python3-asyncssh is in EPEL on RHEL/Rocky/Alma; install if available.
        dnf install -y -q python3-asyncssh 2>/dev/null || true
        ;;
    apk)
        apk add --no-cache \
            python3 py3-pip \
            py3-cryptography py3-flask py3-yaml \
            py3-click py3-requests py3-asyncssh \
            openssh openssh-server openssh-client
        ;;
esac

# ---- 3. Create the run user (if missing) ----------------------------------
if ! id -u "$RUN_USER" >/dev/null 2>&1; then
    echo "==> creating system user: $RUN_USER"
    case "$PKG" in
        apk) adduser -D -H -s /sbin/nologin "$RUN_USER" ;;
        *)   useradd  -r    -s /usr/sbin/nologin "$RUN_USER" ;;
    esac
fi

# ---- 4. Extract tarball ---------------------------------------------------
echo "==> extracting $TARBALL to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
tar -xzf "$TARBALL" -C "$INSTALL_DIR" --strip-components=0
# Sanity: the tarball should contain python/, config/, systemd/ at top level.
if [ ! -d "$INSTALL_DIR/python" ] || [ ! -d "$INSTALL_DIR/config" ]; then
    echo "tarball did not extract expected python/ and config/ at $INSTALL_DIR" >&2
    exit 4
fi
chown -R "$RUN_USER:$RUN_USER" "$INSTALL_DIR"

# ---- 5. Build the venv ----------------------------------------------------
echo "==> creating venv at $INSTALL_DIR/venv"
python3 -m venv "$INSTALL_DIR/venv"
# Some distros (Alpine) don't ship pip in venv; bootstrap if needed.
"$INSTALL_DIR/venv/bin/python" -m ensurepip --upgrade 2>/dev/null || true
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip

echo "==> installing mssh package into venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet -e "$INSTALL_DIR/python"

# ---- 6. Symlinks into /usr/local/bin --------------------------------------
echo "==> linking binaries into /usr/local/bin"
for bin in mssh msshd mssh-ca mssh-admin ssh-rt-debug-sshd; do
    if [ -f "$INSTALL_DIR/venv/bin/$bin" ]; then
        ln -sf "$INSTALL_DIR/venv/bin/$bin" "/usr/local/bin/$bin"
    fi
done

# ---- 7. Systemd units (disabled) ------------------------------------------
if [ "$NO_SYSTEMD" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    echo "==> installing systemd units (DISABLED — operator enables explicitly)"
    if [ -d "$INSTALL_DIR/systemd" ]; then
        cp -p "$INSTALL_DIR/systemd/"*.service /etc/systemd/system/ 2>/dev/null || true
    fi
    # Generate a minimal msshd unit if the tarball didn't ship one.
    if [ ! -f /etc/systemd/system/msshd.service ]; then
        cat > /etc/systemd/system/msshd.service <<EOF
[Unit]
Description=mssh server-side gateway daemon
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/msshd --config /etc/mssh/wrapper.yaml
Restart=on-failure
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    fi
    systemctl daemon-reload
fi

# ---- 8. Default config templates ------------------------------------------
mkdir -p /etc/mssh
if [ -f "$INSTALL_DIR/config/wrapper.yaml.example" ] \
   && [ ! -f /etc/mssh/wrapper.yaml ]; then
    cp -p "$INSTALL_DIR/config/wrapper.yaml.example" /etc/mssh/wrapper.yaml.example
    echo "==> placed /etc/mssh/wrapper.yaml.example — edit and save as wrapper.yaml"
fi
if [ -f "$INSTALL_DIR/config/sshd_config.template" ]; then
    cp -p "$INSTALL_DIR/config/sshd_config.template" /etc/mssh/sshd_config.template
fi
# State dir for msshd (banner files, local user-CA, etc.)
mkdir -p /var/lib/mssh /var/lib/mssh/inner-sshd /var/log/mssh
chown -R "$RUN_USER:$RUN_USER" /var/lib/mssh /var/log/mssh

# ---- 9. Done --------------------------------------------------------------
cat <<EOF

Installed mssh into $INSTALL_DIR.
Binaries linked into /usr/local/bin: mssh, msshd, mssh-ca, mssh-admin.

Next steps (NOT done by this script):

  1. Enrol this host at your CA:
        # on your operator workstation:
        mssh-admin server add <this-host-name> --groups <group>
     Capture the printed mTLS cert + key and provision them onto
     this host as /etc/mssh/server-mtls.{crt,key}.

  2. Edit /etc/mssh/wrapper.yaml:
        cp /etc/mssh/wrapper.yaml.example /etc/mssh/wrapper.yaml
        $EDITOR /etc/mssh/wrapper.yaml
     Start in mode: fallback. Flip to mode: enforce after you've
     verified the gateway is wired in.

  3. Start msshd:
        systemctl enable --now msshd

See docs/operations.md for the full adoption journey.
EOF
