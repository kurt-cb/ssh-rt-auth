#!/usr/bin/env bash
# Apply our patches against openssh-portable/ and build.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SUB="$HERE/openssh-portable"
SERIES="$HERE/patches/series"

APPLY_ALL=1
APPLY_INVESTIGATION=0
CLEAN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean)                CLEAN=1 ;;
        --apply-investigation)  APPLY_INVESTIGATION=1 ;;
        --no-apply-all)         APPLY_ALL=0 ;;
        -h|--help)
            cat <<EOF
$0 — apply ssh-rt-auth-openssh patches and build sshd

  --clean                 reset openssh-portable/ to upstream HEAD first
  --apply-investigation   apply patches under investigation/ too (markers,
                          not for submission)
  --no-apply-all          skip applying patches/series (use to debug
                          submodule build only)
EOF
            exit 0 ;;
        *)
            echo "unknown arg: $1" >&2; exit 1 ;;
    esac
    shift
done

if [[ ! -d "$SUB/.git" && ! -f "$SUB/.git" ]]; then
    echo "openssh-portable/ submodule not initialised. Run:" >&2
    echo "  git submodule add https://github.com/openssh/openssh-portable.git \\" >&2
    echo "      openssh-portable && git -C openssh-portable checkout V_9_9_P1" >&2
    exit 1
fi

if (( CLEAN )); then
    echo "[clean] resetting openssh-portable/ to upstream HEAD"
    git -C "$SUB" reset --hard HEAD
    git -C "$SUB" clean -fdx
fi

if (( APPLY_ALL )); then
    if [[ -f "$SERIES" ]]; then
        # Each non-comment line in `series` is treated as a glob relative
        # to patches/. So a literal filename works, and so does `0*.patch`
        # to auto-pick up every numbered patch in order.
        shopt -s nullglob
        while IFS= read -r p; do
            [[ -z "$p" || "$p" =~ ^# ]] && continue
            matched=("$HERE/patches/"$p)
            if (( ${#matched[@]} == 0 )); then
                echo "[warn] series entry $p matched no files"
                continue
            fi
            for f in "${matched[@]}"; do
                echo "[apply] $(basename "$f")"
                git -C "$SUB" apply --index "$f"
            done
        done < "$SERIES"
        shopt -u nullglob
    else
        echo "[apply] no patches/series yet; skipping"
    fi
fi

if (( APPLY_INVESTIGATION )); then
    for p in "$HERE"/investigation/*.patch; do
        [[ -f "$p" ]] || continue
        echo "[apply] investigation/$(basename "$p")"
        git -C "$SUB" apply --index "$p"
    done
fi

echo "[configure] inside openssh-portable/"
cd "$SUB"
# Regenerate the configure script if missing OR if configure.ac (or any
# other autotools input) is newer — upstream ships a generated configure
# but git's checkout doesn't preserve mtimes, so a fresh clone often
# triggers `configure.ac newer than configure, run autoreconf`.
if [[ ! -f configure || configure.ac -nt configure \
        || Makefile.in -nt configure ]]; then
    if ! command -v autoreconf >/dev/null; then
        echo "[err] autoreconf not found. On Debian/Ubuntu:" >&2
        echo "    sudo apt-get install -y autoconf automake libtool" >&2
        exit 1
    fi
    echo "[autoreconf] regenerating configure (configure.ac is newer)"
    autoreconf -i
fi
./configure --prefix="$HERE/build-out" --without-zlib-version-check
make -j"$(nproc)"

echo
echo "[done] sshd built at $SUB/sshd"
echo "       ssh-keygen at $SUB/ssh-keygen"
echo "       install:   sudo install -m 755 $SUB/sshd /usr/local/sbin/sshd-patched"
