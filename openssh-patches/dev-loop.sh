#!/usr/bin/env bash
# Developer convenience: pop the series → hack → re-export.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SUB="$HERE/openssh-portable"
SERIES="$HERE/patches/series"

usage() {
    cat <<EOF
$0 — hack / export workflow for the ssh-rt-auth-openssh patch series

Usage:
  $0 hack
      Apply patches/series so openssh-portable/ has all changes in-tree
      as ordinary git commits. Now you can edit, commit, etc.

  $0 export
      Run \`git format-patch\` on the submodule's commits above upstream
      tag, write them into patches/, and rebuild patches/series.

  $0 reset
      Drop everything in openssh-portable/ that isn't upstream
      (\`git reset --hard upstream-tag && git clean -fdx\`).
EOF
}

cmd="${1:-help}"; shift || true

case "$cmd" in
    hack)
        echo "[hack] applying series as commits in $SUB"
        while IFS= read -r p; do
            [[ -z "$p" || "$p" =~ ^# ]] && continue
            echo "  am  patches/$p"
            git -C "$SUB" am "$HERE/patches/$p"
        done < "$SERIES"
        echo "[hack] done — edit + commit as usual in $SUB"
        ;;
    export)
        echo "[export] format-patch from $SUB"
        upstream_tag="$(git -C "$SUB" describe --tags --abbrev=0 --match='V_*')"
        rm -f "$HERE"/patches/0*.patch
        # NOTE: -o needs an absolute path. With -C SUB, a relative path
        # resolves inside the submodule (we got bitten by that once).
        git -C "$SUB" format-patch -o "$HERE/patches" "$upstream_tag"..
        # series uses a glob entry by default so newly-exported patches
        # are picked up without further edits.
        cat > "$SERIES" <<'EOF'
# patches/series — read by build.sh.
# Each non-comment line is a glob relative to patches/.
# Default: pick up every numbered patch in order.
0*.patch
EOF
        echo "[export] patches/series rewritten (glob entry)"
        ;;
    reset)
        upstream_tag="$(git -C "$SUB" describe --tags --abbrev=0)"
        echo "[reset] $SUB → $upstream_tag"
        git -C "$SUB" reset --hard "$upstream_tag"
        git -C "$SUB" clean -fdx
        ;;
    *)
        usage
        ;;
esac
