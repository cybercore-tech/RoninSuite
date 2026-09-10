#!/usr/bin/env bash
# Put `ronin` on your PATH by symlinking the portable launcher into ~/.local/bin.
# Re-run any time; it just refreshes the link. Uninstall: rm ~/.local/bin/ronin
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LAUNCHER="$REPO/bin/ronin"
BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
LINK="$BIN_DIR/ronin"

[[ -x "$LAUNCHER" ]] || chmod +x "$LAUNCHER"
mkdir -p "$BIN_DIR"
ln -sf "$LAUNCHER" "$LINK"
echo "linked  $LINK  ->  $LAUNCHER"

# --- system install: keep data out of the code checkout ----------------------
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/roninsuite"
if [[ -f "$REPO/.ronin-portable" ]]; then
    echo "portable checkout (.ronin-portable) — data stays in $REPO"
elif [[ -e "$REPO/ronin.db" || -d "$REPO/engagements" ]]; then
    mkdir -p "$DATA_DIR"
    moved=0
    for item in ronin.db audit.log engagements reports brand.yaml tools; do
        if [[ -e "$REPO/$item" && ! -e "$DATA_DIR/$item" ]]; then
            mv "$REPO/$item" "$DATA_DIR/$item"; moved=1
        fi
    done
    [[ $moved -eq 1 ]] && echo "migrated existing data → $DATA_DIR" \
                       || echo "data already at $DATA_DIR"
else
    echo "system install — data will live in $DATA_DIR"
fi

case ":$PATH:" in
    *":$BIN_DIR:"*) echo "PATH ok — run:  ronin help" ;;
    *) echo
       echo "⚠  $BIN_DIR is not on your PATH. Add to your shell rc:"
       echo "     export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
