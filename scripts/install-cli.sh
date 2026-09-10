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

case ":$PATH:" in
    *":$BIN_DIR:"*) echo "PATH ok — run:  ronin help" ;;
    *) echo
       echo "⚠  $BIN_DIR is not on your PATH. Add to your shell rc:"
       echo "     export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
