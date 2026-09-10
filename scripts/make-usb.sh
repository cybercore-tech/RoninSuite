#!/usr/bin/env bash
# Copy RoninSuite onto a USB stick (or any target dir) as a self-contained,
# runnable folder.  Excludes the venv and per-engagement data.
#
#   scripts/make-usb.sh /run/media/$USER/MYSTICK
#   scripts/make-usb.sh /run/media/$USER/SUBGRIDSEC/Tools     # onto the field stick
#
# Afterwards, on any Linux with network (once):  cd <dest>/RoninSuite && ./bin/ronin
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:?usage: make-usb.sh <destination-dir>}"

[[ -d "$DEST" ]] || { echo "destination not found: $DEST" >&2; exit 1; }
OUT="$DEST/RoninSuite"
mkdir -p "$OUT"

echo ">> syncing $SRC  ->  $OUT"
rsync -a --delete \
  --exclude '.venv/' --exclude '.cache/' --exclude '__pycache__/' \
  --exclude '*.pyc' --exclude '.pytest_cache/' \
  --exclude 'engagements/' --exclude 'reports/' \
  --exclude 'ronin.db' --exclude 'audit.log' --exclude '.env' \
  --exclude '.git/' \
  "$SRC"/ "$OUT"/

# recreate the runtime dirs so first run has somewhere to write
mkdir -p "$OUT/engagements" "$OUT/reports"
chmod +x "$OUT/bin/ronin" "$OUT/scripts/"*.sh 2>/dev/null || true

FSTYPE=$(stat -f -c %T "$DEST" 2>/dev/null || echo unknown)
echo ">> done.  target filesystem: $FSTYPE"
cat <<EOF

On the target machine:
  cd "$OUT"
  ./bin/ronin doctor            # first run bootstraps uv + Python 3.13 + deps (needs network once)
  ./bin/ronin                   # launch the TUI

Notes:
  * On exFAT/NTFS the Python venv is created under ~/.cache/roninsuite on the host;
    your engagements and reports still live on the stick (RONIN_HOME).
  * For a fully offline stick, run ./bin/ronin once on a networked box first, then
    copy ~/.cache/roninsuite alongside, or install the pentest tools via
    ./bin/ronin doctor --install on the target.
EOF
