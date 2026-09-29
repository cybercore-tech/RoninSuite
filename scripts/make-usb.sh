#!/usr/bin/env bash
# Copy RoninSuite onto a USB stick (or any target dir) as a self-contained,
# runnable folder.  Excludes the venv and per-engagement data.
#
#   scripts/make-usb.sh /run/media/$USER/MYSTICK
#   scripts/make-usb.sh /run/media/$USER/SUBGRIDSEC/Tools     # onto the field stick
#
# Afterwards, on supported x86-64 Linux:  cd <dest>/RoninSuite && ./bin/ronin
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:?usage: make-usb.sh <destination-dir>}"

[[ -d "$DEST" ]] || { echo "destination not found: $DEST" >&2; exit 1; }
# The runtime and tool payloads are provisioned separately from this source
# repository. Refuse to create a code-only stick that looks like a full bundle.
REQUIRED=(
  toolchain/python/bin/python3.13
  toolchain/site-packages
  toolchain/lib
  toolchain/nuclei-templates
  bin/subfinder bin/nmap bin/naabu bin/httpx bin/ffuf bin/feroxbuster
  bin/nuclei bin/nikto bin/testssl.sh bin/sqlmap bin/hydra bin/commix
)
MISSING=()
for path in "${REQUIRED[@]}"; do
  if [[ ! -e "$SRC/$path" ]]; then
    MISSING+=("$path")
  fi
done
if ((${#MISSING[@]})); then
  printf 'portable runtime is incomplete; missing required bundle content:\n' >&2
  printf '  %s\n' "${MISSING[@]}" >&2
  echo "Provision the toolchain/runtime before running make-usb.sh." >&2
  exit 1
fi
if command -v findmnt >/dev/null 2>&1; then
  MOUNT_OPTIONS=$(findmnt -n -o OPTIONS -T "$DEST" 2>/dev/null || true)
  case ",$MOUNT_OPTIONS," in
    *,ro,*)
      echo "destination filesystem is mounted read-only: $DEST" >&2
      echo "unmount it and repair/check its filesystem before updating the USB" >&2
      exit 1
      ;;
  esac
fi
[[ -w "$DEST" ]] || { echo "destination is not writable: $DEST" >&2; exit 1; }
OUT="$DEST/RoninSuite"
mkdir -p "$OUT"

echo ">> syncing $SRC  ->  $OUT"
rsync -a --delete --no-perms --no-owner --no-group \
  --exclude '/.venv/' --exclude '/.cache/' --exclude '__pycache__/' \
  --exclude 'toolchain/perl/share/perl5/core_perl/pod/' \
  --exclude 'toolchain/python/share/terminfo/' \
  --exclude '*.pyc' --exclude '.pytest_cache/' \
  --exclude '/engagements/' --exclude '/reports/' \
  --exclude '/ronin.db' --exclude '/audit.log' --exclude '/.env' \
  --exclude '/.git/' --exclude '/.ronin-portable' \
  "$SRC"/ "$OUT"/

# mark this copy as portable: config.py then keeps all data inside this folder
touch "$OUT/.ronin-portable"
mkdir -p "$OUT/engagements" "$OUT/reports"
chmod +x "$OUT/bin/"* "$OUT/toolchain/bin/"* "$OUT/scripts/"*.sh \
  "$OUT/scripts/"*.py 2>/dev/null || true

FSTYPE=$(stat -f -c %T "$DEST" 2>/dev/null || echo unknown)
echo ">> done.  target filesystem: $FSTYPE"
cat <<EOF

On the target machine:
  cd "$OUT"
  ./bin/ronin doctor            # checks the bundled runtime and tools
  ./bin/ronin                   # launch the TUI

Notes:
  * The USB carries RoninSuite's Python, Perl, app dependencies, native
    libraries, and pentest tools. No first-run download or host venv is needed.
  * Requires Linux x86-64 with glibc 2.44 or newer.
  * Scans use unprivileged TCP connect mode by default. Raw SYN, OS-detection,
    and UDP scans need elevated privileges and are intentionally optional.
EOF
