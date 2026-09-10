# Running RoninSuite from a USB stick

RoninSuite is relocatable. `scripts/make-usb.sh` copies the code to the stick
**and drops a `.ronin-portable` marker** — that marker tells `ronin/config.py` to
keep all data (engagements, evidence, reports, `ronin.db`, `audit.log`) inside the
stick folder, travelling with it.

A normal system install has **no** marker, so its data lives in
`~/.local/share/roninsuite` on the host, completely separate from any USB copy.
`$RONIN_HOME` overrides both.

## 1. Put it on the stick

```bash
# from a normal checkout
scripts/make-usb.sh /run/media/$USER/MYSTICK
#   -> creates /run/media/$USER/MYSTICK/RoninSuite/  (code only; no venv, no
#      engagement data, dirs recreated empty)

# or onto the SUBGRIDSEC field stick's data partition
scripts/make-usb.sh /run/media/$USER/SUBGRIDSEC/Tools
```

`make bundle DEST=/run/media/$USER/MYSTICK` does the same.

## 2. Run it on the target machine

```bash
cd /run/media/$USER/MYSTICK/RoninSuite
./bin/ronin doctor      # first run: bootstraps uv + Python 3.13 + deps
./bin/ronin             # launch the TUI
```

`bin/ronin`:

- resolves the project root from its own location and exports `RONIN_HOME`;
- finds `uv` (system → vendored `.cache/uv/uv` → fetches it, needs network once);
- on **exFAT / NTFS / FAT** it puts the Python virtualenv under
  `~/.cache/roninsuite/venv` on the *host* (those filesystems can't store a venv),
  while your engagements and reports still land on the stick;
- on ext4 / btrfs / xfs the venv sits in the project dir on the stick.

## 3. Offline sticks

The first `./bin/ronin` needs network to fetch `uv`, Python and the Python deps.
For a stick that must work with no connectivity:

1. Run `./bin/ronin doctor` once on a networked machine **with the same CPU
   architecture and libc** (x86-64 glibc for a normal Arch/Debian target).
2. Copy the resulting environment next to the project:
   - ext4/btrfs stick: `.venv/` is already on the stick — done.
   - exFAT stick: also copy `~/.cache/roninsuite/` to the target's
     `~/.cache/roninsuite/`, or accept that the venv rebuilds on first use.
3. The underlying pentest tools (nmap, nuclei, …) are **not** bundled. Either:
   - install them on the target: `./bin/ronin doctor --install`, or
   - boot a distro that already ships them (Kali), or
   - drop static builds of the Go tools (nuclei, httpx, ffuf, naabu) into
     `RoninSuite/bin/` — `bin/` is on `PATH` when launched via `bin/ronin`.

## 4. Pairing with the SUBGRIDSEC Ventoy stick

The SUBGRIDSEC build has an exFAT data partition with a `/Tools` folder that's
invisible to the boot menu. `scripts/make-usb.sh /run/media/$USER/SUBGRIDSEC/Tools`
drops RoninSuite there. Boot the target from the Ubuntu or SystemRescue ISO on
that same stick, then:

```bash
cd /run/media/*/SUBGRIDSEC/Tools/RoninSuite   # or wherever it auto-mounts
./bin/ronin doctor --install                  # pull the toolchain into the live env
./bin/ronin
```

Reports written during a live session persist on the stick's exFAT partition and
are readable from any OS afterwards.

## What travels vs. what doesn't

| Travels on the stick | Stays on the host |
|---|---|
| All `ronin/` code, templates, scripts | Python virtualenv (on exFAT/NTFS) |
| `engagements/<slug>/` (scope, evidence) | `uv`'s global download cache |
| `reports/<slug>/` (MD/HTML/PDF) | system packages (nmap, nuclei, …) unless installed there |
| `ronin.db`, `audit.log` | |
