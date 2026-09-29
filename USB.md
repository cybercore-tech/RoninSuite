# Running RoninSuite from a USB stick

RoninSuite is relocatable. `scripts/make-usb.sh` copies the code to the stick
**and drops a `.ronin-portable` marker** — that marker tells `ronin/config.py` to
keep all data (engagements, evidence, reports, `ronin.db`, `audit.log`) inside the
stick folder, travelling with it.

A normal system install has **no** marker, so its data lives in
`~/.local/share/roninsuite` on the host, completely separate from any USB copy.
`$RONIN_HOME` overrides both.

## 1. Put it on the stick

`make-usb.sh` packages a **provisioned staging checkout**. The Git repository
contains the RoninSuite application and packaging scripts, but does not store
the generated Python runtime, native libraries, or pentest-tool payloads. Those
must already be present under `toolchain/` and `bin/` as in the completed build;
the script checks for the required components and stops if any are missing. A
plain Git clone by itself is not a complete offline USB build.

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
./bin/ronin doctor      # checks the bundled runtime and tools
./bin/ronin             # launch the TUI
```

`bin/ronin`:

- resolves the project root from its own location and exports `RONIN_HOME`;
- runs bundled CPython 3.13 and preinstalled application dependencies;
- does not download packages or create a Python virtualenv at first launch.

## 3. First launch

Run `./bin/ronin doctor` on Linux. The app, Python runtime, dependencies, native
libraries, pentest tools, and their data are carried on the USB. No network
access or host Python/pentest-tool installation is needed.

The portable build includes the 12 tools that currently have RoninSuite
adapters: subfinder, nmap, naabu, httpx, ffuf, feroxbuster, nuclei, nikto,
testssl.sh, sqlmap, hydra, and commix. Nuclei templates are included too.
Their launchers are in `bin/` and payloads are under `toolchain/`.

## 4. Pairing with the SUBGRIDSEC Ventoy stick

The SUBGRIDSEC build has an exFAT data partition with a `/Tools` folder that's
invisible to the boot menu. `scripts/make-usb.sh /run/media/$USER/SUBGRIDSEC/Tools`
drops RoninSuite there. Boot the target from the Ubuntu or SystemRescue ISO on
that same stick, then:

```bash
cd /run/media/*/SUBGRIDSEC/Tools/RoninSuite   # or wherever it auto-mounts
./bin/ronin doctor                             # check the bundled toolchain
./bin/ronin
```

Reports written during a live session persist on the stick's exFAT partition and
are readable from any OS afterwards.

## What travels vs. what doesn't

The compiled tools and bundled runtimes are Linux x86-64 builds. The USB is exFAT
for file storage and exchange on Windows and macOS, but those systems cannot run
this Linux application/toolchain. The current bundled native libraries require
glibc 2.44 or newer on Linux x86-64; the USB bundles the other tool libraries
and runtimes. Basic TCP
scans run without root; raw SYN, OS-detection, and UDP scans require elevated
privileges. The USB does not grant capabilities or elevate processes.
`doctor --all` also lists extra catalog entries without RoninSuite adapters;
they are not included in this integrated bundle.

| Travels on the stick | Stays on the host |
|---|---|
| App, runtimes, tools, templates, Python dependencies | Nothing required for the app runtime |
| `engagements/<slug>/`, reports, `ronin.db`, `audit.log` | |
