# RoninSuite

A portable **TUI pentest toolkit for Linux** with a focus on the tactical /
offensive side, and a three-tier reporting engine (Executive / Technical /
Remediation) driven by a normalized findings model with CVSS v3.1 scoring.

> **Authorized testing only.** RoninSuite hard-blocks any target that is not in
> the engagement's `scope.yaml` and writes an append-only `audit.log` of every
> scope decision and command. Use it only against systems you have written
> permission to test.

---

## What it does

- **Cybercore TUI** (Textual) with a tabbed console:
  **Dashboard** (context, overdue-retest and outdated-tool alerts, recent runs) ·
  **Tools** (catalog + configure/run/stream) · **Reports** · **Clients** ·
  **Updates** · **Toolbox**. Number keys `1–6` jump tabs, `e` picks the
  engagement, `/` filters a table.

- **Clients & retest cadence** — a client record groups engagements, tracks the
  last test date, and (with a `cadence_days`) shows the next-due date and flags
  overdue retests. Per-client remediation progress rolls up from finding status.

- **Finding status workflow** — `open → in progress → fixed → accepted → closed`,
  cycled with `s` in the findings view; feeds the Clients progress bars.

- **Wraps real tools** through thin adapters. Each adapter builds a safe command,
  streams output live, and parses the tool's machine-readable results into one
  `Finding` schema (severity, CVSS vector + score, CWE/CVE, evidence,
  request/response, PoC, attack path, remediation).

- **Enforces scope.** Per-engagement `scope.yaml` (in/out-of-scope hosts, CIDRs,
  domains, URL prefixes, testing window, rules of engagement). Out-of-scope
  targets are refused unless you `--force` with a written, logged justification.

- **Reports in three tiers**, each containing the four sections you need:
  
  1. Scope & Methodology
  2. Vulnerability Details (the findings)
  3. Proof of Concept (PoC) & Attack Paths
  4. Remediation Recommendations
  
  rendered to **Markdown + HTML + PDF** under
  `reports/<engagement>/<timestamp>/`.

- **Regenerates reports from stored findings** (SQLite) — no re-scan needed.

- **Portable.** The whole folder runs from a USB stick; see `USB.md`.

## Tool catalog

Wired adapters (parse output → normalized findings):

| Phase                   | Tools                                 |
| ----------------------- | ------------------------------------- |
| Recon                   | **subfinder**                         |
| Scan                    | **nmap**, **naabu**                   |
| Web content             | **ffuf**, **feroxbuster**             |
| Vuln                    | **nuclei**, **nikto**, **testssl.sh** |
| Exploitation *(active)* | **sqlmap**, **hydra**, **commix**     |
| Web probe               | **httpx**                             |

`ronin doctor` additionally knows install recipes for the rest of the offensive
kit — amass, dnsx, katana, masscan, rustscan, whatweb, wafw00f, sslscan, wpscan,
medusa, netexec, enum4linux-ng, kerbrute, hashcat, john — so you can provision
the box now and adapters land incrementally.

Tools flagged **active** (ffuf, feroxbuster, sqlmap, hydra, commix, wpscan,
netexec, kerbrute) require an explicit confirmation in the CLI/TUI before they
run.

## Install

This section installs a development/system copy. The prebuilt USB bundle has
its own Python runtime and dependencies and does not require `uv`; see
[`USB.md`](USB.md).

Requires [`uv`](https://docs.astral.sh/uv/). Python 3.13 is fetched automatically.

```bash
cd ~/Toolkits/RoninSuite
uv sync --extra dev            # or: make setup
scripts/install-cli.sh        # put `ronin` on PATH (~/.local/bin symlink)
ronin doctor                  # see what's installed
ronin doctor --install --only nmap,nuclei,httpx,ffuf,testssl
```

After `install-cli.sh` everything is just `ronin …` from any directory — no
`uv run`. `$RONIN_HOME` overrides the project root (see `USB.md`).

System libraries for PDF (WeasyPrint) — Pango / Cairo / gdk-pixbuf — are already
present on most desktop Arch installs. If PDF export is unavailable, MD + HTML
still render.

## Use

```bash
# 1. client + engagement (scope.yaml is scaffolded for you)
ronin new client --name "Acme Widgets LLC" --contact "J. Okafor" --cadence-days 90
ronin new engagement --client "Acme Widgets LLC" --client-slug acme-widgets-llc --slug acme-q3
$EDITOR engagements/acme-q3/scope.yaml            # set in_scope

# 2. check a target
ronin scope acme-q3 https://app.acme.example

# 3. run a tool (parses findings + writes all three reports; -e optional if there's one engagement)
ronin run nuclei -e acme-q3 -t https://app.acme.example -o severity=medium,high,critical

# 4. look around
ronin list findings acme-q3 --severity high
ronin search CVE-2021
ronin client acme-widgets-llc                     # last tested / next due / % remediated
ronin report acme-q3                              # re-render from stored findings

# toolchain
ronin update tools                                # installed vs latest
ronin add dalfox certipy subfinder               # from the awesome-list catalog
ronin sync                                        # refresh + nuclei templates

# or just:
ronin                                            # the TUI
```

Full command + Python API reference: **[`docs/REFERENCE.md`](docs/REFERENCE.md)**.

CLI knobs: `-o k=v` (repeatable) sets tool options, `--intensity
stealth|normal|aggressive` scales rate limits and nmap timing, `--force --reason
"..."` overrides scope (logged), `--run <id>` scopes a report to one run.

## Layout

```
ronin/
  config.py          portable path resolution (RONIN_HOME or repo root)
  core/
    models.py        Severity, Finding, ToolRun, Engagement, dedupe()
    cvss.py          self-contained CVSS v3.1 base-score calculator
    scope.py         scope.yaml loading + in/out-of-scope decisions
    db.py            SQLite store (engagements / runs / findings)
    audit.py         append-only JSONL audit trail
    runner.py        scope-check -> exec + stream -> parse -> persist -> audit
  tools/
    base.py          ToolAdapter ABC + RunContext
    registry.py      adapter registry + full install CATALOG
    nmap|httpx|nuclei|ffuf|testssl.py
  reports/
    render.py        context builder + MD/HTML/PDF renderer
    templates/       Jinja2: _macros + executive|technical|remediation + HTML shell
  doctor.py          detect / install the toolchain on Arch
  updates.py         toolchain currency (installed vs latest, template age)
  cli/app.py         Typer CLI (`ronin ...`)
  tui/app.py         Textual TUI (cybercore theme in tui/theme.py)
engagements/<slug>/  scope.yaml, evidence/<run-id>/...
reports/<slug>/<ts>/ executive|technical|remediation .{md,html,pdf} + index.html
ronin.db  audit.log
```

## Add a tool adapter

Create `ronin/tools/<tool>.py` with a `ToolAdapter` subclass implementing
`build_argv(ctx)` and `parse(run, ctx)`, register it in
`ronin/tools/registry.py`, and add a golden-file test in `tests/` (paste real
tool output into `tests/data/`, assert the extracted `Finding`s). Prefer the
tool's JSON/XML output mode and write result files via `ctx.out("name.ext")`.

## Tests

```bash
make test        # uv run pytest -q
```

A full worked example (all three tiers × MD/HTML/PDF, branded) is in
`examples/sample-report/`.

## Report branding

Copy `brand.example.yaml` → `brand.yaml` (project root) to put your consultancy
name, logo, accent colour, classification banner and footer on every generated
report. The logo is embedded as a data URI so PDFs are self-contained.

## Roadmap

- More adapters (amass, katana, whatweb, netexec, wpscan, …)
- Cross-tool finding correlation beyond title/target/CVE fingerprint
- Engagement-to-engagement diffing (retest deltas)
- API-key wiring for recon sources (Shodan/Censys/Chaos)
- Windows toolkit (separate, later)

## License

MIT — see `LICENSE`. Set your name/organisation in the copyright line.
