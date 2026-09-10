# RoninSuite Reference

Everything you can call — the `ronin` CLI, the TUI keys, and the Python API.

- [1. CLI](#1-cli)
- [2. TUI](#2-tui)
- [3. Python API](#3-python-api)
- [4. On-disk layout](#4-on-disk-layout)

---

## 1. CLI

Install the launcher once: `scripts/install-cli.sh` (symlinks `bin/ronin` into
`~/.local/bin`, and migrates any legacy in-repo data). After that everything is
`ronin …` from anywhere — no `uv run`.

**Where data lives** (`ronin/config.py` decides):

1. `$RONIN_HOME` if set.
2. **Portable / USB** — a `.ronin-portable` marker next to the code (dropped by
   `scripts/make-usb.sh`) → data stays inside that folder, travelling with the stick.
3. **System install** — `$XDG_DATA_HOME/roninsuite` (`~/.local/share/roninsuite`),
   kept separate from the code checkout.

So your system install and any USB build have **independent** engagements /
reports / `ronin.db`.

### Overview

| Command | Purpose |
|---|---|
| `ronin` | launch the TUI |
| `ronin help [command]` | overview, or help for one command |
| `ronin run <tool> -t <target> [-e <eng>]` | run a scan → parse findings → write reports |
| `ronin report [<eng>]` | (re)generate the three report tiers from stored findings |
| `ronin scope <eng> <target>` | is this target in scope? (exit 0 / 2) |
| `ronin list <what> [filter]` | `tools` · `clients` · `engagements` · `reports` · `runs` · `findings` |
| `ronin show <what> <id>` | `client` · `engagement` · `finding` · `run` · `report` |
| `ronin search <text> [--type …]` | fuzzy match across findings, clients, engagements, tools, reports |
| `ronin new client …` / `ronin new engagement …` | create records |
| `ronin invoice new/list/status` | lightweight invoice tracking per client |
| `ronin link <eng> <client>` | attach an engagement to a client |
| `ronin client [<id>]` | list clients, or one client's retest + remediation status |
| `ronin engagement [<id>]` | list engagements, or one engagement's runs + findings |
| `ronin doctor [--install] [--all]` | toolchain health; install what's missing |
| `ronin add <tool> …` | install tool(s) from the core / extended catalog |
| `ronin update [<tool> …]` | update outdated tools (`ronin update tools` shows the table) |
| `ronin sync` | refresh the update cache + nuclei templates |

### `ronin run`

```
ronin run TOOL -t TARGET [-e ENGAGEMENT] [-o k=v]... [--intensity stealth|normal|aggressive]
                         [--force --reason "…"] [-y] [--no-report]
```

- `TOOL` — an adapter name (`ronin list tools`): `nmap httpx nuclei ffuf feroxbuster
  nikto testssl subfinder naabu sqlmap hydra commix`.
- `-e` may be omitted when there is exactly one engagement.
- `-o` repeats: `-o severity=high,critical -o dast=true`. Values `true/false/<int>` are coerced.
- Out-of-scope targets are **blocked** unless `--force` + `--reason` (logged to `audit.log`).
- Aggressive tools prompt unless `-y`.
- On success, reports for that run are generated automatically (`--no-report` to skip).

Example: `ronin run nuclei -t https://app.acme.example -o severity=medium,high,critical`

### `ronin report`

```
ronin report [ENGAGEMENT] [--run RUN_ID] [--level executive|technical|remediation|all] [--format md,html,pdf]
```
Regenerates from the findings DB — no re-scan. `--run` scopes to one run.

### `ronin list`

```
ronin list tools [category]                 # wired adapters
ronin list clients
ronin list engagements
ronin list reports [engagement-substring]
ronin list runs [engagement]
ronin list findings [engagement] [--severity high] [--status open]
```

### `ronin show`

```
ronin show client <slug>          # = ronin client <slug>
ronin show engagement <slug>      # = ronin engagement <slug>  (runs + findings)
ronin show finding <finding-id>   # full write-up incl. PoC
ronin show run <run-id>           # argv, evidence dir, findings
ronin show report <engagement>/<stamp>
```

### `ronin new`

```
ronin new client --name "Acme Widgets LLC" [--slug acme] [--contact "J. Okafor"]
                 [--email j@acme.example] [--phone …] [--address …] [--website …]
                 [--x @acme] [--facebook …] [--linkedin …] [--rate 185]
                 [--cadence-days 90]
ronin new engagement --client "Acme Widgets LLC" [--slug acme-q3] [--tester raven]
                     [--days 14] [--client-slug acme]
```
Re-running `new client` with the same slug **updates** it (only non-empty flags
change). `--cadence-days` drives the "next due / overdue" reminders; `--rate` is a
default unit rate for invoicing.

### `ronin invoice`

Lightweight tracking now; a full billing / invoice-generator / mail panel is
planned as a separate Rust web app that shares this database.

```
ronin invoice new -c <client-slug> -a 8500 [--number INV-2026-014] [--engagement acme-q3]
                  [--due 2026-10-01] [--currency USD] [--status draft|sent|paid|void] [-d "…"]
ronin invoice list [<client-slug>]        # + billed / paid / outstanding totals
ronin invoice status <id|prefix> paid     # draft | sent | paid | void
```
`ronin client <slug>` and `ronin list clients` show billed / paid / outstanding.

### `ronin add`

```
ronin add                              # interactive picker: numbered list → choose → install
ronin add --category recon             # …scoped to one category
ronin add --search xss                 # …scoped by text
ronin add nuclei dalfox certipy        # install by name (confirm, or -y)
ronin add --list [--category] [--search]   # just print the catalog, no prompt
ronin add --missing [-y]               # target every not-installed adapter tool (one confirm)
ronin add --missing --extended         # …include the extended catalog
ronin add <name> --dry-run             # print the install commands only
```

Picker input accepts numbers, ranges and names: `1 4 7-9 nuclei`, or `all`, or
Enter to cancel. By default only *not-installed* tools are shown.

Resolves against the **core catalog** (adapters) then the **extended catalog**
(`ronin/data/extended_tools.py`, ~55 awesome-pentest tools). Recipes are tried
`pacman → aur (yay) → go install → pipx/uv tool → git clone`. `git` tools land in
`$RONIN_HOME/tools/<name>` and are **not** put on PATH.

### `ronin update`

```
ronin update                 # check → summary → prompt to update outdated,
                             #   then prompt to install missing tools
ronin update tools           # just print the currency table (no changes)
ronin update nuclei httpx    # update specific tools
ronin update --all -y        # update outdated + install missing, no prompts
ronin update --no-missing    # skip the "install missing" offer
ronin update --offline       # prefer the cached check
```
`nuclei` also triggers `-update-templates`. To only install missing tools without
touching updates: `ronin add --missing`.

### `ronin sync`

Runs an online currency check and refreshes nuclei templates. `--offline` just
re-reads local state.

### `ronin doctor`

```
ronin doctor                         # status table (core catalog)
ronin doctor --all                   # include the extended catalog
ronin doctor --install               # install everything missing
ronin doctor --install --only nmap,nuclei,httpx
ronin doctor --install --dry-run
```

### Exit codes

`0` ok · `1` usage / not-found · `2` scope violation or "out of scope".

---

## 2. TUI

`ronin` (no args). Cybercore theme, six tabs.

| Key | Action |
|---|---|
| `1`–`6` | Dashboard · Tools · Reports · Clients · Updates · Toolbox |
| `j` `k` `h` `l` | vim cursor move (down/up/left/right) — arrow keys also work |
| `g` / `G` | jump to top / bottom · `ctrl+d` / `ctrl+u` half-page |
| `e` | pick / create the active engagement |
| `E` | open the active engagement's `scope.yaml` in `$EDITOR` / neovim (TUI suspends) |
| `q` | quit · `ctrl+p` command palette |
| `/` | (Tools) toggle the filter box |
| `enter` | activate the selected row (configure a tool, open a detail) |
| `s` | (Findings) cycle remediation status `open → in_progress → fixed → accepted → closed` |
| `n` | (Clients) new client — or, on a highlighted row, edit it |
| `v` | (Reports) open the selected `technical.md` in the editor |
| `f` / `r` | (after a run) jump to Findings / Reports |
| `o` | (Reports) open `index.html` in the browser · `ctrl+g` generate |
| `c` | (Updates) check now · `u` update selected |
| `i` / `a` | (Toolbox) install selected / install all missing |
| `escape` | back / close modal |

Panes:

- **Dashboard** — active client + engagement, finding counts, and an ATTENTION
  panel (retests overdue, tools outdated/missing, nuclei-template age) + recent runs.
- **Tools** — adapter catalog → configure modal (live scope check) → streaming run
  → Findings / Reports.
- **Reports** — every generated report set on disk; generate; open.
- **Clients** — recurring clients with cadence, next-due, overdue flag, remediation
  %; detail panel with status mix and open-by-severity.
- **Updates** — installed vs latest per tool; update selected / all outdated.
- **Toolbox** — the `doctor` survey with install / install-all-missing / update.

---

## 3. Python API

Import root is `ronin`. Public surface, module by module.

### `ronin.config`

| Object | Signature | Notes |
|---|---|---|
| `paths()` | `() -> Paths` | cached; project layout under the root |
| `Paths.root` | `Path` | `$RONIN_HOME` → `.ronin-portable` folder → `~/.local/share/roninsuite` |
| `Paths.db` / `.audit_log` / `.env_file` | `Path` | files at the root |
| `Paths.engagements` / `.reports` / `.cache` | `Path` | dirs (created on access) |
| `Paths.engagement_dir(slug)` | `-> Path` | |
| `Paths.scope_file(slug)` | `-> Path` | `engagements/<slug>/scope.yaml` |
| `Paths.evidence_dir(slug, run_id)` | `-> Path` | |
| `Paths.report_dir(slug, stamp)` | `-> Path` | |
| `load_dotenv()` | `() -> None` | loads `.env` (env wins) |
| `INTENSITY` | `dict` | `stealth`/`normal`/`aggressive` → nmap timing, rate, concurrency |

### `ronin.core.models`

Pydantic models + enums.

| Object | Key fields / methods |
|---|---|
| `Severity(str, Enum)` | `INFO LOW MEDIUM HIGH CRITICAL`; `.rank`; `Severity.from_score(float)` |
| `RunStatus(str, Enum)` | `PENDING RUNNING OK ERROR TIMEOUT BLOCKED` |
| `FindingStatus(str, Enum)` | `OPEN IN_PROGRESS FIXED ACCEPTED CLOSED`; `FindingStatus.cycle(current) -> str` |
| `InvoiceStatus(str, Enum)` | `DRAFT SENT PAID VOID` |
| `Client` | `slug name contact_name contact_email phone address website x facebook linkedin notes cadence_days rate created`; `.socials -> dict` |
| `Invoice` | `id client_slug number engagement issued due amount currency status description created` |
| `Engagement` | `slug client tester authorized_by created notes client_slug` |
| `ToolRun` | `id engagement tool target argv status started finished exit_code evidence_dir result_files forced force_reason error`; `.duration_s` |
| `Finding` | `id engagement run_id tool title target severity cvss_vector cvss_score confidence status description evidence request response poc attack_path remediation references cwe cve tags first_seen fingerprint`; `.finalize()` (fills CVSS-derived severity + fingerprint); `.merge(other)` |
| `Option` | `key label kind default choices help aggressive` — one tool knob |
| `ScopeDecision` | `target allowed reason matched_rule within_window` |
| `dedupe(list[Finding]) -> list[Finding]` | finalize + collapse by fingerprint, sort by severity/CVSS desc |

### `ronin.core.cvss`

| Function | Signature |
|---|---|
| `base_score(vector)` | `(str) -> float` — CVSS v3.1 base score (raises `ValueError` on a bad vector) |
| `severity_for(score)` | `(float) -> str` — band name |
| `score_and_severity(vector)` | `(str) -> tuple[float, str]` |
| `parse_vector(vector)` | `(str) -> dict[str, str]` |
| `SEVERITY_BANDS` | tuple of `(lo, hi, name)` |

### `ronin.core.scope`

| Object | Signature / notes |
|---|---|
| `Scope.load(path)` | `-> Scope` (raises `FileNotFoundError`) |
| `Scope(data, path=None)` | `.client .tester .authorized_by .roe .in_scope .out_of_scope .window_start .window_end` |
| `Scope.check(target)` | `-> ScopeDecision` |
| `Scope.within_window(when=None)` | `-> bool` |
| `ScopeViolation(RuntimeError)` | `.decision` |
| `SCOPE_TEMPLATE` | str — scaffold for a new `scope.yaml` |

### `ronin.core.db`  (SQLite, one file at `paths().db`)

Clients: `upsert_client(Client)` · `get_client(slug) -> Client|None` ·
`list_clients() -> list[Client]` · `delete_client(slug)` (cascades invoices).

Invoices: `upsert_invoice(Invoice)` · `get_invoice(id) -> Invoice|None` ·
`list_invoices(client_slug=None) -> list[Invoice]` · `set_invoice_status(id, status)` ·
`delete_invoice(id)` · `invoice_totals(client_slug=None) -> {count, drafts, billed,
paid, outstanding, currency}`.

Engagements: `upsert_engagement(Engagement)` · `upsert_engagement_stub(slug)` ·
`get_engagement(slug)` · `list_engagements(client_slug=None) -> list[Engagement]` ·
`set_engagement_client(engagement_slug, client_slug)`.

Runs: `save_run(ToolRun)` · `get_run(run_id) -> ToolRun|None` ·
`list_runs(engagement) -> list[ToolRun]`.

Findings: `save_findings(list[Finding])` · `get_findings(engagement, run_id=None) -> list[Finding]` ·
`set_finding_status(finding_id, status)`.

State + rollup: `set_state(key, value)` · `get_state(key, default="") -> str` ·
`client_progress(slug) -> dict` (adds `billing` = `invoice_totals(slug)`) with keys
`client engagements last_tested next_due overdue findings_total status_mix
open_by_severity resolved progress_pct`.

Low-level: `connect()` context manager (schema + migrations applied on open).

### `ronin.core.audit`

`record(event, **fields) -> None` — append one JSON line to `audit.log`
(`ts event operator host pid` + your fields).

### `ronin.core.runner`

```python
run_tool(adapter, engagement, target, *, options=None, intensity="normal",
         scope=None, force=False, force_reason="", timeout=None, on_line=None) -> ToolRun
```
Scope-check → build argv → exec with per-line streaming (`on_line(stream, text)`,
`stream ∈ {"out","err","sys"}`) → parse → dedupe → persist run + findings →
audit. Raises `ScopeViolation` (blocked, not forced), `ValueError` (force without
reason), `FileNotFoundError` (tool binary missing).

### `ronin.tools.base`

| Object | Notes |
|---|---|
| `ToolAdapter` (ABC) | class attrs `name binary summary categories doc_url install aggressive default_timeout`; `is_installed() -> bool`; `options() -> list[Option]`; `option_defaults() -> dict`; **abstract** `build_argv(ctx) -> list[str]`, `parse(run, ctx) -> list[Finding]`; helper `_f(run, ctx, **kw) -> Finding` |
| `RunContext` | `engagement target evidence_dir options intensity result_files`; `.out(name) -> Path` (registers a result file) |

### `ronin.tools.registry`

`adapters() -> dict[str, ToolAdapter]` · `get(name) -> ToolAdapter` (raises
`KeyError`) · `CATALOG: dict[str, dict]` — core install map (`category`,
`install`, `aggressive`, `binary`).

### `ronin.data.extended_tools`

`EXTENDED: dict[str, dict]` — `{category, desc, install, url}` per tool ·
`categories() -> list[str]`.

### `ronin.doctor`

| Function | Signature |
|---|---|
| `survey(include_extended=False) -> list[ToolStatus]` | `ToolStatus(name category binary installed path has_adapter aggressive recipe extended desc)` |
| `catalog_lookup(name) -> dict|None` | `{category recipe desc extended binary}` |
| `install(names, *, dry_run=False) -> dict[str,str]` | outcome per tool |
| `update(names, *, dry_run=False) -> dict[str,str]` | |
| `install_recipe(name, recipe, *, dry_run=False, update=False) -> str` | run one recipe |

### `ronin.updates`

| Function | Signature |
|---|---|
| `check(*, online=True) -> UpdateReport` | query GitHub / pacman, cache in `state` |
| `cached() -> UpdateReport|None` | last cached check |
| `UpdateReport` | `.tools .checked_at .nuclei_templates_age_days .pacman_updates`; `.outdated`, `.missing` |
| `ToolUpdate` | `name category installed installed_version latest_version source status note` |

### `ronin.reports.render`

| Function | Signature |
|---|---|
| `render(slug, *, run_id=None, levels=LEVELS, formats=FORMATS, out_dir=None) -> dict[str, dict[str, Path]]` | write MD/HTML/PDF for each level; returns `{level: {fmt: path}}` |
| `build_context(slug, run_id=None) -> ReportContext` | the data the templates see |
| `load_brand() -> dict` | reads `brand.yaml` (company, logo→data-URI, accent, classification, footer) |
| `LEVELS` | `("executive", "technical", "remediation")` |
| `FORMATS` | `("md", "html", "pdf")` |

Templates: `ronin/reports/templates/` — `_macros.md.j2` (the four sections,
depth-parametrised) + `executive|technical|remediation.md.j2` + `report.html.j2`.

---

## 4. On-disk layout

Data root = `~/.local/share/roninsuite` (system install), the code folder if it
carries a `.ronin-portable` marker (USB), or `$RONIN_HOME`.

```
<data root>/
├── ronin.db                 SQLite: clients, invoices, engagements, runs, findings, state
├── audit.log                append-only JSONL: scope decisions + every command
├── brand.yaml               optional report branding (brand.example.yaml → copy)
├── engagements/<slug>/
│   ├── scope.yaml           the authorisation boundary
│   └── evidence/<run-id>/   command.txt, stdout.log, stderr.log, <tool>.<ext>, findings.json
├── reports/<slug>/<stamp>/  executive|technical|remediation .{md,html,pdf} + index.html
└── tools/<name>/            git-cloned extended tools (not on PATH)
```
