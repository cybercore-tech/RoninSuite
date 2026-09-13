"""RoninSuite command line — verb-first, minimal typing.

    ronin                     launch the TUI
    ronin help [command]      help
    ronin run <tool> -t <t>   run a scan (auto-generates reports)
    ronin report <eng>        (re)generate tiered reports
    ronin scope <eng> <t>     scope check
    ronin list <what>         tools | clients | engagements | reports | runs | findings
    ronin show <what> <id>    client | engagement | finding | run | report
    ronin search <text>       across findings, clients, engagements, tools, reports
    ronin new client|engagement …
    ronin link <eng> <client>
    ronin client [<id>]       list clients, or show one
    ronin engagement [<id>]   list engagements, or show one
    ronin doctor              toolchain health
    ronin add <tool> …        install tool(s) from the catalog / awesome list
    ronin update [<tool> …]   update outdated tools  (`ronin update tools` = show table)
    ronin sync                refresh update cache + nuclei templates
"""
from __future__ import annotations

import datetime as _dt
import os
import re
import sys

import typer
from rich.console import Console
from rich.table import Table

from ronin.config import load_dotenv, paths
from ronin.core import db
from ronin.core.models import Client, Engagement, Invoice
from ronin.core.scope import SCOPE_TEMPLATE, Scope, ScopeViolation

app = typer.Typer(add_completion=False, no_args_is_help=False, rich_markup_mode="rich",
                  help="RoninSuite — portable offensive toolkit for Linux with tiered CVSS reporting.")
new_app = typer.Typer(help="Create clients and engagements.")
invoice_app = typer.Typer(help="Lightweight invoice tracking (full billing panel comes later).")
app.add_typer(new_app, name="new")
app.add_typer(invoice_app, name="invoice")
con = Console()
err = Console(stderr=True)

_LISTABLE = ("tools", "clients", "engagements", "reports", "runs", "findings")
_SHOWABLE = ("client", "engagement", "finding", "run", "report")
_SEV_COL = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
_ST_COL = {"current": "green", "outdated": "yellow", "missing": "red", "unknown": "dim"}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def _table(*cols: str, title: str = "") -> Table:
    t = Table(title=title or None, header_style="bold cyan", border_style="blue")
    for c in cols:
        t.add_column(c)
    return t


def _resolve_engagement(slug: str | None) -> str:
    if slug:
        return slug
    es = db.list_engagements()
    if len(es) == 1:
        return es[0].slug
    if not es:
        err.print("[red]no engagements — `ronin new engagement --client \"Acme\"`[/red]")
        raise typer.Exit(1)
    err.print("[yellow]multiple engagements; pass -e <slug>. recent:[/yellow] "
              + ", ".join(e.slug for e in es[:6]))
    raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context):
    load_dotenv()
    if ctx.invoked_subcommand is None:
        from ronin.tui.app import run as run_tui

        run_tui()
        raise typer.Exit()


@app.command()
def help(command: str = typer.Argument("", help="command to explain")):  # noqa: A001
    """Show help — `ronin help` for the overview, `ronin help run` for one command."""
    from click import Context

    root = typer.main.get_command(app)
    if not command:
        con.print(root.get_help(Context(root, info_name="ronin")))
        return
    sub = root.get_command(Context(root, info_name="ronin"), command)
    if sub is None:
        err.print(f"[red]no command '{command}'[/red]  ({', '.join(sorted(_LISTABLE))} …)")
        raise typer.Exit(1)
    con.print(sub.get_help(Context(sub, info_name=f"ronin {command}")))


# ══════════════════════════════════════════════════════════════════ doing
@app.command()
def run(
    tool: str = typer.Argument(..., help="adapter name (see `ronin list tools`)"),
    target: str = typer.Option(..., "--target", "-t"),
    engagement: str = typer.Option("", "--engagement", "-e", help="default: the only/one engagement"),
    opt: list[str] = typer.Option([], "--opt", "-o", help="tool option k=v (repeatable)"),
    intensity: str = typer.Option("normal", help="stealth | normal | aggressive"),
    force: bool = typer.Option(False, help="run even if out of scope"),
    reason: str = typer.Option("", help="written justification required with --force"),
    yes: bool = typer.Option(False, "--yes", "-y", help="skip the aggressive-tool prompt"),
    no_report: bool = typer.Option(False, help="don't auto-generate reports"),
):
    """Run one TOOL against one TARGET, parse findings, write reports."""
    from ronin.core.runner import run_tool
    from ronin.tools.registry import get

    eng = _resolve_engagement(engagement)
    try:
        adapter = get(tool)
    except KeyError as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    options = {}
    for kv in opt:
        if "=" not in kv:
            err.print(f"[red]bad --opt {kv!r}, expected k=v[/red]")
            raise typer.Exit(1)
        k, v = kv.split("=", 1)
        options[k] = _coerce(v)

    scope = None
    sf = paths().scope_file(eng)
    if sf.is_file():
        scope = Scope.load(sf)
    else:
        con.print(f"[yellow]no scope file for {eng}; scope checks skipped[/yellow]")

    if adapter.aggressive and not yes:
        typer.confirm(f"'{tool}' is an active/aggressive tool. Proceed against {target}?", abort=True)
    if force and not reason:
        err.print("[red]--force requires --reason[/red]")
        raise typer.Exit(1)

    con.print(f"[bold]▶ {tool}[/bold] → {target}   (engagement {eng})")
    try:
        r = run_tool(adapter, eng, target, options=options, intensity=intensity, scope=scope,
                     force=force, force_reason=reason, on_line=lambda s, l: con.print(_line(s, l)))
    except ScopeViolation as v:
        err.print(f"[red]BLOCKED[/red] — {v.decision.reason}. Use --force --reason '…' (logged).")
        raise typer.Exit(2)
    except FileNotFoundError as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    finds = db.get_findings(eng, r.id)
    con.print(f"\n[bold]{len(finds)} findings[/bold]  status={r.status.value}  evidence={r.evidence_dir}")
    _print_findings(finds)
    if not no_report:
        _do_report(eng, run_id=r.id)


@app.command()
def report(
    engagement: str = typer.Argument("", help="engagement slug (default: the only one)"),
    run_id: str = typer.Option("", "--run", help="scope the report to one run id"),
    level: str = typer.Option("all", help="executive | technical | remediation | all"),
    fmt: str = typer.Option("md,html,pdf", "--format", help="comma list"),
):
    """(Re)generate the tiered reports for ENGAGEMENT from stored findings."""
    _do_report(_resolve_engagement(engagement), run_id=run_id or None, level=level, fmt=fmt)


@app.command()
def scope(engagement: str, target: str):
    """Check whether TARGET is in scope for ENGAGEMENT."""
    sf = paths().scope_file(engagement)
    if not sf.is_file():
        err.print(f"[red]no scope file[/red] at {sf}")
        raise typer.Exit(1)
    d = Scope.load(sf).check(target)
    col = "green" if d.allowed else "red"
    con.print(f"[{col}]{'IN SCOPE' if d.allowed else 'OUT OF SCOPE'}[/{col}] — {d.reason}")
    if d.allowed and not d.within_window:
        con.print("[yellow]note: outside the testing window[/yellow]")
    raise typer.Exit(0 if d.allowed else 2)


# ══════════════════════════════════════════════════════════════════ looking
@app.command("list")
def list_(
    what: str = typer.Argument(..., help="tools | clients | engagements | reports | runs | findings"),
    target: str = typer.Argument("", help="engagement slug for runs/findings; category for tools"),
    severity: str = typer.Option("", help="findings filter: info|low|medium|high|critical"),
    status: str = typer.Option("", help="findings filter: open|in_progress|fixed|accepted|closed"),
):
    """List RoninSuite objects."""
    what = what.rstrip("s") + "s" if what.rstrip("s") + "s" in _LISTABLE else what
    if what == "tools":
        _list_tools(target)
    elif what == "clients":
        _list_clients()
    elif what == "engagements":
        _list_engagements()
    elif what == "reports":
        _list_reports(target)
    elif what == "runs":
        _list_runs(_resolve_engagement(target or None))
    elif what == "findings":
        _list_findings(_resolve_engagement(target or None), severity, status)
    else:
        err.print(f"[red]can't list '{what}'[/red] — one of: {', '.join(_LISTABLE)}")
        raise typer.Exit(1)


@app.command()
def show(what: str, id: str):  # noqa: A002
    """Show one object in detail: client | engagement | finding | run | report."""
    what = what.rstrip("s")
    if what == "client":
        _show_client(id)
    elif what == "engagement":
        _show_engagement(id)
    elif what == "finding":
        _show_finding(id)
    elif what == "run":
        _show_run(id)
    elif what == "report":
        con.print(f"open: file://{paths().reports / id}/index.html")
    else:
        err.print(f"[red]can't show '{what}'[/red] — one of: {', '.join(_SHOWABLE)}")
        raise typer.Exit(1)


@app.command()
def search(
    text: str,
    type: str = typer.Option("", "--type", help="narrow: findings|clients|engagements|tools|reports"),
):
    """Fuzzy search across findings, clients, engagements, the tool catalogs and reports."""
    q = text.lower()
    want = {x.strip() for x in type.split(",") if x.strip()}
    hit = 0

    def sect(name):
        return not want or name in want

    if sect("tools"):
        from ronin.data.extended_tools import EXTENDED
        from ronin.tools.registry import CATALOG, adapters

        rows = []
        for n, m in CATALOG.items():
            d = adapters()[n].summary if n in adapters() else ""
            if q in f"{n} {m['category']} {d}".lower():
                rows.append((n, m["category"], "core", d))
        for n, m in EXTENDED.items():
            if q in f"{n} {m['category']} {m['desc']}".lower():
                rows.append((n, m["category"], "add", m["desc"]))
        if rows:
            hit += len(rows)
            t = _table("tool", "category", "src", "description", title="tools")
            for r in sorted(rows):
                t.add_row(*[str(x)[:70] for x in r])
            con.print(t)

    if sect("clients"):
        rows = [c for c in db.list_clients()
                if q in f"{c.slug} {c.name} {c.contact_name} {c.contact_email}".lower()]
        if rows:
            hit += len(rows)
            t = _table("slug", "name", "contact", title="clients")
            for c in rows:
                t.add_row(c.slug, c.name, c.contact_name or "-")
            con.print(t)

    if sect("engagements"):
        rows = [e for e in db.list_engagements()
                if q in f"{e.slug} {e.client} {e.client_slug} {e.notes}".lower()]
        if rows:
            hit += len(rows)
            t = _table("slug", "client", "linked", title="engagements")
            for e in rows:
                t.add_row(e.slug, e.client, e.client_slug or "-")
            con.print(t)

    if sect("findings"):
        rows = []
        for e in db.list_engagements():
            for f in db.get_findings(e.slug):
                blob = f"{f.title} {f.target} {' '.join(f.cve)} {' '.join(f.tags)} {f.tool}".lower()
                if q in blob:
                    rows.append((e.slug, f))
        if rows:
            hit += len(rows)
            t = _table("engagement", "sev", "title", "target", "status", title="findings")
            for es, f in sorted(rows, key=lambda x: x[1].severity.rank, reverse=True)[:40]:
                t.add_row(es, f"[{_SEV_COL.get(f.severity.value,'')}]{f.severity.value.upper()}[/]",
                          f.title[:52], f.target[:34], f.status)
            con.print(t)

    if sect("reports"):
        rows = [p for p in paths().reports.glob("*/*") if p.is_dir() and q in str(p).lower()]
        if rows:
            hit += len(rows)
            t = _table("engagement", "stamp", "path", title="reports")
            for p in sorted(rows)[:30]:
                t.add_row(p.parent.name, p.name, str(p))
            con.print(t)

    if not hit:
        con.print(f"[dim]no matches for {text!r}[/dim]")


# ── noun shortcuts ────────────────────────────────────────────────────────
@app.command()
def client(id: str = typer.Argument("", help="client slug; omit to list")):  # noqa: A002
    """List clients, or show one client's retest + remediation status."""
    _show_client(id) if id else _list_clients()


@app.command()
def engagement(id: str = typer.Argument("", help="engagement slug; omit to list")):  # noqa: A002
    """List engagements, or show one engagement's runs and findings."""
    _show_engagement(id) if id else _list_engagements()


@invoice_app.command("new")
def invoice_new(
    client: str = typer.Option(..., "--client", "-c", help="client slug"),
    amount: float = typer.Option(..., "--amount", "-a"),
    number: str = typer.Option("", help="human invoice number, e.g. INV-2026-014"),
    engagement: str = typer.Option("", help="link to an engagement slug"),
    due: str = typer.Option("", help="due date YYYY-MM-DD"),
    currency: str = typer.Option("USD"),
    status: str = typer.Option("draft", help="draft | sent | paid | void"),
    description: str = typer.Option("", "--description", "-d"),
):
    """Record an invoice for a client."""
    if not db.get_client(client):
        err.print(f"[red]no client '{client}'[/red]")
        raise typer.Exit(1)
    inv = Invoice(client_slug=client, number=number, engagement=engagement,
                  amount=amount, currency=currency, status=status, description=description,
                  due=_dt.date.fromisoformat(due) if due else None)
    db.upsert_invoice(inv)
    con.print(f"[green]invoice[/green] {inv.number or inv.id[:8]}  {currency} {amount:,.2f}  "
              f"[{status}]  → {client}")


@invoice_app.command("list")
def invoice_list(client: str = typer.Argument("", help="client slug; omit for all")):
    """List invoices."""
    invs = db.list_invoices(client or None)
    if not invs:
        con.print("[dim]no invoices[/dim]")
        return
    t = _table("id", "number", "client", "amount", "status", "issued", "due", "for")
    for i in invs:
        col = {"paid": "green", "sent": "yellow", "void": "dim"}.get(i.status, "cyan")
        t.add_row(i.id[:8], i.number or "-", i.client_slug,
                  f"{i.currency} {i.amount:,.2f}", f"[{col}]{i.status}[/]",
                  str(i.issued), str(i.due) if i.due else "-",
                  (i.engagement or i.description)[:28])
    con.print(t)
    tot = db.invoice_totals(client or None)
    con.print(f"billed {tot['currency']} {tot['billed']:,.2f} · paid {tot['paid']:,.2f} · "
              f"[yellow]outstanding {tot['outstanding']:,.2f}[/]")


@invoice_app.command("status")
def invoice_status(invoice_id: str, status: str):
    """Set an invoice's status: draft | sent | paid | void  (id may be the short prefix)."""
    inv = db.get_invoice(invoice_id) or next(
        (x for x in db.list_invoices() if x.id.startswith(invoice_id)), None)
    if not inv:
        err.print(f"[red]no invoice '{invoice_id}'[/red]")
        raise typer.Exit(1)
    db.set_invoice_status(inv.id, status)
    con.print(f"[green]{inv.number or inv.id[:8]}[/green] → {status}")


@app.command()
def link(engagement: str, client: str):
    """Attach an existing ENGAGEMENT to a CLIENT record."""
    if not db.get_client(client):
        err.print(f"[red]no client '{client}'[/red] — `ronin new client --name …`")
        raise typer.Exit(1)
    db.set_engagement_client(engagement, client)
    con.print(f"[green]linked[/green] {engagement} → {client}")


# ══════════════════════════════════════════════════════════════════ making
@new_app.command("client")
def new_client(
    name: str = typer.Option(..., help="client / organisation name"),
    slug: str = typer.Option("", help="short id (default: slugified name)"),
    contact: str = typer.Option("", help="primary contact name"),
    email: str = typer.Option("", help="primary contact email"),
    phone: str = typer.Option("", help="phone number"),
    address: str = typer.Option("", help="postal address"),
    website: str = typer.Option("", help="website"),
    x: str = typer.Option("", help="X / Twitter handle or URL"),
    facebook: str = typer.Option("", help="Facebook page"),
    linkedin: str = typer.Option("", help="LinkedIn page"),
    rate: float = typer.Option(0.0, help="default hourly/day rate"),
    cadence_days: int = typer.Option(0, help="retest reminder interval; 0 = none"),
):
    """Add / update a recurring client (contact, socials, rate, retest cadence)."""
    slug = slug or _slug(name)
    existing = db.get_client(slug)
    base = existing.model_dump() if existing else {}
    base.update(dict(slug=slug, name=name, contact_name=contact or base.get("contact_name", ""),
                     contact_email=email or base.get("contact_email", ""),
                     phone=phone or base.get("phone", ""),
                     address=address or base.get("address", ""),
                     website=website or base.get("website", ""),
                     x=x or base.get("x", ""), facebook=facebook or base.get("facebook", ""),
                     linkedin=linkedin or base.get("linkedin", ""),
                     rate=rate or base.get("rate", 0.0),
                     cadence_days=cadence_days or base.get("cadence_days", 0)))
    db.upsert_client(Client(**base))
    con.print(f"[green]client[/green] [bold]{slug}[/bold] "
              + ("updated" if existing else "saved")
              + (f"  ·  retest every {base['cadence_days']}d" if base["cadence_days"] else "")
              + (f"  ·  ${base['rate']:g}/unit" if base["rate"] else ""))


@new_app.command("engagement")
def new_engagement(
    client: str = typer.Option(..., help="client / organisation name"),
    tester: str = typer.Option("", help="your name (defaults to $USER)"),
    slug: str = typer.Option("", help="short id; default: <client>-<date>"),
    days: int = typer.Option(14, help="testing-window length from today"),
    client_slug: str = typer.Option("", "--client-slug", help="link to a `ronin client` record"),
):
    """Create an engagement and scaffold its scope.yaml."""
    import getpass

    tester = tester or getpass.getuser()
    if client_slug and not db.get_client(client_slug):
        con.print(f"[yellow]no client '{client_slug}' yet[/yellow]")
    slug = slug or f"{_slug(client)}-{_dt.date.today():%Y%m%d}"
    db.upsert_engagement(Engagement(slug=slug, client=client, tester=tester, client_slug=client_slug))
    sf = paths().scope_file(slug)
    if not sf.exists():
        end = _dt.date.today() + _dt.timedelta(days=days)
        sf.write_text(SCOPE_TEMPLATE.format(client=client, slug=slug, tester=tester,
                                            start=_dt.date.today(), end=end))
    con.print(f"[green]created[/green] engagement [bold]{slug}[/bold]  ·  scope: {sf}")
    con.print(f"  edit in_scope, then:  [cyan]ronin run nmap -e {slug} -t <host>[/cyan]")


# ══════════════════════════════════════════════════════════════════ toolchain
@app.command()
def doctor(
    install: bool = typer.Option(False, "--install", help="install what's missing"),
    only: str = typer.Option("", help="comma list of tools to act on"),
    all_: bool = typer.Option(False, "--all", help="also show the extended (addable) catalog"),
    dry_run: bool = typer.Option(False, help="print commands without running them"),
):
    """Show the offensive toolchain; optionally install what's missing."""
    from ronin.doctor import install as do_install
    from ronin.doctor import survey

    rows = survey(include_extended=all_)
    t = _table("tool", "category", "adapter", "active", "status", title="RoninSuite toolchain")
    for s in rows:
        t.add_row(s.name, s.category, "core" if s.has_adapter else ("add" if s.extended else "·"),
                  "[red]yes[/red]" if s.aggressive else "·",
                  f"[green]{s.path}[/green]" if s.installed else "[yellow]missing[/yellow]")
    con.print(t)
    con.print(f"{sum(s.installed for s in rows)}/{len(rows)} installed  ·  "
              f"adapters: {sum(s.has_adapter for s in rows)}")
    if install:
        wanted = [x.strip() for x in only.split(",") if x.strip()] or \
                 [s.name for s in rows if not s.installed]
        con.print(f"\n[bold]installing:[/bold] {', '.join(wanted)}")
        for n, o in do_install(wanted, dry_run=dry_run).items():
            c = "green" if o in ("installed", "updated") or "already" in o else "yellow"
            con.print(f"  [{c}]{n}: {o}[/{c}]")


def _catalog_rows(category: str = "", search: str = "", include_installed: bool = True):
    """(name, category, src, installed, description) for the full addable catalog."""
    import shutil

    from ronin.data.extended_tools import EXTENDED
    from ronin.tools.registry import CATALOG, adapters

    rows = []
    for n, m in CATALOG.items():
        d = adapters()[n].summary if n in adapters() else ""
        rows.append((n, m["category"], "core", CATALOG[n].get("binary", n), d))
    for n, m in EXTENDED.items():
        rows.append((n, m["category"], "add", m.get("binary", n), m["desc"]))
    out = []
    for n, cat, src, binary, desc in sorted(rows):
        if category and cat != category:
            continue
        if search and search.lower() not in f"{n} {cat} {desc}".lower():
            continue
        inst = shutil.which(binary) is not None
        if not include_installed and inst:
            continue
        out.append((n, cat, src, inst, desc))
    return out


def _parse_selection(raw: str, names: list[str]) -> list[str]:
    """'1 4 7-9 nuclei, all' -> resolved list of tool names (order preserved, deduped)."""
    raw = raw.strip().lower()
    if raw in ("all", "*"):
        return list(names)
    picked: list[str] = []
    for tok in re.split(r"[,\s]+", raw):
        if not tok:
            continue
        if "-" in tok and all(p.isdigit() for p in tok.split("-", 1)):
            a, b = (int(x) for x in tok.split("-", 1))
            for i in range(a, b + 1):
                if 1 <= i <= len(names):
                    picked.append(names[i - 1])
        elif tok.isdigit():
            i = int(tok)
            if 1 <= i <= len(names):
                picked.append(names[i - 1])
        elif tok in names:
            picked.append(tok)
    return list(dict.fromkeys(picked))


@app.command()
def add(
    tools: list[str] = typer.Argument(None, help="tool name(s) to install; omit for the picker"),
    list_: bool = typer.Option(False, "--list", help="print the catalog and exit (no prompt)"),
    missing: bool = typer.Option(False, "--missing", help="target every not-installed tool"),
    extended: bool = typer.Option(False, "--extended", help="include the extended catalog"),
    category: str = typer.Option("", help="filter to one category"),
    search: str = typer.Option("", help="filter by text"),
    yes: bool = typer.Option(False, "--yes", "-y", help="don't prompt (with --missing / explicit names)"),
    dry_run: bool = typer.Option(False, help="print commands without running them"),
):
    """Install pentest tool(s) from the core + extended (awesome-list) catalog.

    `ronin add`            interactive picker
    `ronin add nuclei gau` install by name
    `ronin add --list`     just print the catalog
    `ronin add --missing`  target everything not installed
    """
    from ronin.data.extended_tools import categories
    from ronin.doctor import catalog_lookup
    from ronin.doctor import install as do_install

    # ── explicit names ────────────────────────────────────────────────────
    if tools:
        unknown = [x for x in tools if not catalog_lookup(x)]
        if unknown:
            err.print(f"[red]unknown:[/red] {', '.join(unknown)} — try `ronin add --search <text>`")
            raise typer.Exit(1)
        if not yes and not dry_run:
            typer.confirm(f"install {', '.join(tools)}? (sudo/yay may prompt)", abort=True)
        for n, o in do_install(list(tools), dry_run=dry_run).items():
            _outcome(n, o)
        return

    rows = _catalog_rows(category, search, include_installed=list_)
    if not missing:
        rows = [r for r in rows if not r[3]] if not list_ else rows

    # ── --list : dump and exit ───────────────────────────────────────────
    if list_:
        t = _table("tool", "category", "src", "installed", "description", title="addable tools")
        for n, cat, src, inst, desc in rows:
            t.add_row(n, cat, src, "[green]yes[/green]" if inst else "[dim]no[/dim]", desc[:64])
        con.print(t)
        con.print(f"categories: {', '.join(categories())}  ·  "
                  "pick interactively: [cyan]ronin add[/cyan]")
        return

    if not rows:
        con.print("[green]nothing to add[/green] (all matching tools are installed)")
        return
    names = [r[0] for r in rows]

    # ── --missing : all of them, one confirm ────────────────────────────
    if missing:
        con.print(f"[bold]{len(names)} not installed:[/bold] {', '.join(names[:14])}"
                  + (" …" if len(names) > 14 else ""))
        if not yes and not dry_run:
            typer.confirm("install all of these?", abort=True)
        for n, o in do_install(names, dry_run=dry_run).items():
            _outcome(n, o)
        return

    # ── interactive picker ──────────────────────────────────────────────
    t = _table("#", "tool", "category", "src", "description",
               title=f"addable — {len(names)} not installed"
                     + (f" · {category}" if category else ""))
    for i, (n, cat, src, _inst, desc) in enumerate(rows, 1):
        t.add_row(str(i), n, cat, src, desc[:58])
    con.print(t)
    raw = typer.prompt("select tools (e.g. 1 4 7-9 nuclei · 'all' · Enter to cancel)",
                       default="", show_default=False)
    chosen = _parse_selection(raw, names)
    if not chosen:
        con.print("[dim]nothing selected[/dim]")
        return
    con.print(f"[bold]installing:[/bold] {', '.join(chosen)}  (sudo/yay may prompt)")
    if not dry_run:
        typer.confirm("proceed?", abort=True)
    for n, o in do_install(chosen, dry_run=dry_run).items():
        _outcome(n, o)


@app.command()
def update(
    tools: list[str] = typer.Argument(None, help="tool(s) to update; 'tools' = just show the table"),
    all_: bool = typer.Option(False, "--all", help="act on everything, no prompts"),
    missing: bool = typer.Option(True, "--missing/--no-missing",
                                 help="also offer to install missing tools"),
    yes: bool = typer.Option(False, "--yes", "-y", help="don't prompt"),
    offline: bool = typer.Option(False, help="use the cached check, no network"),
    dry_run: bool = typer.Option(False, help="print commands without running them"),
):
    """Update outdated tools, and offer to install missing ones.

    `ronin update tools` just shows the currency table.
    `ronin update nuclei httpx` updates those.  `ronin update --all -y` does the lot.
    """
    from ronin import updates as up
    from ronin.doctor import install as do_install
    from ronin.doctor import update as do_update

    tools = list(tools or [])
    rep = up.cached() if offline else up.check(online=True)
    if rep is None:
        rep = up.check(online=False)   # no cache yet -> local-only survey

    if tools == ["tools"]:
        _print_currency(rep)
        return
    auto = yes or all_

    # explicit list -> just update those
    if tools:
        for n, o in do_update(tools, dry_run=dry_run).items():
            _outcome(n, o)
        return

    _print_currency(rep, summary_only=True)

    # 1) update outdated
    if rep.outdated:
        names = [x.name for x in rep.outdated]
        con.print(f"[yellow]{len(names)} outdated:[/yellow] {', '.join(names)}")
        if auto or (not dry_run and typer.confirm("  update them now?")):
            for n, o in do_update(names, dry_run=dry_run).items():
                _outcome(n, o)
    else:
        con.print("[green]all installed tools are current[/green]")

    # 2) install missing
    miss = [x.name for x in rep.missing]
    if miss and missing:
        con.print(f"\n[yellow]{len(miss)} not installed:[/yellow] {', '.join(miss[:12])}"
                  + (" …" if len(miss) > 12 else ""))
        if auto or (not dry_run and typer.confirm("  install the missing tools now?")):
            for n, o in do_install(miss, dry_run=dry_run).items():
                _outcome(n, o)
        else:
            con.print("  [dim]later:[/dim] [cyan]ronin add --missing[/cyan]  "
                      "[dim]or[/dim] [cyan]ronin add <name> …[/cyan]")


def _print_currency(rep, summary_only: bool = False):
    if not summary_only:
        t = _table("tool", "cat", "installed", "latest", "src", "status", title="toolchain currency")
        for x in rep.tools:
            t.add_row(x.name, x.category,
                      x.installed_version or ("-" if x.installed else "not installed"),
                      x.latest_version or "-", x.source,
                      f"[{_ST_COL.get(x.status,'dim')}]{x.status}[/]")
        con.print(t)
    con.print(f"checked {rep.checked_at:%Y-%m-%d %H:%M}Z  ·  "
              f"[yellow]{len(rep.outdated)}[/yellow] outdated · "
              f"[yellow]{len(rep.missing)}[/yellow] missing · "
              f"pacman: {len(rep.pacman_updates)} · nuclei templates: "
              f"{rep.nuclei_templates_age_days if rep.nuclei_templates_age_days is not None else '?'}d old")


def _outcome(name: str, out: str):
    good = out in ("installed", "updated", "refreshed") or "already" in out or "cloned" in out
    con.print(f"  [{'green' if good else 'yellow'}]{name}: {out}[/]")


@app.command()
def sync(
    remote: str = typer.Option("", help="SubgridSec Deck base URL (persisted after first use)"),
    token: str = typer.Option("", help="Deck API token (keep it in .env as RONIN_DECK_TOKEN)"),
    remote_only: bool = typer.Option(False, help="skip the toolchain refresh"),
    pull_only: bool = typer.Option(False, help="only pull customers from the Deck"),
    push_only: bool = typer.Option(False, help="only push engagements/findings to the Deck"),
    full: bool = typer.Option(False, help="pull every customer, ignore the last-pull cursor"),
    with_reports: bool = typer.Option(
        False, "--with-reports", help="also upload rendered report files for the client portal"),
    offline: bool = typer.Option(False, help="skip network, just re-read local state"),
):
    """Refresh the toolchain, and (if a Deck is configured) sync clients + findings."""
    import shutil

    from ronin import updates as up

    if not remote_only and not offline:
        con.print("↻ checking toolchain currency…")
        rep = up.check(online=True)
        con.print(f"  {len(rep.outdated)} outdated · {len(rep.missing)} missing · "
                  f"pacman: {len(rep.pacman_updates)}")
        if shutil.which("nuclei"):
            con.print("↻ nuclei -update-templates…")
            import subprocess

            subprocess.run(["nuclei", "-update-templates", "-silent"])

    from ronin import sync_remote as sr

    if remote or token or os.environ.get("RONIN_DECK_URL") or db.get_state("sync.deck_url", ""):
        try:
            base, tok = sr.resolve(remote or None, token or None)
        except sr.DeckError as e:
            err.print(f"[yellow]deck sync skipped:[/yellow] {e}")
        else:
            con.print(f"↻ deck: {base}")
            try:
                if not push_only:
                    n = sr.pull_customers(base, tok, full=full)
                    con.print(f"  pulled [green]{n}[/green] customer(s)")
                if not pull_only:
                    r = sr.push_all(base, tok, with_reports=with_reports)
                    con.print(f"  pushed [green]{r.get('engagements_upserted',0)}[/green] engagements · "
                              f"{r.get('findings_synced',0)} findings · "
                              f"{r.get('reports_recorded',0)} reports · "
                              f"{r.get('invoices_synced',0)} invoices"
                              + (f" · [green]{r['reports_uploaded']}[/green] report file(s)"
                                 if with_reports else "")
                              + (f"  ([yellow]{len(r['conflicts'])} conflict(s)[/yellow])"
                                 if r.get('conflicts') else ""))
                    for c in r.get("conflicts", []):
                        con.print(f"    [dim]{c}[/dim]")
            except sr.DeckError as e:
                err.print(f"[red]deck sync failed:[/red] {e}")
                raise typer.Exit(1)

    con.print("[green]sync complete[/green]")


# ══════════════════════════════════════════════════════════════════ renderers
def _list_tools(cat: str = ""):
    from ronin.tools.registry import adapters

    t = _table("tool", "category", "installed", "active", "summary", title="adapters")
    for n, a in adapters().items():
        if cat and cat not in a.categories:
            continue
        t.add_row(n, ", ".join(a.categories),
                  "[green]yes[/green]" if a.is_installed() else "[yellow]no[/yellow]",
                  "[red]yes[/red]" if a.aggressive else "·", a.summary[:58])
    con.print(t)
    con.print("more tools: [cyan]ronin add --list[/cyan]")


def _list_clients():
    rows = db.list_clients()
    if not rows:
        con.print("no clients — `ronin new client --name \"Acme\" --cadence-days 180`")
        return
    t = _table("slug", "name", "contact", "engagements", "last tested", "next due",
               "remediated", "outstanding")
    for c in rows:
        p = db.client_progress(c.slug)
        due = "-"
        if p["next_due"]:
            due = p["next_due"].strftime("%Y-%m-%d")
            if p["overdue"]:
                due = f"[red]{due} !"
        b = p["billing"]
        out = (f"[yellow]{b['currency']} {b['outstanding']:,.0f}[/]"
               if b["outstanding"] else "-")
        t.add_row(c.slug, c.name, c.contact_name or "-", str(p["engagements"]),
                  p["last_tested"].strftime("%Y-%m-%d") if p["last_tested"] else "never", due,
                  f"{p['progress_pct']}%" if p["progress_pct"] is not None else "-", out)
    con.print(t)


def _list_engagements():
    rows = db.list_engagements()
    if not rows:
        con.print("no engagements — `ronin new engagement --client \"Acme\"`")
        return
    t = _table("slug", "client", "linked", "tester", "created", "runs", "findings")
    for e in rows:
        t.add_row(e.slug, e.client, e.client_slug or "-", e.tester,
                  e.created.strftime("%Y-%m-%d"),
                  str(len(db.list_runs(e.slug))), str(len(db.get_findings(e.slug))))
    con.print(t)


def _list_runs(eng: str):
    rows = db.list_runs(eng)
    if not rows:
        con.print(f"[dim]no runs for {eng}[/dim]")
        return
    t = _table("id", "started", "tool", "target", "status", "findings")
    for r in rows:
        t.add_row(r.id, r.started.strftime("%Y-%m-%d %H:%M"), r.tool, r.target[:40],
                  r.status.value, str(len(db.get_findings(eng, r.id))))
    con.print(t)


def _list_reports(slug_filter: str = ""):
    base = paths().reports
    t = _table("engagement", "generated", "levels", "path", title="reports")
    n = 0
    for slug_dir in sorted(base.glob("*")):
        if not slug_dir.is_dir() or (slug_filter and slug_filter not in slug_dir.name):
            continue
        for stamp in sorted(slug_dir.glob("*"), reverse=True):
            if stamp.is_dir():
                lv = ", ".join(sorted(p.stem for p in stamp.glob("*.md"))) or "-"
                t.add_row(slug_dir.name, stamp.name, lv, str(stamp))
                n += 1
    con.print(t if n else "[dim]no reports generated yet[/dim]")


def _list_findings(eng: str, severity: str, status: str):
    fs = db.get_findings(eng)
    if severity:
        fs = [f for f in fs if f.severity.value == severity.lower()]
    if status:
        fs = [f for f in fs if getattr(f, "status", "open") == status.lower()]
    fs.sort(key=lambda f: (f.severity.rank, f.cvss_score or 0), reverse=True)
    _print_findings(fs, full=True)


def _show_client(slug: str):
    p = db.client_progress(slug)
    if not p["client"]:
        err.print(f"[red]no client '{slug}'[/red]")
        raise typer.Exit(1)
    c = p["client"]
    con.print(f"[bold cyan]{c.name}[/bold cyan]  ({c.slug})")
    con.print(f"  contact   : {c.contact_name or '-'}  <{c.contact_email or 'no email'}>"
              + (f"  ·  {c.phone}" if c.phone else ""))
    if c.address:
        con.print(f"  address   : {c.address}")
    if c.socials:
        con.print("  online    : " + "  ".join(f"{k}={v}" for k, v in c.socials.items()))
    con.print(f"  rate      : {('$' + format(c.rate, 'g') + '/unit') if c.rate else '-'}"
              f"   ·   cadence: {str(c.cadence_days) + 'd' if c.cadence_days else 'none'}")
    con.print(f"  last test : {p['last_tested'].strftime('%Y-%m-%d') if p['last_tested'] else 'never'}"
              + (f"   next due: {p['next_due'].strftime('%Y-%m-%d')}" if p["next_due"] else "")
              + ("  [red]OVERDUE[/red]" if p["overdue"] else ""))
    con.print(f"  findings  : {p['findings_total']} total · {p['resolved']} resolved"
              + (f" ({p['progress_pct']}%)" if p["progress_pct"] is not None else ""))
    if p["open_by_severity"]:
        con.print("  open      : " + "  ".join(
            f"[{_SEV_COL.get(k,'')}]{k}:{v}[/]" for k, v in p["open_by_severity"].items()))
    b = p["billing"]
    if b["count"]:
        con.print(f"  billing   : {b['currency']} {b['billed']:,.2f} billed · "
                  f"{b['paid']:,.2f} paid · [yellow]{b['outstanding']:,.2f} outstanding[/] "
                  f"({b['count']} invoice(s), {b['drafts']} draft)")
    engs = db.list_engagements(slug)
    if engs:
        con.print("  engagements: " + ", ".join(e.slug for e in engs))
    invs = db.list_invoices(slug)
    if invs:
        con.print("\n  [dim]invoices:[/dim]")
        for i in invs:
            con.print(f"    {i.number or i.id[:8]:<16} {i.currency} {i.amount:>10,.2f}  "
                      f"{i.status:<7} issued {i.issued}"
                      + (f"  due {i.due}" if i.due else "")
                      + (f"  — {i.description}" if i.description else ""))


def _show_engagement(slug: str):
    e = db.get_engagement(slug)
    if not e:
        err.print(f"[red]no engagement '{slug}'[/red]")
        raise typer.Exit(1)
    con.print(f"[bold cyan]{e.slug}[/bold cyan]  ·  client {e.client}"
              + (f"  ·  linked → {e.client_slug}" if e.client_slug else ""))
    con.print(f"  tester {e.tester}  ·  created {e.created:%Y-%m-%d}  ·  "
              f"scope: {paths().scope_file(slug)}")
    _list_runs(slug)
    _print_findings(sorted(db.get_findings(slug),
                           key=lambda f: (f.severity.rank, f.cvss_score or 0), reverse=True))


def _show_finding(fid: str):
    for e in db.list_engagements():
        for f in db.get_findings(e.slug):
            if f.id == fid:
                con.print(f"[bold]{f.title}[/bold]")
                for k in ("engagement", "target", "severity", "status", "confidence", "tool"):
                    con.print(f"  {k:11}: {getattr(f, k) if k != 'engagement' else e.slug}")
                if f.cvss_score:
                    con.print(f"  cvss       : {f.cvss_score} {f.cvss_vector or ''}")
                if f.cve:
                    con.print(f"  cve        : {', '.join(f.cve)}")
                for label, val in (("description", f.description), ("evidence", f.evidence),
                                   ("poc", f.poc), ("attack path", f.attack_path),
                                   ("remediation", f.remediation)):
                    if val:
                        con.print(f"\n[u]{label}[/u]\n{val}")
                return
    err.print(f"[red]no finding '{fid}'[/red]")
    raise typer.Exit(1)


def _show_run(rid: str):
    r = db.get_run(rid)
    if not r:
        err.print(f"[red]no run '{rid}'[/red]")
        raise typer.Exit(1)
    con.print(f"[bold]{r.tool}[/bold] → {r.target}   ({r.engagement})")
    con.print(f"  status {r.status.value}  ·  exit {r.exit_code}  ·  "
              f"{r.started:%Y-%m-%d %H:%M} for {r.duration_s or 0:.0f}s")
    con.print(f"  argv: {' '.join(r.argv)}")
    con.print(f"  evidence: {r.evidence_dir}")
    _print_findings(db.get_findings(r.engagement, r.id))


# ── shared helpers ───────────────────────────────────────────────────────
def _coerce(v: str):
    low = v.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    return int(v) if v.isdigit() else v


def _line(stream: str, line: str) -> str:
    tag = {"out": "[dim]│[/dim]", "err": "[yellow]│[/yellow]", "sys": "[cyan]▸[/cyan]"}.get(stream, "│")
    return f"{tag} {line}"


def _print_findings(fs, full: bool = False):
    if not fs:
        con.print("[dim]no findings[/dim]")
        return
    t = _table("severity", "cvss", "status", "title", "target", "src")
    for f in fs:
        t.add_row(f"[{_SEV_COL.get(f.severity.value,'')}]{f.severity.value.upper()}[/]",
                  f"{f.cvss_score:.1f}" if f.cvss_score else "-",
                  getattr(f, "status", "open"),
                  f.title if full else f.title[:64],
                  f.target if full else f.target[:38], f.tool)
    con.print(t)


def _do_report(engagement: str, *, run_id=None, level="all", fmt="md,html,pdf"):
    from ronin.reports.render import LEVELS, render

    levels = tuple(LEVELS) if level == "all" else (level,)
    formats = tuple(x.strip() for x in fmt.split(",") if x.strip())
    made = render(engagement, run_id=run_id, levels=levels, formats=formats)
    con.print("\n[bold green]reports written[/bold green]")
    for lvl, files in made.items():
        for f, p in files.items():
            con.print(f"  {lvl:12} {f:5} {p}")


def main():
    app()


if __name__ == "__main__":
    sys.exit(main())
