"""RoninSuite command line.  ``ronin`` with no subcommand launches the TUI."""
from __future__ import annotations

import datetime as _dt
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from ronin.config import load_dotenv, paths
from ronin.core import db
from ronin.core.models import Client, Engagement
from ronin.core.scope import SCOPE_TEMPLATE, Scope, ScopeViolation

app = typer.Typer(
    add_completion=False, no_args_is_help=False,
    help="RoninSuite - portable offensive toolkit for Linux with tiered CVSS reporting.",
)
engagement_app = typer.Typer(help="Create and inspect engagements.")
client_app = typer.Typer(help="Manage recurring clients and retest cadence.")
app.add_typer(engagement_app, name="engagement")
app.add_typer(client_app, name="client")
con = Console()


def _slugify(s: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context):
    load_dotenv()
    if ctx.invoked_subcommand is None:
        from ronin.tui.app import run as run_tui

        run_tui()
        raise typer.Exit()


# --------------------------------------------------------------------------- doctor
@app.command()
def doctor(
    install: bool = typer.Option(False, "--install", help="attempt installation"),
    only: str = typer.Option("", help="comma list of tools to act on"),
    dry_run: bool = typer.Option(False, help="print install commands without running"),
):
    """Show which offensive tools are present; optionally install the rest (Arch)."""
    from ronin.doctor import install as do_install
    from ronin.doctor import survey

    rows = survey()
    t = Table(title="RoninSuite toolchain", header_style="bold")
    for c in ("tool", "category", "adapter", "aggressive", "status"):
        t.add_column(c)
    for s in rows:
        t.add_row(
            s.name, s.category,
            "yes" if s.has_adapter else "-",
            "[red]yes[/red]" if s.aggressive else "-",
            f"[green]{s.path}[/green]" if s.installed else "[yellow]missing[/yellow]",
        )
    con.print(t)
    present = sum(s.installed for s in rows)
    con.print(f"{present}/{len(rows)} installed  ·  adapters wired: "
              f"{sum(s.has_adapter for s in rows)}")

    if install:
        wanted = [x.strip() for x in only.split(",") if x.strip()] or \
                 [s.name for s in rows if not s.installed]
        con.print(f"\n[bold]Installing:[/bold] {', '.join(wanted)}")
        for name, outcome in do_install(wanted, dry_run=dry_run).items():
            col = "green" if outcome in ("installed",) or "already" in outcome else "yellow"
            con.print(f"  [{col}]{name}: {outcome}[/{col}]")


# ----------------------------------------------------------------------- engagement
@engagement_app.command("new")
def engagement_new(
    client: str = typer.Option(..., help="client / organisation name"),
    tester: str = typer.Option("", help="your name (defaults to $USER)"),
    slug: str = typer.Option("", help="short id; default derived from client + date"),
    days: int = typer.Option(14, help="length of the testing window from today"),
    client_slug: str = typer.Option("", "--client-slug",
                                    help="link to an existing `ronin client` record"),
):
    """Create an engagement and scaffold its scope.yaml."""
    import getpass

    tester = tester or getpass.getuser()
    if client_slug and not db.get_client(client_slug):
        con.print(f"[yellow]no client '{client_slug}' - create it with `ronin client new`[/yellow]")
    if not slug:
        slug = f"{_slugify(client)}-{_dt.date.today():%Y%m%d}"
    start = _dt.date.today()
    end = start + _dt.timedelta(days=days)

    e = Engagement(slug=slug, client=client, tester=tester, client_slug=client_slug)
    db.upsert_engagement(e)
    sf = paths().scope_file(slug)
    if not sf.exists():
        sf.write_text(SCOPE_TEMPLATE.format(
            client=client, slug=slug, tester=tester, start=start, end=end))
    con.print(f"[green]created[/green] engagement [bold]{slug}[/bold]")
    con.print(f"  scope file: {sf}")
    con.print(f"  edit in_scope / out_of_scope, then:  ronin run nmap --engagement {slug} --target <host>")


@engagement_app.command("list")
def engagement_list():
    """List engagements."""
    rows = db.list_engagements()
    if not rows:
        con.print("no engagements yet — `ronin engagement new --client \"Acme\"`")
        return
    t = Table(header_style="bold")
    for c in ("slug", "client", "tester", "created", "runs", "findings"):
        t.add_column(c)
    for e in rows:
        runs = db.list_runs(e.slug)
        finds = db.get_findings(e.slug)
        t.add_row(e.slug, e.client, e.tester, e.created.strftime("%Y-%m-%d"),
                  str(len(runs)), str(len(finds)))
    con.print(t)


@client_app.command("new")
def client_new(
    name: str = typer.Option(..., help="client / organisation name"),
    slug: str = typer.Option("", help="short id (default: slugified name)"),
    contact: str = typer.Option("", help="primary contact name"),
    email: str = typer.Option("", help="primary contact email"),
    cadence_days: int = typer.Option(0, help="retest reminder interval; 0 = none"),
):
    """Add a recurring client with an optional retest cadence."""
    slug = slug or _slugify(name)
    db.upsert_client(Client(slug=slug, name=name, contact_name=contact,
                            contact_email=email, cadence_days=cadence_days))
    con.print(f"[green]client[/green] [bold]{slug}[/bold] saved"
              + (f"  (retest every {cadence_days}d)" if cadence_days else ""))


@client_app.command("list")
def client_list():
    """List clients with engagement counts and retest status."""
    rows = db.list_clients()
    if not rows:
        con.print("no clients yet - `ronin client new --name \"Acme\" --cadence-days 180`")
        return
    t = Table(header_style="bold")
    for c in ("slug", "name", "contact", "engagements", "last tested", "next due", "remediation"):
        t.add_column(c)
    for cl in rows:
        p = db.client_progress(cl.slug)
        due = p["next_due"].strftime("%Y-%m-%d") if p["next_due"] else "-"
        if p["overdue"]:
            due = f"[red]{due} !"
        prog = f"{p['progress_pct']}%" if p["progress_pct"] is not None else "-"
        t.add_row(cl.slug, cl.name, cl.contact_name or "-", str(p["engagements"]),
                  p["last_tested"].strftime("%Y-%m-%d") if p["last_tested"] else "-",
                  due, prog)
    con.print(t)


@client_app.command("link")
def client_link(engagement: str, client_slug: str):
    """Attach an existing ENGAGEMENT to a CLIENT record."""
    if not db.get_client(client_slug):
        con.print(f"[red]no client '{client_slug}'[/red]")
        raise typer.Exit(1)
    db.set_engagement_client(engagement, client_slug)
    con.print(f"[green]linked[/green] {engagement} -> {client_slug}")


@app.command()
def updates(check: bool = typer.Option(False, "--check", help="run an online check now"),
            offline: bool = typer.Option(False, help="skip network lookups")):
    """Show toolchain currency (installed vs latest, pacman updates, template age)."""
    from ronin import updates as up

    rep = up.check(online=not offline) if check else (up.cached() or up.check(online=not offline))
    t = Table(title="Toolchain currency", header_style="bold")
    for c in ("tool", "cat", "installed", "latest", "src", "status"):
        t.add_column(c)
    for x in rep.tools:
        col = {"current": "green", "outdated": "yellow", "missing": "red"}.get(x.status, "dim")
        t.add_row(x.name, x.category, x.installed_version or ("-" if x.installed else "not installed"),
                  x.latest_version or "-", x.source, f"[{col}]{x.status}[/{col}]")
    con.print(t)
    con.print(f"checked: {rep.checked_at:%Y-%m-%d %H:%M UTC}  ·  "
              f"pacman updates: {len(rep.pacman_updates)}  ·  "
              f"nuclei templates age: "
              f"{rep.nuclei_templates_age_days if rep.nuclei_templates_age_days is not None else '?'}d")
    if rep.outdated:
        con.print(f"[yellow]{len(rep.outdated)} outdated:[/yellow] "
                  + ", ".join(x.name for x in rep.outdated)
                  + "   -> ronin doctor --install --only <name>  (or update via the TUI)")


@app.command("scope")
def scope_check(engagement: str, target: str):
    """Check whether TARGET is in scope for ENGAGEMENT."""
    sf = paths().scope_file(engagement)
    if not sf.is_file():
        con.print(f"[red]no scope file[/red] at {sf}")
        raise typer.Exit(1)
    d = Scope.load(sf).check(target)
    colour = "green" if d.allowed else "red"
    con.print(f"[{colour}]{'IN SCOPE' if d.allowed else 'OUT OF SCOPE'}[/{colour}] — {d.reason}")
    if d.allowed and not d.within_window:
        con.print("[yellow]note: outside the testing window[/yellow]")
    raise typer.Exit(0 if d.allowed else 2)


# --------------------------------------------------------------------------- run
@app.command()
def run(
    tool: str = typer.Argument(..., help="adapter name (see `ronin doctor`)"),
    engagement: str = typer.Option(..., "--engagement", "-e"),
    target: str = typer.Option(..., "--target", "-t"),
    opt: list[str] = typer.Option([], "--opt", "-o", help="tool option k=v (repeatable)"),
    intensity: str = typer.Option("normal", help="stealth | normal | aggressive"),
    force: bool = typer.Option(False, help="run even if out of scope"),
    reason: str = typer.Option("", help="written justification required with --force"),
    yes: bool = typer.Option(False, "--yes", "-y", help="skip the confirmation prompt"),
    no_report: bool = typer.Option(False, help="don't auto-generate reports afterwards"),
):
    """Run one TOOL against one TARGET, parse findings, and write reports."""
    from ronin.core.runner import run_tool
    from ronin.tools.registry import get

    try:
        adapter = get(tool)
    except KeyError as e:
        con.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    options = {}
    for kv in opt:
        if "=" not in kv:
            con.print(f"[red]bad --opt {kv!r}, expected k=v[/red]")
            raise typer.Exit(1)
        k, v = kv.split("=", 1)
        options[k] = _coerce(v)

    scope = None
    sf = paths().scope_file(engagement)
    if sf.is_file():
        scope = Scope.load(sf)
    else:
        con.print(f"[yellow]no scope file for {engagement}; scope checks skipped[/yellow]")

    if adapter.aggressive and not yes:
        typer.confirm(f"'{tool}' is an active/aggressive tool. Proceed against {target}?",
                      abort=True)
    if force and not reason:
        con.print("[red]--force requires --reason[/red]")
        raise typer.Exit(1)

    con.print(f"[bold]running {tool}[/bold] → {target}  (engagement {engagement})")
    try:
        r = run_tool(adapter, engagement, target, options=options, intensity=intensity,
                     scope=scope, force=force, force_reason=reason,
                     on_line=lambda s, l: con.print(_line(s, l)))
    except ScopeViolation as v:
        con.print(f"[red]BLOCKED[/red] — {v.decision.reason}. "
                  f"Use --force --reason '...' to override (logged).")
        raise typer.Exit(2)
    except FileNotFoundError as e:
        con.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    finds = db.get_findings(engagement, r.id)
    con.print(f"\n[bold]{len(finds)} findings[/bold]  status={r.status.value}  "
              f"evidence={r.evidence_dir}")
    _print_findings(finds)

    if not no_report:
        _do_report(engagement, run_id=r.id)


# --------------------------------------------------------------------------- report
@app.command()
def report(
    engagement: str,
    run_id: Optional[str] = typer.Option(None, "--run", help="scope report to one run"),
    level: str = typer.Option("all", help="executive | technical | remediation | all"),
    fmt: str = typer.Option("md,html,pdf", "--format", help="comma list"),
):
    """(Re)generate the tiered reports for ENGAGEMENT from stored findings."""
    _do_report(engagement, run_id=run_id, level=level, fmt=fmt)


@app.command()
def findings(engagement: str, severity: str = typer.Option("", help="filter, e.g. high")):
    """List stored findings for ENGAGEMENT."""
    fs = db.get_findings(engagement)
    if severity:
        fs = [f for f in fs if f.severity.value == severity.lower()]
    fs.sort(key=lambda f: (f.severity.rank, f.cvss_score or 0), reverse=True)
    _print_findings(fs, full=True)


@app.command()
def tui():
    """Launch the RoninSuite TUI."""
    from ronin.tui.app import run as run_tui

    run_tui()


# --------------------------------------------------------------------------- helpers
def _coerce(v: str):
    low = v.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if v.isdigit():
        return int(v)
    return v


def _line(stream: str, line: str) -> str:
    tag = {"out": "[dim]│[/dim]", "err": "[yellow]│[/yellow]", "sys": "[cyan]▸[/cyan]"}.get(stream, "│")
    return f"{tag} {line}"


_SEV_COL = {"critical": "bold red", "high": "red", "medium": "yellow",
            "low": "cyan", "info": "dim"}


def _print_findings(fs, full: bool = False):
    if not fs:
        con.print("[dim]no findings[/dim]")
        return
    t = Table(header_style="bold", show_lines=full)
    for c in ("severity", "cvss", "title", "target", "src"):
        t.add_column(c)
    for f in fs:
        t.add_row(
            f"[{_SEV_COL.get(f.severity.value,'')}]{f.severity.value.upper()}[/]",
            f"{f.cvss_score:.1f}" if f.cvss_score else "-",
            f.title if full else (f.title[:70]),
            f.target if full else (f.target[:40]),
            f.tool,
        )
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
