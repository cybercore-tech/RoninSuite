"""RoninSuite TUI (Textual).

Flow:  Engagements  ->  Tool catalog  ->  Configure + scope-check  ->  Run (live)
       ->  Findings  ->  Reports.
"""
from __future__ import annotations

import datetime as _dt
import webbrowser
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button, Checkbox, DataTable, Footer, Header, Input, Label, RichLog, Rule,
    Select, Static,
)

from ronin.config import load_dotenv, paths
from ronin.core import db
from ronin.core.models import Engagement
from ronin.core.runner import run_tool
from ronin.core.scope import SCOPE_TEMPLATE, Scope, ScopeViolation
from ronin.reports.render import LEVELS, render
from ronin.tools.registry import adapters, get

_SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow",
              "low": "cyan", "info": "dim"}


class NewEngagementModal(ModalScreen[Engagement | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def action_cancel(self) -> None:
        self.dismiss(None)

    def compose(self) -> ComposeResult:
        with Vertical(id="modal"):
            yield Label("New engagement", id="modal-title")
            yield Input(placeholder="Client / organisation name", id="client")
            yield Input(placeholder="Tester (your name)", id="tester")
            yield Input(placeholder="Slug (optional)", id="slug")
            with Horizontal(id="modal-buttons"):
                yield Button("Create", variant="primary", id="create")
                yield Button("Cancel", id="cancel")

    @on(Button.Pressed, "#cancel")
    def _cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#create")
    def _create(self) -> None:
        import getpass
        import re

        client = self.query_one("#client", Input).value.strip()
        if not client:
            self.query_one("#client", Input).focus()
            return
        tester = self.query_one("#tester", Input).value.strip() or getpass.getuser()
        slug = self.query_one("#slug", Input).value.strip()
        if not slug:
            base = re.sub(r"[^a-z0-9]+", "-", client.lower()).strip("-")
            slug = f"{base}-{_dt.date.today():%Y%m%d}"
        e = Engagement(slug=slug, client=client, tester=tester)
        db.upsert_engagement(e)
        sf = paths().scope_file(slug)
        if not sf.exists():
            end = _dt.date.today() + _dt.timedelta(days=14)
            sf.write_text(SCOPE_TEMPLATE.format(
                client=client, slug=slug, tester=tester,
                start=_dt.date.today(), end=end))
        self.dismiss(e)


class EngagementScreen(Screen):
    BINDINGS = [("n", "new", "New engagement"), ("r", "refresh", "Refresh"),
               ("enter", "select", "Open")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Select an engagement, or press [b]n[/b] to create one.", id="hint")
        yield DataTable(id="eng-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        t = self.query_one(DataTable)
        t.add_columns("slug", "client", "tester", "created", "runs", "findings")
        self.action_refresh()

    def action_refresh(self) -> None:
        t = self.query_one(DataTable)
        t.clear()
        for e in db.list_engagements():
            t.add_row(e.slug, e.client, e.tester, e.created.strftime("%Y-%m-%d"),
                      str(len(db.list_runs(e.slug))), str(len(db.get_findings(e.slug))),
                      key=e.slug)

    @work
    async def action_new(self) -> None:
        e = await self.app.push_screen_wait(NewEngagementModal())
        if e:
            self.action_refresh()
            self.notify(f"created {e.slug}  -  edit its scope.yaml before scanning")

    def action_select(self) -> None:
        t = self.query_one(DataTable)
        if t.row_count == 0:
            return
        slug = t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
        self.app.engagement = slug  # type: ignore[attr-defined]
        self.app.push_screen(CatalogScreen())

    @on(DataTable.RowSelected)
    def _row(self, ev: DataTable.RowSelected) -> None:
        self.app.engagement = ev.row_key.value  # type: ignore[attr-defined]
        self.app.push_screen(CatalogScreen())


class CatalogScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("enter", "run", "Configure")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="cat-eng")
        yield DataTable(id="cat-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#cat-eng", Static).update(
            f"Engagement: [b]{self.app.engagement}[/b]")  # type: ignore[attr-defined]
        t = self.query_one(DataTable)
        t.add_columns("tool", "category", "installed", "aggressive", "summary")
        for name, ad in adapters().items():
            t.add_row(
                name, ", ".join(ad.categories),
                "[green]yes[/green]" if ad.is_installed() else "[yellow]no[/yellow]",
                "[red]yes[/red]" if ad.aggressive else "-",
                ad.summary, key=name)

    def action_run(self) -> None:
        t = self.query_one(DataTable)
        name = t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
        self.app.push_screen(RunConfigScreen(name))

    @on(DataTable.RowSelected)
    def _row(self, ev: DataTable.RowSelected) -> None:
        self.app.push_screen(RunConfigScreen(ev.row_key.value))


class RunConfigScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, tool: str) -> None:
        super().__init__()
        self.tool = tool
        self.adapter = get(tool)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with VerticalScroll(id="cfg"):
            yield Label(f"[b]{self.tool}[/b] — {self.adapter.summary}")
            yield Input(placeholder="target  (host / CIDR / URL)", id="target")
            yield Static("", id="scope-status")
            yield Rule()
            yield Label("Options")
            for o in self.adapter.options():
                if o.kind == "bool":
                    yield Checkbox(o.label + (" [aggressive]" if o.aggressive else ""),
                                   value=bool(o.default), id=f"opt-{o.key}")
                elif o.kind == "choice":
                    yield Label(o.label)
                    choices = [(c, c) for c in o.choices if c not in ("", None)]
                    if o.default:
                        yield Select(choices, value=o.default, id=f"opt-{o.key}",
                                     allow_blank=True)
                    else:
                        yield Select(choices, id=f"opt-{o.key}", allow_blank=True,
                                     prompt="(none)")
                else:
                    yield Label(o.label + (f"  — {o.help}" if o.help else ""))
                    yield Input(value="" if o.default in (None, 0) else str(o.default),
                                id=f"opt-{o.key}")
            yield Rule()
            yield Select([(i, i) for i in ("stealth", "normal", "aggressive")],
                         value="normal", id="intensity", allow_blank=False)
            yield Checkbox("Force (run even if out of scope — logged)", id="force")
            yield Input(placeholder="force justification (required if forcing)", id="reason")
            with Horizontal(id="cfg-buttons"):
                yield Button("Run", variant="primary", id="go")
                yield Button("Cancel", id="cancel")
        yield Footer()

    def on_mount(self) -> None:
        self._scope = None
        sf = paths().scope_file(self.app.engagement)  # type: ignore[attr-defined]
        if sf.is_file():
            try:
                self._scope = Scope.load(sf)
            except Exception as e:
                self.notify(f"scope file error: {e}", severity="error")
        self.query_one("#target", Input).focus()

    @on(Input.Changed, "#target")
    def _scope_check(self, ev: Input.Changed) -> None:
        s = self.query_one("#scope-status", Static)
        tgt = ev.value.strip()
        if not tgt:
            s.update("")
            return
        if not self._scope:
            s.update("[yellow]no scope file — checks disabled[/yellow]")
            return
        d = self._scope.check(tgt)
        if d.allowed:
            extra = "" if d.within_window else "  [yellow](outside window)[/yellow]"
            s.update(f"[green]IN SCOPE[/green] — {d.reason}{extra}")
        else:
            s.update(f"[red]OUT OF SCOPE[/red] — {d.reason}")

    @on(Button.Pressed, "#cancel")
    def _cancel(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#go")
    def _go(self) -> None:
        target = self.query_one("#target", Input).value.strip()
        if not target:
            self.notify("target is required", severity="error")
            return
        opts: dict = {}
        for o in self.adapter.options():
            w = self.query_one(f"#opt-{o.key}")
            if isinstance(w, Checkbox):
                opts[o.key] = w.value
            elif isinstance(w, Select):
                opts[o.key] = "" if w.is_blank() else w.value
            else:
                v = w.value.strip()
                opts[o.key] = int(v) if v.isdigit() else v
        force = self.query_one("#force", Checkbox).value
        reason = self.query_one("#reason", Input).value.strip()
        if force and not reason:
            self.notify("force needs a written justification", severity="error")
            return
        intensity = self.query_one("#intensity", Select).value
        self.app.push_screen(RunScreen(self.tool, target, opts, intensity, force, reason,
                                       self._scope))


class RunScreen(Screen):
    BINDINGS = [("escape", "back", "Back"), ("f", "findings", "Findings"),
               ("r", "reports", "Reports")]

    def __init__(self, tool, target, opts, intensity, force, reason, scope) -> None:
        super().__init__()
        self.args = (tool, target, opts, intensity, force, reason, scope)
        self.run_id: str | None = None
        self.done = False

    def compose(self) -> ComposeResult:
        tool, target, *_ = self.args
        yield Header(show_clock=True)
        yield Static(f"[b]{tool}[/b] → [b]{target}[/b]", id="run-title")
        yield RichLog(id="log", wrap=True, markup=False, highlight=True)
        yield Static("running…", id="run-status")
        with Horizontal(id="run-buttons"):
            yield Button("Findings", id="to-findings", disabled=True)
            yield Button("Generate reports", id="to-reports", disabled=True, variant="primary")
            yield Button("Back to catalog", id="to-back")
        yield Footer()

    def on_mount(self) -> None:
        self._execute()

    @work(thread=True)
    def _execute(self) -> None:
        tool, target, opts, intensity, force, reason, scope = self.args
        log = self.query_one(RichLog)
        app = self.app

        def line(stream: str, text: str) -> None:
            prefix = {"sys": "▸ ", "err": "! "}.get(stream, "  ")
            app.call_from_thread(log.write, prefix + text)

        try:
            run = run_tool(get(tool), app.engagement, target, options=opts,
                           intensity=intensity, scope=scope, force=force,
                           force_reason=reason, on_line=line)
            self.run_id = run.id
            n = len(db.get_findings(app.engagement, run.id))
            app.call_from_thread(self._finished, f"done — status {run.status.value}, "
                                                 f"{n} findings", True)
        except ScopeViolation as v:
            app.call_from_thread(self._finished, f"BLOCKED — {v.decision.reason}", False)
        except Exception as e:  # noqa: BLE001
            app.call_from_thread(self._finished, f"error — {e}", False)

    def _finished(self, msg: str, ok: bool) -> None:
        self.done = True
        self.query_one("#run-status", Static).update(("[green]" if ok else "[red]") + msg)
        for bid in ("#to-findings", "#to-reports"):
            self.query_one(bid, Button).disabled = not ok

    @on(Button.Pressed, "#to-back")
    def action_back(self) -> None:
        self.app.pop_screen()
        self.app.pop_screen()

    @on(Button.Pressed, "#to-findings")
    def action_findings(self) -> None:
        if self.done:
            self.app.push_screen(FindingsScreen(self.run_id))

    @on(Button.Pressed, "#to-reports")
    def action_reports(self) -> None:
        if self.done:
            self.app.push_screen(ReportScreen(self.run_id))


class FindingsScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("enter", "detail", "Detail")]

    def __init__(self, run_id: str | None = None) -> None:
        super().__init__()
        self.run_id = run_id

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="find-head")
        yield DataTable(id="find-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self._data = sorted(
            db.get_findings(self.app.engagement, self.run_id),  # type: ignore[attr-defined]
            key=lambda f: (f.severity.rank, f.cvss_score or 0), reverse=True)
        self.query_one("#find-head", Static).update(
            f"{len(self._data)} findings — engagement [b]{self.app.engagement}[/b]"  # type: ignore[attr-defined]
            + (f"  (run {self.run_id})" if self.run_id else ""))
        t = self.query_one(DataTable)
        t.add_columns("severity", "cvss", "title", "target", "tool")
        for i, f in enumerate(self._data):
            style = _SEV_STYLE.get(f.severity.value, "")
            t.add_row(f"[{style}]{f.severity.value.upper()}[/]",
                      f"{f.cvss_score:.1f}" if f.cvss_score else "-",
                      f.title[:64], f.target[:38], f.tool, key=str(i))

    def action_detail(self) -> None:
        t = self.query_one(DataTable)
        if t.row_count:
            i = int(t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value)
            self.app.push_screen(FindingDetail(self._data[i]))


class FindingDetail(ModalScreen):
    BINDINGS = [("escape", "close", "Close")]

    def __init__(self, finding) -> None:
        super().__init__()
        self.f = finding

    def action_close(self) -> None:
        self.dismiss()

    def compose(self) -> ComposeResult:
        f = self.f
        body = [
            f"[b]{f.title}[/b]", "",
            f"severity: {f.severity.value.upper()}"
            + (f"   CVSS {f.cvss_score:.1f}  {f.cvss_vector or ''}" if f.cvss_score else ""),
            f"target:   {f.target}",
            f"source:   {f.tool} / {f.confidence}",
        ]
        if f.cve:
            body.append(f"CVE:      {', '.join(f.cve)}")
        if f.cwe:
            body.append(f"CWE:      {', '.join(f.cwe)}")
        body += ["", "[u]Description[/u]", f.description or "-"]
        if f.evidence:
            body += ["", "[u]Evidence[/u]", f.evidence[:1500]]
        if f.poc:
            body += ["", "[u]PoC[/u]", f.poc]
        if f.attack_path:
            body += ["", "[u]Attack path[/u]", f.attack_path]
        body += ["", "[u]Remediation[/u]", f.remediation or "-"]
        with VerticalScroll(id="modal-wide"):
            yield Static("\n".join(body))
            yield Button("Close", id="close")

    @on(Button.Pressed, "#close")
    def _c(self) -> None:
        self.dismiss()


class ReportScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("o", "open", "Open in browser")]

    def __init__(self, run_id: str | None = None) -> None:
        super().__init__()
        self.run_id = run_id
        self.index: Path | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(f"Reports for [b]{self.app.engagement}[/b]"  # type: ignore[attr-defined]
                     + (f" — run {self.run_id}" if self.run_id else " — all findings"))
        with Vertical(id="rep-opts"):
            yield Label("Levels")
            for lvl in LEVELS:
                yield Checkbox(lvl.title(), value=True, id=f"lvl-{lvl}")
            yield Label("Formats")
            for fmt in ("md", "html", "pdf"):
                yield Checkbox(fmt.upper(), value=True, id=f"fmt-{fmt}")
            yield Button("Generate", variant="primary", id="gen")
        yield RichLog(id="rep-log", markup=True, wrap=True)
        yield Footer()

    @on(Button.Pressed, "#gen")
    def _gen(self) -> None:
        self._generate()

    @work(thread=True)
    def _generate(self) -> None:
        levels = tuple(l for l in LEVELS if self.query_one(f"#lvl-{l}", Checkbox).value)
        formats = tuple(f for f in ("md", "html", "pdf")
                        if self.query_one(f"#fmt-{f}", Checkbox).value)
        log = self.query_one(RichLog)
        app = self.app
        try:
            made = render(app.engagement, run_id=self.run_id, levels=levels, formats=formats)
        except Exception as e:  # noqa: BLE001
            app.call_from_thread(log.write, f"[red]failed: {e}[/red]")
            return
        for lvl, files in made.items():
            for fmt, p in files.items():
                app.call_from_thread(log.write, f"[green]{lvl:12}[/green] {fmt:5} {p}")
                if fmt == "html":
                    self.index = p.parent / "index.html"
        if self.index:
            app.call_from_thread(log.write, f"\n[b]press 'o' to open[/b] {self.index}")

    def action_open(self) -> None:
        if self.index and self.index.exists():
            webbrowser.open(self.index.as_uri())
            self.notify("opened in browser")


class RoninApp(App):
    CSS_PATH = "app.tcss"
    TITLE = "RoninSuite"
    SUB_TITLE = "tactical & offensive · Linux"
    BINDINGS = [("q", "quit", "Quit")]

    engagement: str | None = None

    def on_mount(self) -> None:
        load_dotenv()
        self.push_screen(EngagementScreen())


def run() -> None:
    RoninApp().run()
