"""RoninSuite TUI - cybercore theme, tabbed console.

Tabs:  Dashboard · Tools · Reports · Clients · Updates · Toolbox
Sub-flows (configure/run/findings/report) are pushed screens over the tabs.
"""
from __future__ import annotations

import datetime as _dt
import re
import webbrowser
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button, Checkbox, DataTable, Footer, Header, Input, Label,
    RichLog, Rule, Select, Static, TabbedContent, TabPane,
)

from ronin.config import load_dotenv, paths
from ronin.core import db
from ronin.core.models import Client, Engagement, FindingStatus
from ronin.core.runner import run_tool
from ronin.core.scope import SCOPE_TEMPLATE, Scope, ScopeViolation
from ronin.reports.render import LEVELS, render
from ronin.tools.registry import adapters, get
from ronin.tui.theme import BANNER, CYBERCORE, SEV_STYLE, STATUS_STYLE


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def _ago(dt: _dt.datetime | None) -> str:
    if not dt:
        return "never"
    days = (_dt.datetime.now(_dt.timezone.utc) - dt.replace(tzinfo=_dt.timezone.utc)
            if dt.tzinfo is None else _dt.datetime.now(_dt.timezone.utc) - dt).days
    return "today" if days == 0 else f"{days}d ago"


# ═══════════════════════════════════════════════════════════════════ modals
class TextPrompt(ModalScreen[dict | None]):
    """Generic multi-field prompt.  fields = [(key, label, default)]."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, title: str, fields: list[tuple[str, str, str]]) -> None:
        super().__init__()
        self._title = title
        self._fields = fields

    def compose(self) -> ComposeResult:
        with Vertical(id="modal"):
            yield Label(self._title, id="modal-title")
            for key, label, default in self._fields:
                yield Label(label)
                yield Input(value=default, id=f"f-{key}")
            with Horizontal(id="modal-buttons"):
                yield Button("OK", variant="primary", id="ok")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query(Input).first().focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#cancel")
    def _c(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#ok")
    @on(Input.Submitted)
    def _ok(self) -> None:
        self.dismiss({k: self.query_one(f"#f-{k}", Input).value.strip()
                      for k, _, _ in self._fields})


class EngagementPicker(ModalScreen[str | None]):
    BINDINGS = [("escape", "cancel", "Close"), ("n", "new", "New engagement")]

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-wide"):
            yield Label("◈ SELECT ENGAGEMENT", id="modal-title")
            yield DataTable(id="ep-table", cursor_type="row")
            with Horizontal(id="modal-buttons"):
                yield Button("Open", variant="primary", id="open")
                yield Button("New…", id="new")
                yield Button("Close", id="cancel")

    def on_mount(self) -> None:
        t = self.query_one(DataTable)
        t.add_columns("slug", "client", "linked", "runs", "findings", "created")
        self._reload()

    def _reload(self) -> None:
        t = self.query_one(DataTable)
        t.clear()
        for e in db.list_engagements():
            t.add_row(e.slug, e.client, e.client_slug or "-",
                      str(len(db.list_runs(e.slug))), str(len(db.get_findings(e.slug))),
                      e.created.strftime("%Y-%m-%d"), key=e.slug)

    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#cancel")
    def _c(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#open")
    @on(DataTable.RowSelected)
    def _open(self, ev=None) -> None:
        t = self.query_one(DataTable)
        if t.row_count:
            key = t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
            self.dismiss(key)

    @work
    async def action_new(self) -> None:
        res = await self.app.push_screen_wait(TextPrompt(
            "◈ NEW ENGAGEMENT",
            [("client", "Client / organisation", ""),
             ("tester", "Tester", ""),
             ("slug", "Slug (optional)", ""),
             ("client_slug", "Link to client slug (optional)", "")]))
        if not res or not res["client"]:
            return
        import getpass

        slug = res["slug"] or f"{_slug(res['client'])}-{_dt.date.today():%Y%m%d}"
        e = Engagement(slug=slug, client=res["client"],
                       tester=res["tester"] or getpass.getuser(),
                       client_slug=res["client_slug"])
        db.upsert_engagement(e)
        sf = paths().scope_file(slug)
        if not sf.exists():
            end = _dt.date.today() + _dt.timedelta(days=14)
            sf.write_text(SCOPE_TEMPLATE.format(
                client=res["client"], slug=slug,
                tester=e.tester, start=_dt.date.today(), end=end))
        self._reload()
        self.app.notify(f"created {slug} · edit its scope.yaml before scanning")


class RunConfig(ModalScreen[dict | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, tool: str, scope: Scope | None) -> None:
        super().__init__()
        self.tool = tool
        self.adapter = get(tool)
        self.scope = scope

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="modal-wide"):
            a = self.adapter
            yield Label(f"◈ {self.tool.upper()}  —  {a.summary}", id="modal-title")
            if a.aggressive:
                yield Static("⚠ ACTIVE / INTRUSIVE TOOL — authorised targets only",
                             id="warn")
            yield Input(placeholder="target  (host / CIDR / URL)", id="target")
            yield Static("", id="scope-status")
            yield Rule()
            for o in a.options():
                if o.kind == "bool":
                    yield Checkbox(o.label + ("  [aggressive]" if o.aggressive else ""),
                                   value=bool(o.default), id=f"opt-{o.key}")
                elif o.kind == "choice":
                    yield Label(o.label)
                    ch = [(c, c) for c in o.choices if c not in ("", None)]
                    if o.default:
                        yield Select(ch, value=o.default, id=f"opt-{o.key}", allow_blank=True)
                    else:
                        yield Select(ch, id=f"opt-{o.key}", allow_blank=True, prompt="(none)")
                else:
                    yield Label(o.label + (f"   {o.help}" if o.help else ""))
                    yield Input(value="" if o.default in (None, 0) else str(o.default),
                                id=f"opt-{o.key}")
            yield Rule()
            yield Label("Intensity")
            yield Select([(i, i) for i in ("stealth", "normal", "aggressive")],
                         value="normal", id="intensity", allow_blank=False)
            yield Checkbox("Force (run even if out of scope — logged)", id="force")
            yield Input(placeholder="force justification", id="reason")
            with Horizontal(id="modal-buttons"):
                yield Button("▶ RUN", variant="primary", id="go")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#target", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#cancel")
    def _c(self) -> None:
        self.dismiss(None)

    @on(Input.Changed, "#target")
    def _scope(self, ev: Input.Changed) -> None:
        s = self.query_one("#scope-status", Static)
        t = ev.value.strip()
        if not t:
            s.update("")
        elif not self.scope:
            s.update("[#ffcf3f]no scope file — checks disabled[/]")
        else:
            d = self.scope.check(t)
            if d.allowed:
                extra = "" if d.within_window else "  [#ffcf3f](outside window)[/]"
                s.update(f"[#00ffa3]▸ IN SCOPE[/] — {d.reason}{extra}")
            else:
                s.update(f"[#ff3b6b]✕ OUT OF SCOPE[/] — {d.reason}")

    @on(Button.Pressed, "#go")
    def _go(self) -> None:
        target = self.query_one("#target", Input).value.strip()
        if not target:
            self.app.notify("target is required", severity="error")
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
            self.app.notify("force needs a written justification", severity="error")
            return
        self.dismiss({"target": target, "options": opts, "force": force,
                      "reason": reason,
                      "intensity": self.query_one("#intensity", Select).value})


class RunScreen(Screen):
    BINDINGS = [("escape", "back", "Back"), ("f", "findings", "Findings"),
                ("r", "reports", "Reports")]

    def __init__(self, tool, engagement, params, scope) -> None:
        super().__init__()
        self.tool, self.engagement, self.params, self.scope = tool, engagement, params, scope
        self.run_id: str | None = None
        self.ok = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(f"▶ [b]{self.tool}[/b]  →  [b]{self.params['target']}[/b]"
                     f"   ·  engagement {self.engagement}", id="run-title")
        yield RichLog(id="log", wrap=True, markup=False, highlight=True)
        yield Static("◌ running…", id="run-status")
        with Horizontal(id="modal-buttons"):
            yield Button("Findings", id="to-findings", disabled=True)
            yield Button("Generate reports", id="to-reports", disabled=True, variant="primary")
            yield Button("Back", id="to-back")
        yield Footer()

    def on_mount(self) -> None:
        self._go()

    @work(thread=True)
    def _go(self) -> None:
        log = self.query_one(RichLog)
        app = self.app
        p = self.params

        def line(stream: str, text: str) -> None:
            app.call_from_thread(log.write,
                                 {"sys": "▸ ", "err": "! "}.get(stream, "  ") + text)

        try:
            r = run_tool(get(self.tool), self.engagement, p["target"],
                         options=p["options"], intensity=p["intensity"], scope=self.scope,
                         force=p["force"], force_reason=p["reason"], on_line=line)
            self.run_id = r.id
            n = len(db.get_findings(self.engagement, r.id))
            app.call_from_thread(self._done, f"done — {r.status.value}, {n} findings", True)
        except ScopeViolation as v:
            app.call_from_thread(self._done, f"BLOCKED — {v.decision.reason}", False)
        except Exception as e:  # noqa: BLE001
            app.call_from_thread(self._done, f"error — {e}", False)

    def _done(self, msg: str, ok: bool) -> None:
        self.ok = ok
        self.query_one("#run-status", Static).update(
            (f"[#00ffa3]▸ {msg}" if ok else f"[#ff3b6b]✕ {msg}"))
        for b in ("#to-findings", "#to-reports"):
            self.query_one(b, Button).disabled = not ok
        if ok:
            self.app.notify("scan complete", timeout=4)

    @on(Button.Pressed, "#to-back")
    def action_back(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#to-findings")
    def action_findings(self) -> None:
        if self.ok:
            self.app.push_screen(FindingsScreen(self.engagement, self.run_id))

    @on(Button.Pressed, "#to-reports")
    def action_reports(self) -> None:
        if self.ok:
            self.app.push_screen(ReportScreen(self.engagement, self.run_id))


class FindingsScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("enter", "detail", "Detail"),
                ("s", "cycle", "Cycle status")]

    def __init__(self, engagement: str, run_id: str | None = None) -> None:
        super().__init__()
        self.engagement, self.run_id = engagement, run_id

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="find-head")
        yield DataTable(id="find-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        t = self.query_one(DataTable)
        t.add_columns("sev", "cvss", "status", "title", "target", "tool")
        self._reload()

    def _reload(self) -> None:
        self._data = sorted(db.get_findings(self.engagement, self.run_id),
                            key=lambda f: (f.severity.rank, f.cvss_score or 0), reverse=True)
        self.query_one("#find-head", Static).update(
            f"◈ {len(self._data)} findings · engagement [b]{self.engagement}[/b]"
            + (f" · run {self.run_id}" if self.run_id else "")
            + "   [dim]— press s to change remediation status[/dim]")
        t = self.query_one(DataTable)
        t.clear()
        for i, f in enumerate(self._data):
            t.add_row(
                f"[{SEV_STYLE.get(f.severity.value,'')}]{f.severity.value.upper()}[/]",
                f"{f.cvss_score:.1f}" if f.cvss_score else "·",
                f"[{STATUS_STYLE.get(getattr(f,'status','open'),'')}]"
                f"{getattr(f,'status','open')}[/]",
                f.title[:58], f.target[:34], f.tool, key=str(i))

    def _sel(self):
        t = self.query_one(DataTable)
        if not t.row_count:
            return None
        return self._data[int(t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value)]

    def action_detail(self) -> None:
        f = self._sel()
        if f:
            self.app.push_screen(FindingDetail(f))

    def action_cycle(self) -> None:
        f = self._sel()
        if not f:
            return
        nxt = FindingStatus.cycle(getattr(f, "status", "open"))
        db.set_finding_status(f.id, nxt)
        self._reload()
        self.app.notify(f"{f.title[:40]} → {nxt}")


class FindingDetail(ModalScreen):
    BINDINGS = [("escape", "close", "Close")]

    def __init__(self, finding) -> None:
        super().__init__()
        self.f = finding

    def action_close(self) -> None:
        self.dismiss()

    def compose(self) -> ComposeResult:
        f = self.f
        b = [f"[b]{f.title}[/b]", "",
             f"severity : {f.severity.value.upper()}"
             + (f"   CVSS {f.cvss_score:.1f}  {f.cvss_vector or ''}" if f.cvss_score else ""),
             f"target   : {f.target}",
             f"status   : {getattr(f,'status','open')}",
             f"source   : {f.tool} / {f.confidence}"]
        if f.cve:
            b.append(f"CVE      : {', '.join(f.cve)}")
        if f.cwe:
            b.append(f"CWE      : {', '.join(f.cwe)}")
        b += ["", "[u]Description[/u]", f.description or "-"]
        if f.evidence:
            b += ["", "[u]Evidence[/u]", f.evidence[:1600]]
        if f.poc:
            b += ["", "[u]PoC[/u]", f.poc]
        if f.attack_path:
            b += ["", "[u]Attack path[/u]", f.attack_path]
        b += ["", "[u]Remediation[/u]", f.remediation or "-"]
        with VerticalScroll(id="modal-wide"):
            yield Static("\n".join(b))
            yield Button("Close", id="close")

    @on(Button.Pressed, "#close")
    def _c(self) -> None:
        self.dismiss()


class ReportScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("o", "open", "Open in browser")]

    def __init__(self, engagement: str, run_id: str | None = None) -> None:
        super().__init__()
        self.engagement, self.run_id = engagement, run_id
        self.index: Path | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(f"◈ REPORTS · [b]{self.engagement}[/b]"
                     + (f" · run {self.run_id}" if self.run_id else " · all findings"))
        with Horizontal(id="rep-opts"):
            with Vertical():
                yield Label("Levels")
                for lvl in LEVELS:
                    yield Checkbox(lvl.title(), value=True, id=f"lvl-{lvl}")
            with Vertical():
                yield Label("Formats")
                for fmt in ("md", "html", "pdf"):
                    yield Checkbox(fmt.upper(), value=True, id=f"fmt-{fmt}")
            with Vertical():
                yield Label(" ")
                yield Button("▶ GENERATE", variant="primary", id="gen")
        yield RichLog(id="rep-log", markup=True, wrap=True)
        yield Footer()

    @on(Button.Pressed, "#gen")
    def _g(self) -> None:
        self._generate()

    @work(thread=True)
    def _generate(self) -> None:
        levels = tuple(x for x in LEVELS if self.query_one(f"#lvl-{x}", Checkbox).value)
        formats = tuple(x for x in ("md", "html", "pdf")
                        if self.query_one(f"#fmt-{x}", Checkbox).value)
        log = self.query_one(RichLog)
        app = self.app
        try:
            made = render(self.engagement, run_id=self.run_id, levels=levels, formats=formats)
        except Exception as e:  # noqa: BLE001
            app.call_from_thread(log.write, f"[#ff3b6b]failed: {e}[/]")
            return
        for lvl, files in made.items():
            for fmt, p in files.items():
                app.call_from_thread(log.write, f"[#00ffa3]{lvl:12}[/] {fmt:5} {p}")
                if fmt == "html":
                    self.index = p.parent / "index.html"
        if self.index:
            app.call_from_thread(log.write, f"\n[b]press o[/b] to open {self.index}")

    def action_open(self) -> None:
        if self.index and self.index.exists():
            webbrowser.open(self.index.as_uri())
            self.app.notify("opened in browser")


# ═══════════════════════════════════════════════════════════════════ panes
class Pane(Vertical):
    """Base tab pane - subclasses implement refresh_data()."""

    def refresh_data(self) -> None:  # noqa: D401
        ...


class DashboardPane(Pane):
    def compose(self) -> ComposeResult:
        yield Static(BANNER, id="banner")
        yield Static("tactical & offensive · linux", id="banner-sub")
        yield Rule()
        with Horizontal(id="dash-row"):
            yield Static(id="dash-context")
            yield Static(id="dash-alerts")
        yield Rule()
        yield Label("◈ RECENT ACTIVITY")
        yield DataTable(id="dash-runs", cursor_type="row")

    def on_mount(self) -> None:
        self.query_one("#dash-runs", DataTable).add_columns(
            "when", "tool", "target", "status", "findings", "engagement")
        self.refresh_data()

    def refresh_data(self) -> None:
        app = self.app
        eng = app.engagement
        e = db.get_engagement(eng) if eng else None
        cl = db.get_client(e.client_slug) if (e and e.client_slug) else None
        ctx = ["[b #00FFFF]◈ CONTEXT[/]",
               f"client      : {cl.name if cl else '[dim]— none —[/]'}",
               f"engagement  : {eng or '[dim]— none — press e[/]'}"]
        if e:
            fs = db.get_findings(eng)
            ctx.append(f"findings    : {len(fs)}  "
                       + " ".join(f"[{SEV_STYLE[s]}]{sum(1 for x in fs if x.severity.value==s)}{s[0].upper()}[/]"
                                 for s in ("critical", "high", "medium", "low", "info")))
        self.query_one("#dash-context", Static).update("\n".join(ctx))

        # alerts: overdue clients + outdated tools
        from ronin import updates as up

        alerts = ["[b #00FFFF]◈ ATTENTION[/]"]
        overdue = [c for c in db.list_clients() if db.client_progress(c.slug)["overdue"]]
        alerts.append(f"retests overdue : "
                      + (f"[#ff3b6b]{len(overdue)}[/] ({', '.join(c.slug for c in overdue)})"
                         if overdue else "[#00ffa3]0[/]"))
        rep = up.cached()
        if rep:
            alerts.append(f"tools outdated  : "
                          + (f"[#ffcf3f]{len(rep.outdated)}[/]" if rep.outdated else "[#00ffa3]0[/]")
                          + f"   ·  missing {len(rep.missing)}")
            age = rep.nuclei_templates_age_days
            if age is not None:
                alerts.append(f"nuclei tpl age  : "
                              + (f"[#ffcf3f]{age}d[/]" if age > 14 else f"{age}d"))
            alerts.append(f"[dim]last checked {_ago(rep.checked_at)} · Updates tab to refresh[/]")
        else:
            alerts.append("[dim]run a check in the Updates tab[/]")
        self.query_one("#dash-alerts", Static).update("\n".join(alerts))

        t = self.query_one("#dash-runs", DataTable)
        t.clear()
        runs = []
        for en in db.list_engagements():
            runs += db.list_runs(en.slug)
        for r in sorted(runs, key=lambda r: r.started, reverse=True)[:12]:
            n = len(db.get_findings(r.engagement, r.id))
            t.add_row(r.started.strftime("%m-%d %H:%M"), r.tool, r.target[:30],
                      r.status.value, str(n), r.engagement)


class ToolsPane(Pane):
    BINDINGS = [("e", "pick", "Engagement"), ("enter", "run", "Configure & run"),
                ("slash", "filter", "Filter")]

    def compose(self) -> ComposeResult:
        yield Static(id="tools-ctx")
        yield Input(placeholder="/ filter tools", id="tools-filter")
        yield DataTable(id="tools-table", cursor_type="row")

    def on_mount(self) -> None:
        self.query_one("#tools-filter", Input).display = False
        self.query_one("#tools-table", DataTable).add_columns(
            "tool", "category", "installed", "active", "summary")
        self.refresh_data()

    def refresh_data(self) -> None:
        eng = self.app.engagement
        self.query_one("#tools-ctx", Static).update(
            f"◈ engagement: [b]{eng or '— none — press e to choose —'}[/b]"
            + ("   [dim]scope loaded[/dim]" if eng and paths().scope_file(eng).is_file() else ""))
        self._fill(self.query_one("#tools-filter", Input).value)

    def _fill(self, needle: str = "") -> None:
        t = self.query_one("#tools-table", DataTable)
        t.clear()
        for name, ad in adapters().items():
            hay = f"{name} {' '.join(ad.categories)} {ad.summary}".lower()
            if needle and needle.lower() not in hay:
                continue
            t.add_row(
                name, ", ".join(ad.categories),
                "[#00ffa3]yes[/]" if ad.is_installed() else "[#ffcf3f]no[/]",
                "[#ff3b6b]yes[/]" if ad.aggressive else "·",
                ad.summary[:60], key=name)

    def action_filter(self) -> None:
        f = self.query_one("#tools-filter", Input)
        f.display = not f.display
        if f.display:
            f.focus()

    @on(Input.Changed, "#tools-filter")
    def _flt(self, ev: Input.Changed) -> None:
        self._fill(ev.value)

    @work
    async def action_pick(self) -> None:
        sel = await self.app.push_screen_wait(EngagementPicker())
        if sel:
            self.app.set_engagement(sel)

    @on(DataTable.RowSelected, "#tools-table")
    def action_run(self, ev: DataTable.RowSelected | None = None) -> None:
        eng = self.app.engagement
        if not eng:
            self.app.notify("pick an engagement first (press e)", severity="warning")
            return
        t = self.query_one("#tools-table", DataTable)
        if not t.row_count:
            return
        name = (ev.row_key.value if ev
                else t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value)
        ad = get(name)
        if not ad.is_installed():
            self.app.notify(f"{name} not installed — see the Toolbox tab", severity="error")
            return
        scope = None
        sf = paths().scope_file(eng)
        if sf.is_file():
            try:
                scope = Scope.load(sf)
            except Exception as e:  # noqa: BLE001
                self.app.notify(f"scope error: {e}", severity="error")
        self._launch(name, eng, scope)

    @work
    async def _launch(self, name, eng, scope) -> None:
        params = await self.app.push_screen_wait(RunConfig(name, scope))
        if params:
            self.app.push_screen(RunScreen(name, eng, params, scope))


class ReportsPane(Pane):
    BINDINGS = [("g", "generate", "Generate"), ("o", "open", "Open latest")]

    def compose(self) -> ComposeResult:
        yield Static("◈ REPORTS", id="rep-head")
        yield DataTable(id="rep-table", cursor_type="row")
        with Horizontal(id="rep-actions"):
            yield Button("▶ Generate for active engagement", variant="primary", id="rp-gen")
            yield Button("Open selected", id="rp-open")

    def on_mount(self) -> None:
        self.query_one("#rep-table", DataTable).add_columns(
            "engagement", "generated", "levels", "path")
        self.refresh_data()

    def refresh_data(self) -> None:
        self.query_one("#rep-head", Static).update(
            f"◈ REPORTS · active engagement: [b]{self.app.engagement or '— none —'}[/b]")
        t = self.query_one("#rep-table", DataTable)
        t.clear()
        base = paths().reports
        rows = []
        for slug_dir in sorted(base.glob("*")):
            if not slug_dir.is_dir():
                continue
            for stamp in sorted(slug_dir.glob("*"), reverse=True):
                if not stamp.is_dir():
                    continue
                lvls = sorted({p.stem for p in stamp.glob("*.md")})
                rows.append((slug_dir.name, stamp.name, ", ".join(lvls) or "-", str(stamp)))
        for r in rows[:60]:
            t.add_row(*r, key=r[3])

    @on(Button.Pressed, "#rp-gen")
    def action_generate(self) -> None:
        if not self.app.engagement:
            self.app.notify("no active engagement (Tools tab › e)", severity="warning")
            return
        self.app.push_screen(ReportScreen(self.app.engagement))

    @on(Button.Pressed, "#rp-open")
    def action_open(self) -> None:
        t = self.query_one("#rep-table", DataTable)
        if not t.row_count:
            return
        d = Path(t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value)
        idx = d / "index.html"
        if idx.exists():
            webbrowser.open(idx.as_uri())
            self.app.notify("opened in browser")


class ClientsPane(Pane):
    BINDINGS = [("n", "new", "New client"), ("enter", "detail", "Detail"),
                ("d", "delete", "Delete")]

    def compose(self) -> ComposeResult:
        yield Static("◈ CLIENTS  —  recurring customers & retest cadence", id="cl-head")
        yield DataTable(id="cl-table", cursor_type="row")
        yield Static(id="cl-detail")
        with Horizontal(id="cl-actions"):
            yield Button("＋ New client", variant="primary", id="cl-new")
            yield Button("Set active engagement…", id="cl-eng")
            yield Button("Delete", id="cl-del")

    def on_mount(self) -> None:
        self.query_one("#cl-table", DataTable).add_columns(
            "client", "contact", "engagements", "last tested", "cadence", "next due", "progress")
        self.refresh_data()

    def refresh_data(self) -> None:
        t = self.query_one("#cl-table", DataTable)
        t.clear()
        for c in db.list_clients():
            p = db.client_progress(c.slug)
            due = "-"
            if p["next_due"]:
                due = p["next_due"].strftime("%Y-%m-%d")
                if p["overdue"]:
                    due = f"[#ff3b6b]{due} ⚠[/]"
            prog = f"{p['progress_pct']}%" if p["progress_pct"] is not None else "-"
            t.add_row(c.name, c.contact_name or "-", str(p["engagements"]),
                      p["last_tested"].strftime("%Y-%m-%d") if p["last_tested"] else "never",
                      f"{c.cadence_days}d" if c.cadence_days else "-", due, prog, key=c.slug)
        self._detail()

    def _sel_slug(self) -> str | None:
        t = self.query_one("#cl-table", DataTable)
        if not t.row_count:
            return None
        return t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value

    @on(DataTable.RowHighlighted, "#cl-table")
    def _detail(self, *_) -> None:
        slug = self._sel_slug()
        d = self.query_one("#cl-detail", Static)
        if not slug:
            d.update("[dim]no clients — press n to add one[/dim]")
            return
        p = db.client_progress(slug)
        c = p["client"]
        lines = [f"[b #00FFFF]{c.name}[/]  ·  {c.contact_name} <{c.contact_email or 'no email'}>",
                 f"engagements: {p['engagements']}   last tested: {_ago(p['last_tested'])}"
                 f"   next due: " + (p["next_due"].strftime("%Y-%m-%d") if p["next_due"] else "n/a")
                 + ("  [#ff3b6b]OVERDUE[/]" if p["overdue"] else "")]
        mix = p["status_mix"]
        if mix:
            lines.append("remediation: " + "  ".join(
                f"[{STATUS_STYLE.get(k,'')}]{k}:{v}[/]" for k, v in sorted(mix.items())))
        ob = p["open_by_severity"]
        if ob:
            lines.append("open by severity: " + "  ".join(
                f"[{SEV_STYLE[k]}]{k}:{v}[/]" for k, v in sorted(
                    ob.items(), key=lambda kv: -{'critical':4,'high':3,'medium':2,'low':1,'info':0}[kv[0]])))
        engs = db.list_engagements(slug)
        if engs:
            lines.append("engagements: " + ", ".join(e.slug for e in engs[:6]))
        d.update("\n".join(lines))

    @work
    async def action_new(self) -> None:
        res = await self.app.push_screen_wait(TextPrompt(
            "◈ NEW CLIENT",
            [("name", "Name", ""), ("contact", "Contact name", ""),
             ("email", "Contact email", ""), ("cadence", "Retest every N days (0=none)", "0")]))
        if not res or not res["name"]:
            return
        db.upsert_client(Client(
            slug=_slug(res["name"]), name=res["name"], contact_name=res["contact"],
            contact_email=res["email"],
            cadence_days=int(res["cadence"]) if res["cadence"].isdigit() else 0))
        self.refresh_data()
        self.app.notify(f"client {res['name']} added")

    @on(Button.Pressed, "#cl-new")
    def _new_btn(self) -> None:
        self.action_new()

    def action_detail(self) -> None:
        self._detail()

    @on(Button.Pressed, "#cl-del")
    def action_delete(self) -> None:
        slug = self._sel_slug()
        if slug:
            db.delete_client(slug)
            self.refresh_data()
            self.app.notify(f"deleted client {slug}")

    @on(Button.Pressed, "#cl-eng")
    @work
    async def _pick_eng(self) -> None:
        slug = self._sel_slug()
        sel = await self.app.push_screen_wait(EngagementPicker())
        if sel:
            self.app.set_engagement(sel)
            if slug:
                db.set_engagement_client(sel, slug)
                self.refresh_data()
                self.app.notify(f"{sel} linked to {slug}")


class UpdatesPane(Pane):
    BINDINGS = [("c", "check", "Check now"), ("u", "update_sel", "Update selected")]

    def compose(self) -> ComposeResult:
        yield Static(id="up-head")
        yield DataTable(id="up-table", cursor_type="row")
        with Horizontal(id="up-actions"):
            yield Button("⟳ Check now (online)", variant="primary", id="up-check")
            yield Button("↑ Update selected", id="up-upd")
            yield Button("↑ Update all outdated", id="up-updall")
        yield RichLog(id="up-log", markup=True, wrap=True)

    def on_mount(self) -> None:
        self.query_one("#up-table", DataTable).add_columns(
            "tool", "cat", "installed", "latest", "src", "status")
        self.refresh_data()

    def refresh_data(self) -> None:
        from ronin import updates as up

        rep = up.cached()
        h = self.query_one("#up-head", Static)
        t = self.query_one("#up-table", DataTable)
        t.clear()
        if not rep:
            h.update("◈ UPDATES — no check yet · press [b]c[/b] or the button")
            return
        h.update(
            f"◈ UPDATES — checked {_ago(rep.checked_at)} · "
            f"[#ffcf3f]{len(rep.outdated)} outdated[/] · {len(rep.missing)} missing · "
            f"pacman: {len(rep.pacman_updates)} · "
            f"nuclei templates: "
            + (f"{rep.nuclei_templates_age_days}d old"
               if rep.nuclei_templates_age_days is not None else "unknown"))
        for x in rep.tools:
            col = {"current": "#00ffa3", "outdated": "#ffcf3f",
                   "missing": "#ff3b6b"}.get(x.status, "#5f7a92")
            t.add_row(x.name, x.category,
                      x.installed_version or ("-" if x.installed else "—"),
                      x.latest_version or "-", x.source,
                      f"[{col}]{x.status}[/]", key=x.name)

    @on(Button.Pressed, "#up-check")
    def action_check(self) -> None:
        self._check()

    @work(thread=True)
    def _check(self) -> None:
        from ronin import updates as up

        log = self.query_one("#up-log", RichLog)
        self.app.call_from_thread(log.write, "⟳ checking (querying GitHub + pacman)…")
        up.check(online=True)
        self.app.call_from_thread(self.refresh_data)
        self.app.call_from_thread(log.write, "[#00ffa3]done[/]")

    def _sel(self) -> str | None:
        t = self.query_one("#up-table", DataTable)
        if not t.row_count:
            return None
        return t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value

    @on(Button.Pressed, "#up-upd")
    def action_update_sel(self) -> None:
        name = self._sel()
        if name:
            self._update([name])

    @on(Button.Pressed, "#up-updall")
    def _update_all(self) -> None:
        from ronin import updates as up

        rep = up.cached()
        names = [x.name for x in rep.outdated] if rep else []
        if not names:
            self.app.notify("nothing marked outdated", severity="warning")
            return
        self._update(names)

    @work(thread=True)
    def _update(self, names: list[str]) -> None:
        from ronin import doctor

        log = self.query_one("#up-log", RichLog)
        self.app.call_from_thread(log.write, f"↑ updating {', '.join(names)} …")
        for k, v in doctor.update(names).items():
            self.app.call_from_thread(log.write, f"  {k}: {v}")
        self.app.call_from_thread(self._check)


class ToolboxPane(Pane):
    BINDINGS = [("i", "install_sel", "Install"), ("space", "toggle_sel", "Select"),
                ("a", "install_missing", "Install all missing")]

    def compose(self) -> ComposeResult:
        yield Static("◈ TOOLBOX — add & update the offensive toolchain (Arch)", id="tb-head")
        yield DataTable(id="tb-table", cursor_type="row", zebra_stripes=True)
        with Horizontal(id="tb-actions"):
            yield Button("↓ Install selected", variant="primary", id="tb-inst")
            yield Button("↓ Install all missing", id="tb-instmiss")
            yield Button("↑ Update selected", id="tb-upd")
        yield RichLog(id="tb-log", markup=True, wrap=True)

    def on_mount(self) -> None:
        self.query_one("#tb-table", DataTable).add_columns(
            "tool", "category", "adapter", "active", "recipe", "status")
        self.refresh_data()

    def refresh_data(self) -> None:
        from ronin.doctor import survey

        t = self.query_one("#tb-table", DataTable)
        t.clear()
        rows = survey()
        n_have = sum(s.installed for s in rows)
        self.query_one("#tb-head", Static).update(
            f"◈ TOOLBOX — {n_have}/{len(rows)} installed · "
            f"adapters wired: {sum(s.has_adapter for s in rows)} · "
            "select a row then i to install, u to update")
        for s in rows:
            recipe = next(iter(s.recipe), "-") if s.recipe else "-"
            t.add_row(
                s.name, s.category, "yes" if s.has_adapter else "·",
                "[#ff3b6b]yes[/]" if s.aggressive else "·", recipe,
                f"[#00ffa3]{Path(s.path).name}[/]" if s.installed else "[#ffcf3f]missing[/]",
                key=s.name)

    def _sel(self) -> str | None:
        t = self.query_one("#tb-table", DataTable)
        if not t.row_count:
            return None
        return t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value

    @on(Button.Pressed, "#tb-inst")
    def action_install_sel(self) -> None:
        n = self._sel()
        if n:
            self._install([n])

    @on(Button.Pressed, "#tb-instmiss")
    def action_install_missing(self) -> None:
        from ronin.doctor import survey

        miss = [s.name for s in survey() if not s.installed]
        if not miss:
            self.app.notify("everything's installed", severity="information")
            return
        self._install(miss)

    @on(Button.Pressed, "#tb-upd")
    def _upd(self) -> None:
        n = self._sel()
        if n:
            self._install([n], mode="update")

    @work(thread=True)
    def _install(self, names: list[str], mode: str = "install") -> None:
        from ronin import doctor

        log = self.query_one("#tb-log", RichLog)
        self.app.call_from_thread(
            log.write, f"↓ {mode} {', '.join(names)} — sudo/yay may prompt in this terminal…")
        fn = doctor.update if mode == "update" else doctor.install
        for k, v in fn(names).items():
            colour = "#00ffa3" if v in ("installed", "updated") or "already" in v else "#ffcf3f"
            self.app.call_from_thread(log.write, f"  [{colour}]{k}: {v}[/]")
        self.app.call_from_thread(self.refresh_data)


# ═══════════════════════════════════════════════════════════════════ main
_TABS = [
    ("Dashboard", "tab-dash", DashboardPane),
    ("Tools", "tab-tools", ToolsPane),
    ("Reports", "tab-reports", ReportsPane),
    ("Clients", "tab-clients", ClientsPane),
    ("Updates", "tab-updates", UpdatesPane),
    ("Toolbox", "tab-toolbox", ToolboxPane),
]


class MainScreen(Screen):
    BINDINGS = [
        *[(str(i + 1), f"tab('{tid}')", name) for i, (name, tid, _) in enumerate(_TABS)],
        ("e", "engagement", "Engagement"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="ctxbar")
        with TabbedContent(initial="tab-dash"):
            for name, tid, cls in _TABS:
                with TabPane(name, id=tid):
                    yield cls()
        yield Footer()

    def on_mount(self) -> None:
        self._ctxbar()
        self._refresh_active()

    def _ctxbar(self) -> None:
        eng = self.app.engagement
        e = db.get_engagement(eng) if eng else None
        cl = db.get_client(e.client_slug) if (e and e.client_slug) else None
        self.query_one("#ctxbar", Static).update(
            f"[#00FFFF]▓ RONIN⟊SUITE[/]   [#00BFFF]│[/]   "
            f"◈ CLIENT [#B026FF]{cl.name if cl else '—'}[/]   [#00BFFF]│[/]   "
            f"◈ ENGAGEMENT [#B026FF]{eng or '— press e —'}[/]")

    def _refresh_active(self) -> None:
        try:
            pane = self.query_one(TabbedContent).get_pane(
                self.query_one(TabbedContent).active)
            for child in pane.walk_children(Pane):
                child.refresh_data()
        except Exception:  # noqa: BLE001
            pass

    @on(TabbedContent.TabActivated)
    def _tab_changed(self) -> None:
        self._refresh_active()

    def action_tab(self, tid: str) -> None:
        self.query_one(TabbedContent).active = tid

    @work
    async def action_engagement(self) -> None:
        sel = await self.app.push_screen_wait(EngagementPicker())
        if sel:
            self.app.set_engagement(sel)


class RoninApp(App):
    CSS_PATH = "app.tcss"
    TITLE = "RoninSuite"
    SUB_TITLE = "cybercore console"
    BINDINGS = [("q", "quit", "Quit")]

    engagement: str | None = None

    def on_mount(self) -> None:
        load_dotenv()
        self.register_theme(CYBERCORE)
        self.theme = "cybercore"
        self.push_screen(MainScreen())

    def set_engagement(self, slug: str | None) -> None:
        self.engagement = slug
        scr = self.screen
        if isinstance(scr, MainScreen):
            scr._ctxbar()
            scr._refresh_active()
        self.notify(f"active engagement → {slug}" if slug else "engagement cleared")


def run() -> None:
    RoninApp().run()
