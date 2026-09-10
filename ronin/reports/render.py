"""Report engine: build a context from the findings DB and render three tiers
(Executive / Technical / Remediation), each in Markdown, HTML and PDF.

Every tier contains the same four sections you asked for:
  1. Scope & Methodology
  2. Vulnerability Details (the findings)
  3. Proof of Concept (PoC) & Attack Paths
  4. Remediation Recommendations
...rendered at a depth and register appropriate to the audience.
"""
from __future__ import annotations

import base64
import datetime as _dt
import html as _html
import mimetypes
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import markdown as _md
import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ronin.config import paths
from ronin.core import db
from ronin.core.models import Engagement, Finding, Severity, ToolRun
from ronin.core.scope import Scope

_TPL_DIR = Path(__file__).parent / "templates"
LEVELS = ("executive", "technical", "remediation")
FORMATS = ("md", "html", "pdf")

_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": None}
_EFFORT = {"critical": "High", "high": "Medium-High", "medium": "Medium",
           "low": "Low", "info": "Low"}

_BRAND_DEFAULTS = {
    "company": "",                 # your consultancy name; blank = generic
    "tagline": "",
    "logo": "",                    # path to png/svg/jpg, embedded as a data URI
    "accent_color": "#b026ff",
    "footer": "Prepared with RoninSuite. Handle per the engagement NDA.",
    "classification": "CONFIDENTIAL",
}


def load_brand() -> dict:
    """Optional report branding from ``brand.yaml`` at the project root."""
    b = dict(_BRAND_DEFAULTS)
    f = paths().root / "brand.yaml"
    if f.is_file():
        try:
            b.update({k: v for k, v in (yaml.safe_load(f.read_text()) or {}).items()
                      if v is not None})
        except yaml.YAMLError:
            pass
    logo = b.get("logo")
    b["logo_data_uri"] = ""
    if logo:
        lp = (paths().root / logo) if not Path(logo).is_absolute() else Path(logo)
        if lp.is_file():
            mime = mimetypes.guess_type(str(lp))[0] or "image/png"
            b["logo_data_uri"] = (
                f"data:{mime};base64," + base64.b64encode(lp.read_bytes()).decode()
            )
    return b


@dataclass
class MethodStep:
    tool: str
    target: str
    command: str
    started: str
    duration: str
    status: str
    findings: int


@dataclass
class ReportContext:
    engagement: Engagement
    scope: Scope | None
    generated: str
    findings: list[Finding]
    method: list[MethodStep]
    counts: dict[str, int]
    total: int
    risk_rating: str
    scope_targets: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    window: str = ""
    roe: str = ""
    brand: dict = field(default_factory=dict)

    # convenience for templates
    def by_sev(self, *names: str) -> list[Finding]:
        want = set(names)
        return [f for f in self.findings if f.severity.value in want]

    def actionable(self) -> list[Finding]:
        return [f for f in self.findings if f.severity != Severity.INFO]

    def sla_days(self, sev: str) -> int | None:
        return _SLA_DAYS.get(sev)

    def effort(self, f: Finding) -> str:
        for t in f.tags:
            if t in ("xss", "sqli", "idor", "rce", "auth-bypass"):
                return "Medium-High"
            if t in ("headers", "tls", "banner", "content-discovery"):
                return "Low"
        return _EFFORT.get(f.severity.value, "Medium")


def _risk_rating(counts: dict[str, int]) -> str:
    if counts.get("critical"):
        return "Critical"
    if counts.get("high", 0) >= 2 or (counts.get("high") and counts.get("medium", 0) >= 3):
        return "High"
    if counts.get("high") or counts.get("medium", 0) >= 3:
        return "Elevated"
    if counts.get("medium"):
        return "Moderate"
    if counts.get("low"):
        return "Low"
    return "Informational"


def _fmt_dur(run: ToolRun) -> str:
    d = run.duration_s
    if d is None:
        return "-"
    m, s = divmod(int(d), 60)
    return f"{m}m{s:02d}s" if m else f"{s}s"


def build_context(slug: str, run_id: str | None = None) -> ReportContext:
    eng = db.get_engagement(slug) or Engagement(slug=slug, client=slug, tester="unknown")
    findings = db.get_findings(slug, run_id)
    findings.sort(key=lambda f: (f.severity.rank, f.cvss_score or 0.0), reverse=True)

    runs = db.list_runs(slug)
    if run_id:
        runs = [r for r in runs if r.id == run_id]
    fcount_by_run = Counter(f.run_id for f in db.get_findings(slug))
    method = [
        MethodStep(
            tool=r.tool, target=r.target,
            command=" ".join(r.argv),
            started=r.started.strftime("%Y-%m-%d %H:%M"),
            duration=_fmt_dur(r), status=r.status.value,
            findings=fcount_by_run.get(r.id, 0),
        )
        for r in sorted(runs, key=lambda r: r.started)
    ]

    counts = Counter(f.severity.value for f in findings)
    scope = None
    sf = paths().scope_file(slug)
    if sf.is_file():
        try:
            scope = Scope.load(sf)
        except Exception:
            scope = None

    return ReportContext(
        engagement=eng,
        scope=scope,
        generated=_dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        findings=findings,
        method=method,
        counts=dict(counts),
        total=len(findings),
        risk_rating=_risk_rating(counts),
        scope_targets=list(scope.in_scope) if scope else sorted({m.target for m in method}),
        out_of_scope=list(scope.out_of_scope) if scope else [],
        window=(f"{scope.window_start:%Y-%m-%d} to {scope.window_end:%Y-%m-%d}"
                if scope and scope.window_start and scope.window_end else "not specified"),
        roe=scope.roe if scope else "",
        brand=load_brand(),
    )


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(_TPL_DIR),
        autoescape=select_autoescape(enabled_extensions=("html",)),
        trim_blocks=True, lstrip_blocks=True,
    )
    env.filters["sev_badge"] = lambda s: f"`{s.upper()}`"
    env.filters["e"] = lambda s: _html.escape(str(s or ""))
    return env


def _md_to_html(md_text: str, title: str, brand: dict) -> str:
    body = _md.markdown(
        md_text,
        extensions=["tables", "fenced_code", "toc", "attr_list", "sane_lists"],
    )
    tpl = _env().get_template("report.html.j2")
    return tpl.render(title=title, body=body, brand=brand)


def render(
    slug: str,
    *,
    run_id: str | None = None,
    levels: tuple[str, ...] = LEVELS,
    formats: tuple[str, ...] = FORMATS,
    out_dir: Path | None = None,
) -> dict[str, dict[str, Path]]:
    ctx = build_context(slug, run_id)
    env = _env()
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S") + (f"-{run_id}" if run_id else "")
    out_dir = out_dir or paths().report_dir(slug, stamp)
    made: dict[str, dict[str, Path]] = {}

    pdf_ok = "pdf" in formats
    _weasy = None
    if pdf_ok:
        try:
            from weasyprint import HTML as _WeasyHTML  # noqa: N811

            _weasy = _WeasyHTML
        except Exception as e:  # missing system libs -> degrade gracefully
            print(f"[reports] PDF disabled: {e}")
            pdf_ok = False

    for level in levels:
        md_text = env.get_template(f"{level}.md.j2").render(ctx=ctx, level=level)
        entry: dict[str, Path] = {}
        if "md" in formats:
            p = out_dir / f"{level}.md"
            p.write_text(md_text)
            entry["md"] = p
        html_text = _md_to_html(md_text, f"{ctx.engagement.client} - {level.title()} Report",
                                ctx.brand)
        if "html" in formats:
            p = out_dir / f"{level}.html"
            p.write_text(html_text)
            entry["html"] = p
        if pdf_ok and _weasy is not None:
            p = out_dir / f"{level}.pdf"
            try:
                _weasy(string=html_text, base_url=str(out_dir)).write_pdf(str(p))
                entry["pdf"] = p
            except Exception as e:
                print(f"[reports] {level}.pdf failed: {e}")
        made[level] = entry

    _write_index(out_dir, ctx, made)
    return made


def _write_index(out_dir: Path, ctx: ReportContext, made: dict) -> None:
    links = []
    for level, fmts in made.items():
        parts = " &middot; ".join(
            f'<a href="{p.name}">{fmt.upper()}</a>' for fmt, p in fmts.items()
        )
        links.append(f"<li><strong>{level.title()}</strong> &mdash; {parts}</li>")
    body = (
        f"<h1>{_html.escape(ctx.engagement.client)}</h1>"
        f"<p>Engagement <code>{_html.escape(ctx.engagement.slug)}</code> &middot; "
        f"generated {ctx.generated} &middot; risk rating "
        f"<strong>{ctx.risk_rating}</strong> &middot; {ctx.total} findings</p>"
        f"<ul>{''.join(links)}</ul>"
    )
    (out_dir / "index.html").write_text(_env().get_template("report.html.j2").render(
        title=f"{ctx.engagement.client} - RoninSuite reports", body=body, brand=ctx.brand))
