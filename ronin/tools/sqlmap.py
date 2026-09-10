"""sqlmap - automated SQL injection detection and exploitation.

Aggressive: this actively attacks the parameter(s). Only run it in scope, with
authorisation, and preferably against a staging copy.
"""
from __future__ import annotations

import csv
import re

from ronin.core.models import Finding, Option, Severity, ToolRun
from ronin.tools.base import RunContext, ToolAdapter


class SqlmapAdapter(ToolAdapter):
    name = "sqlmap"
    binary = "sqlmap"
    summary = "Detect & exploit SQL injection in a URL/parameter (active)."
    categories = ("exploit",)
    doc_url = "https://github.com/sqlmapproject/sqlmap/wiki/Usage"
    install = {"pacman": "sqlmap"}
    aggressive = True
    default_timeout = 3600

    def options(self) -> list[Option]:
        return [
            Option(key="data", label="POST data", kind="str", default="",
                   help="body for a POST request, e.g. id=1&x=2"),
            Option(key="param", label="Test only this parameter (-p)", kind="str", default=""),
            Option(key="level", label="Level (1-5)", kind="int", default=1, aggressive=True),
            Option(key="risk", label="Risk (1-3)", kind="int", default=1, aggressive=True),
            Option(key="dbs", label="Enumerate databases if injectable", kind="bool",
                   default=False, aggressive=True),
            Option(key="technique", label="Techniques (BEUSTQ)", kind="str", default=""),
        ]

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = ctx.options
        argv = ["sqlmap", "-u", ctx.target, "--batch", "--disable-coloring",
                "--output-dir", str(ctx.evidence_dir),
                "--results-file", str(ctx.out("sqlmap-results.csv")),
                "--flush-session",
                "--level", str(o.get("level") or 1), "--risk", str(o.get("risk") or 1)]
        if o.get("data"):
            argv += ["--data", str(o["data"])]
        if o.get("param"):
            argv += ["-p", str(o["param"])]
        if o.get("technique"):
            argv += ["--technique", str(o["technique"]).upper()]
        if o.get("dbs"):
            argv += ["--dbs"]
        return argv

    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        results = ctx.evidence_dir / "sqlmap-results.csv"
        log = ctx.evidence_dir / "stdout.log"
        text = log.read_text(errors="replace") if log.is_file() else ""
        out: list[Finding] = []

        rows: list[dict] = []
        if results.is_file():
            try:
                rows = list(csv.DictReader(results.read_text(errors="replace").splitlines()))
            except csv.Error:
                rows = []

        dbms = None
        m = re.search(r"back-end DBMS:\s*(.+)", text)
        if m:
            dbms = m.group(1).strip()

        for r in rows:
            param = (r.get("Parameter") or r.get("parameter") or "").strip()
            place = (r.get("Place") or r.get("place") or "").strip()
            tech = (r.get("Technique(s)") or r.get("technique") or "").strip()
            if not param:
                continue
            out.append(self._f(
                run, ctx, target=ctx.target, severity=Severity.CRITICAL, confidence="confirmed",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                title=f"SQL injection in {place} parameter '{param}'"
                      + (f" ({dbms})" if dbms else ""),
                description=f"sqlmap confirmed SQL injection via `{param}` ({place}). "
                            f"Technique(s): {tech or 'see log'}."
                            + (f" Back-end DBMS: {dbms}." if dbms else ""),
                evidence="\n".join(_grep(text, "is vulnerable", "Type:", "Payload:",
                                          "Title:", "back-end DBMS"))[:4000],
                poc=" ".join(run.argv),
                attack_path=("Full read (and often write) of the database: dump credentials "
                             "and PII, escalate to auth bypass, and where stacked queries or "
                             "file privileges exist, to command execution on the DB host."),
                remediation="Use parameterised queries / prepared statements everywhere; "
                            "apply least-privilege DB accounts; add a WAF rule as a stop-gap; "
                            "retest with the same sqlmap command.",
                references=["https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
                cwe=["CWE-89"],
                tags=["sqlmap", "sqli", place.lower()],
            ))

        if not out and rows == [] and re.search(r"all tested parameters do not appear to be injectable", text):
            out.append(self._f(
                run, ctx, target=ctx.target, severity=Severity.INFO, confidence="firm",
                title="No SQL injection detected",
                description="sqlmap tested the supplied parameters and did not confirm an "
                            "injection at the configured level/risk.",
                evidence="\n".join(_grep(text, "testing", "do not appear to be injectable"))[:2000],
                remediation="No action. Consider a higher --level/--risk or authenticated "
                            "testing for coverage.",
                tags=["sqlmap"],
            ))
        return out


def _grep(text: str, *needles: str) -> list[str]:
    return [ln for ln in text.splitlines() if any(n.lower() in ln.lower() for n in needles)]
