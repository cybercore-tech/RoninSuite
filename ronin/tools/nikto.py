"""nikto - web server misconfiguration and known-issue scanner."""
from __future__ import annotations

import json

from ronin.core.models import Finding, Option, Severity, ToolRun
from ronin.tools.base import RunContext, ToolAdapter

_HIGH_KW = ("remote", "rce", "sql inject", "traversal", "upload", "shell", "backdoor",
            "default credentials", "authentication bypass")
_MED_KW = ("outdated", "deprecated", "disclosure", "phpinfo", "directory indexing",
           "backup", ".git", "debug", "server-status", "test page")


class NiktoAdapter(ToolAdapter):
    name = "nikto"
    binary = "nikto"
    summary = "Classic web server scanner: headers, files, versions, common flaws."
    categories = ("vuln", "web")
    doc_url = "https://github.com/sullo/nikto"
    install = {"pacman": "nikto"}
    default_timeout = 2400

    def options(self) -> list[Option]:
        return [
            Option(key="ssl", label="Force HTTPS", kind="bool", default=False),
            Option(key="tuning", label="Tuning string (-T)", kind="str", default="",
                   help="e.g. 123bde ; empty = default set"),
            Option(key="maxtime", label="Max runtime (seconds)", kind="int", default=1200),
        ]

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = ctx.options
        out = ctx.out("nikto.json")
        argv = ["nikto", "-h", ctx.target, "-Format", "json", "-output", str(out),
                "-nointeractive", "-ask", "no"]
        if o.get("ssl"):
            argv.append("-ssl")
        if o.get("tuning"):
            argv += ["-Tuning", str(o["tuning"])]
        if o.get("maxtime"):
            argv += ["-maxtime", str(o["maxtime"])]
        return argv

    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        p = ctx.evidence_dir / "nikto.json"
        if not p.is_file():
            return []
        txt = p.read_text(errors="replace").strip()
        try:
            data = json.loads(txt)
        except json.JSONDecodeError:
            # nikto sometimes emits one object per host, newline separated
            data = []
            for line in txt.splitlines():
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        hosts = data if isinstance(data, list) else [data]
        out: list[Finding] = []
        for h in hosts:
            base = h.get("host") or ctx.target
            for v in h.get("vulnerabilities", []) or []:
                msg = v.get("msg") or v.get("message") or ""
                low = msg.lower()
                sev = Severity.INFO
                if any(k in low for k in _HIGH_KW):
                    sev = Severity.HIGH
                elif any(k in low for k in _MED_KW):
                    sev = Severity.MEDIUM
                elif v.get("OSVDB") and v.get("OSVDB") != "0":
                    sev = Severity.LOW
                url = v.get("url") or v.get("uri") or ""
                where = f"{base}{url}" if url.startswith("/") else (url or base)
                refs = [r for r in (v.get("references") or "").split() if r.startswith("http")]
                out.append(self._f(
                    run, ctx, target=where, severity=sev,
                    confidence="tentative" if sev.rank <= 1 else "firm",
                    title=f"nikto: {msg[:120]}",
                    description=f"nikto reported on {where}: {msg}",
                    evidence=json.dumps(v, indent=2),
                    poc=f"{v.get('method', 'GET')} {where}",
                    remediation="Validate the finding manually; remove/patch the "
                                "affected component or restrict access to it.",
                    references=refs,
                    tags=["nikto", f"id:{v.get('id', '?')}"],
                ))
        return out
