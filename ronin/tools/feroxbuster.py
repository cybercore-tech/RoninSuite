"""feroxbuster - recursive content discovery."""
from __future__ import annotations

import json
from pathlib import Path

from ronin.config import INTENSITY
from ronin.core.models import Finding, Option, Severity, ToolRun
from ronin.tools.base import RunContext, ToolAdapter

_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]
_JUICY = (".git", ".env", ".svn", "backup", "dump", "phpinfo", "server-status",
          "actuator", "wp-config", "config.php", "id_rsa", ".bak", ".old", ".sql")
_INTERESTING = ("admin", "api", "internal", "private", "upload", "console", "debug",
                "test", "dev", "staging", "portal", "manager")


class FeroxbusterAdapter(ToolAdapter):
    name = "feroxbuster"
    binary = "feroxbuster"
    summary = "Recursive directory/file brute-force with auto-filtering."
    categories = ("web",)
    doc_url = "https://github.com/epi052/feroxbuster"
    install = {"pacman": "feroxbuster"}
    aggressive = True
    default_timeout = 2400

    def options(self) -> list[Option]:
        return [
            Option(key="wordlist", label="Wordlist", kind="str", default=""),
            Option(key="depth", label="Recursion depth", kind="int", default=2),
            Option(key="extensions", label="Extensions", kind="str", default="",
                   help="comma list, e.g. php,bak,txt"),
            Option(key="status_codes", label="Only these status codes", kind="str",
                   default="200,204,301,302,307,401,403,405,500"),
        ]

    def _wordlist(self, opt: str) -> str | None:
        if opt and Path(opt).is_file():
            return opt
        return next((w for w in _WORDLISTS if Path(w).is_file()), None)

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = ctx.options
        wl = self._wordlist(o.get("wordlist", ""))
        if not wl:
            raise FileNotFoundError("no wordlist found - install seclists or set the option")
        rate = INTENSITY[ctx.intensity]["rate"]
        conc = INTENSITY[ctx.intensity]["concurrency"]
        argv = ["feroxbuster", "-u", ctx.target, "-w", wl,
                "--json", "-o", str(ctx.out("feroxbuster.json")),
                "--silent", "-k", "-d", str(o.get("depth", 2) or 2),
                "--rate-limit", str(rate), "-t", str(conc),
                "-s", str(o.get("status_codes") or "200")]
        if o.get("extensions"):
            argv += ["-x", str(o["extensions"])]
        return argv

    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        p = ctx.evidence_dir / "feroxbuster.json"
        if not p.is_file():
            return []
        out: list[Finding] = []
        for line in p.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("type") != "response":
                continue
            url = d.get("url", ctx.target)
            status = d.get("status")
            low = url.lower()
            sev = Severity.INFO
            if any(k in low for k in _JUICY):
                sev = Severity.MEDIUM
            elif any(k in low for k in _INTERESTING) or status in (401, 403, 500):
                sev = Severity.LOW
            out.append(self._f(
                run, ctx, target=url, severity=sev, confidence="confirmed",
                title=f"Discovered [{status}] {url}",
                description=f"feroxbuster: {url} -> {status} "
                            f"({d.get('content_length', '?')} bytes, "
                            f"{d.get('line_count', '?')} lines).",
                evidence=line,
                poc=f"curl -ski {url}",
                attack_path=("Inspect for source/secret exposure, unauthenticated admin "
                             "functionality, backups, or an upload/file-write primitive."),
                remediation="Remove or authenticate the resource; deny VCS metadata, "
                            "backups and debug/status endpoints at the edge.",
                cwe=["CWE-538"] if sev != Severity.INFO else [],
                tags=["content-discovery", f"status:{status}"],
            ))
        return out
