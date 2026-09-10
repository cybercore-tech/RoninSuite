"""ffuf - content / path discovery on a web target."""
from __future__ import annotations

import json
from pathlib import Path

from ronin.config import INTENSITY
from ronin.core.models import Finding, Option, Severity, ToolRun
from ronin.tools.base import RunContext, ToolAdapter

_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]
_INTERESTING = ("admin", "backup", "config", ".git", ".env", "api", "test", "dev",
                "old", "private", "upload", "phpinfo", "server-status", "actuator")


class FfufAdapter(ToolAdapter):
    name = "ffuf"
    binary = "ffuf"
    summary = "Fuzz for hidden directories and files (FUZZ keyword in the URL)."
    categories = ("web",)
    doc_url = "https://github.com/ffuf/ffuf/wiki"
    install = {"pacman": "ffuf", "go": "github.com/ffuf/ffuf/v2@latest"}
    aggressive = True          # generates a lot of requests
    default_timeout = 1800

    def options(self) -> list[Option]:
        return [
            Option(key="wordlist", label="Wordlist path", kind="str", default="",
                   help="empty = first found SecLists/dirb list"),
            Option(key="extensions", label="Extensions", kind="str", default="",
                   help="e.g. .php,.bak,.txt"),
            Option(key="match_codes", label="Match status codes", kind="str",
                   default="200,204,301,302,307,401,403,405"),
            Option(key="filter_size", label="Filter response sizes", kind="str", default="",
                   help="comma list to hide, e.g. 0,1234"),
        ]

    def _wordlist(self, opt: str) -> str | None:
        if opt and Path(opt).is_file():
            return opt
        for c in _WORDLIST_CANDIDATES:
            if Path(c).is_file():
                return c
        return None

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = ctx.options
        base = ctx.target.rstrip("/")
        url = base if "FUZZ" in base else base + "/FUZZ"
        wl = self._wordlist(o.get("wordlist", ""))
        if not wl:
            raise FileNotFoundError(
                "no wordlist found - install seclists (`ronin doctor --install seclists`) "
                "or set the wordlist option"
            )
        rate = INTENSITY[ctx.intensity]["rate"]
        argv = [
            "ffuf", "-u", url, "-w", f"{wl}:FUZZ",
            "-o", str(ctx.out("ffuf.json")), "-of", "json",
            "-mc", str(o.get("match_codes") or "all"),
            "-rate", str(rate), "-t", str(INTENSITY[ctx.intensity]["concurrency"]),
            "-noninteractive", "-s",
        ]
        if o.get("extensions"):
            argv += ["-e", str(o["extensions"])]
        if o.get("filter_size"):
            argv += ["-fs", str(o["filter_size"])]
        return argv

    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        p = ctx.evidence_dir / "ffuf.json"
        if not p.is_file():
            return []
        try:
            data = json.loads(p.read_text(errors="replace") or "{}")
        except json.JSONDecodeError:
            return []
        out: list[Finding] = []
        for r in data.get("results", []):
            url = r.get("url", ctx.target)
            status = r.get("status")
            length = r.get("length")
            low = url.lower()
            sev = Severity.INFO
            if any(k in low for k in (".git", ".env", "backup", "phpinfo", "server-status", "actuator")):
                sev = Severity.MEDIUM
            elif any(k in low for k in _INTERESTING):
                sev = Severity.LOW
            out.append(self._f(
                run, ctx, target=url, severity=sev, confidence="confirmed",
                title=f"Discovered path [{status}] {url.split('/')[-1] or url}",
                description=f"ffuf found {url} responding {status} ({length} bytes).",
                evidence=json.dumps(r, indent=2),
                poc=f"curl -ski {url}",
                attack_path=("Inspect for sensitive content, unauthenticated admin "
                             "functions, source/secret exposure, or an upload primitive."),
                remediation=("Remove or authenticate the resource; block access to VCS "
                             "metadata, backups, and status/debug endpoints at the proxy."),
                cwe=["CWE-538"] if sev != Severity.INFO else [],
                tags=["content-discovery", f"status:{status}"],
            ))
        return out
