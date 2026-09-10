"""subfinder (ProjectDiscovery) - passive subdomain enumeration."""
from __future__ import annotations

import json

from ronin.core.models import Finding, Option, Severity, ToolRun
from ronin.tools.base import RunContext, ToolAdapter


class SubfinderAdapter(ToolAdapter):
    name = "subfinder"
    binary = "subfinder"
    summary = "Passive subdomain discovery from ~30 public sources."
    categories = ("recon",)
    doc_url = "https://github.com/projectdiscovery/subfinder"
    install = {"pacman": "subfinder",
               "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"}
    default_timeout = 900

    def options(self) -> list[Option]:
        return [
            Option(key="all_sources", label="Use all sources (slower)", kind="bool",
                   default=False),
            Option(key="recursive", label="Recursive enumeration", kind="bool",
                   default=False),
        ]

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = ctx.options
        dom = ctx.target.split("://")[-1].split("/")[0]
        argv = ["subfinder", "-d", dom, "-oJ", "-o", str(ctx.out("subfinder.jsonl")),
                "-silent", "-no-color"]
        if o.get("all_sources"):
            argv.append("-all")
        if o.get("recursive"):
            argv.append("-recursive")
        return argv

    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        p = ctx.evidence_dir / "subfinder.jsonl"
        if not p.is_file():
            return []
        seen: set[str] = set()
        out: list[Finding] = []
        for line in p.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = d.get("host") or d.get("subdomain")
            if not host or host in seen:
                continue
            seen.add(host)
            src = d.get("sources") or d.get("source") or []
            out.append(self._f(
                run, ctx, target=host, severity=Severity.INFO, confidence="firm",
                title=f"Subdomain discovered: {host}",
                description=f"`{host}` was enumerated for `{ctx.target}`"
                            + (f" (sources: {', '.join(src)})" if src else "") + ".",
                evidence=line,
                poc=f"dig +short {host}",
                attack_path=("Expands the attack surface - probe with httpx/nuclei; "
                             "forgotten staging/admin hosts are common weak points."),
                remediation="Confirm each exposed host is intended and maintained; "
                            "retire stale DNS records.",
                tags=["recon", "subdomain"],
            ))
        return out
