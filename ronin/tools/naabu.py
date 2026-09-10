"""naabu (ProjectDiscovery) - fast SYN/CONNECT port scan."""
from __future__ import annotations

import json
import os

from ronin.config import INTENSITY
from ronin.core.models import Finding, Option, Severity, ToolRun
from ronin.tools.base import RunContext, ToolAdapter

# ports that warrant more than an INFO note when found exposed
_SENSITIVE = {
    3389: ("RDP", Severity.MEDIUM), 5900: ("VNC", Severity.MEDIUM),
    23: ("Telnet", Severity.MEDIUM), 21: ("FTP", Severity.LOW),
    3306: ("MySQL", Severity.MEDIUM), 5432: ("PostgreSQL", Severity.MEDIUM),
    6379: ("Redis", Severity.HIGH), 27017: ("MongoDB", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH), 11211: ("Memcached", Severity.HIGH),
    445: ("SMB", Severity.LOW), 135: ("MSRPC", Severity.LOW),
}


class NaabuAdapter(ToolAdapter):
    name = "naabu"
    binary = "naabu"
    summary = "Fast port discovery (host -> open ports) with rate control."
    categories = ("scan",)
    doc_url = "https://github.com/projectdiscovery/naabu"
    install = {"go": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"}
    default_timeout = 1800

    def options(self) -> list[Option]:
        return [
            Option(key="ports", label="Ports", kind="str", default="",
                   help="e.g. 80,443,8080 or 1-65535. Empty = naabu top 100"),
            Option(key="top_ports", label="Top-ports preset", kind="choice", default="100",
                   choices=["100", "1000", "full"]),
        ]

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = ctx.options
        rate = INTENSITY[ctx.intensity]["rate"]
        host = ctx.target.split("://")[-1].split("/")[0]
        argv = ["naabu", "-host", host, "-json",
                "-o", str(ctx.out("naabu.jsonl")),
                "-silent", "-no-color", "-rate", str(rate)]
        if os.geteuid() != 0:
            argv += ["-scan-type", "c"]           # CONNECT scan when unprivileged
        if o.get("ports"):
            argv += ["-p", str(o["ports"])]
        elif o.get("top_ports"):
            argv += ["-top-ports", str(o["top_ports"])]
        return argv

    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        p = ctx.evidence_dir / "naabu.jsonl"
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
            ip = d.get("ip") or d.get("host") or ctx.target
            port = d.get("port")
            if port is None:
                continue
            label, sev = _SENSITIVE.get(int(port), (d.get("service") or "", Severity.INFO))
            where = f"{ip}:{port}/tcp"
            out.append(self._f(
                run, ctx, target=where, severity=sev, confidence="confirmed",
                title=f"Open port {port}/tcp{f' - {label}' if label else ''}",
                description=f"naabu found {port}/tcp open on {ip}."
                            + (f" {label} is often high-value/misconfigured when internet-facing."
                               if sev != Severity.INFO else ""),
                evidence=line,
                poc=f"nmap -sV -p {port} {ip}",
                attack_path=("Enumerate the service for weak/no auth and known CVEs; "
                             "data stores on this list are frequently unauthenticated."
                             if sev != Severity.INFO else "Fingerprint and assess the service."),
                remediation="Restrict exposure to the networks that require it; require "
                            "authentication and TLS; patch to current.",
                tags=["port", *( [label.lower()] if label else [])],
            ))
        return out
