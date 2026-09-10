"""httpx (ProjectDiscovery) - live web host probing, tech + TLS + header hygiene."""
from __future__ import annotations

import json
import shutil
import subprocess

from ronin.config import INTENSITY
from ronin.core.models import Finding, Option, Severity, ToolRun
from ronin.tools.base import RunContext, ToolAdapter

_SEC_HEADERS = {
    "strict-transport-security": ("HSTS not set", Severity.LOW,
        "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`."),
    "content-security-policy": ("No Content-Security-Policy", Severity.LOW,
        "Define a CSP that restricts script/style/frame sources to break XSS chains."),
    "x-frame-options": ("Clickjacking protection missing", Severity.LOW,
        "Send `X-Frame-Options: DENY` or a CSP `frame-ancestors` directive."),
    "x-content-type-options": ("MIME-sniffing not disabled", Severity.INFO,
        "Send `X-Content-Type-Options: nosniff`."),
}


class HttpxAdapter(ToolAdapter):
    name = "httpx"
    binary = "httpx"
    summary = "Probe which hosts serve HTTP(S); grab status, title, tech, server, TLS."
    categories = ("web", "recon")
    doc_url = "https://github.com/projectdiscovery/httpx"
    install = {"go": "github.com/projectdiscovery/httpx/cmd/httpx@latest", "pacman": "httpx"}
    default_timeout = 900

    def is_installed(self) -> bool:
        """Guard against the unrelated Python `httpx` package's console script."""
        path = shutil.which(self.resolved_binary)
        if not path:
            return False
        try:
            if open(path, "rb").read(2) == b"#!":        # a script shim, not the Go tool
                return False
            r = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=8)
            return "projectdiscovery" in (r.stdout + r.stderr).lower() or r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return True

    def options(self) -> list[Option]:
        return [
            Option(key="ports", label="Extra ports", kind="str", default="",
                   help="comma list, e.g. 8080,8443"),
            Option(key="paths", label="Probe paths", kind="str", default="",
                   help="comma list of paths to also request, e.g. /,/admin"),
            Option(key="follow_redirects", label="Follow redirects", kind="bool", default=True),
        ]

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = ctx.options
        conc = INTENSITY[ctx.intensity]["concurrency"]
        argv = [
            "httpx", "-u", ctx.target, "-json",
            "-o", str(ctx.out("httpx.jsonl")),
            "-status-code", "-title", "-tech-detect", "-web-server",
            "-tls-grab", "-ip", "-cname", "-include-response-header",
            "-no-color", "-silent", "-threads", str(conc),
        ]
        if o.get("follow_redirects"):
            argv.append("-follow-redirects")
        if o.get("ports"):
            argv += ["-ports", str(o["ports"])]
        if o.get("paths"):
            argv += ["-path", str(o["paths"])]
        return argv

    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        p = ctx.evidence_dir / "httpx.jsonl"
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
            url = d.get("url") or d.get("input") or ctx.target
            sc = d.get("status_code")
            tech = d.get("tech") or d.get("technologies") or []
            server = d.get("webserver") or d.get("server") or ""
            title = d.get("title") or ""
            out.append(self._f(
                run, ctx, target=url, severity=Severity.INFO, confidence="confirmed",
                title=f"Live HTTP service {sc} - {title[:80] or url}",
                description="; ".join(filter(None, [
                    f"status {sc}", f"server: {server}" if server else "",
                    f"tech: {', '.join(tech)}" if tech else "",
                    f"ip: {d.get('host','')}" if d.get("host") else "",
                ])),
                evidence=json.dumps(d, indent=2)[:4000],
                poc=f"curl -skiL {url}",
                remediation="Inventory item. Ensure this endpoint is meant to be exposed.",
                tags=["web", *(["tech:" + t for t in tech])],
            ))
            # header hygiene (only meaningful for 2xx/3xx)
            hdrs = {k.lower(): v for k, v in (d.get("header") or d.get("response_headers") or {}).items()} \
                if isinstance(d.get("header") or d.get("response_headers"), dict) else {}
            raw_hdr = (d.get("raw_header") or "").lower()
            if sc and 200 <= int(sc) < 400:
                for h, (msg, sev, fix) in _SEC_HEADERS.items():
                    present = h in hdrs or (h + ":") in raw_hdr
                    if not present:
                        out.append(self._f(
                            run, ctx, target=url, severity=sev, confidence="firm",
                            title=f"{msg} ({url})",
                            description=f"Response from {url} is missing the `{h}` header.",
                            evidence=d.get("raw_header", "")[:2000],
                            poc=f"curl -skI {url}",
                            remediation=fix,
                            references=["https://owasp.org/www-project-secure-headers/"],
                            cwe=["CWE-693"],
                            tags=["headers", h],
                        ))
            if server and any(c.isdigit() for c in server):
                out.append(self._f(
                    run, ctx, target=url, severity=Severity.INFO, confidence="firm",
                    title=f"Server version disclosed: {server}",
                    description=f"The `Server` header on {url} reveals `{server}`, aiding "
                                "targeted exploit selection.",
                    poc=f"curl -skI {url} | grep -i ^server",
                    remediation="Suppress or genericize the Server/X-Powered-By banners.",
                    cwe=["CWE-200"], tags=["headers", "banner"],
                ))
        return out
