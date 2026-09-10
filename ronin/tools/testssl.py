"""testssl.sh - TLS/SSL configuration and known-vuln assessment."""
from __future__ import annotations

import json
import re

from ronin.core.models import Finding, Option, Severity, ToolRun
from ronin.tools.base import RunContext, ToolAdapter

_SEV = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW, "WARN": Severity.LOW, "INFO": Severity.INFO, "OK": Severity.INFO,
    "DEBUG": Severity.INFO,
}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


class TestsslAdapter(ToolAdapter):
    name = "testssl"
    binary = "testssl.sh"
    summary = "Deep TLS check: protocols, ciphers, cert, and named vulns (ROBOT, etc.)."
    categories = ("vuln", "web")
    doc_url = "https://github.com/drwetter/testssl.sh"
    install = {"pacman": "testssl.sh"}
    default_timeout = 1200

    def options(self) -> list[Option]:
        return [
            Option(key="starttls", label="STARTTLS protocol", kind="choice", default="",
                   choices=["", "smtp", "imap", "pop3", "ftp", "xmpp", "ldap", "postgres"],
                   help="set for non-HTTPS TLS services"),
            Option(key="fast", label="Fast mode (skip slow cipher probes)", kind="bool",
                   default=True),
        ]

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = ctx.options
        argv = ["testssl.sh", "--quiet", "--color", "0", "--warnings", "batch",
                "--jsonfile", str(ctx.out("testssl.json")),
                "--logfile", str(ctx.out("testssl.log"))]
        if o.get("fast"):
            argv += ["--fast"]
        if o.get("starttls"):
            argv += ["--starttls", str(o["starttls"])]
        argv.append(_hostport(ctx.target))
        return argv

    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        p = ctx.evidence_dir / "testssl.json"
        if not p.is_file():
            return []
        try:
            items = json.loads(p.read_text(errors="replace") or "[]")
        except json.JSONDecodeError:
            return []
        out: list[Finding] = []
        for it in items:
            sev_raw = (it.get("severity") or "INFO").upper()
            if sev_raw in ("OK", "INFO", "DEBUG"):
                continue  # keep the report signal-dense; raw log has everything
            sev = _SEV.get(sev_raw, Severity.INFO)
            fid = it.get("id", "")
            finding = it.get("finding", "")
            cves = sorted(set(m.upper() for m in _CVE_RE.findall(
                " ".join([it.get("cve", ""), finding]))))
            where = f"{it.get('ip', _hostport(ctx.target))}:{it.get('port', '443')}"
            out.append(self._f(
                run, ctx, target=where, severity=sev, confidence="firm",
                title=f"TLS: {fid} - {finding[:110]}",
                description=f"testssl.sh flagged `{fid}` on {where}: {finding}",
                evidence=json.dumps(it, indent=2),
                cve=cves, cwe=[it["cwe"]] if it.get("cwe") else [],
                poc=f"testssl.sh --severity {sev_raw} {where}",
                attack_path=_tls_path(fid),
                remediation=_tls_fix(fid),
                references=["https://ssl-config.mozilla.org/",
                            "https://github.com/drwetter/testssl.sh/blob/3.2/doc/testssl.1.md"],
                tags=["tls", fid],
            ))
        return out


def _hostport(t: str) -> str:
    if "://" in t:
        from urllib.parse import urlparse

        u = urlparse(t)
        return f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"
    return t if ":" in t else f"{t}:443"


def _tls_path(fid: str) -> str:
    f = fid.lower()
    if any(k in f for k in ("heartbleed", "robot", "ccs", "ticketbleed")):
        return "Direct memory/key disclosure - can lead to session or private-key theft."
    if any(k in f for k in ("sslv2", "sslv3", "poodle", "drown", "beast", "freak", "logjam")):
        return "Downgrade / decryption attack against a MITM-positioned adversary."
    if "cert" in f or "expire" in f or "chain" in f:
        return "Cert trust weakness enables convincing MITM / phishing of this host."
    return "Weak transport crypto assists interception or downgrade of client traffic."


def _tls_fix(fid: str) -> str:
    f = fid.lower()
    if "cert" in f or "expire" in f:
        return "Reissue/renew the certificate with a full valid chain from a trusted CA."
    return ("Adopt the Mozilla 'Intermediate' TLS profile: disable SSLv2/v3 and TLS 1.0/1.1, "
            "remove RC4/3DES/EXPORT/NULL ciphers, enable TLS 1.2+ with forward-secret suites.")
