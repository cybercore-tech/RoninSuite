"""nmap - host discovery, port/service enumeration, NSE script findings."""
from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET

from ronin.config import INTENSITY
from ronin.core.models import Finding, Option, Severity, ToolRun
from ronin.tools.base import RunContext, ToolAdapter

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# NSE scripts whose output should be raised above INFO when they fire
_VULN_SCRIPTS = {"vulners", "vuln", "http-vuln", "smb-vuln", "ssl-poodle",
                 "ssl-heartbleed", "ssl-dh-params", "http-slowloris-check"}


class NmapAdapter(ToolAdapter):
    name = "nmap"
    binary = "nmap"
    summary = "Port & service enumeration with default + vuln NSE scripts."
    categories = ("scan",)
    doc_url = "https://nmap.org/book/man.html"
    install = {"pacman": "nmap"}
    default_timeout = 3600

    def options(self) -> list[Option]:
        return [
            Option(key="ports", label="Ports", kind="str", default="",
                   help="e.g. 22,80,443 or 1-65535. Empty = --top-ports 1000"),
            Option(key="pn", label="Skip host discovery (-Pn)", kind="bool", default=True),
            Option(key="scripts", label="NSE scripts", kind="str", default="default,vulners",
                   help="comma list passed to --script"),
            Option(key="udp", label="Also scan top UDP ports", kind="bool", default=False,
                   aggressive=True),
            Option(key="os_detect", label="OS detection (-O, needs root)", kind="bool",
                   default=False),
        ]

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = ctx.options
        timing = INTENSITY[ctx.intensity]["nmap_timing"]
        argv = ["nmap", f"-{timing}", "-sV", "--version-light",
                "-oX", str(ctx.out("nmap.xml")), "-oN", str(ctx.out("nmap.txt")),
                "--stats-every", "15s"]
        argv += ["-sS"] if os.geteuid() == 0 else ["-sT"]
        if o.get("pn"):
            argv.append("-Pn")
        if o.get("os_detect") and os.geteuid() == 0:
            argv.append("-O")
        scripts = (o.get("scripts") or "").strip()
        if scripts:
            argv += ["--script", scripts]
        if o.get("ports"):
            argv += ["-p", str(o["ports"])]
        else:
            argv += ["--top-ports", "1000"]
        if o.get("udp") and os.geteuid() == 0:
            argv += ["-sU", "--top-ports", "50"]
        argv.append(_bare_host(ctx.target))
        return argv

    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        xmlp = ctx.evidence_dir / "nmap.xml"
        if not xmlp.is_file():
            return []
        try:
            root = ET.parse(xmlp).getroot()
        except ET.ParseError:
            return []
        out: list[Finding] = []
        for host in root.findall("host"):
            addr = _host_addr(host)
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                pnum = port.get("portid")
                proto = port.get("protocol")
                svc = port.find("service")
                sname = svc.get("name", "unknown") if svc is not None else "unknown"
                product = " ".join(
                    x for x in [svc.get("product"), svc.get("version")] if x
                ) if svc is not None else ""
                where = f"{addr}:{pnum}/{proto}"
                out.append(self._f(
                    run, ctx, target=where, severity=Severity.INFO, confidence="confirmed",
                    title=f"Open port {pnum}/{proto} - {sname}"
                          + (f" ({product})" if product else ""),
                    description=f"nmap reports {sname} listening on {where}."
                                + (f" Banner: {product}." if product else ""),
                    evidence=ET.tostring(port, encoding="unicode").strip(),
                    poc=f"nmap -sV -p {pnum} {addr}",
                    remediation="Confirm the service is required and reachable only from "
                                "networks that need it; firewall or bind to localhost "
                                "otherwise. Keep the service patched.",
                    tags=["service", sname],
                ))
                # NSE script output attached to this port
                for scr in port.findall("script"):
                    out.append(self._script_finding(run, ctx, where, scr, addr, pnum))
            # host-level scripts (e.g. smb-os-discovery, smb-vuln-*)
            for scr in host.findall("./hostscript/script"):
                out.append(self._script_finding(run, ctx, addr, scr, addr, None))
        return [f for f in out if f is not None]

    def _script_finding(self, run, ctx, where, scr, addr, pnum) -> Finding | None:
        sid = scr.get("id", "")
        output = (scr.get("output") or "").strip()
        if not output:
            return None
        cves = sorted(set(m.upper() for m in _CVE_RE.findall(output)))
        vulnish = any(k in sid for k in _VULN_SCRIPTS) or "VULNERABLE" in output.upper()
        sev = Severity.INFO
        if cves and vulnish:
            sev = Severity.HIGH
        elif vulnish:
            sev = Severity.MEDIUM
        return self._f(
            run, ctx, target=where, severity=sev,
            confidence="firm" if vulnish else "tentative",
            title=f"NSE {sid}: {output.splitlines()[0][:110]}",
            description=f"Output of nmap NSE script `{sid}` against {where}.",
            evidence=output[:4000],
            cve=cves,
            poc=(f"nmap -p {pnum} --script {sid} {addr}" if pnum
                 else f"nmap --script {sid} {addr}"),
            remediation="Review the script output; if it confirms a known CVE, patch the "
                        "affected service to a fixed version.",
            references=[f"https://nmap.org/nsedoc/scripts/{sid}.html"],
            tags=["nse", sid],
        )


def _bare_host(t: str) -> str:
    if "://" in t:
        from urllib.parse import urlparse

        return urlparse(t).hostname or t
    return t.split("/")[0].split(":")[0] if t.count(":") == 1 else t.split("/")[0]


def _host_addr(host) -> str:
    for a in host.findall("address"):
        if a.get("addrtype") in ("ipv4", "ipv6"):
            return a.get("addr")
    hn = host.find("./hostnames/hostname")
    return hn.get("name") if hn is not None else "?"
