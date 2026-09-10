"""nuclei (ProjectDiscovery) - template-based vulnerability scanning.

Richest single source of normalized findings: nuclei's JSONL already carries
severity, CVE/CWE classification, a CVSS vector, references, and a repro
``curl-command``.  We map that straight onto :class:`Finding`.
"""
from __future__ import annotations

import json

from ronin.config import INTENSITY
from ronin.core.models import Finding, Option, Severity, ToolRun
from ronin.tools.base import RunContext, ToolAdapter

_SEV_MAP = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL, "unknown": Severity.INFO,
}


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    binary = "nuclei"
    summary = "Community template vulnerability scanner (CVEs, misconfig, exposures)."
    categories = ("vuln",)
    doc_url = "https://docs.projectdiscovery.io/tools/nuclei"
    install = {"pacman": "nuclei",
               "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}
    default_timeout = 3600

    def options(self) -> list[Option]:
        return [
            Option(key="severity", label="Severities", kind="str",
                   default="low,medium,high,critical",
                   help="comma list: info,low,medium,high,critical"),
            Option(key="tags", label="Only these tags", kind="str", default="",
                   help="e.g. cve,exposure,misconfig"),
            Option(key="exclude_tags", label="Exclude tags", kind="str",
                   default="fuzz,dos,intrusive"),
            Option(key="dast", label="Enable DAST / fuzzing templates", kind="bool",
                   default=False, aggressive=True),
            Option(key="rate", label="Requests/sec cap", kind="int", default=0,
                   help="0 = use intensity preset"),
        ]

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = ctx.options
        rate = int(o.get("rate") or INTENSITY[ctx.intensity]["rate"])
        argv = [
            "nuclei", "-u", ctx.target, "-jsonl",
            "-output", str(ctx.out("nuclei.jsonl")),
            "-no-color", "-stats", "-rate-limit", str(rate),
            "-timeout", "10", "-retries", "1",
            "-include-rr",                       # embed request/response for PoC
        ]
        if o.get("severity"):
            argv += ["-severity", str(o["severity"])]
        if o.get("tags"):
            argv += ["-tags", str(o["tags"])]
        if o.get("exclude_tags") and not o.get("dast"):
            argv += ["-exclude-tags", str(o["exclude_tags"])]
        if o.get("dast"):
            argv += ["-dast"]
        return argv

    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        p = ctx.evidence_dir / "nuclei.jsonl"
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
            info = d.get("info", {})
            cls = info.get("classification") or {}
            sev = _SEV_MAP.get((info.get("severity") or "info").lower(), Severity.INFO)
            matched = d.get("matched-at") or d.get("host") or ctx.target
            vector = _first(cls.get("cvss-metrics"))
            score = cls.get("cvss-score")
            refs = list(info.get("reference") or [])
            cves = [c.upper() for c in _aslist(cls.get("cve-id"))]
            cwes = [c.upper() for c in _aslist(cls.get("cwe-id"))]

            req = d.get("request")
            resp = d.get("response")
            poc = d.get("curl-command") or (f"nuclei -id {d.get('template-id')} -u {matched}")

            out.append(self._f(
                run, ctx, target=matched, severity=sev, confidence="firm",
                cvss_vector=f"CVSS:3.1/{vector}" if vector and not vector.startswith("CVSS") else vector,
                cvss_score=float(score) if isinstance(score, (int, float)) else None,
                title=info.get("name") or d.get("template-id") or "nuclei finding",
                description=(info.get("description") or "").strip()
                            or f"nuclei template `{d.get('template-id')}` matched {matched}.",
                evidence=(d.get("extracted-results") and json.dumps(d["extracted-results"]))
                         or d.get("matcher-name") or json.dumps(d)[:2000],
                request=req, response=(resp[:8000] if isinstance(resp, str) else None),
                poc=poc,
                attack_path=_attack_path(info, cves),
                remediation=(info.get("remediation") or "").strip()
                            or "Apply the vendor patch or configuration change referenced "
                               "above; retest with the same template.",
                references=refs, cve=cves, cwe=cwes,
                tags=["nuclei", d.get("template-id", ""), *(_aslist(info.get("tags")))],
            ))
        return out


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _aslist(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [x.strip() for x in v.replace(",", " ").split() if x.strip()]
    return [str(x) for x in v]


def _attack_path(info: dict, cves: list[str]) -> str:
    sev = (info.get("severity") or "").lower()
    if sev in ("high", "critical"):
        base = ("Directly exploitable from the stated position - chain into initial "
                "access / code execution.")
    elif sev == "medium":
        base = ("Use as a stepping stone: combine with credential reuse or another "
                "medium finding to escalate.")
    else:
        base = "Low direct impact; useful for fingerprinting and target selection."
    if cves:
        base += f" Public exploit likely for {', '.join(cves)}."
    return base
