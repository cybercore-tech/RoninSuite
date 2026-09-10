"""commix - automated OS command injection detection and exploitation (active)."""
from __future__ import annotations

import re

from ronin.core.models import Finding, Option, Severity, ToolRun
from ronin.tools.base import RunContext, ToolAdapter

_HIT_RE = re.compile(
    r"(?:parameter '(?P<param>[^']+)' is vulnerable|"
    r"appears to be injectable|the .* parameter '(?P<param2>[^']+)'.*injectable)", re.I)


class CommixAdapter(ToolAdapter):
    name = "commix"
    binary = "commix"
    summary = "Detect & exploit OS command injection in a URL/parameter (active)."
    categories = ("exploit",)
    doc_url = "https://github.com/commixproject/commix/wiki"
    install = {"aur": "commix"}
    aggressive = True
    default_timeout = 3600

    def options(self) -> list[Option]:
        return [
            Option(key="data", label="POST data", kind="str", default=""),
            Option(key="param", label="Test only this parameter (-p)", kind="str", default=""),
            Option(key="level", label="Level (1-3)", kind="int", default=1, aggressive=True),
            Option(key="technique", label="Techniques (ctfeo)", kind="str", default=""),
        ]

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = ctx.options
        argv = ["commix", "--url", ctx.target, "--batch",
                "--output-dir", str(ctx.evidence_dir),
                "--level", str(o.get("level") or 1)]
        if o.get("data"):
            argv += ["--data", str(o["data"])]
        if o.get("param"):
            argv += ["-p", str(o["param"])]
        if o.get("technique"):
            argv += ["--technique", str(o["technique"])]
        return argv

    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        log = ctx.evidence_dir / "stdout.log"
        text = log.read_text(errors="replace") if log.is_file() else ""
        if not text:
            return []
        params: set[str] = set()
        injectable = False
        for m in _HIT_RE.finditer(text):
            injectable = True
            p = m.group("param") or m.group("param2")
            if p:
                params.add(p)
        if not injectable:
            if re.search(r"(all tested parameters .* not injectable|does not seem to be injectable)", text, re.I):
                return [self._f(
                    run, ctx, target=ctx.target, severity=Severity.INFO, confidence="firm",
                    title="No command injection detected",
                    description="commix tested the parameters and did not confirm OS "
                                "command injection at the configured level.",
                    evidence="\n".join(_grep(text, "testing", "not injectable"))[:2000],
                    remediation="No action. Consider a higher --level or authenticated testing.",
                    tags=["commix"])]
            return []

        return [self._f(
            run, ctx, target=ctx.target, severity=Severity.CRITICAL, confidence="confirmed",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            title="OS command injection"
                  + (f" via parameter(s) {', '.join(sorted(params))}" if params else ""),
            description="commix confirmed OS command injection - arbitrary commands run on "
                        "the web host with the privileges of the web process.",
            evidence="\n".join(_grep(text, "vulnerable", "injectable", "Payload",
                                     "command(s)", "pseudo-terminal"))[:4000],
            poc=" ".join(run.argv) + "   # then --os-shell for an interactive shell",
            attack_path=("Immediate code execution on the server -> read app secrets, pivot "
                         "to the internal network, establish persistence."),
            remediation="Never pass user input to a shell. Use language-native APIs with an "
                        "argument vector (no shell), strict allow-listing, and least "
                        "privilege for the web process. Retest with the same command.",
            references=["https://owasp.org/www-community/attacks/Command_Injection"],
            cwe=["CWE-78"],
            tags=["commix", "cmdi"])]


def _grep(text: str, *needles: str) -> list[str]:
    return [ln for ln in text.splitlines() if any(n.lower() in ln.lower() for n in needles)]
