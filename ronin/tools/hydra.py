"""hydra - online credential brute-force / password spraying.

Very aggressive and noisy, and it can lock accounts.  Keep lists small, respect
the engagement's business-hours rule, and confirm lockout policy first.
"""
from __future__ import annotations

import json
from pathlib import Path

from ronin.config import INTENSITY
from ronin.core.models import Finding, Option, Severity, ToolRun
from ronin.tools.base import RunContext, ToolAdapter

_COMMON_USERS = [
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "/usr/share/wordlists/metasploit/unix_users.txt",
]
_COMMON_PASS = [
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
    "/usr/share/wordlists/rockyou.txt",
]


class HydraAdapter(ToolAdapter):
    name = "hydra"
    binary = "hydra"
    summary = "Online login brute-force across many protocols (active, noisy)."
    categories = ("exploit",)
    doc_url = "https://github.com/vanhauser-thc/thc-hydra"
    install = {"pacman": "hydra"}
    aggressive = True
    default_timeout = 3600

    def options(self) -> list[Option]:
        return [
            Option(key="service", label="Service/module", kind="choice", default="ssh",
                   choices=["ssh", "ftp", "http-get", "http-post-form", "rdp", "smb",
                            "mysql", "postgres", "vnc", "smtp", "imap", "pop3"]),
            Option(key="username", label="Single username", kind="str", default="",
                   help="use this OR a userlist"),
            Option(key="userlist", label="Userlist path", kind="str", default=""),
            Option(key="passlist", label="Password list path", kind="str", default=""),
            Option(key="port", label="Port (blank = default)", kind="str", default=""),
            Option(key="form", label="http-post-form string", kind="str", default="",
                   help='e.g. "/login:user=^USER^&pass=^PASS^:F=incorrect"'),
            Option(key="tasks", label="Parallel tasks (-t)", kind="int", default=4,
                   aggressive=True),
        ]

    def _pick(self, given: str, candidates: list[str]) -> str | None:
        if given and Path(given).is_file():
            return given
        return next((c for c in candidates if Path(c).is_file()), None)

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = ctx.options
        host = ctx.target.split("://")[-1].split("/")[0].split(":")[0]
        service = o.get("service") or "ssh"
        out = ctx.out("hydra.json")
        argv = ["hydra", "-o", str(out), "-b", "json",
                "-t", str(o.get("tasks") or 4), "-I", "-f"]

        if o.get("username"):
            argv += ["-l", str(o["username"])]
        else:
            ul = self._pick(o.get("userlist", ""), _COMMON_USERS)
            if not ul:
                raise FileNotFoundError("no username / userlist - set 'username' or 'userlist'")
            argv += ["-L", ul]

        pl = self._pick(o.get("passlist", ""), _COMMON_PASS)
        if not pl:
            raise FileNotFoundError("no password list - set 'passlist' (e.g. rockyou)")
        argv += ["-P", pl]

        if o.get("port"):
            argv += ["-s", str(o["port"])]
        rate = INTENSITY[ctx.intensity]["concurrency"]
        argv += ["-w", "5", "-W", str(max(1, 30 // max(rate, 1)))]

        target = f"{service}://{host}"
        if service == "http-post-form" and o.get("form"):
            target += o["form"] if str(o["form"]).startswith("/") else "/" + str(o["form"])
        argv.append(target)
        return argv

    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        p = ctx.evidence_dir / "hydra.json"
        if not p.is_file():
            return []
        try:
            data = json.loads(p.read_text(errors="replace") or "{}")
        except json.JSONDecodeError:
            return []
        out: list[Finding] = []
        for r in data.get("results", []):
            host = r.get("host", ctx.target)
            login = r.get("login", "")
            pw = r.get("password", "")
            port = r.get("port", "")
            out.append(self._f(
                run, ctx, target=f"{host}:{port}" if port else host,
                severity=Severity.CRITICAL, confidence="confirmed",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                title=f"Valid credentials found: {login}:{pw} on {host}",
                description=f"hydra authenticated to {host} as `{login}` with password "
                            f"`{pw}` via {r.get('service', ctx.options.get('service'))}.",
                evidence=json.dumps(r, indent=2),
                poc=f"# service {r.get('service','')} on {host}:{port}\n"
                    f"#   username: {login}\n#   password: {pw}",
                attack_path=("Direct authenticated access. Pivot: reuse the credential "
                             "across other services/hosts, escalate privileges, establish "
                             "persistence."),
                remediation="Reset the credential immediately. Enforce a strong password "
                            "policy + MFA, lockout/backoff on failed logins, and restrict "
                            "the exposed service to trusted networks.",
                references=["https://owasp.org/www-community/attacks/Brute_force_attack"],
                cwe=["CWE-307", "CWE-521"],
                tags=["hydra", "credentials", str(r.get("service", ""))],
            ))
        if not out:
            out.append(self._f(
                run, ctx, target=ctx.target, severity=Severity.INFO, confidence="firm",
                title="No valid credentials recovered",
                description="hydra completed without finding a working login for the "
                            "supplied lists.",
                remediation="No action. A negative result is not proof of a strong policy - "
                            "review lockout and MFA configuration separately.",
                tags=["hydra"],
            ))
        return out
