"""Toolchain currency: what's installed, what's the latest, what needs attention.

Best-effort and network-tolerant.  Results are cached in the ``state`` table so
the Updates tab can show "last checked N ago" without hammering GitHub.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass, field

from ronin.core import db
from ronin.tools.registry import CATALOG, adapters

_VER_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)?)")
_STATE_KEY = "updates.cache"
_TPL_KEY = "updates.nuclei_templates"


@dataclass
class ToolUpdate:
    name: str
    category: str
    installed: bool
    installed_version: str = ""
    latest_version: str = ""
    source: str = ""                 # pacman | aur | go | github
    status: str = "unknown"          # current | outdated | missing | unknown
    note: str = ""


@dataclass
class UpdateReport:
    tools: list[ToolUpdate] = field(default_factory=list)
    checked_at: _dt.datetime | None = None
    nuclei_templates_age_days: int | None = None
    pacman_updates: list[str] = field(default_factory=list)

    @property
    def outdated(self) -> list[ToolUpdate]:
        return [t for t in self.tools if t.status == "outdated"]

    @property
    def missing(self) -> list[ToolUpdate]:
        return [t for t in self.tools if not t.installed]


def _run(cmd: list[str], timeout: int = 8) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + "\n" + r.stderr).strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _installed_version(binary: str) -> str:
    for flag in ("-version", "--version", "-V", "version"):
        out = _run([binary, flag])
        if not out:
            continue
        # prefer a line that actually mentions a version, to avoid matching
        # incidental numbers (IPs in help text, years, etc.)
        for line in out.splitlines():
            if re.search(r"version|v\d", line, re.I) and "127.0.0" not in line:
                m = _VER_RE.search(line)
                if m:
                    return m.group(1)
        m = _VER_RE.search(out.splitlines()[0])
        if m and "127.0.0" not in out.splitlines()[0]:
            return m.group(1)
    return ""


def _github_repo_from_go(module: str) -> str | None:
    # github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest -> projectdiscovery/nuclei
    m = re.match(r"github\.com/([^/]+)/([^/@]+)", module)
    return f"{m.group(1)}/{m.group(2)}" if m else None


def _latest_github(repo: str) -> str:
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/releases/latest",
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "roninsuite-updates"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            tag = json.loads(resp.read()).get("tag_name", "")
        m = _VER_RE.search(tag)
        return m.group(1) if m else ""
    except Exception:
        return ""


def _pacman_upgradable() -> list[str]:
    if not shutil.which("pacman"):
        return []
    out = _run(["pacman", "-Qu"], timeout=10)
    return [ln.split()[0] for ln in out.splitlines() if ln and not ln.startswith("::")]


def _nuclei_templates_age() -> int | None:
    from pathlib import Path

    for p in (Path.home() / ".local/nuclei-templates",
              Path.home() / "nuclei-templates",
              Path.home() / ".config/nuclei/.templates-config.json"):
        if p.exists():
            mtime = _dt.datetime.fromtimestamp(p.stat().st_mtime)
            return (_dt.datetime.now() - mtime).days
    return None


def check(*, online: bool = True) -> UpdateReport:
    """Run the full check and cache it.  ``online=False`` skips network lookups."""
    ads = adapters()
    pac = _pacman_upgradable() if online else []
    rep = UpdateReport(checked_at=_dt.datetime.now(_dt.timezone.utc),
                       pacman_updates=pac,
                       nuclei_templates_age_days=_nuclei_templates_age())

    for name, meta in sorted(CATALOG.items(), key=lambda kv: (kv[1]["category"], kv[0])):
        binary = ads[name].resolved_binary if name in ads else meta.get("binary", name)
        path = shutil.which(binary)
        tu = ToolUpdate(name=name, category=meta["category"], installed=path is not None)
        recipe = meta.get("install", {})
        if not path:
            tu.status = "missing"
            tu.source = next(iter(recipe), "")
            rep.tools.append(tu)
            continue
        tu.installed_version = _installed_version(binary)
        if "pacman" in recipe:
            tu.source = "pacman"
            tu.status = "outdated" if recipe["pacman"] in pac else "current"
        elif "go" in recipe and online:
            tu.source = "go"
            repo = _github_repo_from_go(recipe["go"])
            tu.latest_version = _latest_github(repo) if repo else ""
            if tu.latest_version and tu.installed_version:
                tu.status = ("outdated"
                             if _cmp(tu.installed_version, tu.latest_version) < 0
                             else "current")
        elif "aur" in recipe:
            tu.source = "aur"
            tu.status = "unknown"
            tu.note = "check with your AUR helper (yay -Qua)"
        rep.tools.append(tu)

    db.set_state(_STATE_KEY, json.dumps({
        "checked_at": rep.checked_at.isoformat(),
        "tools": [t.__dict__ for t in rep.tools],
        "pacman_updates": pac,
        "nuclei_templates_age_days": rep.nuclei_templates_age_days,
    }))
    return rep


def cached() -> UpdateReport | None:
    raw = db.get_state(_STATE_KEY, "")
    if not raw:
        return None
    try:
        d = json.loads(raw)
    except json.JSONDecodeError:
        return None
    rep = UpdateReport(
        checked_at=_dt.datetime.fromisoformat(d["checked_at"]),
        pacman_updates=d.get("pacman_updates", []),
        nuclei_templates_age_days=d.get("nuclei_templates_age_days"),
    )
    rep.tools = [ToolUpdate(**t) for t in d.get("tools", [])]
    return rep


def _cmp(a: str, b: str) -> int:
    pa = [int(x) for x in a.split(".")]
    pb = [int(x) for x in b.split(".")]
    return (pa > pb) - (pa < pb)
