"""`ronin doctor` - detect the offensive toolchain and (optionally) install it on Arch.

Install strategy, in order of preference per tool:
  1. pacman  (official repos)      - sudo pacman -S --needed <pkg>
  2. AUR     (via yay)             - yay -S --needed <pkg>
  3. go install                    - GOBIN=~/.local/bin go install <module>
  4. pipx / uv tool                - for Python CLIs

Nothing is installed without ``--install``.  Go-based tools land in
``~/.local/bin`` so they work from a normal user account.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from ronin.tools.registry import CATALOG, adapters


@dataclass
class ToolStatus:
    name: str
    category: str
    binary: str
    installed: bool
    path: str | None
    has_adapter: bool
    aggressive: bool
    recipe: dict


def _binary_for(name: str, meta: dict) -> str:
    if name in adapters():
        return adapters()[name].resolved_binary
    return meta.get("binary", name)


def survey() -> list[ToolStatus]:
    ads = adapters()
    out: list[ToolStatus] = []
    for name, meta in sorted(CATALOG.items(), key=lambda kv: (kv[1]["category"], kv[0])):
        binary = _binary_for(name, meta)
        path = shutil.which(binary)
        agg = meta.get("aggressive", False) or (name in ads and ads[name].aggressive)
        out.append(ToolStatus(
            name=name, category=meta["category"], binary=binary,
            installed=path is not None, path=path,
            has_adapter=name in ads, aggressive=agg,
            recipe=meta.get("install", {}),
        ))
    return out


def _run(cmd: list[str], dry: bool) -> bool:
    print("   $", " ".join(cmd))
    if dry:
        return True
    try:
        return subprocess.run(cmd).returncode == 0
    except FileNotFoundError:
        print("   ! command not found:", cmd[0])
        return False


def install(names: list[str], *, dry_run: bool = False) -> dict[str, str]:
    """Attempt to install each named tool.  Returns {name: outcome}."""
    have_yay = shutil.which("yay") is not None
    have_go = shutil.which("go") is not None
    gobin = os.path.expanduser("~/.local/bin")
    results: dict[str, str] = {}
    statuses = {s.name: s for s in survey()}

    for name in names:
        st = statuses.get(name)
        if not st:
            results[name] = "unknown tool"
            continue
        if st.installed:
            results[name] = f"already installed ({st.path})"
            continue
        r = st.recipe
        ok = False
        if "pacman" in r:
            ok = _run(["sudo", "pacman", "-S", "--needed", "--noconfirm", r["pacman"]], dry_run)
        if not ok and "aur" in r and have_yay:
            ok = _run(["yay", "-S", "--needed", "--noconfirm", r["aur"]], dry_run)
        if not ok and "go" in r and have_go:
            env = {**os.environ, "GOBIN": gobin}
            print("   $ GOBIN=%s go install %s" % (gobin, r["go"]))
            if dry_run:
                ok = True
            else:
                ok = subprocess.run(["go", "install", r["go"]], env=env).returncode == 0
        if not ok and "pipx" in r:
            runner = ["uv", "tool", "install"] if shutil.which("uv") else ["pipx", "install"]
            ok = _run(runner + [r["pipx"]], dry_run)
        results[name] = "installed" if ok else "FAILED - install manually: " + str(r)
    return results
