"""Toolchain provisioning for ``ronin doctor`` / ``ronin add`` / ``ronin update``.

Install strategy per recipe, tried in order:
  1. pacman  (official repos)   - sudo pacman -S --needed <pkg>
  2. AUR     (via yay)          - yay -S --needed <pkg>
  3. go install                 - GOBIN=~/.local/bin go install <module>
  4. pipx / uv tool             - Python CLIs
  5. git                        - clone into $RONIN_HOME/tools/<name> (not on PATH)

Nothing is installed without an explicit action.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from ronin.config import paths
from ronin.data.extended_tools import EXTENDED
from ronin.tools.registry import CATALOG, adapters

_GOBIN = os.path.expanduser("~/.local/bin")


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
    extended: bool = False
    desc: str = ""


def _binary_for(name: str, meta: dict) -> str:
    if name in adapters():
        return adapters()[name].resolved_binary
    return meta.get("binary", name)


def catalog_lookup(name: str) -> dict | None:
    """Return {'category','recipe','desc','extended','binary'} for a tool name, or None."""
    if name in CATALOG:
        m = CATALOG[name]
        return {"category": m["category"], "recipe": m.get("install", {}),
                "desc": (adapters()[name].summary if name in adapters() else ""),
                "extended": False, "binary": _binary_for(name, m)}
    if name in EXTENDED:
        m = EXTENDED[name]
        return {"category": m["category"], "recipe": m.get("install", {}),
                "desc": m.get("desc", ""), "extended": True,
                "binary": m.get("binary", name)}
    return None


def survey(include_extended: bool = False) -> list[ToolStatus]:
    ads = adapters()
    out: list[ToolStatus] = []
    for name, meta in sorted(CATALOG.items(), key=lambda kv: (kv[1]["category"], kv[0])):
        binary = _binary_for(name, meta)
        path = shutil.which(binary)
        agg = meta.get("aggressive", False) or (name in ads and ads[name].aggressive)
        out.append(ToolStatus(
            name=name, category=meta["category"], binary=binary,
            installed=path is not None, path=path, has_adapter=name in ads,
            aggressive=agg, recipe=meta.get("install", {}),
            desc=ads[name].summary if name in ads else ""))
    if include_extended:
        for name, meta in sorted(EXTENDED.items(), key=lambda kv: (kv[1]["category"], kv[0])):
            binary = meta.get("binary", name)
            path = shutil.which(binary)
            out.append(ToolStatus(
                name=name, category=meta["category"], binary=binary,
                installed=path is not None, path=path, has_adapter=False,
                aggressive=False, recipe=meta.get("install", {}),
                extended=True, desc=meta.get("desc", "")))
    return out


def _sh(cmd: list[str], dry: bool) -> bool:
    print("   $", " ".join(cmd))
    if dry:
        return True
    try:
        return subprocess.run(cmd).returncode == 0
    except FileNotFoundError:
        print("   ! command not found:", cmd[0])
        return False


def install_recipe(name: str, recipe: dict, *, dry_run: bool = False,
                   update: bool = False) -> str:
    """Run a single recipe.  Returns a short outcome string."""
    if not recipe:
        return "no install recipe - add it manually"
    have_yay = shutil.which("yay") is not None
    have_go = shutil.which("go") is not None
    needed = [] if update else ["--needed"]
    ok = False
    if "pacman" in recipe:
        ok = _sh(["sudo", "pacman", "-S", *needed, "--noconfirm", recipe["pacman"]], dry_run)
    if not ok and "aur" in recipe and have_yay:
        ok = _sh(["yay", "-S", *needed, "--noconfirm", recipe["aur"]], dry_run)
    if not ok and "go" in recipe and have_go:
        print(f"   $ GOBIN={_GOBIN} go install {recipe['go']}")
        ok = dry_run or subprocess.run(
            ["go", "install", recipe["go"]], env={**os.environ, "GOBIN": _GOBIN}
        ).returncode == 0
    if not ok and "pipx" in recipe:
        runner = ["uv", "tool", "install"] if shutil.which("uv") else ["pipx", "install"]
        if update:
            runner = (["uv", "tool", "upgrade"] if shutil.which("uv")
                      else ["pipx", "upgrade"])
        ok = _sh(runner + [recipe["pipx"]], dry_run)
    if not ok and "git" in recipe:
        dest = paths().root / "tools" / name
        if dest.exists():
            ok = _sh(["git", "-C", str(dest), "pull", "--ff-only"], dry_run)
        else:
            (paths().root / "tools").mkdir(parents=True, exist_ok=True)
            ok = _sh(["git", "clone", "--depth", "1", recipe["git"], str(dest)], dry_run)
        if ok:
            return f"cloned to {dest} (not on PATH - run its script directly)"
    if ok:
        return "updated" if update else "installed"
    return "FAILED - install manually: " + str(recipe)


def install(names: list[str], *, dry_run: bool = False) -> dict[str, str]:
    """Install named tools from the core or extended catalog."""
    installed = {s.name: s for s in survey(include_extended=True)}
    out: dict[str, str] = {}
    for name in names:
        st = installed.get(name)
        info = catalog_lookup(name)
        if not info:
            out[name] = "unknown tool (try `ronin add --search <text>`)"
            continue
        if st and st.installed:
            out[name] = f"already installed ({st.path})"
            continue
        out[name] = install_recipe(name, info["recipe"], dry_run=dry_run)
    return out


def update(names: list[str], *, dry_run: bool = False) -> dict[str, str]:
    """Update already-installed tools to their latest version."""
    installed = {s.name: s for s in survey(include_extended=True)}
    out: dict[str, str] = {}
    for name in names:
        st = installed.get(name)
        info = catalog_lookup(name)
        if not info:
            out[name] = "unknown tool"
            continue
        if not (st and st.installed):
            out[name] = "not installed - use `ronin add`"
            continue
        out[name] = install_recipe(name, info["recipe"], dry_run=dry_run, update=True)
    if "nuclei" in names and shutil.which("nuclei"):
        _sh(["nuclei", "-update-templates", "-silent"], dry_run)
        out["nuclei-templates"] = "refreshed"
    return out
