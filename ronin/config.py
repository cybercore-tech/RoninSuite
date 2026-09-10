"""Runtime paths and settings for RoninSuite.

Data (engagements, reports, ronin.db, audit.log) lives under one root, resolved:

1. ``$RONIN_HOME`` if set.
2. **Portable / USB mode** - if a ``.ronin-portable`` marker sits next to the
   code, the code folder IS the root, so everything travels with the stick
   (``scripts/make-usb.sh`` drops that marker).
3. **Legacy** - if ``ronin.db`` already sits in the code folder (pre-split
   installs), keep using it in place.
4. **System install** - ``$XDG_DATA_HOME/roninsuite`` (``~/.local/share/roninsuite``),
   kept separate from the code checkout.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


def _repo_dir() -> Path | None:
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        if (parent / "pyproject.toml").is_file() or (parent / ".git").exists():
            return parent
    return None


def _detect_root() -> Path:
    env = os.environ.get("RONIN_HOME")
    if env:
        return Path(env).expanduser().resolve()
    repo = _repo_dir()
    if repo is not None:
        if (repo / ".ronin-portable").exists():
            return repo                       # USB / portable — data travels with the folder
        if (repo / "ronin.db").exists():
            return repo                       # legacy in-repo data (pre-split)
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else (Path.home() / ".local" / "share")
    return (base / "roninsuite").resolve()


class Paths:
    """Lazily-created directory layout under the project root."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or _detect_root()
        # a fresh $RONIN_HOME (e.g. first run, or a USB launcher) may not exist yet
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    # --- files ---------------------------------------------------------------
    @property
    def db(self) -> Path:
        return self.root / "ronin.db"

    @property
    def audit_log(self) -> Path:
        return self.root / "audit.log"

    @property
    def env_file(self) -> Path:
        return self.root / ".env"

    # --- directories ------------------------------------------------------------
    @property
    def engagements(self) -> Path:
        return self._ensure(self.root / "engagements")

    @property
    def reports(self) -> Path:
        return self._ensure(self.root / "reports")

    @property
    def cache(self) -> Path:
        return self._ensure(self.root / ".cache")

    def engagement_dir(self, slug: str) -> Path:
        return self._ensure(self.engagements / slug)

    def scope_file(self, slug: str) -> Path:
        return self.engagement_dir(slug) / "scope.yaml"

    def evidence_dir(self, slug: str, run_id: str) -> Path:
        return self._ensure(self.engagement_dir(slug) / "evidence" / run_id)

    def report_dir(self, slug: str, stamp: str) -> Path:
        return self._ensure(self.reports / slug / stamp)

    @staticmethod
    def _ensure(p: Path) -> Path:
        p.mkdir(parents=True, exist_ok=True)
        return p


@lru_cache(maxsize=1)
def paths() -> Paths:
    return Paths()


def load_dotenv() -> None:
    """Minimal .env loader (no dependency).  Values already in the environment win."""
    f = paths().env_file
    if not f.is_file():
        return
    for line in f.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


# Intensity presets - deliberately conservative so a scan never knocks over a
# small client.  Adapters translate these to tool-specific flags.
INTENSITY = {
    "stealth": {"nmap_timing": "T2", "rate": 50, "concurrency": 10},
    "normal": {"nmap_timing": "T3", "rate": 150, "concurrency": 25},
    "aggressive": {"nmap_timing": "T4", "rate": 500, "concurrency": 50},
}
DEFAULT_INTENSITY = "normal"
