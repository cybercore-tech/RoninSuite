"""Runtime paths and settings for RoninSuite.

Everything is resolved relative to a single project root so the whole folder
(code + engagements + reports + db) can be copied onto a USB stick and run from
any Linux host.  Root resolution order:

1. ``$RONIN_HOME`` if set.
2. The repository root that contains this ``ronin`` package (walk up until a
   ``pyproject.toml`` or ``.git`` is found).
3. The current working directory (last resort).
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


def _detect_root() -> Path:
    env = os.environ.get("RONIN_HOME")
    if env:
        return Path(env).expanduser().resolve()
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        if (parent / "pyproject.toml").is_file() or (parent / ".git").exists():
            return parent
    return Path.cwd().resolve()


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
