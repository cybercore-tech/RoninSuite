"""Tool adapter contract.

Each supported tool is one subclass of :class:`ToolAdapter`.  An adapter knows
how to (a) tell whether the tool is installed and how to install it on Arch,
(b) build a safe argv for a target, and (c) parse the tool's machine-readable
output into normalized :class:`~ronin.core.models.Finding` objects.
"""
from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ronin.core.models import Finding, Option, ToolRun


@dataclass
class RunContext:
    engagement: str
    target: str
    evidence_dir: Path
    options: dict
    intensity: str = "normal"
    # output files the adapter asked the tool to write, filled in by build_argv
    result_files: list[Path] = field(default_factory=list)

    def out(self, name: str) -> Path:
        p = self.evidence_dir / name
        self.result_files.append(p)
        return p


class ToolAdapter(ABC):
    # --- identity (override) ------------------------------------------------
    name: str = ""
    binary: str = ""
    summary: str = ""
    categories: tuple[str, ...] = ()
    doc_url: str = ""
    #: install recipes, tried in order by `ronin doctor` on Arch
    install: dict[str, str] = {}
    #: True => the tool actively attacks / brute-forces; TUI & CLI gate it
    aggressive: bool = False
    default_timeout: int = 1800

    # --- capability -------------------------------------------------------------
    @property
    def resolved_binary(self) -> str:
        return self.binary or self.name

    def is_installed(self) -> bool:
        return shutil.which(self.resolved_binary) is not None

    def version(self) -> str:
        return ""

    # --- options -------------------------------------------------------------
    def options(self) -> list[Option]:
        return []

    def option_defaults(self) -> dict:
        return {o.key: o.default for o in self.options()}

    # --- execution ----------------------------------------------------------
    @abstractmethod
    def build_argv(self, ctx: RunContext) -> list[str]:
        """Return the full command.  Use ``ctx.out('name')`` for result files."""

    @abstractmethod
    def parse(self, run: ToolRun, ctx: RunContext) -> list[Finding]:
        """Turn the tool's output files / stdout into Findings."""

    # --- helpers for subclasses ------------------------------------------------
    def _f(self, run: ToolRun, ctx: RunContext, **kw) -> Finding:
        kw.setdefault("engagement", run.engagement)
        kw.setdefault("run_id", run.id)
        kw.setdefault("tool", self.name)
        kw.setdefault("target", ctx.target)
        return Finding(**kw)
