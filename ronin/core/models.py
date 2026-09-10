"""Core data model shared by every tool adapter and the report engine."""
from __future__ import annotations

import datetime as _dt
import enum
import hashlib
import re
import uuid
from typing import Any

from pydantic import BaseModel, Field

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CONF_RANK = {"tentative": 0, "firm": 1, "confirmed": 2}


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _uid() -> str:
    return uuid.uuid4().hex[:12]


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEV_RANK[self.value]

    def __lt__(self, other: "Severity") -> bool:  # enables sorting
        return self.rank < other.rank

    @classmethod
    def from_score(cls, score: float | None) -> "Severity":
        if score is None:
            return cls.INFO
        from ronin.core.cvss import severity_for

        return cls(severity_for(score))


class RunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"          # scope check refused the target


class Engagement(BaseModel):
    slug: str
    client: str
    tester: str
    authorized_by: str = ""
    created: _dt.datetime = Field(default_factory=_now)
    notes: str = ""


class ToolRun(BaseModel):
    id: str = Field(default_factory=_uid)
    engagement: str
    tool: str
    target: str
    argv: list[str] = Field(default_factory=list)
    status: RunStatus = RunStatus.PENDING
    started: _dt.datetime = Field(default_factory=_now)
    finished: _dt.datetime | None = None
    exit_code: int | None = None
    evidence_dir: str = ""
    result_files: list[str] = Field(default_factory=list)
    forced: bool = False
    force_reason: str = ""
    error: str = ""

    @property
    def duration_s(self) -> float | None:
        if self.finished is None:
            return None
        return (self.finished - self.started).total_seconds()


class Finding(BaseModel):
    id: str = Field(default_factory=_uid)
    engagement: str
    run_id: str
    tool: str

    title: str
    target: str                              # affected asset (host / url / host:port)
    severity: Severity = Severity.INFO
    cvss_vector: str | None = None
    cvss_score: float | None = None
    confidence: str = "firm"                  # tentative | firm | confirmed

    description: str = ""
    evidence: str = ""                        # matched output / raw snippet
    request: str | None = None                # web: raw HTTP request
    response: str | None = None               # web: raw HTTP response (may be truncated)
    poc: str = ""                             # reproduction steps / exact command
    attack_path: str = ""                     # how this chains toward impact
    remediation: str = ""

    references: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    first_seen: _dt.datetime = Field(default_factory=_now)
    fingerprint: str = ""

    # -- helpers ---------------------------------------------------------------
    def finalize(self) -> "Finding":
        """Fill CVSS-derived severity and the dedup fingerprint.  Idempotent."""
        if self.cvss_vector and self.cvss_score is None:
            try:
                from ronin.core.cvss import base_score

                self.cvss_score = base_score(self.cvss_vector)
            except ValueError:
                self.cvss_vector = None
        if self.cvss_score is not None:
            self.severity = Severity.from_score(self.cvss_score)
        if not self.fingerprint:
            key = "|".join(
                [
                    _norm(self.title),
                    _norm(self.target),
                    ",".join(sorted(c.upper() for c in self.cve)),
                ]
            )
            self.fingerprint = hashlib.sha1(key.encode()).hexdigest()[:16]
        return self

    def merge(self, other: "Finding") -> None:
        """Fold a duplicate (same fingerprint) into this one, keeping the strongest signal."""
        if other.severity.rank > self.severity.rank:
            self.severity = other.severity
        if (other.cvss_score or -1) > (self.cvss_score or -1):
            self.cvss_score, self.cvss_vector = other.cvss_score, other.cvss_vector
        if _CONF_RANK.get(other.confidence, 1) > _CONF_RANK.get(self.confidence, 1):
            self.confidence = other.confidence
        for attr in ("references", "cwe", "cve", "tags"):
            merged = list(dict.fromkeys(getattr(self, attr) + getattr(other, attr)))
            setattr(self, attr, merged)
        self.tags = list(dict.fromkeys(self.tags + [f"also:{other.tool}"]))
        if not self.poc and other.poc:
            self.poc = other.poc
        if not self.request and other.request:
            self.request, self.response = other.request, other.response


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that share a fingerprint (e.g. nuclei + nikto on the same TLS issue)."""
    out: dict[str, Finding] = {}
    for f in findings:
        f.finalize()
        if f.fingerprint in out:
            out[f.fingerprint].merge(f)
        else:
            out[f.fingerprint] = f
    return sorted(
        out.values(),
        key=lambda x: (x.severity.rank, x.cvss_score or 0.0),
        reverse=True,
    )


class ScopeDecision(BaseModel):
    target: str
    allowed: bool
    reason: str
    matched_rule: str | None = None
    within_window: bool = True


class Option(BaseModel):
    """One configurable knob for a tool adapter - drives the TUI form and CLI flags."""

    key: str
    label: str
    kind: str = "str"                # str | bool | int | choice
    default: Any = None
    choices: list[str] = Field(default_factory=list)
    help: str = ""
    aggressive: bool = False         # gating: needs explicit opt-in
