"""SQLite persistence for engagements, tool runs, and findings.

Stdlib ``sqlite3`` only - one file (``ronin.db``) at the project root, keyed by
engagement slug.  List/rich fields are stored as JSON text.  Reports are always
regenerated from this store, so re-rendering never needs a re-scan.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Iterator

from ronin.config import paths
from ronin.core.models import Engagement, Finding, ToolRun

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    slug          TEXT PRIMARY KEY,
    client        TEXT NOT NULL,
    tester        TEXT NOT NULL,
    authorized_by TEXT DEFAULT '',
    created       TEXT NOT NULL,
    notes         TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS runs (
    id           TEXT PRIMARY KEY,
    engagement   TEXT NOT NULL REFERENCES engagements(slug),
    tool         TEXT NOT NULL,
    target       TEXT NOT NULL,
    argv         TEXT NOT NULL,
    status       TEXT NOT NULL,
    started      TEXT NOT NULL,
    finished     TEXT,
    exit_code    INTEGER,
    evidence_dir TEXT DEFAULT '',
    result_files TEXT DEFAULT '[]',
    forced       INTEGER DEFAULT 0,
    force_reason TEXT DEFAULT '',
    error        TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    engagement  TEXT NOT NULL REFERENCES engagements(slug),
    run_id      TEXT NOT NULL REFERENCES runs(id),
    tool        TEXT NOT NULL,
    title       TEXT NOT NULL,
    target      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    cvss_vector TEXT,
    cvss_score  REAL,
    confidence  TEXT DEFAULT 'firm',
    fingerprint TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    data        TEXT NOT NULL          -- full Finding as JSON
);
CREATE INDEX IF NOT EXISTS idx_runs_eng ON runs(engagement);
CREATE INDEX IF NOT EXISTS idx_find_eng ON findings(engagement);
CREATE INDEX IF NOT EXISTS idx_find_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_find_fp  ON findings(engagement, fingerprint);
"""


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(paths().db)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.executescript(_SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


# --- engagements -------------------------------------------------------------
def upsert_engagement(e: Engagement) -> None:
    with connect() as c:
        c.execute(
            "INSERT INTO engagements(slug,client,tester,authorized_by,created,notes) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(slug) DO UPDATE SET "
            "client=excluded.client, tester=excluded.tester, "
            "authorized_by=excluded.authorized_by, notes=excluded.notes",
            (e.slug, e.client, e.tester, e.authorized_by, e.created.isoformat(), e.notes),
        )


def upsert_engagement_stub(slug: str) -> None:
    """Ensure an engagement row exists so run/finding FKs hold (ad-hoc runs)."""
    import datetime as _dt

    with connect() as c:
        c.execute(
            "INSERT OR IGNORE INTO engagements(slug,client,tester,created,notes) "
            "VALUES(?,?,?,?,?)",
            (slug, slug, "unknown", _dt.datetime.now(_dt.timezone.utc).isoformat(),
             "auto-created by an ad-hoc run"),
        )


def get_engagement(slug: str) -> Engagement | None:
    with connect() as c:
        r = c.execute("SELECT * FROM engagements WHERE slug=?", (slug,)).fetchone()
    return Engagement(**dict(r)) if r else None


def list_engagements() -> list[Engagement]:
    with connect() as c:
        rows = c.execute("SELECT * FROM engagements ORDER BY created DESC").fetchall()
    return [Engagement(**dict(r)) for r in rows]


# --- runs -----------------------------------------------------------------------
def save_run(run: ToolRun) -> None:
    with connect() as c:
        c.execute(
            "INSERT INTO runs(id,engagement,tool,target,argv,status,started,finished,"
            "exit_code,evidence_dir,result_files,forced,force_reason,error) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET status=excluded.status, "
            "finished=excluded.finished, exit_code=excluded.exit_code, "
            "result_files=excluded.result_files, error=excluded.error",
            (
                run.id, run.engagement, run.tool, run.target, json.dumps(run.argv),
                run.status.value, run.started.isoformat(),
                run.finished.isoformat() if run.finished else None,
                run.exit_code, run.evidence_dir, json.dumps(run.result_files),
                int(run.forced), run.force_reason, run.error,
            ),
        )


def get_run(run_id: str) -> ToolRun | None:
    with connect() as c:
        r = c.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["argv"] = json.loads(d["argv"])
    d["result_files"] = json.loads(d["result_files"])
    d["forced"] = bool(d["forced"])
    return ToolRun(**d)


def list_runs(engagement: str) -> list[ToolRun]:
    with connect() as c:
        rows = c.execute(
            "SELECT * FROM runs WHERE engagement=? ORDER BY started DESC", (engagement,)
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["argv"] = json.loads(d["argv"])
        d["result_files"] = json.loads(d["result_files"])
        d["forced"] = bool(d["forced"])
        out.append(ToolRun(**d))
    return out


# --- findings ---------------------------------------------------------------
def save_findings(findings: list[Finding]) -> None:
    if not findings:
        return
    with connect() as c:
        c.executemany(
            "INSERT INTO findings(id,engagement,run_id,tool,title,target,severity,"
            "cvss_vector,cvss_score,confidence,fingerprint,first_seen,data) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "severity=excluded.severity, cvss_score=excluded.cvss_score, data=excluded.data",
            [
                (
                    f.id, f.engagement, f.run_id, f.tool, f.title, f.target,
                    f.severity.value, f.cvss_vector, f.cvss_score, f.confidence,
                    f.fingerprint, f.first_seen.isoformat(),
                    f.model_dump_json(),
                )
                for f in findings
            ],
        )


def get_findings(engagement: str, run_id: str | None = None) -> list[Finding]:
    q = "SELECT data FROM findings WHERE engagement=?"
    args: list = [engagement]
    if run_id:
        q += " AND run_id=?"
        args.append(run_id)
    with connect() as c:
        rows = c.execute(q, args).fetchall()
    return [Finding.model_validate_json(r["data"]) for r in rows]
