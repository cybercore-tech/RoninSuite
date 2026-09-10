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
from ronin.core.models import Client, Engagement, Finding, ToolRun

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    slug          TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    contact_name  TEXT DEFAULT '',
    contact_email TEXT DEFAULT '',
    notes         TEXT DEFAULT '',
    cadence_days  INTEGER DEFAULT 0,
    created       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS engagements (
    slug          TEXT PRIMARY KEY,
    client        TEXT NOT NULL,
    tester        TEXT NOT NULL,
    authorized_by TEXT DEFAULT '',
    created       TEXT NOT NULL,
    notes         TEXT DEFAULT '',
    client_slug   TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS state (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL,
    updated TEXT NOT NULL
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
    status      TEXT DEFAULT 'open',
    fingerprint TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    data        TEXT NOT NULL          -- full Finding as JSON
);
CREATE INDEX IF NOT EXISTS idx_runs_eng ON runs(engagement);
CREATE INDEX IF NOT EXISTS idx_find_eng ON findings(engagement);
CREATE INDEX IF NOT EXISTS idx_find_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_find_fp  ON findings(engagement, fingerprint);
"""


_MIGRATIONS = [
    ("engagements", "client_slug", "TEXT DEFAULT ''"),
    ("findings", "status", "TEXT DEFAULT 'open'"),
]


def _migrate(conn: sqlite3.Connection) -> None:
    for table, col, decl in _MIGRATIONS:
        cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        if col not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
    # indexes that depend on migrated columns
    conn.execute("CREATE INDEX IF NOT EXISTS idx_eng_client ON engagements(client_slug)")


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(paths().db)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.executescript(_SCHEMA)
        _migrate(conn)
        yield conn
        conn.commit()
    finally:
        conn.close()


# --- clients ---------------------------------------------------------------
def upsert_client(cl: Client) -> None:
    with connect() as c:
        c.execute(
            "INSERT INTO clients(slug,name,contact_name,contact_email,notes,cadence_days,created) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(slug) DO UPDATE SET "
            "name=excluded.name, contact_name=excluded.contact_name, "
            "contact_email=excluded.contact_email, notes=excluded.notes, "
            "cadence_days=excluded.cadence_days",
            (cl.slug, cl.name, cl.contact_name, cl.contact_email, cl.notes,
             cl.cadence_days, cl.created.isoformat()),
        )


def get_client(slug: str) -> Client | None:
    with connect() as c:
        r = c.execute("SELECT * FROM clients WHERE slug=?", (slug,)).fetchone()
    return Client(**dict(r)) if r else None


def list_clients() -> list[Client]:
    with connect() as c:
        rows = c.execute("SELECT * FROM clients ORDER BY name").fetchall()
    return [Client(**dict(r)) for r in rows]


def delete_client(slug: str) -> None:
    with connect() as c:
        c.execute("UPDATE engagements SET client_slug='' WHERE client_slug=?", (slug,))
        c.execute("DELETE FROM clients WHERE slug=?", (slug,))


# --- key/value state ------------------------------------------------------------
def set_state(key: str, value: str) -> None:
    import datetime as _dt

    with connect() as c:
        c.execute(
            "INSERT INTO state(key,value,updated) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
            (key, value, _dt.datetime.now(_dt.timezone.utc).isoformat()),
        )


def get_state(key: str, default: str = "") -> str:
    with connect() as c:
        r = c.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


# --- engagements -------------------------------------------------------------
def upsert_engagement(e: Engagement) -> None:
    with connect() as c:
        c.execute(
            "INSERT INTO engagements(slug,client,tester,authorized_by,created,notes,client_slug) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(slug) DO UPDATE SET "
            "client=excluded.client, tester=excluded.tester, "
            "authorized_by=excluded.authorized_by, notes=excluded.notes, "
            "client_slug=excluded.client_slug",
            (e.slug, e.client, e.tester, e.authorized_by, e.created.isoformat(),
             e.notes, e.client_slug),
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


def list_engagements(client_slug: str | None = None) -> list[Engagement]:
    q = "SELECT * FROM engagements"
    args: tuple = ()
    if client_slug is not None:
        q += " WHERE client_slug=?"
        args = (client_slug,)
    q += " ORDER BY created DESC"
    with connect() as c:
        rows = c.execute(q, args).fetchall()
    return [Engagement(**dict(r)) for r in rows]


def set_engagement_client(engagement_slug: str, client_slug: str) -> None:
    with connect() as c:
        c.execute("UPDATE engagements SET client_slug=? WHERE slug=?",
                  (client_slug, engagement_slug))


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
            "cvss_vector,cvss_score,confidence,status,fingerprint,first_seen,data) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "severity=excluded.severity, cvss_score=excluded.cvss_score, data=excluded.data",
            [
                (
                    f.id, f.engagement, f.run_id, f.tool, f.title, f.target,
                    f.severity.value, f.cvss_vector, f.cvss_score, f.confidence,
                    getattr(f, "status", "open"),
                    f.fingerprint, f.first_seen.isoformat(),
                    f.model_dump_json(),
                )
                for f in findings
            ],
        )


def set_finding_status(finding_id: str, status: str) -> None:
    """Update a finding's remediation status (open/in_progress/fixed/accepted/closed)."""
    with connect() as c:
        r = c.execute("SELECT data FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not r:
            return
        d = json.loads(r["data"])
        d["status"] = status
        c.execute("UPDATE findings SET status=?, data=? WHERE id=?",
                  (status, json.dumps(d), finding_id))


def get_findings(engagement: str, run_id: str | None = None) -> list[Finding]:
    q = "SELECT data FROM findings WHERE engagement=?"
    args: list = [engagement]
    if run_id:
        q += " AND run_id=?"
        args.append(run_id)
    with connect() as c:
        rows = c.execute(q, args).fetchall()
    return [Finding.model_validate_json(r["data"]) for r in rows]


# --- aggregates for the Clients dashboard -------------------------------------
def client_progress(slug: str) -> dict:
    """Roll-up for one client: engagements, last/next test dates, finding status mix."""
    import datetime as _dt

    cl = get_client(slug)
    engs = list_engagements(slug)
    eng_slugs = [e.slug for e in engs]
    last_run = None
    status_mix: dict[str, int] = {}
    sev_open: dict[str, int] = {}
    total = 0
    with connect() as c:
        for es in eng_slugs:
            r = c.execute("SELECT MAX(started) m FROM runs WHERE engagement=?", (es,)).fetchone()
            if r and r["m"] and (last_run is None or r["m"] > last_run):
                last_run = r["m"]
            for row in c.execute(
                "SELECT status, severity, COUNT(*) n FROM findings WHERE engagement=? "
                "GROUP BY status, severity", (es,)):
                total += row["n"]
                status_mix[row["status"]] = status_mix.get(row["status"], 0) + row["n"]
                if row["status"] not in ("closed", "accepted"):
                    sev_open[row["severity"]] = sev_open.get(row["severity"], 0) + row["n"]

    def _aware(s: str | None):
        if not s:
            return None
        d = _dt.datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=_dt.timezone.utc)

    last_dt = _aware(last_run)
    cadence = cl.cadence_days if cl else 0
    next_due = (last_dt + _dt.timedelta(days=cadence)) if (last_dt and cadence) else None
    now = _dt.datetime.now(_dt.timezone.utc)
    overdue = bool(next_due and next_due < now)
    resolved = status_mix.get("closed", 0) + status_mix.get("accepted", 0)
    return {
        "client": cl,
        "engagements": len(engs),
        "last_tested": last_dt,
        "next_due": next_due,
        "overdue": overdue,
        "findings_total": total,
        "status_mix": status_mix,
        "open_by_severity": sev_open,
        "resolved": resolved,
        "progress_pct": round(100 * resolved / total) if total else None,
    }
