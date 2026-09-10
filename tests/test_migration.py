"""An older ronin.db (pre-clients) must upgrade in place on first open."""
import sqlite3

from ronin.config import paths
from ronin.core import db
from ronin.core.models import Client

_OLD = (
    "CREATE TABLE engagements(slug TEXT PRIMARY KEY, client TEXT, tester TEXT, "
    "authorized_by TEXT DEFAULT '', created TEXT, notes TEXT DEFAULT '');"
    "CREATE TABLE runs(id TEXT PRIMARY KEY, engagement TEXT, tool TEXT, target TEXT, "
    "argv TEXT, status TEXT, started TEXT, finished TEXT, exit_code INTEGER, "
    "evidence_dir TEXT DEFAULT '', result_files TEXT DEFAULT '[]', forced INTEGER DEFAULT 0, "
    "force_reason TEXT DEFAULT '', error TEXT DEFAULT '');"
    "CREATE TABLE findings(id TEXT PRIMARY KEY, engagement TEXT, run_id TEXT, tool TEXT, "
    "title TEXT, target TEXT, severity TEXT, cvss_vector TEXT, cvss_score REAL, "
    "confidence TEXT DEFAULT 'firm', fingerprint TEXT, first_seen TEXT, data TEXT);"
)


def test_old_db_upgrades():
    c = sqlite3.connect(paths().db)
    c.executescript(_OLD)
    c.execute("INSERT INTO engagements VALUES('e','Old','r','','2026-01-01T00:00:00','')")
    c.execute(
        "INSERT INTO findings VALUES('f','e','r','nmap','t','x','info',NULL,NULL,'firm',"
        "'fp','2026-01-01T00:00:00','{\"id\":\"f\",\"engagement\":\"e\",\"run_id\":\"r\","
        "\"tool\":\"nmap\",\"title\":\"t\",\"target\":\"x\",\"severity\":\"info\","
        "\"confidence\":\"firm\",\"fingerprint\":\"fp\",\"first_seen\":\"2026-01-01T00:00:00\"}')"
    )
    c.commit()
    c.close()

    # first call through the new code path runs the migration
    e = db.get_engagement("e")
    assert e.client_slug == ""
    assert db.get_findings("e")[0].status == "open"

    db.set_finding_status("f", "closed")
    assert db.get_findings("e")[0].status == "closed"

    db.upsert_client(Client(slug="old", name="Old"))
    db.set_engagement_client("e", "old")
    assert db.client_progress("old")["engagements"] == 1
