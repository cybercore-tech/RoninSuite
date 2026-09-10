import datetime as dt

from ronin.core import db
from ronin.core.models import (Client, Engagement, Finding, FindingStatus,
                               RunStatus, Severity, ToolRun, dedupe)


def _finding(slug, run_id, title, sev=Severity.HIGH):
    return Finding(engagement=slug, run_id=run_id, tool="nuclei", title=title,
                   target="https://x", severity=sev, description="x")


def test_client_crud_and_link():
    db.upsert_client(Client(slug="acme", name="Acme Ltd", contact_name="Jo",
                            cadence_days=90))
    assert db.get_client("acme").name == "Acme Ltd"
    assert [c.slug for c in db.list_clients()] == ["acme"]

    db.upsert_engagement(Engagement(slug="acme-1", client="Acme Ltd", tester="r"))
    db.set_engagement_client("acme-1", "acme")
    assert [e.slug for e in db.list_engagements("acme")] == ["acme-1"]

    db.delete_client("acme")
    assert db.get_client("acme") is None
    assert db.get_engagement("acme-1").client_slug == ""     # unlinked, not deleted


def test_finding_status_cycle_and_persist():
    db.upsert_engagement(Engagement(slug="e1", client="C", tester="r"))
    run = ToolRun(engagement="e1", tool="nuclei", target="x", status=RunStatus.OK)
    db.save_run(run)
    f = _finding("e1", run.id, "issue A")
    db.save_findings(dedupe([f]))

    assert FindingStatus.cycle("open") == "in_progress"
    assert FindingStatus.cycle("closed") == "open"

    db.set_finding_status(f.id, "fixed")
    got = db.get_findings("e1")[0]
    assert got.status == "fixed"


def test_client_progress_rollup():
    db.upsert_client(Client(slug="beta", name="Beta", cadence_days=30))
    db.upsert_engagement(Engagement(slug="beta-1", client="Beta", tester="r",
                                    client_slug="beta"))
    old = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    run = ToolRun(engagement="beta-1", tool="nuclei", target="x", status=RunStatus.OK,
                  started=old, finished=old)
    db.save_run(run)
    fs = dedupe([_finding("beta-1", run.id, f"f{i}", Severity.HIGH) for i in range(4)])
    db.save_findings(fs)
    db.set_finding_status(fs[0].id, "closed")
    db.set_finding_status(fs[1].id, "accepted")

    p = db.client_progress("beta")
    assert p["engagements"] == 1
    assert p["findings_total"] == 4
    assert p["resolved"] == 2
    assert p["progress_pct"] == 50
    assert p["open_by_severity"].get("high") == 2
    assert p["overdue"] is True                              # last run in 2020, 30d cadence


def test_state_kv():
    db.set_state("k", "v1")
    assert db.get_state("k") == "v1"
    db.set_state("k", "v2")
    assert db.get_state("k") == "v2"
    assert db.get_state("missing", "d") == "d"
