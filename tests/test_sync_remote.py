"""ronin.sync_remote — pull/push against a stubbed Deck (no network)."""
import datetime as dt

import pytest

from ronin import sync_remote as sr
from ronin.core import db
from ronin.core.models import Engagement, Finding, RunStatus, Severity, ToolRun, dedupe


def test_resolve_precedence(monkeypatch):
    monkeypatch.delenv("RONIN_DECK_URL", raising=False)
    monkeypatch.delenv("RONIN_DECK_TOKEN", raising=False)
    with pytest.raises(sr.DeckError):
        sr.resolve(None, None)
    url, tok = sr.resolve("https://deck.example/", "abc")
    assert url == "https://deck.example" and tok == "abc"
    # url persisted to state, token not
    assert db.get_state("sync.deck_url") == "https://deck.example"
    monkeypatch.setenv("RONIN_DECK_TOKEN", "envtok")
    url2, tok2 = sr.resolve(None, None)
    assert url2 == "https://deck.example" and tok2 == "envtok"


def test_pull_customers_upserts(monkeypatch):
    payload = {
        "server_time": "2026-09-10T00:00:00+00:00",
        "customers": [
            {"slug": "acme", "name": "Acme Widgets LLC", "status": "active",
             "website": "acme.example", "phone": "+1 555 0100", "x": "@acme",
             "facebook": "", "linkedin": "company/acme", "cadence_days": 90,
             "currency": "USD", "primary_contact_name": "J. Okafor",
             "primary_contact_email": "j@acme.example",
             "updated_at": "2026-09-01T00:00:00+00:00"},
        ],
    }
    monkeypatch.setattr(sr, "_req", lambda *a, **k: payload)
    n = sr.pull_customers("https://deck.example", "tok")
    assert n == 1
    c = db.get_client("acme")
    assert c.name == "Acme Widgets LLC" and c.phone == "+1 555 0100"
    assert c.contact_name == "J. Okafor" and c.cadence_days == 90
    assert db.get_state("sync.customers_pulled_at") == "2026-09-10T00:00:00+00:00"


def test_push_all_shapes_payload(monkeypatch):
    db.upsert_engagement(Engagement(slug="acme-q3", client="Acme", tester="raven",
                                    client_slug="acme"))
    run = ToolRun(engagement="acme-q3", tool="nuclei", target="x", status=RunStatus.OK)
    db.save_run(run)
    db.save_findings(dedupe([
        Finding(engagement="acme-q3", run_id=run.id, tool="nuclei", title="RCE",
                target="https://x", severity=Severity.CRITICAL, description="x",
                cve=["CVE-2021-42013"]),
    ]))

    captured = {}

    def fake_req(method, url, token, body=None):
        captured["method"] = method
        captured["url"] = url
        captured["body"] = body
        return {"engagements_upserted": 1, "findings_synced": 1, "reports_recorded": 0,
                "conflicts": []}

    monkeypatch.setattr(sr, "_req", fake_req)
    resp = sr.push_all("https://deck.example", "tok")
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/api/v1/sync/push")
    b = captured["body"]
    assert b["engagements"][0]["slug"] == "acme-q3"
    assert b["engagements"][0]["customer_slug"] == "acme"
    assert b["findings"][0]["fingerprint"] and b["findings"][0]["severity"] == "critical"
    assert resp["engagements_upserted"] == 1
    assert db.get_state("sync.pushed_at")


def test_multipart_builder_roundtrips():
    ct, body = sr._multipart(
        {"engagement_slug": "acme-q3", "level": "executive", "format": "pdf"},
        file_field="file", filename="executive.pdf",
        content_type="application/pdf", data=b"%PDF-1.4 hi",
    )
    boundary = ct.split("boundary=", 1)[1]
    assert boundary in ct
    text = body.decode("latin1")
    assert f'--{boundary}\r\n' in text
    assert 'name="engagement_slug"' in text and 'acme-q3' in text
    assert 'filename="executive.pdf"' in text
    assert "Content-Type: application/pdf" in text
    assert "%PDF-1.4 hi" in text
    assert body.rstrip().endswith(f"--{boundary}--".encode())


def test_push_report_files_uploads(monkeypatch):
    from ronin.config import paths

    db.upsert_engagement(Engagement(slug="acme-rep", client="Acme", tester="raven",
                                    client_slug="acme"))
    rdir = paths().reports / "acme-rep" / "2026-09-10T00-00-00"
    rdir.mkdir(parents=True)
    (rdir / "executive.pdf").write_bytes(b"%PDF-1.4 exec")
    (rdir / "technical.md").write_text("# technical")

    calls = []
    monkeypatch.setattr(
        sr, "_post_multipart",
        lambda url, token, ct, body: calls.append((url, ct, body)) or {"stored": True})

    out = sr.push_report_files("https://deck.example", "tok")
    assert out["uploaded"] == 2 and out["failed"] == 0
    assert {u for u, _, _ in calls} == {"https://deck.example/api/v1/sync/reports/file"}
    sent_levels = {b.decode("latin1").split('name="level"\r\n\r\n', 1)[1].split("\r\n", 1)[0]
                   for _, _, b in calls}
    assert sent_levels == {"executive", "technical"}
    assert db.get_state("sync.reports_pushed_at")
