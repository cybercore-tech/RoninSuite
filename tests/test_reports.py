import datetime as dt

from ronin.core import db
from ronin.core.models import (Engagement, Finding, RunStatus, Severity, ToolRun,
                               dedupe)
from ronin.reports.render import render


def _seed():
    slug = "unit-demo"
    db.upsert_engagement(Engagement(slug=slug, client="Unit Demo Inc", tester="pytest"))
    run = ToolRun(engagement=slug, tool="nuclei", target="https://u.example",
                  status=RunStatus.OK, argv=["nuclei", "-u", "https://u.example"],
                  started=dt.datetime(2026, 9, 1, 9), finished=dt.datetime(2026, 9, 1, 9, 5))
    db.save_run(run)
    raw = [
        Finding(engagement=slug, run_id=run.id, tool="nuclei",
                title="RCE via CVE-2021-42013", target="https://u.example",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                description="Path traversal to RCE.", poc="curl ...",
                attack_path="unauth read -> RCE -> foothold",
                remediation="Upgrade Apache to 2.4.51+.", cve=["CVE-2021-42013"]),
        Finding(engagement=slug, run_id=run.id, tool="httpx",
                title="HSTS not set (https://u.example)", target="https://u.example",
                severity=Severity.LOW, description="missing HSTS",
                remediation="Add Strict-Transport-Security."),
    ]
    db.save_findings(dedupe(raw))
    return slug


def test_render_three_tiers(tmp_path):
    slug = _seed()
    made = render(slug)
    assert set(made) == {"executive", "technical", "remediation"}
    for level, files in made.items():
        assert files["md"].exists() and files["html"].exists()
        text = files["md"].read_text()
        # all four required sections in every tier
        assert "Scope & Methodology" in text
        assert "Vulnerability Details" in text
        assert "Proof of Concept" in text
        assert "Remediation Recommendations" in text

    tech = made["technical"]["md"].read_text()
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in tech   # vector shown to engineers
    assert "curl ..." in tech                                       # verbatim PoC

    exec_md = made["executive"]["md"].read_text()
    assert "curl ..." not in exec_md                                # no raw commands for management
    assert "Critical" in exec_md                                    # risk rating rolled up

    rem_md = made["remediation"]["md"].read_text()
    assert "Suggested SLA" in rem_md and "7 days" in rem_md         # critical SLA


def test_render_single_run_scope(tmp_path):
    slug = _seed()
    runs = db.list_runs(slug)
    made = render(slug, run_id=runs[0].id, formats=("md",))
    assert made["technical"]["md"].exists()
