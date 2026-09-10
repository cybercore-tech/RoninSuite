import json

from ronin import updates as up
from ronin.core import db


def test_offline_check_and_cache():
    rep = up.check(online=False)
    assert rep.tools and rep.checked_at is not None
    # offline => no GitHub latest lookups, no pacman list
    assert rep.pacman_updates == []
    names = {t.name for t in rep.tools}
    assert {"nmap", "nuclei", "sqlmap"} <= names

    cached = up.cached()
    assert cached is not None
    assert {t.name for t in cached.tools} == names


def test_cached_none_when_empty():
    assert up.cached() is None


def test_report_helpers():
    db.set_state(up._STATE_KEY, json.dumps({
        "checked_at": "2026-09-10T00:00:00+00:00",
        "tools": [
            {"name": "nuclei", "category": "vuln", "installed": True,
             "installed_version": "3.1.0", "latest_version": "3.4.0",
             "source": "go", "status": "outdated", "note": ""},
            {"name": "sqlmap", "category": "exploit", "installed": False,
             "installed_version": "", "latest_version": "", "source": "pacman",
             "status": "missing", "note": ""},
        ],
        "pacman_updates": ["foo"],
        "nuclei_templates_age_days": 30,
    }))
    rep = up.cached()
    assert [t.name for t in rep.outdated] == ["nuclei"]
    assert [t.name for t in rep.missing] == ["sqlmap"]


def test_version_compare():
    assert up._cmp("3.1.0", "3.4.0") < 0
    assert up._cmp("3.4.0", "3.4.0") == 0
    assert up._cmp("3.10.0", "3.9.0") > 0
