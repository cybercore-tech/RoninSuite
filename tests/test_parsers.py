import shutil
from pathlib import Path

import pytest

from ronin.core.models import RunStatus, Severity, ToolRun
from ronin.tools.base import RunContext
from ronin.tools.httpx import HttpxAdapter
from ronin.tools.nmap import NmapAdapter
from ronin.tools.nuclei import NucleiAdapter

DATA = Path(__file__).parent / "data"


def _ctx_with(tmp_path, sample_name, dest_name, target):
    ev = tmp_path / "ev"
    ev.mkdir()
    shutil.copy(DATA / sample_name, ev / dest_name)
    run = ToolRun(engagement="t", tool="x", target=target, status=RunStatus.OK)
    ctx = RunContext(engagement="t", target=target, evidence_dir=ev, options={})
    return run, ctx


def test_nmap_parser(tmp_path):
    run, ctx = _ctx_with(tmp_path, "nmap_sample.xml", "nmap.xml", "scanme.example")
    fs = NmapAdapter().parse(run, ctx)
    titles = [f.title for f in fs]
    # open 22 + open 80 (not the closed 443)
    assert any("Open port 22/tcp" in t for t in titles)
    assert any("Open port 80/tcp" in t for t in titles)
    assert not any("443" in t for t in titles)
    # vulners NSE script promoted to HIGH and carries the CVEs
    vuln = [f for f in fs if "vulners" in " ".join(f.tags)]
    assert vuln and vuln[0].severity == Severity.HIGH
    assert "CVE-2021-42013" in vuln[0].cve
    # host script surfaced
    assert any("smb-os-discovery" in " ".join(f.tags) for f in fs)


def test_httpx_parser(tmp_path):
    run, ctx = _ctx_with(tmp_path, "httpx_sample.jsonl", "httpx.jsonl",
                         "https://app.acme.example")
    fs = HttpxAdapter().parse(run, ctx)
    # live-service inventory for both lines
    assert sum(1 for f in fs if f.title.startswith("Live HTTP service")) == 2
    # app.acme.example is missing CSP/HSTS/XFO -> low/info header findings
    app_headers = [f for f in fs if "headers" in f.tags and "app.acme.example" in f.target]
    assert any("Content-Security-Policy" in f.title for f in app_headers)
    # the fully-hardened nginx host should NOT raise header findings
    assert not any("acme.example" == f.target.replace("https://", "") and "headers" in f.tags
                   for f in fs if "app" not in f.target)
    # server banner with a version disclosed
    assert any("Server version disclosed" in f.title for f in fs)


def test_nuclei_parser(tmp_path):
    run, ctx = _ctx_with(tmp_path, "nuclei_sample.jsonl", "nuclei.jsonl",
                         "https://app.acme.example")
    fs = NucleiAdapter().parse(run, ctx)
    crit = [f for f in fs if f.severity == Severity.CRITICAL]
    assert crit, [f.severity for f in fs]
    f = crit[0]
    assert f.cvss_score == 9.8
    assert "CVE-2021-42013" in f.cve and "CWE-22" in f.cwe
    assert f.poc.startswith("curl")
    assert f.request and f.response
    assert "exploit" in f.attack_path.lower() or "access" in f.attack_path.lower()
