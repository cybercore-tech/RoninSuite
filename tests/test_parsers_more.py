"""Golden-file parser tests for the second adapter batch."""
import shutil
from pathlib import Path

from ronin.core.models import RunStatus, Severity, ToolRun, dedupe
from ronin.tools.base import RunContext
from ronin.tools.commix import CommixAdapter
from ronin.tools.feroxbuster import FeroxbusterAdapter
from ronin.tools.hydra import HydraAdapter
from ronin.tools.naabu import NaabuAdapter
from ronin.tools.nikto import NiktoAdapter
from ronin.tools.sqlmap import SqlmapAdapter
from ronin.tools.subfinder import SubfinderAdapter

DATA = Path(__file__).parent / "data"


def _ctx(tmp_path, sample, dest, target, opts=None):
    ev = tmp_path / "ev"
    ev.mkdir(parents=True)
    if sample:
        shutil.copy(DATA / sample, ev / dest)
    run = ToolRun(engagement="t", tool="x", target=target, status=RunStatus.OK)
    ctx = RunContext(engagement="t", target=target, evidence_dir=ev, options=opts or {})
    return run, ctx


def test_subfinder(tmp_path):
    run, ctx = _ctx(tmp_path, "subfinder_sample.jsonl", "subfinder.jsonl", "acme.example")
    fs = SubfinderAdapter().parse(run, ctx)
    hosts = {f.target for f in fs}
    assert hosts == {"www.acme.example", "staging.acme.example"}          # deduped
    assert all(f.severity == Severity.INFO for f in fs)
    assert all("subdomain" in f.tags for f in fs)


def test_naabu(tmp_path):
    run, ctx = _ctx(tmp_path, "naabu_sample.jsonl", "naabu.jsonl", "acme.example")
    fs = {f.target: f for f in NaabuAdapter().parse(run, ctx)}
    assert fs["203.0.113.10:6379/tcp"].severity == Severity.HIGH        # exposed Redis
    assert fs["203.0.113.10:22/tcp"].severity == Severity.INFO
    assert fs["203.0.113.10:8080/tcp"].severity == Severity.INFO


def test_feroxbuster(tmp_path):
    run, ctx = _ctx(tmp_path, "feroxbuster_sample.json", "feroxbuster.json",
                    "https://app.acme.example")
    fs = {f.target: f for f in FeroxbusterAdapter().parse(run, ctx)}
    assert "https://app.acme.example/.git/HEAD" in fs
    assert fs["https://app.acme.example/.git/HEAD"].severity == Severity.MEDIUM
    assert fs["https://app.acme.example/admin"].severity == Severity.LOW  # 401
    # the statistics line is ignored
    assert all("statistics" not in f.title.lower() for f in fs.values())


def test_nikto(tmp_path):
    run, ctx = _ctx(tmp_path, "nikto_sample.json", "nikto.json", "https://app.acme.example")
    fs = NiktoAdapter().parse(run, ctx)
    sevs = sorted((f.severity for f in fs), key=lambda s: s.rank)
    assert Severity.HIGH in sevs                                         # shellshock RCE
    assert any("CVE-2014-6271" in " ".join(f.references) for f in fs)
    assert any(f.severity == Severity.MEDIUM for f in fs)                # directory indexing


def test_sqlmap_positive(tmp_path):
    run, ctx = _ctx(tmp_path, None, None, "http://vuln.example/item.php?id=1")
    (ctx.evidence_dir / "sqlmap-results.csv").write_text(
        "Target URL,Place,Parameter,Technique(s),Note(s)\r\n"
        "http://vuln.example/item.php?id=1,GET,id,BEUST,\r\n")
    (ctx.evidence_dir / "stdout.log").write_text(
        "GET parameter 'id' is vulnerable.\nback-end DBMS: MySQL >= 5.6\n")
    run.argv = ["sqlmap", "-u", ctx.target, "--batch"]
    fs = dedupe(SqlmapAdapter().parse(run, ctx))
    assert fs and fs[0].severity == Severity.CRITICAL
    assert fs[0].cvss_score == 9.8 and "CWE-89" in fs[0].cwe
    assert "id" in fs[0].title and "MySQL" in fs[0].title


def test_sqlmap_negative(tmp_path):
    run, ctx = _ctx(tmp_path, None, None, "http://safe.example/?q=1")
    (ctx.evidence_dir / "stdout.log").write_text(
        "all tested parameters do not appear to be injectable.\n")
    fs = dedupe(SqlmapAdapter().parse(run, ctx))
    assert len(fs) == 1 and fs[0].severity == Severity.INFO


def test_hydra_positive(tmp_path):
    run, ctx = _ctx(tmp_path, None, None, "ssh://10.0.0.5", {"service": "ssh"})
    (ctx.evidence_dir / "hydra.json").write_text(
        '{"results":[{"host":"10.0.0.5","login":"admin","password":"admin123",'
        '"port":22,"service":"ssh"}]}')
    fs = dedupe(HydraAdapter().parse(run, ctx))
    assert fs[0].severity == Severity.CRITICAL
    assert "admin" in fs[0].title and "admin123" in fs[0].title
    assert fs[0].cvss_score == 9.8


def test_commix_positive(tmp_path):
    run, ctx = _ctx(tmp_path, None, None, "http://vuln.example/ping.php?ip=1")
    (ctx.evidence_dir / "stdout.log").write_text(
        "[+] The (GET) parameter 'ip' is vulnerable to command injection.\n")
    run.argv = ["commix", "--url", ctx.target, "--batch"]
    fs = dedupe(CommixAdapter().parse(run, ctx))
    assert fs[0].severity == Severity.CRITICAL and "CWE-78" in fs[0].cwe
    assert "ip" in fs[0].title


def test_build_argv_smoke(tmp_path):
    """Every new adapter builds a plausible argv without raising."""
    for Ad, target, opts in [
        (SubfinderAdapter, "acme.example", {}),
        (NaabuAdapter, "acme.example", {"top_ports": "100"}),
        (NiktoAdapter, "https://acme.example", {}),
        (SqlmapAdapter, "http://x/?id=1", {"level": 1, "risk": 1}),
        (CommixAdapter, "http://x/?ip=1", {}),
    ]:
        ad = Ad()
        _, ctx = _ctx(tmp_path / Ad.__name__, None, None, target, {**ad.option_defaults(), **opts})
        argv = ad.build_argv(ctx)
        assert argv[0] == ad.binary and target.split("://")[-1].split("/")[0] in " ".join(argv)
