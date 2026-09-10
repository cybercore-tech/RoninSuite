from typer.testing import CliRunner

from ronin.cli.app import app
from ronin.core import db

runner = CliRunner()


def r(*args):
    # wide terminal so Rich tables don't truncate cells we assert on
    return runner.invoke(app, list(args), env={"COLUMNS": "220"})


def test_help_overview_and_command():
    out = r("help").output
    assert "run" in out and "list" in out and "add" in out and "update" in out
    assert "TOOL" in r("help", "run").output


def test_new_client_and_engagement_and_list():
    assert r("new", "client", "--name", "Acme Widgets LLC",
             "--contact", "Jo", "--cadence-days", "90").exit_code == 0
    assert r("new", "engagement", "--client", "Acme Widgets LLC",
             "--slug", "acme-q3", "--client-slug", "acme-widgets-llc").exit_code == 0
    assert db.get_client("acme-widgets-llc").cadence_days == 90

    assert "acme-widgets-llc" in r("list", "clients").output
    assert "acme-q3" in r("list", "engagements").output
    assert "acme-q3" in r("engagement", "acme-q3").output          # noun shortcut
    assert "Acme Widgets LLC" in r("client", "acme-widgets-llc").output


def test_list_tools_and_add_list():
    assert "nuclei" in r("list", "tools").output
    assert "httpx" in r("list", "tools", "web").output
    add = r("add", "--list", "--category", "recon").output
    assert "assetfinder" in add and "subfinder" in add            # extended + core


def test_search():
    r("new", "client", "--name", "Nimbus Retail", "--contact", "Rivera")
    out = r("search", "nimbus").output
    assert "Nimbus Retail" in out
    assert "subdomain" in r("search", "subdomain").output.lower()  # tool catalog hit


def test_add_dry_run_known_and_unknown():
    ok = r("add", "assetfinder", "--dry-run")
    assert ok.exit_code == 0 and "go install" in ok.output
    bad = r("add", "definitely-not-a-tool")
    assert bad.exit_code == 1 and "unknown" in bad.output.lower()


def test_update_tools_table_no_action():
    out = r("update", "tools", "--offline").output
    assert "toolchain currency" in out.lower() or "status" in out.lower()


def test_scope_exit_codes(tmp_path, monkeypatch):
    from ronin.config import paths

    r("new", "engagement", "--client", "C", "--slug", "e1")
    paths().scope_file("e1").write_text(
        'client: "C"\nengagement: "e1"\ntester: "r"\n'
        'in_scope: ["*.acme.example"]\nout_of_scope: []\n')
    assert r("scope", "e1", "https://x.acme.example").exit_code == 0
    assert r("scope", "e1", "https://evil.example").exit_code == 2


def test_add_picker_selection_parsing():
    from ronin.cli.app import _parse_selection
    names = ["nmap", "nuclei", "httpx", "ffuf", "gau"]
    assert _parse_selection("1 3", names) == ["nmap", "httpx"]
    assert _parse_selection("2-4", names) == ["nuclei", "httpx", "ffuf"]
    assert _parse_selection("gau, 1", names) == ["gau", "nmap"]
    assert _parse_selection("all", names) == names
    assert _parse_selection("", names) == []
    assert _parse_selection("99 bogus", names) == []


def test_add_picker_flow(monkeypatch):
    out = runner.invoke(app, ["add", "--category", "recon", "--dry-run"],
                        env={"COLUMNS": "220"}, input="1\n").output
    assert "select tools" in out
    assert "go install" in out or "pacman" in out or "would install" in out


def test_new_client_fields_and_invoices():
    assert r("new", "client", "--name", "Acme Widgets LLC", "--phone", "+1 555 0100",
             "--website", "acme.example", "--x", "@acme", "--rate", "185",
             "--cadence-days", "90").exit_code == 0
    from ronin.core import db
    c = db.get_client("acme-widgets-llc")
    assert c.phone == "+1 555 0100" and c.rate == 185.0

    assert r("invoice", "new", "-c", "acme-widgets-llc", "-a", "8500",
             "--number", "INV-1", "--status", "sent").exit_code == 0
    assert r("invoice", "new", "-c", "acme-widgets-llc", "-a", "6200",
             "--status", "paid").exit_code == 0
    lst = r("invoice", "list").output
    assert "INV-1" in lst and "outstanding 8,500" in lst
    assert "8,500" in r("client", "acme-widgets-llc").output          # billing in detail
    assert "outstanding" in r("show", "client", "acme-widgets-llc").output


def test_editor_resolution():
    from ronin.tui.app import _editor
    assert _editor()                                                  # non-empty list
