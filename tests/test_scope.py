import datetime as dt

from ronin.core.scope import Scope

BASE = {
    "in_scope": ["*.acme.example", "acme.example", "203.0.113.0/24",
                 "https://app.acme.example"],
    "out_of_scope": ["mail.acme.example", "203.0.113.7"],
}


def s(**over):
    return Scope({**BASE, **over})


def test_subdomain_and_apex():
    assert s().check("www.acme.example").allowed
    assert s().check("acme.example").allowed
    assert s().check("https://deep.app.acme.example/x").allowed


def test_out_of_scope_wins():
    d = s().check("mail.acme.example")
    assert not d.allowed and "out-of-scope" in d.reason


def test_cidr():
    assert s().check("203.0.113.42").allowed
    assert not s().check("203.0.113.7").allowed          # excluded host
    assert not s().check("198.51.100.9").allowed


def test_unrelated_denied():
    assert not s().check("evil.example").allowed
    assert not s().check("8.8.8.8").allowed


def test_url_prefix_rule():
    assert s().check("https://app.acme.example/login").allowed


def test_window():
    past = s(window={"start": "2000-01-01", "end": "2000-12-31"})
    d = past.check("acme.example")
    assert d.allowed and not d.within_window
    now = s(window={"start": (dt.date.today() - dt.timedelta(days=1)).isoformat(),
                    "end": (dt.date.today() + dt.timedelta(days=1)).isoformat()})
    assert now.check("acme.example").within_window
