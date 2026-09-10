"""Engagement scope: the authorization boundary every scan is checked against.

A scope file (``engagements/<slug>/scope.yaml``) declares what you are allowed to
touch.  ``Scope.check(target)`` returns a :class:`ScopeDecision`.  The run
orchestrator hard-blocks out-of-scope targets unless the operator passes an
explicit ``--force`` with a written justification (which is logged).
"""
from __future__ import annotations

import datetime as _dt
import fnmatch
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

import yaml

from ronin.core.models import ScopeDecision

SCOPE_TEMPLATE = """\
# RoninSuite engagement scope - the authorization boundary for every scan.
client: "{client}"
engagement: "{slug}"
tester: "{tester}"
authorized_by: ""            # name + role of the person who signed off

window:                       # engagement testing window (local time)
  start: "{start}"
  end:   "{end}"

rules_of_engagement: |
  No denial-of-service. No social engineering. Credential brute-force only
  outside the client's business hours. Stop and report immediately on evidence
  of a pre-existing compromise.

in_scope:                     # IPs, CIDRs, domains (glob ok), or URL prefixes
  - "example.com"
  - "*.example.com"
  # - "203.0.113.0/24"
  # - "https://app.example.com"

out_of_scope:                 # always wins over in_scope
  # - "mail.example.com"
  # - "203.0.113.7"
"""


class Scope:
    def __init__(self, data: dict, path: Path | None = None):
        self.path = path
        self.client = data.get("client", "")
        self.engagement = data.get("engagement", "")
        self.tester = data.get("tester", "")
        self.authorized_by = data.get("authorized_by", "")
        self.roe = data.get("rules_of_engagement", "")
        self.in_scope = [str(x).strip() for x in (data.get("in_scope") or [])]
        self.out_of_scope = [str(x).strip() for x in (data.get("out_of_scope") or [])]
        w = data.get("window") or {}
        self.window_start = _parse_dt(w.get("start"))
        self.window_end = _parse_dt(w.get("end"))

    # -- loading ---------------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"scope file not found: {path}")
        return cls(yaml.safe_load(path.read_text()) or {}, path)

    # -- checks --------------------------------------------------------------
    def within_window(self, when: _dt.datetime | None = None) -> bool:
        when = when or _dt.datetime.now()
        if self.window_start and when < self.window_start:
            return False
        if self.window_end and when > self.window_end:
            return False
        return True

    def check(self, target: str) -> ScopeDecision:
        target = target.strip()
        host = _host_of(target)
        win = self.within_window()

        for rule in self.out_of_scope:
            if _matches(target, host, rule):
                return ScopeDecision(
                    target=target, allowed=False, within_window=win,
                    matched_rule=rule,
                    reason=f"target matches out-of-scope rule '{rule}'",
                )
        for rule in self.in_scope:
            if _matches(target, host, rule):
                reason = f"in scope via '{rule}'"
                if not win:
                    reason += " (WARNING: outside testing window)"
                return ScopeDecision(
                    target=target, allowed=True, within_window=win,
                    matched_rule=rule, reason=reason,
                )
        return ScopeDecision(
            target=target, allowed=False, within_window=win,
            reason="target does not match any in-scope rule",
        )


class ScopeViolation(RuntimeError):
    def __init__(self, decision: ScopeDecision):
        self.decision = decision
        super().__init__(decision.reason)


# --- helpers -------------------------------------------------------------------
def _parse_dt(v) -> _dt.datetime | None:
    if not v:
        return None
    if isinstance(v, _dt.datetime):
        return v
    if isinstance(v, _dt.date):
        return _dt.datetime.combine(v, _dt.time.min)
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return _dt.datetime.strptime(str(v), fmt)
        except ValueError:
            continue
    return None


def _host_of(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    # strip :port and path fragments for bare host:port entries
    t = target.split("/")[0]
    if t.count(":") == 1:
        t = t.split(":")[0]
    return t.lower()


def _as_ip(s: str):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def _matches(target: str, host: str, rule: str) -> bool:
    rule = rule.strip()
    # URL-prefix rule
    if "://" in rule:
        return target.startswith(rule.rstrip("/"))
    # CIDR / IP-range rule
    if "/" in rule:
        try:
            net = ipaddress.ip_network(rule, strict=False)
            ip = _as_ip(host) or _as_ip(target)
            return ip is not None and ip in net
        except ValueError:
            return False
    # single IP rule
    rip = _as_ip(rule)
    if rip is not None:
        hip = _as_ip(host) or _as_ip(target)
        return hip == rip
    # domain / glob rule
    host = host or _host_of(target)
    if not host:
        return False
    if rule.startswith("*."):
        base = rule[2:].lower()
        return host == base or host.endswith("." + base)
    return fnmatch.fnmatch(host, rule.lower())
