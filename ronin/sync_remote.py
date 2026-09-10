"""Remote sync with a SubgridSec Deck instance.

The Deck owns customers + invoices; RoninSuite owns engagements + findings +
report metadata.  This module pulls the customer list down into RoninSuite's
``clients`` table and pushes engagement / finding / report summaries up.  Raw
evidence never leaves the local machine.

Stdlib only (urllib).  Config resolution for URL/token:
  explicit arg  ->  env RONIN_DECK_URL / RONIN_DECK_TOKEN  ->  db state.
The URL is persisted to db state; the token is not (keep it in .env).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import urllib.error
import urllib.request

from ronin.core import db
from ronin.core.models import Client

_UA = "roninsuite-sync/1"
_K_URL = "sync.deck_url"
_K_PULLED = "sync.customers_pulled_at"
_K_PUSHED = "sync.pushed_at"


class DeckError(RuntimeError):
    pass


def resolve(url: str | None, token: str | None) -> tuple[str, str]:
    url = (url or os.environ.get("RONIN_DECK_URL") or db.get_state(_K_URL, "")).rstrip("/")
    token = token or os.environ.get("RONIN_DECK_TOKEN", "")
    if not url:
        raise DeckError("no Deck URL — pass --remote or set RONIN_DECK_URL")
    if not token:
        raise DeckError("no Deck token — pass --token or set RONIN_DECK_TOKEN")
    db.set_state(_K_URL, url)
    return url, token


def _req(method: str, url: str, token: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "User-Agent": _UA,
        "Accept": "application/json",
        **({"Content-Type": "application/json"} if data else {}),
    })
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise DeckError(f"{method} {url} -> HTTP {e.code}: {e.read()[:200].decode(errors='replace')}")
    except urllib.error.URLError as e:
        raise DeckError(f"{method} {url} -> {e.reason}")


# ── pull: Deck customers -> RoninSuite clients ─────────────────────────────
def pull_customers(base: str, token: str, *, full: bool = False) -> int:
    since = "" if full else db.get_state(_K_PULLED, "")
    q = f"?since={since}" if since else ""
    payload = _req("GET", f"{base}/api/v1/sync/customers{q}", token)
    n = 0
    for c in payload.get("customers", []):
        existing = db.get_client(c["slug"])
        base_fields = existing.model_dump() if existing else {}
        base_fields.update(
            slug=c["slug"], name=c["name"],
            contact_name=c.get("primary_contact_name") or base_fields.get("contact_name", ""),
            contact_email=c.get("primary_contact_email") or base_fields.get("contact_email", ""),
            phone=c.get("phone", ""), website=c.get("website", ""),
            x=c.get("x", ""), facebook=c.get("facebook", ""), linkedin=c.get("linkedin", ""),
            cadence_days=int(c.get("cadence_days", 0) or 0),
        )
        db.upsert_client(Client(**base_fields))
        n += 1
    db.set_state(_K_PULLED, payload.get("server_time", _now_iso()))
    return n


# ── push: RoninSuite engagements/findings/reports -> Deck ──────────────────
def push_all(base: str, token: str) -> dict:
    engs, finds, reps = [], [], []
    for e in db.list_engagements():
        cl = db.get_client(e.client_slug) if e.client_slug else None
        engs.append({
            "slug": e.slug,
            "customer_slug": e.client_slug or None,
            "title": e.slug,
            "tester": e.tester,
            "authorized_by": cl.name if cl else "",
            "scope_hash": _scope_hash(e.slug),
            "risk_rating": _risk_rating(e.slug),
            "updated_at": e.created.astimezone(_dt.timezone.utc).isoformat(),
        })
        for f in db.get_findings(e.slug):
            finds.append({
                "engagement_slug": e.slug, "fingerprint": f.fingerprint,
                "title": f.title, "target": f.target, "severity": f.severity.value,
                "cvss_score": f.cvss_score, "status": getattr(f, "status", "open"),
                "cve": list(f.cve),
            })
        for r in _reports_for(e.slug):
            reps.append(r)
    resp = _req("POST", f"{base}/api/v1/sync/push", token,
                {"engagements": engs, "findings": finds, "reports": reps})
    db.set_state(_K_PUSHED, _now_iso())
    return resp


# ── helpers ───────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _scope_hash(slug: str) -> str:
    from ronin.config import paths

    p = paths().scope_file(slug)
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else ""


def _risk_rating(slug: str) -> str:
    from ronin.reports.render import build_context

    try:
        return build_context(slug).risk_rating
    except Exception:  # noqa: BLE001
        return ""


def _reports_for(slug: str) -> list[dict]:
    from ronin.config import paths

    out = []
    base = paths().reports / slug
    if not base.is_dir():
        return out
    for stamp in sorted(base.glob("*")):
        for p in stamp.glob("*.*"):
            if p.suffix.lstrip(".") not in ("md", "html", "pdf"):
                continue
            out.append({
                "engagement_slug": slug, "level": p.stem, "format": p.suffix.lstrip("."),
                "filename": p.name,
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                "bytes": p.stat().st_size,
            })
    return out
