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
import uuid as _uuid

from ronin.core import db
from ronin.core.models import Client

_UA = "roninsuite-sync/1"
_K_URL = "sync.deck_url"
_K_PULLED = "sync.customers_pulled_at"
_K_PUSHED = "sync.pushed_at"
_K_REPORTS = "sync.reports_pushed_at"

_REPORT_EXT = ("md", "html", "pdf")


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


def _multipart(fields: dict, *, file_field: str, filename: str,
               content_type: str, data: bytes) -> tuple[str, bytes]:
    """Build a multipart/form-data body with stdlib only."""
    boundary = "----roninsuite-" + _uuid.uuid4().hex
    crlf = b"\r\n"
    buf = bytearray()
    for k, v in fields.items():
        buf += b"--" + boundary.encode() + crlf
        buf += f'Content-Disposition: form-data; name="{k}"'.encode() + crlf + crlf
        buf += str(v).encode() + crlf
    buf += b"--" + boundary.encode() + crlf
    buf += (f'Content-Disposition: form-data; name="{file_field}"; '
            f'filename="{filename}"').encode() + crlf
    buf += f"Content-Type: {content_type}".encode() + crlf + crlf
    buf += data + crlf
    buf += b"--" + boundary.encode() + b"--" + crlf
    return f"multipart/form-data; boundary={boundary}", bytes(buf)


def _post_multipart(url: str, token: str, content_type: str, body: bytes) -> dict:
    r = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "User-Agent": _UA,
        "Accept": "application/json",
        "Content-Type": content_type,
    })
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise DeckError(f"POST {url} -> HTTP {e.code}: {e.read()[:200].decode(errors='replace')}")
    except urllib.error.URLError as e:
        raise DeckError(f"POST {url} -> {e.reason}")


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
def push_all(base: str, token: str, *, with_reports: bool = False) -> dict:
    engs, finds, reps, invs = [], [], [], []
    for iv in db.list_invoices():
        invs.append({
            "external_ref": iv.id,
            "customer_slug": iv.client_slug,
            "number": iv.number or None,
            "currency": iv.currency,
            "status": iv.status if iv.status in ("draft", "sent") else "draft",
            "issued_on": iv.issued.isoformat() if iv.issued else None,
            "due_on": iv.due.isoformat() if iv.due else None,
            "amount_cents": round(iv.amount * 100),
            "description": iv.description,
        })
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
                {"engagements": engs, "findings": finds, "reports": reps, "invoices": invs})
    db.set_state(_K_PUSHED, _now_iso())
    if with_reports:
        up = push_report_files(base, token)
        resp["reports_uploaded"] = up["uploaded"]
        resp["reports_upload_failed"] = up["failed"]
        if up["errors"]:
            resp.setdefault("conflicts", []).extend(up["errors"])
    return resp


def push_report_files(base: str, token: str) -> dict:
    """Upload the latest rendered report file per (engagement, level, format) so the
    Deck client portal can serve them.  Metadata must already be on the Deck
    (``push_all`` sends it); the sha256 links the file to its row."""
    uploaded = failed = 0
    errors: list[str] = []
    for e in db.list_engagements():
        for p in _latest_report_files(e.slug):
            data = p.read_bytes()
            fields = {
                "engagement_slug": e.slug,
                "level": p.stem,
                "format": p.suffix.lstrip("."),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            ctype = {
                "pdf": "application/pdf",
                "html": "text/html",
                "md": "text/plain",
            }.get(fields["format"], "application/octet-stream")
            ct, body = _multipart(fields, file_field="file", filename=p.name,
                                  content_type=ctype, data=data)
            try:
                _post_multipart(f"{base}/api/v1/sync/reports/file", token, ct, body)
                uploaded += 1
            except DeckError as ex:  # noqa: PERF203
                failed += 1
                errors.append(f"{e.slug}/{p.name}: {ex}")
    db.set_state(_K_REPORTS, _now_iso())
    return {"uploaded": uploaded, "failed": failed, "errors": errors}


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
    out = []
    for p in _iter_report_files(slug):
        out.append({
            "engagement_slug": slug, "level": p.stem, "format": p.suffix.lstrip("."),
            "filename": p.name,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            "bytes": p.stat().st_size,
        })
    return out


def _iter_report_files(slug: str):
    """Every rendered report file for an engagement, across all timestamps."""
    from ronin.config import paths

    base = paths().reports / slug
    if not base.is_dir():
        return
    for stamp in sorted(base.glob("*")):
        for p in sorted(stamp.glob("*.*")):
            if p.suffix.lstrip(".") in _REPORT_EXT:
                yield p


def _latest_report_files(slug: str):
    """The newest file for each (level, format) — what the portal should serve."""
    newest: dict[tuple[str, str], object] = {}
    for p in _iter_report_files(slug):
        key = (p.stem, p.suffix.lstrip("."))
        cur = newest.get(key)
        if cur is None or p.stat().st_mtime >= cur.stat().st_mtime:
            newest[key] = p
    return list(newest.values())
