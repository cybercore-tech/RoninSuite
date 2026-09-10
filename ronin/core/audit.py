"""Append-only audit trail.

Every scope decision and every command RoninSuite executes is recorded as one
JSON object per line in ``audit.log`` at the project root.  This is the record
you hand a client (or a lawyer) to show exactly what was run, when, by whom, and
against what.  It is never rewritten.
"""
from __future__ import annotations

import datetime as _dt
import getpass
import json
import os
import socket
from typing import Any

from ronin.config import paths


def record(event: str, **fields: Any) -> None:
    entry = {
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "event": event,
        "operator": os.environ.get("RONIN_OPERATOR") or getpass.getuser(),
        "host": socket.gethostname(),
        "pid": os.getpid(),
        **fields,
    }
    line = json.dumps(entry, default=str, ensure_ascii=False)
    with open(paths().audit_log, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
