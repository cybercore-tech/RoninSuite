"""Self-contained CVSS v3.1 base-score calculator.

No external dependency.  Implements the spec's scoring equations and the 3.1
"roundup" rule exactly (Common Vulnerability Scoring System v3.1: Specification
Document, section 7).  Given a vector string it returns ``(score, severity)``.
"""
from __future__ import annotations

import math

_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# PR depends on Scope
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}

SEVERITY_BANDS = (
    (0.0, 0.0, "info"),
    (0.1, 3.9, "low"),
    (4.0, 6.9, "medium"),
    (7.0, 8.9, "high"),
    (9.0, 10.0, "critical"),
)


def severity_for(score: float) -> str:
    if score <= 0:
        return "info"
    for lo, hi, name in SEVERITY_BANDS:
        if lo <= round(score, 1) <= hi:
            return name
    return "critical"


def _roundup(x: float) -> float:
    """CVSS 3.1 roundup: smallest number to one decimal place >= input."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    out: dict[str, str] = {}
    for p in parts:
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        out[k.upper()] = v.upper()
    return out


def base_score(vector: str) -> float:
    """Return the CVSS v3.1 base score for a vector string.

    Accepts vectors with or without the ``CVSS:3.1/`` prefix.  Raises
    ``ValueError`` if a required base metric is missing/invalid.
    """
    m = parse_vector(vector)
    try:
        scope = m["S"]
        av = _METRICS["AV"][m["AV"]]
        ac = _METRICS["AC"][m["AC"]]
        ui = _METRICS["UI"][m["UI"]]
        pr = _PR["U" if scope == "U" else "C"][m["PR"]]
        c = _METRICS["C"][m["C"]]
        i = _METRICS["I"][m["I"]]
        a = _METRICS["A"][m["A"]]
    except KeyError as e:  # missing or bad metric
        raise ValueError(f"invalid CVSS v3.1 vector {vector!r}: {e}") from None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploit = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploit, 10))
    return _roundup(min(1.08 * (impact + exploit), 10))


def score_and_severity(vector: str) -> tuple[float, str]:
    s = base_score(vector)
    return s, severity_for(s)
