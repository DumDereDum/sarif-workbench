"""Single source of truth for the severity enum, its display order, and the
mapping from SARIF `level`/`security-severity` to it.

Moved here verbatim from `server/swb_server/ingest.py` (T-34) — CLI and
server must import these instead of keeping local copies that can drift.
"""
from __future__ import annotations

from typing import Any

SEV_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "note")

LEVEL_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "note",
}


def sec_sev_to_enum(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "note"


def map_severity(security_severity: Any, level: str) -> str:
    if security_severity is not None:
        try:
            return sec_sev_to_enum(float(security_severity))
        except (TypeError, ValueError):
            pass
    return LEVEL_MAP.get(str(level).lower(), "note")
