"""Parse SARIF + swbmeta dict and return structured data for DB insertion."""
from __future__ import annotations

import json
import re
from typing import Any

_SEV_ORDER = ["critical", "high", "medium", "low", "note"]

_LEVEL_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "note",
}


def _sec_sev_to_enum(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "note"


def _map_severity(security_severity: Any, level: str) -> str:
    if security_severity is not None:
        try:
            return _sec_sev_to_enum(float(security_severity))
        except (TypeError, ValueError):
            pass
    return _LEVEL_MAP.get(str(level).lower(), "note")


def _extract_cwe(rule_id: str, tags: list[str]) -> str | None:
    for tag in tags:
        m = re.match(r"(?i)cwe-(\d+)", tag)
        if m:
            return f"CWE-{m.group(1)}"
    m = re.match(r"(?i)(cwe-\d+)", rule_id)
    if m:
        return m.group(1).upper()
    return None


def _text(obj: Any) -> str:
    if isinstance(obj, dict):
        return obj.get("text", "")
    return str(obj) if obj else ""


class MetaValidationError(ValueError):
    """swbmeta не проходит валидацию ingest'а — ошибка meta-входа, не SARIF'а."""


_LEVEL_TAGS = {"t": "tool", "c": "content", "l": "legacy"}


def _fingerprint_level(swb_id: str, fps: dict) -> str:
    """Level из префикса swb_id (`sw2:{t|c|l}:hash:occ`, ADR 0001 §1)."""
    parts = swb_id.split(":")
    if len(parts) == 4 and parts[0] == "sw2" and parts[1] in _LEVEL_TAGS:
        return _LEVEL_TAGS[parts[1]]
    return fps.get("level") or "legacy"


def ingest(sarif_bytes: bytes, meta: dict) -> dict:
    """
    Returns:
        {
          tool, tool_version,
          rules: {rule_id: {name, description, help_uri, default_severity, cwe}},
          findings: [{...}],
          counts: {critical, high, medium, low, note, all},
        }
    """
    sarif = json.loads(sarif_bytes)
    sarif_runs: list[dict] = sarif.get("runs", [])

    first = sarif_runs[0] if sarif_runs else {}
    driver: dict = first.get("tool", {}).get("driver", {})
    tool_name: str = driver.get("name", "unknown")
    tool_version: str = driver.get("version", "unknown")

    # Build rules lookup
    rules_map: dict[str, dict] = {}
    for rule in driver.get("rules", []):
        rid = rule.get("id", "")
        props = rule.get("properties", {})
        tags = props.get("tags", [])
        sec_sev = props.get("security-severity")
        level = rule.get("defaultConfiguration", {}).get("level", "warning")
        rules_map[rid] = {
            "name": rule.get("name", "") or rid,
            "description": _text(rule.get("fullDescription") or rule.get("shortDescription")),
            "help_uri": rule.get("helpUri"),
            "default_severity": _map_severity(sec_sev, level),
            "security_severity": sec_sev,
            "cwe": _extract_cwe(rid, tags),
        }

    # Build SARIF results lookup: (run_idx, result_idx) -> result
    results_map: dict[tuple[int, int], dict] = {}
    for ri, srun in enumerate(sarif_runs):
        for rj, result in enumerate(srun.get("results", [])):
            results_map[(ri, rj)] = result

    counts = {s: 0 for s in _SEV_ORDER}
    counts["all"] = 0
    findings_out: list[dict] = []

    for i, mf in enumerate(meta.get("findings", [])):
        # swb_id обязателен: identity строится на точном равенстве этой строки
        # (ADR 0001 §1/§6); пустой id схлопнул бы разные находки в одну identity.
        swb_id = mf.get("swb_id") or ""
        if not swb_id:
            raise MetaValidationError(
                f"findings[{i}]: missing swb_id — regenerate the sidecar with swb-cli (swbmeta/v2)"
            )

        loc = mf.get("locator", {})
        run_idx = loc.get("run", 0)
        res_idx = loc.get("result", 0)
        rule_id = loc.get("rule_id", "")
        uri = loc.get("uri", "")
        region = loc.get("region", {})
        start_line = region.get("start_line", 0)
        end_line = region.get("end_line")

        sarif_result = results_map.get((run_idx, res_idx), {})
        rule_info = rules_map.get(rule_id, {})

        message = _text(sarif_result.get("message", ""))
        level = sarif_result.get("level", "warning")
        severity = _map_severity(rule_info.get("security_severity"), level)
        cwe = rule_info.get("cwe") or _extract_cwe(rule_id, [])

        fps = mf.get("fingerprints", {})
        code = mf.get("code") or {}

        counts[severity] = counts.get(severity, 0) + 1
        counts["all"] += 1

        findings_out.append({
            "swb_id": swb_id,
            # ключи fingerprint_* не являются колонками Finding — upload
            # снимает их (pop) при создании/поиске FindingIdentity
            "fingerprint_algo": fps.get("algo") or "swb-fp/2",
            "fingerprint_level": _fingerprint_level(swb_id, fps),
            "occurrence": mf.get("occurrence", 0),
            "rule_id": rule_id,
            "rule_name": rule_info.get("name", ""),
            "rule_description": rule_info.get("description", ""),
            "help_uri": rule_info.get("help_uri"),
            "cwe": cwe,
            "severity": severity,
            "message": message,
            "uri": uri,
            "start_line": start_line,
            "end_line": end_line,
            "scope": fps.get("scope"),
            "snippet": code.get("snippet"),
            "snippet_start": code.get("start_line"),
            "snippet_end": code.get("end_line"),
            "lang": code.get("lang"),
            "git": mf.get("git"),
        })

    return {
        "tool": tool_name,
        "tool_version": tool_version,
        "rules": rules_map,
        "findings": findings_out,
        "counts": counts,
    }
