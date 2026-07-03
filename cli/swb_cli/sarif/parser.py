from __future__ import annotations

import json
from pathlib import Path

from .models import (
    SarifLocation,
    SarifRegion,
    SarifResult,
    SarifRule,
    SarifRun,
    SarifTool,
)


def parse_sarif(path: Path) -> list[SarifRun]:
    """Parse a SARIF 2.1.0 file and return a list of runs."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    return [_parse_run(idx, run) for idx, run in enumerate(data.get("runs", []))]


def _parse_run(idx: int, run: dict) -> SarifRun:
    tool = _parse_tool(run.get("tool", {}))
    results = [
        _parse_result(idx, ridx, r)
        for ridx, r in enumerate(run.get("results", []))
    ]
    bases = run.get("originalUriBaseIds")
    return SarifRun(
        index=idx,
        tool=tool,
        results=results,
        original_uri_base_ids=bases if isinstance(bases, dict) else {},
    )


def _parse_tool(tool: dict) -> SarifTool:
    driver = tool.get("driver", {})
    rules = [_parse_rule(r) for r in driver.get("rules", [])]
    return SarifTool(
        name=driver.get("name", "unknown"),
        version=driver.get("version") or driver.get("semanticVersion"),
        rules=rules,
    )


def _parse_rule(rule: dict) -> SarifRule:
    props = rule.get("properties", {})
    sec_sev = props.get("security-severity")
    return SarifRule(
        rule_id=rule.get("id", ""),
        name=rule.get("name"),
        full_description=_extract_text(rule.get("fullDescription")),
        help_uri=rule.get("helpUri"),
        security_severity=float(sec_sev) if sec_sev is not None else None,
    )


def _parse_result(run_idx: int, result_idx: int, result: dict) -> SarifResult:
    locations = [_parse_location(loc) for loc in result.get("locations", [])]
    return SarifResult(
        run_index=run_idx,
        result_index=result_idx,
        rule_id=result.get("ruleId", ""),
        level=result.get("level", "warning"),
        message=_extract_text(result.get("message", {})),
        locations=locations,
        code_flow_steps=_parse_code_flows(result.get("codeFlows", [])),
        fingerprints=_parse_fingerprint_dict(result.get("fingerprints")),
        partial_fingerprints=_parse_fingerprint_dict(result.get("partialFingerprints")),
    )


def _parse_fingerprint_dict(obj: object) -> dict[str, str]:
    """Tolerant extraction of a SARIF fingerprint dict (values coerced to str)."""
    if not isinstance(obj, dict):
        return {}
    return {str(k): str(v) for k, v in obj.items()}


def _parse_location(loc: dict) -> SarifLocation:
    phys = loc.get("physicalLocation", {})
    artifact = phys.get("artifactLocation", {})
    region = phys.get("region", {})
    return SarifLocation(
        uri=artifact.get("uri", ""),
        region=SarifRegion(
            start_line=region.get("startLine", 1),
            end_line=region.get("endLine"),
            start_column=region.get("startColumn"),
        ),
        uri_base_id=artifact.get("uriBaseId"),
    )


def _parse_code_flows(code_flows: list) -> list[str]:
    steps = []
    for cf in code_flows:
        for tf in cf.get("threadFlows", []):
            for tfl in tf.get("locations", []):
                inner_loc = tfl.get("location", {})
                msg = _extract_text(inner_loc.get("message", {}))
                uri = (
                    inner_loc
                    .get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri", "")
                )
                line = (
                    inner_loc
                    .get("physicalLocation", {})
                    .get("region", {})
                    .get("startLine", "?")
                )
                steps.append(f"{uri}:{line}" + (f" — {msg}" if msg else ""))
    return steps


def _extract_text(obj: dict | str | None) -> str:
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    return obj.get("text", "")
