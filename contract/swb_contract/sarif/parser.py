from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    CodeFlowStep,
    SarifArtifact,
    SarifDocumentInfo,
    SarifCodeFlow,
    SarifLocation,
    SarifRegion,
    SarifRelatedLocation,
    SarifResult,
    SarifRule,
    SarifRun,
    SarifTool,
    SarifThreadFlow,
)


def parse_sarif(path: Path) -> list[SarifRun]:
    """Parse a SARIF 2.1.0 file and return a list of runs."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    return parse_sarif_data(data)


def parse_sarif_data(data: dict) -> list[SarifRun]:
    """Parse an already-decoded SARIF 2.1.0 document (e.g. from
    `json.loads(sarif_bytes)`) and return a list of runs.

    Split out from `parse_sarif` (T-35) so callers that already have the
    bytes/dict in hand (server ingest) don't need a file on disk.
    """
    return [_parse_run(idx, run) for idx, run in enumerate(data.get("runs", []))]


def parse_document_info(data: dict) -> SarifDocumentInfo:
    """Сведения о прогоне из `properties` документа, если анализатор их дал.

    Разбор терпимый: property bag свободный, и чужие ключи не должны ронять
    загрузку. Отсутствующее или не-строковое значение — это None, а не
    выдуманная подстановка.

    Ключи — как их пишет Svacer. Смотрим и в `properties` документа, и в
    `runs[0].properties`: спецификация допускает оба места, и часть
    инструментов кладёт свои сведения на уровень прогона.
    """
    bags = [data.get("properties")]
    runs = data.get("runs")
    if isinstance(runs, list) and runs and isinstance(runs[0], dict):
        bags.append(runs[0].get("properties"))

    def pick(*keys: str) -> str | None:
        for bag in bags:
            if not isinstance(bag, dict):
                continue
            for key in keys:
                value = bag.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return None

    return SarifDocumentInfo(
        project=pick("project_name"),
        branch=pick("branch_name"),
        analyzer_config=pick("checkers_config_version"),
    )


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
        artifacts=_parse_artifacts(run.get("artifacts")),
    )


def _parse_artifacts(artifacts: object) -> list[SarifArtifact]:
    """`run.artifacts[]` with embedded contents where present.

    Order is preserved: a result's `artifactLocation.index` addresses this
    list by position. Parsing is lenient — a malformed entry becomes an
    artifact with no contents rather than failing the whole document.
    """
    if not isinstance(artifacts, list):
        return []
    out: list[SarifArtifact] = []
    for item in artifacts:
        if not isinstance(item, dict):
            out.append(SarifArtifact(uri=""))
            continue
        location = item.get("location")
        uri = location.get("uri", "") if isinstance(location, dict) else ""
        contents = item.get("contents")
        text = contents.get("text") if isinstance(contents, dict) else None
        out.append(SarifArtifact(
            uri=uri if isinstance(uri, str) else "",
            contents=text if isinstance(text, str) else None,
        ))
    return out


def _parse_tool(tool: dict) -> SarifTool:
    driver = tool.get("driver", {})
    rules = [_parse_rule(r) for r in driver.get("rules", [])]
    return SarifTool(
        name=driver.get("name", "unknown"),
        version=driver.get("version") or driver.get("semanticVersion"),
        rules=rules,
    )


def _collect_cwe_refs(rule: dict, props: dict) -> list[str]:
    """CWE-ссылки правила из всех мест, где их размещают анализаторы.

    Порядок сохраняется — первым идёт тот CWE, на который правило нацелено.
    Значения отдаются как написаны, кроме `properties.cwe[].name`: там по
    смыслу поля лежит голый номер (`"120"`), и без префикса его не отличить
    от произвольного числа.

    Разбор терпимый: у третьих сторон эти поля бывают не по спецификации,
    и кривое значение должно вести себя как отсутствующее — как и в
    `_parse_security_severity`.
    """
    refs: list[str] = [t for t in props.get("tags", []) if isinstance(t, str)]

    for entry in props.get("cwe", []) or []:
        name = entry.get("name") if isinstance(entry, dict) else entry
        if not isinstance(name, str) or not name:
            continue
        refs.append(f"CWE-{name}" if name.isdigit() else name)

    for rel in rule.get("relationships", []) or []:
        if not isinstance(rel, dict):
            continue
        target = rel.get("target")
        tid = target.get("id") if isinstance(target, dict) else None
        if isinstance(tid, str) and tid:
            refs.append(tid)

    return refs


def _parse_rule(rule: dict) -> SarifRule:
    props = rule.get("properties", {})
    sec_sev = props.get("security-severity")
    # T-35: consolidates two previously-divergent behaviors (CLI parser had no
    # fallback; server's raw-dict ingest did) — fullDescription wins when
    # present, otherwise fall back to shortDescription.
    full_description = _extract_text(rule.get("fullDescription") or rule.get("shortDescription"))
    return SarifRule(
        rule_id=rule.get("id", ""),
        name=rule.get("name"),
        full_description=full_description,
        help_uri=rule.get("helpUri"),
        security_severity=_parse_security_severity(sec_sev),
        tags=props.get("tags", []),
        default_level=rule.get("defaultConfiguration", {}).get("level", "warning"),
        cwe_refs=_collect_cwe_refs(rule, props),
    )


def _parse_security_severity(sec_sev: Any) -> float | None:
    """Tolerant cast of properties["security-severity"] to float.

    Third-party scanners aren't always spec-clean; a malformed (non-numeric)
    value here must not blow up parsing/ingest — it should just be treated
    as absent, exactly like `swb_contract.severity.map_severity`'s own
    `except (TypeError, ValueError): pass` fallback to level-based severity
    (T-35 regression: this used to be eagerly `float(sec_sev)`d with no
    guard, so a bad value raised ValueError instead of degrading).
    """
    if sec_sev is None:
        return None
    try:
        return float(sec_sev)
    except (TypeError, ValueError):
        return None


def _parse_result(run_idx: int, result_idx: int, result: dict) -> SarifResult:
    locations = [_parse_location(loc) for loc in result.get("locations", [])]
    related_locations = [
        _parse_related_location(loc) for loc in result.get("relatedLocations", [])
    ]
    return SarifResult(
        run_index=run_idx,
        result_index=result_idx,
        rule_id=result.get("ruleId", ""),
        # Дефолт не подставляется: цепочка разрешения уровня требует
        # знать, было ли поле в документе (см. SarifResult.level).
        level=result.get("level"),
        message=_extract_text(result.get("message", {})),
        locations=locations,
        related_locations=related_locations,
        code_flows=_parse_code_flows(result.get("codeFlows", [])),
        fingerprints=_parse_fingerprint_dict(result.get("fingerprints")),
        partial_fingerprints=_parse_fingerprint_dict(result.get("partialFingerprints")),
        tool_severity=_parse_tool_severity(result.get("properties")),
    )


def _parse_tool_severity(props: object) -> str | None:
    """Собственная качественная оценка анализатора из property bag результата.

    `checker_severity` — ключ Svacer. Соседний `severity` берём только когда
    первого нет: у Svacer он несёт severity РАЗМЕТКИ, а не анализатора, и в
    обоих наших отчётах равен Minor у всех находок.
    """
    if not isinstance(props, dict):
        return None
    for key in ("checker_severity", "severity"):
        value = props.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _parse_fingerprint_dict(obj: object) -> dict[str, str]:
    """Tolerant extraction of a SARIF fingerprint dict (values coerced to str)."""
    if not isinstance(obj, dict):
        return {}
    return {str(k): str(v) for k, v in obj.items()}


def _parse_physical_location(loc: dict) -> tuple[str, SarifRegion, str | None, int | None]:
    """Shared (uri, region, uriBaseId) extraction — used by both `locations[]`
    and `relatedLocations[]`, which share the same `physicalLocation` shape."""
    phys = loc.get("physicalLocation", {})
    artifact = phys.get("artifactLocation", {})
    region = phys.get("region", {})
    index = artifact.get("index")
    return (
        artifact.get("uri", ""),
        SarifRegion(
            start_line=region.get("startLine", 1),
            end_line=region.get("endLine"),
            start_column=region.get("startColumn"),
        ),
        artifact.get("uriBaseId"),
        index if isinstance(index, int) else None,
    )


def _parse_location(loc: dict) -> SarifLocation:
    uri, region, uri_base_id, index = _parse_physical_location(loc)
    return SarifLocation(uri=uri, region=region, uri_base_id=uri_base_id, artifact_index=index)


def _parse_related_location(loc: dict) -> SarifRelatedLocation:
    # T-39 (ADR 0001 §8): relatedLocations are payload, not identity material —
    # stored/shown, never fed into swb_id.
    uri, region, uri_base_id, _ = _parse_physical_location(loc)
    return SarifRelatedLocation(
        uri=uri,
        region=region,
        uri_base_id=uri_base_id,
        message=_extract_text(loc.get("message", {})),
    )


def _parse_code_flows(code_flows: list) -> list[SarifCodeFlow]:
    """T-39 (ADR 0001 §8): codeFlow structure is preserved (codeFlows ->
    threadFlows -> steps), not collapsed into display strings — it's payload,
    not identity material. Nesting mirrors the SARIF 2.1.0 shape so multiple
    codeFlows/threadFlows in one result (e.g. several taint paths) aren't
    merged into a single flat list."""
    result: list[SarifCodeFlow] = []
    for cf in code_flows:
        thread_flows: list[SarifThreadFlow] = []
        for tf in cf.get("threadFlows", []):
            steps: list[CodeFlowStep] = []
            for tfl in tf.get("locations", []):
                inner_loc = tfl.get("location", {})
                msg = _extract_text(inner_loc.get("message", {}))
                inner_phys = inner_loc.get("physicalLocation", {})
                uri = inner_phys.get("artifactLocation", {}).get("uri", "")
                line = inner_phys.get("region", {}).get("startLine")
                steps.append(CodeFlowStep(uri=uri, line=line, message=msg))
            thread_flows.append(SarifThreadFlow(steps=steps))
        result.append(SarifCodeFlow(thread_flows=thread_flows))
    return result


def _extract_text(obj: dict | str | None) -> str:
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    return obj.get("text", "")
