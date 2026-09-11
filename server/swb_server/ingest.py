"""Parse SARIF + swbmeta dict and return structured data for DB insertion."""
from __future__ import annotations

import json
import re

from pydantic import ValidationError

from swb_contract.sarif.models import SarifResult, SarifRun
from swb_contract.sarif.parser import parse_document_info, parse_sarif_data
from swb_contract.severity import SEV_ORDER, map_severity
from swb_contract.swbmeta import Finding as MetaFinding


# No two analyzers spell a CWE the same way. Measured on real reports:
#   Semgrep  `CWE-89: Improper Neutralization ...`   (tag)
#   CodeQL   `external/cwe/cwe-089`                  (tag)
#   Svacer   `CWE120`                                (relationships target)
#   Svacer   `CWE-120`                               (properties.cwe, prefixed
#                                                     by the parser)
# Hence a full-string search (`match` anchors at position 0 and never saw a
# single CodeQL tag) and an OPTIONAL separator — Svacer writes none.
_CWE_RE = re.compile(r"(?i)cwe[-_/]?(\d+)")


def _extract_cwes(rule_id: str, cwe_refs: list[str]) -> list[str]:
    """Every CWE of a rule, in the order the analyzer listed them.

    Takes the raw references collected by the parser (`SarifRule.cwe_refs`)
    rather than tags alone: Svacer puts none of its CWEs in tags, so a
    tags-only reading found 0 of its 424 findings.

    The number goes through `int()` so zero-padded ids collapse onto the
    canonical form: `cwe-089` must become `CWE-89`, not `CWE-089`, or it
    joins with nothing — neither the `?cwe=` filter, nor the `by=cwe`
    aggregation, nor any CWE-keyed lookup.

    Order is the analyzer's own and is preserved: first comes the weakness
    the rule actually targets, the rest are related ones (CodeQL routinely
    lists 2-5, e.g. path injection carries CWE-22/23/36/73). Callers that
    need a single value take the first.
    """
    seen: dict[int, None] = {}
    for text in (*cwe_refs, rule_id):
        for m in _CWE_RE.finditer(text):
            seen.setdefault(int(m.group(1)), None)
    return [f"CWE-{n}" for n in seen]


class MetaValidationError(ValueError):
    """swbmeta не проходит валидацию ingest'а — ошибка meta-входа, не SARIF'а."""


_LEVEL_TAGS = {"t": "tool", "c": "content", "l": "legacy"}


def _fingerprint_level(swb_id: str, level: str) -> str:
    """Level из префикса swb_id (`sw2:{t|c|l}:hash:occ`, ADR 0001 §1)."""
    parts = swb_id.split(":")
    if len(parts) == 4 and parts[0] == "sw2" and parts[1] in _LEVEL_TAGS:
        return _LEVEL_TAGS[parts[1]]
    return level


def _format_validation_error(exc: ValidationError) -> str:
    parts = []
    for e in exc.errors():
        loc = ".".join(str(p) for p in e["loc"]) or "<root>"
        parts.append(f"{loc}: {e['msg']}")
    return "; ".join(parts)


def _validate_meta_findings(raw_findings: list) -> list[MetaFinding]:
    """Validate every meta finding against the swbmeta/v3 contract schema
    (`swb_contract.swbmeta.Finding`) instead of reading it field-by-field
    with permissive `mf.get(key, default)` calls.

    T-36: a malformed/incomplete locator (missing/wrong-typed run, result,
    region.start_line, …) used to silently default (`.get("start_line", 0)`)
    instead of failing — this is exactly the "молчаливые дефолты" this task
    removes. Any structural mismatch now rejects the whole upload with a
    clear per-finding message; nothing is written to the DB (ingest() runs
    before any commit in routers/runs.py).
    """
    validated: list[MetaFinding] = []
    for i, mf in enumerate(raw_findings):
        if not isinstance(mf, dict):
            raise MetaValidationError(
                f"findings[{i}]: expected an object, got {type(mf).__name__}"
            )
        try:
            finding = MetaFinding.model_validate(mf)
        except ValidationError as exc:
            raise MetaValidationError(
                f"findings[{i}]: {_format_validation_error(exc)}"
            ) from exc
        # Non-empty swb_id is a business rule, not a structural pydantic
        # constraint (ADR 0001 §1/§6: identity is exact-match on this
        # string; an empty id would collapse distinct findings into one
        # identity) — checked explicitly, same as before T-36.
        if not finding.swb_id:
            raise MetaValidationError(f"findings[{i}]: swb_id must not be empty")
        validated.append(finding)
    return validated


def _reconcile_results_and_meta(sarif_runs: list[SarifRun], findings: list[MetaFinding]) -> None:
    """Strict SARIF<->meta join (T-36 Done when #2): every SARIF result that
    HAS locations must be claimed by exactly one meta finding's locator, and
    every meta finding's locator must point at a real SARIF result that has
    locations. Results without locations are legitimately excluded by the
    CLI (ADR 0001 §8) and must not appear in meta.

    Before this check, a locator pointing past the end of `results` (a
    broken index) silently degraded to an empty message and `level="warning"`
    (`results_map.get(...)` returning `None`) instead of failing — this is
    the anchor bug T-36 fixes. Any mismatch (missing, extra/duplicate,
    broken index) rejects the whole upload with details; nothing is written
    to the DB.
    """
    with_locations: set[tuple[int, int]] = set()
    without_locations: set[tuple[int, int]] = set()
    for srun in sarif_runs:
        for result in srun.results:
            key = (srun.index, result.result_index)
            if result.locations:
                with_locations.add(key)
            else:
                without_locations.add(key)

    seen: dict[tuple[int, int], list[int]] = {}
    problems: list[str] = []
    for i, f in enumerate(findings):
        key = (f.locator.run, f.locator.result)
        if key in without_locations:
            problems.append(
                f"findings[{i}]: locator (run={key[0]}, result={key[1]}) refers to a "
                "SARIF result without locations — the CLI never emits findings for those"
            )
        elif key not in with_locations:
            problems.append(
                f"findings[{i}]: locator (run={key[0]}, result={key[1]}) does not match "
                "any result in the SARIF file — broken locator index"
            )
        else:
            seen.setdefault(key, []).append(i)

    for key, idxs in seen.items():
        if len(idxs) > 1:
            problems.append(
                f"SARIF result (run={key[0]}, result={key[1]}) is claimed by "
                f"{len(idxs)} meta findings {idxs} — expected exactly one"
            )

    missing = sorted(with_locations - set(seen))
    if missing:
        shown = missing[:10]
        suffix = f" (+{len(missing) - 10} more)" if len(missing) > 10 else ""
        problems.append(
            f"{len(missing)} SARIF result(s) with locations have no matching meta finding: "
            f"{shown}{suffix}"
        )

    if problems:
        raise MetaValidationError(
            "meta/SARIF reconciliation failed:\n" + "\n".join(f"  - {p}" for p in problems)
        )


def ingest(sarif_bytes: bytes, meta: dict) -> dict:
    """
    Returns:
        {
          tool, tool_version,
          rules: {rule_id: {name, description, help_uri, default_severity, cwes}},
          findings: [{...}],
          counts: {critical, high, medium, low, note, all},
        }
    """
    sarif = json.loads(sarif_bytes)
    # T-35: structural SARIF parsing (tool/rules/results — message, level,
    # ruleId) is shared with the CLI parser via swb_contract.sarif; only the
    # swb-specific joins below (locator from meta, CWE extraction, severity
    # mapping) stay local to ingest.
    sarif_runs = parse_sarif_data(sarif)

    first = sarif_runs[0] if sarif_runs else None
    tool_name: str = first.tool.name if first else "unknown"
    tool_version: str = (first.tool.version if first else None) or "unknown"

    # Build rules lookup (only the first run's driver, same as before T-35)
    rules_map: dict[str, dict] = {}
    if first is not None:
        for rule in first.tool.rules:
            rid = rule.rule_id
            rules_map[rid] = {
                "name": rule.name or rid,
                "description": rule.full_description or "",
                "help_uri": rule.help_uri,
                "default_severity": map_severity(rule.security_severity, rule.default_level),
                "default_level": rule.default_level,
                "security_severity": rule.security_severity,
                "cwes": _extract_cwes(rid, rule.cwe_refs),
            }

    # Build SARIF results lookup: (run_idx, result_idx) -> result
    results_map: dict[tuple[int, int], SarifResult] = {}
    for srun in sarif_runs:
        for result in srun.results:
            results_map[(srun.index, result.result_index)] = result

    # T-36: meta findings are validated against the swbmeta/v3 contract
    # schema (`swb_contract.swbmeta.Finding`) and then cross-checked against
    # the parsed SARIF results — see docstrings of both helpers. Either
    # check failing raises MetaValidationError, which routers/runs.py turns
    # into a 422 before anything is written to the DB.
    validated_findings = _validate_meta_findings(meta.get("findings", []))
    _reconcile_results_and_meta(sarif_runs, validated_findings)

    counts = {s: 0 for s in SEV_ORDER}
    counts["all"] = 0
    findings_out: list[dict] = []

    for vf in validated_findings:
        swb_id = vf.swb_id
        loc = vf.locator
        rule_id = loc.rule_id
        uri = loc.uri
        start_line = loc.region.start_line
        end_line = loc.region.end_line

        # Guaranteed present: _reconcile_results_and_meta already checked
        # every validated locator matches a real SARIF result with locations.
        sarif_result = results_map[(loc.run, loc.result)]
        rule_info = rules_map.get(rule_id, {})

        message = sarif_result.message
        # SARIF 2.1.0: уровень берётся с самого результата; если поля нет —
        # с defaultConfiguration правила; и лишь затем "warning". Средний шаг
        # раньше пропускался, из-за чего весь вывод Semgrep (он `level` на
        # результате не пишет) схлопывался в один уровень. Последний фолбэк
        # нужен для правил, которых нет в списке драйвера.
        level = sarif_result.level or rule_info.get("default_level") or "warning"
        # Собственная шкала анализатора идёт перед `level`: у Svacer четыре
        # ступени, а в `level` их помещается три, и Major с Normal там
        # неразличимы — 278 находок из 424 в двух отчётах.
        severity = map_severity(
            rule_info.get("security_severity"), level, sarif_result.tool_severity
        )
        # Falls back to the rule id for results whose rule is missing from
        # the driver's rule list (some tools ship an incomplete one).
        cwes = rule_info.get("cwes") or _extract_cwes(rule_id, [])

        fps = vf.fingerprints
        code = vf.code

        counts[severity] = counts.get(severity, 0) + 1
        counts["all"] += 1

        findings_out.append({
            "swb_id": swb_id,
            # ключи fingerprint_* не являются колонками Finding — upload
            # снимает их (pop) при создании/поиске FindingIdentity
            "fingerprint_algo": fps.algo,
            "fingerprint_level": _fingerprint_level(swb_id, fps.level),
            "occurrence": vf.occurrence,
            "rule_id": rule_id,
            "rule_name": rule_info.get("name", ""),
            "rule_description": rule_info.get("description", ""),
            "help_uri": rule_info.get("help_uri"),
            # `cwe` — основной CWE (первый из перечисленных анализатором),
            # на нём держатся фильтр и агрегация; `cwes` — все, для правила
            # максимума п. 17 методики ФСТЭК.
            "cwe": cwes[0] if cwes else None,
            "cwes": cwes,
            "security_severity": rule_info.get("security_severity"),
            "severity": severity,
            "message": message,
            "uri": uri,
            "start_line": start_line,
            "end_line": end_line,
            "scope": fps.scope,
            "snippet": code.snippet if code else None,
            "snippet_start": code.start_line if code else None,
            "snippet_end": code.end_line if code else None,
            "lang": code.lang if code else None,
            "git": vf.git.model_dump() if vf.git else None,
            # T-39 (ADR 0001 §8): multi-location payload, taken straight from
            # the (already-validated) meta finding — same trust boundary as
            # code/git above; not cross-checked against SARIF's own
            # locations[1:]/relatedLocations/codeFlows (ingest doesn't do
            # that for code/git either). Always a list (possibly empty), not
            # None, so the API/UI don't need a null-check.
            "extra_locations": [el.model_dump() for el in vf.extra_locations],
            "related_locations": [rl.model_dump() for rl in vf.related_locations],
            "code_flow": [cf.model_dump() for cf in vf.code_flows],
        })

    return {
        # Сведения о прогоне из property bag документа: имя проекта, ветка,
        # снимок, версия конфигурации анализатора. Нужны там, где их не дал
        # CLI, — например у отчётов Svacer, выгруженных с сервера анализатора
        # без доступа к исходникам.
        "document": parse_document_info(sarif),
        "tool": tool_name,
        "tool_version": tool_version,
        "rules": rules_map,
        "findings": findings_out,
        "counts": counts,
    }
