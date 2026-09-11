"""Разрешение уровня результата: result.level → правило → "warning".

Спецификация SARIF 2.1.0 задаёт три шага, и средний раньше пропускался:
парсер подставлял "warning" прямо при разборе, из-за чего ingest не мог
отличить «в документе было написано warning» от «поля не было вовсе».

Ломалось это на Semgrep: он `level` на результате не пишет никогда, весь
уровень задан в `defaultConfiguration` правил. На реальном прогоне ndpi все
113 находок получали medium, хотя часть правил помечена error.

Проверяется:
  (а) парсер сохраняет отсутствие поля как None, а не как "warning";
  (б) явный level результата выигрывает у правила;
  (в) при отсутствии level берётся defaultConfiguration правила;
  (г) при отсутствии обоих — "warning" (последний фолбэк спецификации);
  (д) правило, которого нет в списке драйвера, тоже даёт "warning";
  (е) security-severity по-прежнему главнее уровня (прежнее поведение);
  (ж) сквозной случай Semgrep: правила с разными уровнями перестают
      схлопываться в один.
"""
from __future__ import annotations

import json

import pytest

import swb_server.ingest as ingest_mod
from swb_contract.sarif.parser import parse_sarif_data


def _rule(rid: str, level: str | None = None, sec_sev: str | None = None) -> dict:
    r: dict = {"id": rid, "properties": {}}
    if level is not None:
        r["defaultConfiguration"] = {"level": level}
    if sec_sev is not None:
        r["properties"]["security-severity"] = sec_sev
    return r


def _result(rid: str, level: str | None = None) -> dict:
    r: dict = {
        "ruleId": rid,
        "message": {"text": "finding"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/a.py"},
            "region": {"startLine": 1},
        }}],
    }
    if level is not None:
        r["level"] = level
    return r


def _sarif(rules: list[dict], results: list[dict]) -> bytes:
    return json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "T", "version": "1", "rules": rules}},
                  "results": results}],
    }).encode()


def _meta(rule_ids: list[str]) -> dict:
    return {"schema": "swbmeta/v3", "findings": [
        {
            "swb_id": f"sw2:t:hash{i}:0",
            "occurrence": 0,
            "locator": {"run": 0, "result": i, "rule_id": rid, "uri": "src/a.py",
                        "norm_uri": "src/a.py", "region": {"start_line": 1}},
            "fingerprints": {"algo": "swb-fp/2", "level": "tool", "rule": rid},
        }
        for i, rid in enumerate(rule_ids)
    ]}


def _severity(rules: list[dict], results: list[dict]) -> list[str]:
    out = ingest_mod.ingest(_sarif(rules, results), _meta([r["ruleId"] for r in results]))
    return [f["severity"] for f in out["findings"]]


# ── (а) парсер ─────────────────────────────────────────────────────────────


def test_parser_keeps_absent_level_as_none():
    """Без этого ingest не отличит «не было поля» от «было warning»."""
    runs = parse_sarif_data(json.loads(_sarif([_rule("R")], [_result("R")])))
    assert runs[0].results[0].level is None


def test_parser_keeps_explicit_level():
    runs = parse_sarif_data(json.loads(_sarif([_rule("R")], [_result("R", level="error")])))
    assert runs[0].results[0].level == "error"


# ── (б)-(д) цепочка разрешения ─────────────────────────────────────────────


def test_result_level_wins_over_rule():
    assert _severity([_rule("R", level="note")], [_result("R", level="error")]) == ["high"]


def test_rule_default_configuration_used_when_result_has_no_level():
    """Ядро правки: раньше здесь безусловно получалось medium."""
    assert _severity([_rule("R", level="error")], [_result("R")]) == ["high"]


@pytest.mark.parametrize(
    "rule_level,expected",
    [("error", "high"), ("warning", "medium"), ("note", "low"), ("none", "note")],
)
def test_every_rule_level_maps_through(rule_level, expected):
    assert _severity([_rule("R", level=rule_level)], [_result("R")]) == [expected]


def test_falls_back_to_warning_when_neither_present():
    """Последний шаг спецификации: ни у результата, ни у правила уровня нет."""
    assert _severity([_rule("R")], [_result("R")]) == ["medium"]


def test_falls_back_to_warning_for_rule_missing_from_driver():
    """Некоторые инструменты присылают неполный список правил."""
    assert _severity([], [_result("UNKNOWN")]) == ["medium"]


# ── (е) прежнее поведение не сломано ───────────────────────────────────────


def test_security_severity_still_outranks_level():
    """Числовая оценка главнее качественного уровня — как и до правки."""
    rules = [_rule("R", level="note", sec_sev="9.5")]
    assert _severity(rules, [_result("R", level="note")]) == ["critical"]


# ── (ж) сквозной случай Semgrep ────────────────────────────────────────────


def test_semgrep_shaped_report_no_longer_collapses_to_one_severity():
    """Semgrep не пишет level ни на одном результате — весь уровень в правилах.

    До правки все находки такого отчёта получали medium независимо от того,
    что написано в defaultConfiguration.
    """
    rules = [_rule("E", level="error"), _rule("W", level="warning"), _rule("N", level="note")]
    results = [_result("E"), _result("W"), _result("N"), _result("E")]
    assert _severity(rules, results) == ["high", "medium", "low", "high"]
