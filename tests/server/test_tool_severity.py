"""Собственная качественная шкала анализатора вместо огрублённого `level`.

В SARIF уровень результата — это `level` с четырьмя значениями, и шкалы
точнее в него не помещаются. Svacer различает Critical / Major / Normal /
Minor, но Major и Normal у него оба становятся `warning`: на двух реальных
отчётах так схлопываются 278 находок из 424. Исходная градация при этом
лежит рядом, в `properties.checker_severity`.

Проверяется:
  (а) парсер достаёт шкалу из property bag результата;
  (б) `checker_severity` важнее соседнего `severity`: у Svacer второй несёт
      severity РАЗМЕТКИ и равен Minor у всех находок обоих отчётов;
  (в) порядок источников: security-severity → шкала анализатора → level;
  (г) незнакомое значение не угадывается и не роняет разбор;
  (д) сквозь ingest: Major и Normal перестают быть неразличимыми.
"""
from __future__ import annotations

import json

import pytest

import swb_server.ingest as ingest_mod
from swb_contract.sarif.parser import parse_sarif_data
from swb_contract.severity import map_severity


def _sarif(results, rules=None):
    return json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Svacer", "version": "12", "rules": rules or []}},
            "results": results,
        }],
    }).encode()


def _result(rule_id="R", level="warning", props=None):
    r = {
        "ruleId": rule_id, "level": level, "message": {"text": "finding"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/a.c"}, "region": {"startLine": 1}}}],
    }
    if props is not None:
        r["properties"] = props
    return r


def _meta(rule_ids):
    return {"schema": "swbmeta/v3", "findings": [
        {
            "swb_id": f"sw2:t:h{i}:0", "occurrence": 0,
            "locator": {"run": 0, "result": i, "rule_id": rid, "uri": "src/a.c",
                        "norm_uri": "src/a.c", "region": {"start_line": 1}},
            "fingerprints": {"algo": "swb-fp/2", "level": "tool", "rule": rid},
        }
        for i, rid in enumerate(rule_ids)
    ]}


# ── (а)-(б) разбор ─────────────────────────────────────────────────────────


def test_parser_reads_checker_severity():
    runs = parse_sarif_data(json.loads(_sarif([_result(props={"checker_severity": "Major"})])))
    assert runs[0].results[0].tool_severity == "Major"


def test_checker_severity_wins_over_marker_severity():
    """У Svacer `properties.severity` — severity разметки: в обоих наших
    отчётах она равна Minor у всех 424 находок, тогда как checker_severity
    различается. Перепутать их значит потерять шкалу целиком."""
    runs = parse_sarif_data(json.loads(_sarif([
        _result(props={"checker_severity": "Critical", "severity": "Minor"})
    ])))
    assert runs[0].results[0].tool_severity == "Critical"


def test_plain_severity_is_used_when_there_is_no_checker_severity():
    runs = parse_sarif_data(json.loads(_sarif([_result(props={"severity": "Major"})])))
    assert runs[0].results[0].tool_severity == "Major"


def test_absent_properties_give_none():
    runs = parse_sarif_data(json.loads(_sarif([_result()])))
    assert runs[0].results[0].tool_severity is None


# ── (в)-(г) отображение ────────────────────────────────────────────────────


@pytest.mark.parametrize("tool_sev,expected", [
    ("Critical", "critical"), ("Major", "high"),
    ("Normal", "medium"), ("Minor", "low"),
    ("MAJOR", "high"), ("  minor  ", "low"),  # регистр и пробелы не важны
])
def test_tool_scale_maps_to_our_levels(tool_sev, expected):
    assert map_severity(None, "warning", tool_sev) == expected


def test_security_severity_still_wins():
    """Числовая оценка CVSS точнее любой качественной шкалы."""
    assert map_severity(9.5, "note", "Minor") == "critical"


def test_tool_scale_beats_level():
    """Ради этого всё и делается: `level` у Svacer грубее его собственной
    шкалы, и Major с Normal в нём неразличимы."""
    assert map_severity(None, "warning", "Major") == "high"
    assert map_severity(None, "warning", "Normal") == "medium"


@pytest.mark.parametrize("junk", ["Катастрофа", "", "   ", 42, None])
def test_unknown_tool_scale_falls_back_to_level(junk):
    """Чужую шкалу не угадываем: непонятное значение уступает `level`."""
    assert map_severity(None, "error", junk) == "high"


# ── (д) сквозь ingest ──────────────────────────────────────────────────────


def test_major_and_normal_stop_being_indistinguishable():
    results = [
        _result("R-CRIT", "error", {"checker_severity": "Critical"}),
        _result("R-MAJ", "warning", {"checker_severity": "Major"}),
        _result("R-NORM", "warning", {"checker_severity": "Normal"}),
        _result("R-MIN", "note", {"checker_severity": "Minor"}),
    ]
    rule_ids = ["R-CRIT", "R-MAJ", "R-NORM", "R-MIN"]
    out = ingest_mod.ingest(_sarif(results), _meta(rule_ids))
    got = {f["rule_id"]: f["severity"] for f in out["findings"]}
    assert got == {
        "R-CRIT": "critical",
        "R-MAJ": "high",     # был бы medium, как и Normal
        "R-NORM": "medium",
        "R-MIN": "low",
    }
