import json
import pytest
from pathlib import Path

from swb_cli.sarif.parser import parse_sarif, _extract_text

DATA = Path(__file__).parent.parent / "data"
VALID = DATA / "valid"
INVALID = DATA / "invalid"


# ── _extract_text ─────────────────────────────────────────────────────────────

def test_extract_text_from_dict():
    assert _extract_text({"text": "hello"}) == "hello"

def test_extract_text_from_string():
    assert _extract_text("hello") == "hello"

def test_extract_text_from_none():
    assert _extract_text(None) == ""

def test_extract_text_missing_key():
    assert _extract_text({"other": "value"}) == ""


# ── valid SARIF ───────────────────────────────────────────────────────────────

def test_minimal_sarif():
    runs = parse_sarif(VALID / "minimal.sarif")
    assert len(runs) == 1
    run = runs[0]
    assert run.tool.name == "TestTool"
    assert run.tool.version == "1.0.0"
    assert len(run.tool.rules) == 1
    assert run.tool.rules[0].rule_id == "CWE-89"
    assert run.tool.rules[0].security_severity == 9.1
    assert len(run.results) == 1
    result = run.results[0]
    assert result.rule_id == "CWE-89"
    assert result.level == "error"
    assert result.locations[0].uri == "src/db.py"
    assert result.locations[0].region.start_line == 42

def test_empty_runs():
    runs = parse_sarif(VALID / "empty_runs.sarif")
    assert runs == []

def test_no_results():
    runs = parse_sarif(VALID / "no_results.sarif")
    assert len(runs) == 1
    assert runs[0].results == []

def test_multi_run():
    runs = parse_sarif(VALID / "multi_run.sarif")
    assert len(runs) == 2
    assert runs[0].tool.name == "ToolA"
    assert runs[1].tool.name == "ToolB"
    assert runs[0].results[0].rule_id == "CWE-79"
    assert runs[1].results[0].rule_id == "CWE-22"

def test_run_indexes_are_correct():
    runs = parse_sarif(VALID / "multi_run.sarif")
    assert runs[0].index == 0
    assert runs[1].index == 1

def test_result_indexes_are_correct():
    runs = parse_sarif(VALID / "minimal.sarif")
    assert runs[0].results[0].result_index == 0

def test_no_locations_result_is_parsed():
    # результат без locations должен парситься, locations просто пустой список
    runs = parse_sarif(VALID / "no_locations.sarif")
    assert len(runs[0].results) == 1
    assert runs[0].results[0].locations == []

def test_message_as_plain_string():
    # message может быть строкой, а не {"text": "..."}
    runs = parse_sarif(VALID / "message_as_string.sarif")
    assert runs[0].results[0].message == "Command injection"

def test_partial_fingerprints_extracted():
    runs = parse_sarif(VALID / "with_partial_fingerprints.sarif")
    result = runs[0].results[0]
    assert result.partial_fingerprints == {
        "primaryLocationLineHash": "39fa2ee980eb94b0:1",
        "primaryLocationStartColumnFingerprint": "4",
    }
    assert result.fingerprints == {}

def test_fingerprints_default_to_empty_dicts():
    runs = parse_sarif(VALID / "minimal.sarif")
    result = runs[0].results[0]
    assert result.fingerprints == {}
    assert result.partial_fingerprints == {}

def test_uri_base_id_and_original_uri_base_ids_default_empty():
    runs = parse_sarif(VALID / "minimal.sarif")
    assert runs[0].original_uri_base_ids == {}
    assert runs[0].results[0].locations[0].uri_base_id is None

def test_not_sarif_json_returns_empty_runs():
    # валидный JSON, но нет ключа "runs" — возвращает пустой список
    runs = parse_sarif(INVALID / "not_sarif.json")
    assert runs == []


# ── invalid SARIF ─────────────────────────────────────────────────────────────

def test_malformed_json_raises():
    with pytest.raises(json.JSONDecodeError):
        parse_sarif(INVALID / "malformed_json.sarif")

def test_empty_file_raises():
    with pytest.raises((json.JSONDecodeError, ValueError)):
        parse_sarif(INVALID / "empty_file.sarif")

def test_wrong_type_runs_raises():
    # "runs" — строка вместо массива, итерация по ней ломается
    with pytest.raises((TypeError, AttributeError)):
        parse_sarif(INVALID / "wrong_type_runs.sarif")
