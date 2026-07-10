"""T-35: swb_contract.sarif — single typed SARIF 2.1.0 parser shared by CLI
and server (was: typed dataclass parser only in the CLI, raw-dict traversal
duplicated in server/swb_server/ingest.py).

Covers:
  (a) parse_sarif(path) / parse_sarif_data(dict) split — file I/O is a thin
      wrapper, structural parsing works directly on an already-decoded dict;
  (b) new SarifRule fields needed by the server (`tags`, `default_level`)
      that the pre-T-35 CLI-only model didn't have;
  (c) the fullDescription -> shortDescription fallback consolidated into the
      shared `_parse_rule` (previously only server's raw-dict ingest had it);
  (d) CLI re-exports the shared parser/models rather than keeping a copy.
"""
from __future__ import annotations

import json
from pathlib import Path

from swb_contract.sarif.models import SarifRule
from swb_contract.sarif.parser import parse_sarif, parse_sarif_data

DATA = Path(__file__).parent.parent / "data"
VALID = DATA / "valid"


# ── (a) parse_sarif / parse_sarif_data split ───────────────────────────────


def test_parse_sarif_data_accepts_predecoded_dict_without_touching_disk():
    data = json.loads((VALID / "minimal.sarif").read_text())
    runs = parse_sarif_data(data)

    assert len(runs) == 1
    assert runs[0].tool.name == "TestTool"
    assert runs[0].results[0].rule_id == "CWE-89"


def test_parse_sarif_is_thin_file_wrapper_around_parse_sarif_data():
    data = json.loads((VALID / "minimal.sarif").read_text())
    via_path = parse_sarif(VALID / "minimal.sarif")
    via_data = parse_sarif_data(data)

    assert via_path == via_data


def test_parse_sarif_data_empty_dict_returns_no_runs():
    assert parse_sarif_data({}) == []


# ── (b) SarifRule.tags / .default_level (needed by server ingest) ─────────


def test_rule_tags_extracted_from_properties():
    data = {
        "runs": [{
            "tool": {"driver": {"name": "T", "rules": [
                {"id": "R1", "properties": {"tags": ["CWE-89", "security"]}},
            ]}},
            "results": [],
        }],
    }
    rule = parse_sarif_data(data)[0].tool.rules[0]
    assert rule.tags == ["CWE-89", "security"]


def test_rule_tags_default_to_empty_list_when_missing():
    data = {
        "runs": [{
            "tool": {"driver": {"name": "T", "rules": [{"id": "R1"}]}},
            "results": [],
        }],
    }
    rule = parse_sarif_data(data)[0].tool.rules[0]
    assert rule.tags == []


def test_rule_default_level_extracted_from_default_configuration():
    data = {
        "runs": [{
            "tool": {"driver": {"name": "T", "rules": [
                {"id": "R1", "defaultConfiguration": {"level": "error"}},
            ]}},
            "results": [],
        }],
    }
    rule = parse_sarif_data(data)[0].tool.rules[0]
    assert rule.default_level == "error"


def test_rule_default_level_defaults_to_warning_when_missing():
    data = {
        "runs": [{
            "tool": {"driver": {"name": "T", "rules": [{"id": "R1"}]}},
            "results": [],
        }],
    }
    rule = parse_sarif_data(data)[0].tool.rules[0]
    assert rule.default_level == "warning"


def test_sarif_rule_dataclass_has_tags_and_default_level_fields():
    rule = SarifRule(rule_id="R1")
    assert rule.tags == []
    assert rule.default_level == "warning"


# ── (b') security-severity cast is tolerant, not a bare float() (regression:
# reviewer round 1 — eager unguarded float() blew up ingest() on malformed
# third-party SARIF instead of degrading like map_severity does) ──────────


def test_security_severity_parses_numeric_string():
    data = {
        "runs": [{
            "tool": {"driver": {"name": "T", "rules": [
                {"id": "R1", "properties": {"security-severity": "9.1"}},
            ]}},
            "results": [],
        }],
    }
    rule = parse_sarif_data(data)[0].tool.rules[0]
    assert rule.security_severity == 9.1


def test_security_severity_malformed_value_becomes_none_not_a_raised_exception():
    data = {
        "runs": [{
            "tool": {"driver": {"name": "T", "rules": [
                {"id": "R1", "properties": {"security-severity": "not-a-number"}},
            ]}},
            "results": [],
        }],
    }
    # must not raise ValueError — mirrors map_severity's own tolerant
    # (TypeError, ValueError) fallback for the same malformed input
    rule = parse_sarif_data(data)[0].tool.rules[0]
    assert rule.security_severity is None


def test_security_severity_missing_is_none():
    data = {
        "runs": [{
            "tool": {"driver": {"name": "T", "rules": [{"id": "R1"}]}},
            "results": [],
        }],
    }
    rule = parse_sarif_data(data)[0].tool.rules[0]
    assert rule.security_severity is None


# ── (c) fullDescription -> shortDescription fallback (consolidated T-35) ──


def test_rule_full_description_prefers_full_over_short():
    data = {
        "runs": [{
            "tool": {"driver": {"name": "T", "rules": [
                {
                    "id": "R1",
                    "fullDescription": {"text": "full text"},
                    "shortDescription": {"text": "short text"},
                },
            ]}},
            "results": [],
        }],
    }
    rule = parse_sarif_data(data)[0].tool.rules[0]
    assert rule.full_description == "full text"


def test_rule_full_description_falls_back_to_short_description_when_full_missing():
    data = {
        "runs": [{
            "tool": {"driver": {"name": "T", "rules": [
                {"id": "R1", "shortDescription": {"text": "short text only"}},
            ]}},
            "results": [],
        }],
    }
    rule = parse_sarif_data(data)[0].tool.rules[0]
    assert rule.full_description == "short text only"


def test_rule_full_description_empty_string_when_neither_present():
    data = {
        "runs": [{
            "tool": {"driver": {"name": "T", "rules": [{"id": "R1"}]}},
            "results": [],
        }],
    }
    rule = parse_sarif_data(data)[0].tool.rules[0]
    assert rule.full_description == ""


# ── (d) CLI re-exports the shared parser, doesn't keep a local copy ────────


def test_cli_sarif_parser_is_contract_sarif_parser():
    import swb_cli.sarif.parser as cli_parser
    import swb_contract.sarif.parser as contract_parser

    for name in ("parse_sarif", "parse_sarif_data", "_extract_text"):
        assert getattr(cli_parser, name) is getattr(contract_parser, name), (
            f"swb_cli.sarif.parser.{name} is not the same object as "
            f"swb_contract.sarif.parser.{name} — looks like a local copy, not a re-export"
        )


def test_cli_sarif_models_are_contract_sarif_models():
    import swb_cli.sarif.models as cli_models
    import swb_contract.sarif.models as contract_models

    for name in (
        "SarifRegion", "SarifLocation", "SarifResult", "SarifRule", "SarifTool", "SarifRun",
    ):
        assert getattr(cli_models, name) is getattr(contract_models, name), (
            f"swb_cli.sarif.models.{name} is not the same object as "
            f"swb_contract.sarif.models.{name} — looks like a local copy, not a re-export"
        )
