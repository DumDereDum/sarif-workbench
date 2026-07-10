"""T-35: server/swb_server/ingest.py stops re-parsing SARIF by hand (raw
dict traversal — `driver.get(...)`, `rule.get(...)`, `result.get(...)`) and
uses the same typed parser as the CLI (`swb_contract.sarif.parser`).

Covers:
  (a) identity check — ingest.py really imports/uses the shared parser,
      not a re-implemented local copy;
  (b) regression: fullDescription -> shortDescription fallback for rule
      description, now applied via the shared `_parse_rule` (T-35 folds this
      previously server-only behavior into the one parser both sides use);
  (c) regression: tool_version falls back to `semanticVersion` when SARIF
      `version` is absent — a behavior the raw-dict ingest() never had
      (it defaulted straight to "unknown"), now inherited from the CLI
      parser's `_parse_tool` as part of the T-35 consolidation;
  (d) tags/CWE extraction and default_severity (defaultConfiguration.level)
      still work end-to-end through ingest() after the switch;
  (e) regression (reviewer round 1): malformed (non-numeric) security-severity
      must not raise inside ingest()/the shared parser — it must degrade to
      level-based severity for that one rule, exactly like HEAD did via
      `map_severity`'s own try/except, not reject the whole upload with 422.

`ingest()` is a pure function (no DB/app fixtures needed) — most of these
are direct unit tests, no HTTP round-trip. The one exception is the (e) HTTP
regression test, which needs the `client` fixture to exercise the actual
`routers/runs.py` except-Exception-> 422 path the bug manifested through.
"""
from __future__ import annotations

import hashlib
import json
import uuid

import swb_server.ingest as ingest_mod


def _sarif(driver: dict, results: list[dict] | None = None) -> bytes:
    return json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results or []}],
    }).encode()


def _meta(findings: list[dict]) -> dict:
    return {"schema": "swbmeta/v2", "findings": findings}


def _finding(swb_id: str, rule_id: str, run: int = 0, result: int = 0, **kw) -> dict:
    return {
        "swb_id": swb_id,
        "locator": {"run": run, "result": result, "rule_id": rule_id, "uri": "src/a.py",
                    "region": {"start_line": 1}},
        "fingerprints": {"algo": "swb-fp/2", "level": "tool"},
        **kw,
    }


# ── (a) ingest.py really uses the shared contract parser ───────────────────


def test_ingest_module_imports_parse_sarif_data_from_contract():
    import swb_contract.sarif.parser as contract_parser

    assert ingest_mod.parse_sarif_data is contract_parser.parse_sarif_data


def test_ingest_no_longer_has_local_raw_dict_text_helper():
    # T-35: `_text()` (manual {"text": ...}/str extraction) duplicated
    # swb_contract.sarif.parser._extract_text — dead after the switch, and
    # removed rather than left unused ("дублирующий код парсинга удалён").
    assert not hasattr(ingest_mod, "_text")


# ── (b) fullDescription -> shortDescription fallback, observed via ingest() ─


def test_rule_description_uses_full_description_when_present():
    driver = {
        "name": "T", "version": "1.0",
        "rules": [{
            "id": "R1",
            "fullDescription": {"text": "the full one"},
            "shortDescription": {"text": "the short one"},
        }],
    }
    result = ingest_mod.ingest(_sarif(driver), _meta([]))
    assert result["rules"]["R1"]["description"] == "the full one"


def test_rule_description_falls_back_to_short_description_when_full_missing():
    driver = {
        "name": "T", "version": "1.0",
        "rules": [{"id": "R1", "shortDescription": {"text": "only short"}}],
    }
    result = ingest_mod.ingest(_sarif(driver), _meta([]))
    assert result["rules"]["R1"]["description"] == "only short"


def test_rule_description_empty_when_neither_description_present():
    driver = {"name": "T", "version": "1.0", "rules": [{"id": "R1"}]}
    result = ingest_mod.ingest(_sarif(driver), _meta([]))
    assert result["rules"]["R1"]["description"] == ""


# ── (c) tool_version falls back to semanticVersion (new, documented change) ─


def test_tool_version_uses_version_field_when_present():
    driver = {"name": "T", "version": "2.3.4", "semanticVersion": "9.9.9", "rules": []}
    result = ingest_mod.ingest(_sarif(driver), _meta([]))
    assert result["tool_version"] == "2.3.4"


def test_tool_version_falls_back_to_semantic_version_when_version_absent():
    driver = {"name": "Semgrep OSS", "semanticVersion": "1.167.0", "rules": []}
    result = ingest_mod.ingest(_sarif(driver), _meta([]))
    assert result["tool_version"] == "1.167.0"


def test_tool_version_defaults_to_unknown_when_neither_present():
    driver = {"name": "T", "rules": []}
    result = ingest_mod.ingest(_sarif(driver), _meta([]))
    assert result["tool_version"] == "unknown"


# ── (d) tags/CWE + default_severity still work end-to-end ──────────────────


def test_cwe_extracted_from_rule_tags_via_typed_rule():
    driver = {
        "name": "T", "version": "1.0",
        "rules": [{
            "id": "hardcoded-password",
            "properties": {"tags": ["CWE-798", "security"], "security-severity": "8.5"},
            "defaultConfiguration": {"level": "error"},
        }],
    }
    result = ingest_mod.ingest(_sarif(driver), _meta([]))
    assert result["rules"]["hardcoded-password"]["cwe"] == "CWE-798"
    assert result["rules"]["hardcoded-password"]["default_severity"] == "high"  # sec-sev 8.5


# ── (e) regression: malformed security-severity must not 422 the whole upload
# (reviewer round 1 finding — `_parse_rule` cast `float(sec_sev)` eagerly with
# no guard, so a non-numeric security-severity from a third-party scanner
# raised ValueError inside ingest(), caught by routers/runs.py's broad
# `except Exception` and turned into a 422 that rejects the ENTIRE upload —
# where HEAD (pre-T-35) tolerated it via map_severity's own try/except and
# fell back to level-based severity for just that rule.


def test_malformed_security_severity_does_not_raise_and_falls_back_to_level():
    driver = {
        "name": "T", "version": "1.0",
        "rules": [{
            "id": "R1",
            "properties": {"security-severity": "not-a-number"},
            "defaultConfiguration": {"level": "warning"},
        }],
    }
    # must not raise — this is what used to blow up ingest() with an
    # uncaught ValueError before the fix
    result = ingest_mod.ingest(_sarif(driver), _meta([]))
    assert result["rules"]["R1"]["security_severity"] is None
    # falls back to level-based severity (warning -> medium), same as HEAD
    assert result["rules"]["R1"]["default_severity"] == "medium"


def test_finding_severity_falls_back_to_level_when_rule_security_severity_is_malformed():
    driver = {
        "name": "T", "version": "1.0",
        "rules": [{"id": "R1", "properties": {"security-severity": "not-a-number"}}],
    }
    results = [{"ruleId": "R1", "level": "error", "message": {"text": "boom"}, "locations": []}]
    meta = _meta([_finding("sw2:t:aaaa:0", "R1")])
    result = ingest_mod.ingest(_sarif(driver, results), meta)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "high"  # level "error" -> high


def test_upload_with_malformed_security_severity_succeeds_not_422(client):
    # HTTP-level version of the same regression: routers/runs.py's broad
    # `except Exception: raise HTTPException(422, {"error": "invalid_sarif"})`
    # around ingest() would previously turn ONE rule's bad security-severity
    # into a hard rejection of the entire upload (all N findings), where
    # HEAD (pre-T-35) accepted the upload and degraded just that rule's
    # severity to the level-based mapping.
    sarif = json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "T", "version": "1.0",
                "rules": [{
                    "id": "CWE-89",
                    "properties": {"security-severity": "not-a-number"},
                }],
            }},
            "results": [{
                "ruleId": "CWE-89", "level": "error",
                "message": {"text": "test finding"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/db.py"},
                    "region": {"startLine": 42},
                }}],
            }],
        }],
        "properties": {"nonce": uuid.uuid4().hex},
    }).encode()
    meta = json.dumps({
        "schema": "swbmeta/v2",
        "generated_by": "tests",
        "generated_at": "2026-07-04T00:00:00Z",
        "source_sarif": {
            "filename": "report.sarif",
            "sha256": hashlib.sha256(sarif).hexdigest(),
            "size_bytes": len(sarif),
        },
        "provenance": {"repo": f"swb-test-{uuid.uuid4().hex[:8]}"},
        "findings": [{
            "swb_id": f"sw2:t:{uuid.uuid4().hex[:24]}:0",
            "occurrence": 0,
            "locator": {"run": 0, "result": 0, "rule_id": "CWE-89", "uri": "src/db.py",
                        "region": {"start_line": 42}},
            "fingerprints": {"algo": "swb-fp/2", "level": "tool"},
        }],
    }).encode()

    resp = client.post(
        "/api/v1/runs",
        files={
            "sarif": ("report.sarif", sarif, "application/json"),
            "meta": ("report.swbmeta.json", meta, "application/json"),
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["finding_count"] == 1

    items = client.get(f"/api/v1/runs/{resp.json()['run_id']}/findings").json()["items"]
    assert len(items) == 1
    assert items[0]["severity"] == "high"  # level "error" -> high (fallback, not a crash)


def test_result_message_and_level_reach_the_finding_via_typed_result():
    driver = {"name": "T", "version": "1.0", "rules": [{"id": "R1"}]}
    results = [{"ruleId": "R1", "level": "error", "message": {"text": "boom"},
                "locations": []}]
    meta = _meta([_finding("sw2:t:aaaa:0", "R1")])
    result = ingest_mod.ingest(_sarif(driver, results), meta)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["message"] == "boom"


def test_missing_sarif_result_for_locator_defaults_message_and_warning_level():
    # locator points past the end of results — sarif_result lookup misses,
    # same tolerant fallback as before T-35 (empty message, "warning" level).
    driver = {"name": "T", "version": "1.0", "rules": []}
    meta = _meta([_finding("sw2:t:aaaa:0", "R1", result=5)])
    result = ingest_mod.ingest(_sarif(driver), meta)
    assert result["findings"][0]["message"] == ""
    assert result["findings"][0]["severity"] == "medium"  # warning -> medium
