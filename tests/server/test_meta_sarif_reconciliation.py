"""T-36: strict SARIF<->meta reconciliation at ingest time, HTTP round-trip.

Before this task, `server/swb_server/ingest.py` trusted the sidecar meta
blindly: a locator with a broken (run, result) index looked up a SARIF
result via `results_map.get(...)`, got `None`, and silently degraded to an
empty message and `level="warning"` (default severity "medium") — no error,
no trace, no warning. Results in meta that simply didn't correspond to any
SARIF result behaved the same way; results in the SARIF file that had no
matching meta finding just never showed up in triage, without a trace.

This file covers the HTTP-level contract (`POST /api/v1/runs`) end to end:
every kind of mismatch named in the Done-when — broken locator index,
missing findings, extra/duplicate findings, a locator pointing at a
SARIF result with no locations, and a structurally malformed locator (not a
silent default) — rejects the upload with 422 `invalid_meta` and writes
nothing to the DB. `tests/server/test_ingest_via_shared_parser.py` covers
the same reconciliation rules at the `ingest()` unit level.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

# `swb_server.models` (and anything importing `swb_server.db`) must NOT be
# imported at module level: pytest collects all test modules before the
# session-scoped `app` fixture (tests/server/conftest.py) sets DATA_DIR /
# DATABASE_URL, so a top-level import here would bind SQLAlchemy's engine to
# the real dev DB (server/data/swb.db) instead of the per-session temp one —
# see conftest.py's own comment on this. Import inside test functions
# instead, same as tests/server/test_ingest_identity.py does.

DATA = Path(__file__).parent.parent / "data"


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _sarif_bytes(results: list[dict], *, driver_rules: list[dict] | None = None) -> bytes:
    doc = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "TestTool", "version": "1.0", "rules": driver_rules or []}},
            "results": results,
        }],
        "properties": {"nonce": uuid.uuid4().hex},  # avoid cross-test dedup collisions
    }
    return json.dumps(doc).encode()


def _result(rule_id: str = "CWE-89", uri: str = "src/db.py", start_line: int = 42,
            with_location: bool = True) -> dict:
    r: dict = {"ruleId": rule_id, "level": "error", "message": {"text": "test finding"}}
    if with_location:
        r["locations"] = [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": start_line},
            },
        }]
    else:
        r["locations"] = []
    return r


def _finding(run: int, result: int, rule_id: str = "CWE-89", uri: str = "src/db.py",
             start_line: int = 42, swb_id: str | None = None) -> dict:
    return {
        "swb_id": swb_id or f"sw2:t:{uuid.uuid4().hex[:24]}:0",
        "occurrence": 0,
        "locator": {
            "run": run, "result": result, "rule_id": rule_id,
            "uri": uri, "norm_uri": uri, "region": {"start_line": start_line},
        },
        "fingerprints": {"algo": "swb-fp/2", "level": "tool", "rule": rule_id},
    }


def _meta_bytes(sarif_bytes: bytes, findings: list[dict], repo: str) -> bytes:
    doc = {
        "schema": "swbmeta/v2",
        "generated_by": "tests",
        "generated_at": "2026-07-04T00:00:00Z",
        "source_sarif": {
            "filename": "report.sarif",
            "sha256": hashlib.sha256(sarif_bytes).hexdigest(),
            "size_bytes": len(sarif_bytes),
        },
        "provenance": {"repo": repo},
        "findings": findings,
    }
    return json.dumps(doc).encode()


def _post(client, sarif_bytes: bytes, meta_bytes: bytes):
    return client.post(
        "/api/v1/runs",
        files={
            "sarif": ("report.sarif", sarif_bytes, "application/json"),
            "meta": ("report.swbmeta.json", meta_bytes, "application/json"),
        },
    )


def _assert_rejected_and_nothing_written(client, db_session, sarif_bytes, meta_bytes, *, match: str):
    from swb_server.models import Run  # noqa: PLC0415 — see module-level comment

    resp = _post(client, sarif_bytes, meta_bytes)
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_meta"
    assert match in detail["message"]

    sha = hashlib.sha256(sarif_bytes).hexdigest()
    assert db_session.query(Run).filter(Run.sarif_sha256 == sha).first() is None


# ── broken locator index (the anchor bug) ───────────────────────────────────


def test_locator_index_past_available_results_rejected(client, db_session):
    repo = _unique_repo()
    sarif = _sarif_bytes([_result()])
    meta = _meta_bytes(sarif, [_finding(run=0, result=7)], repo)
    _assert_rejected_and_nothing_written(client, db_session, sarif, meta, match="broken locator index")


def test_locator_index_wrong_run_rejected(client, db_session):
    repo = _unique_repo()
    sarif = _sarif_bytes([_result()])
    meta = _meta_bytes(sarif, [_finding(run=3, result=0)], repo)
    _assert_rejected_and_nothing_written(client, db_session, sarif, meta, match="broken locator index")


# ── missing / extra / duplicate meta findings ───────────────────────────────


def test_sarif_result_with_no_matching_meta_finding_rejected(client, db_session):
    repo = _unique_repo()
    sarif = _sarif_bytes([_result(rule_id="R1", uri="a.py"), _result(rule_id="R2", uri="b.py")])
    # только одна из двух находок описана в meta — недостача
    meta = _meta_bytes(sarif, [_finding(run=0, result=0, rule_id="R1", uri="a.py")], repo)
    _assert_rejected_and_nothing_written(
        client, db_session, sarif, meta, match="no matching meta finding",
    )


def test_duplicate_meta_findings_for_same_sarif_result_rejected(client, db_session):
    repo = _unique_repo()
    sarif = _sarif_bytes([_result()])
    # две записи meta ссылаются на один и тот же SARIF-результат — лишняя запись
    meta = _meta_bytes(sarif, [_finding(run=0, result=0), _finding(run=0, result=0)], repo)
    _assert_rejected_and_nothing_written(client, db_session, sarif, meta, match="expected exactly one")


def test_meta_finding_referencing_locationless_result_rejected(client, db_session):
    repo = _unique_repo()
    sarif = _sarif_bytes([_result(with_location=False)])
    meta = _meta_bytes(sarif, [_finding(run=0, result=0)], repo)
    _assert_rejected_and_nothing_written(client, db_session, sarif, meta, match="without locations")


# ── structural validation: no silent defaults on a malformed locator ───────


def test_locator_missing_region_rejected_not_defaulted_to_zero(client, db_session):
    """Before T-36: `region.get("start_line", 0)` — a missing region silently
    became start_line=0. Now: 422 with a message naming the missing field.
    """
    repo = _unique_repo()
    sarif = _sarif_bytes([_result()])
    finding = _finding(run=0, result=0)
    del finding["locator"]["region"]
    meta = _meta_bytes(sarif, [finding], repo)
    _assert_rejected_and_nothing_written(client, db_session, sarif, meta, match="region")


def test_locator_start_line_wrong_type_rejected(client, db_session):
    from swb_server.models import Run  # noqa: PLC0415 — see module-level comment

    repo = _unique_repo()
    sarif = _sarif_bytes([_result()])
    finding = _finding(run=0, result=0)
    finding["locator"]["region"]["start_line"] = "not-a-number"
    meta = _meta_bytes(sarif, [finding], repo)

    resp = _post(client, sarif, meta)
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["error"] == "invalid_meta"

    sha = hashlib.sha256(sarif).hexdigest()
    assert db_session.query(Run).filter(Run.sarif_sha256 == sha).first() is None


def test_locator_missing_run_or_result_rejected_not_defaulted_to_zero(client, db_session):
    """Before T-36: `loc.get("run", 0)` / `loc.get("result", 0)` silently
    defaulted a missing index to 0 — potentially matching the WRONG SARIF
    result instead of failing. Now: 422, structural validation error.
    """
    repo = _unique_repo()
    sarif = _sarif_bytes([_result()])
    finding = _finding(run=0, result=0)
    del finding["locator"]["result"]
    meta = _meta_bytes(sarif, [finding], repo)
    _assert_rejected_and_nothing_written(client, db_session, sarif, meta, match="result")


# ── control: valid reconciliation still succeeds ────────────────────────────


def test_locationless_result_correctly_omitted_from_meta_succeeds(client):
    """A SARIF result without locations must NOT be in meta (ADR 0001 §8);
    when the CLI correctly omits it, upload succeeds with just the located
    finding — this is the non-broken counterpart of the rejection tests above.
    """
    repo = _unique_repo()
    sarif = _sarif_bytes([_result(rule_id="R1", uri="a.py"), _result(with_location=False)])
    meta = _meta_bytes(sarif, [_finding(run=0, result=0, rule_id="R1", uri="a.py")], repo)

    resp = _post(client, sarif, meta)
    assert resp.status_code == 201, resp.text
    assert resp.json()["finding_count"] == 1


def test_fully_matching_meta_still_succeeds(client):
    repo = _unique_repo()
    sarif = _sarif_bytes([
        _result(rule_id="R1", uri="a.py", start_line=1),
        _result(rule_id="R2", uri="b.py", start_line=2),
    ])
    meta = _meta_bytes(sarif, [
        _finding(run=0, result=0, rule_id="R1", uri="a.py", start_line=1),
        _finding(run=0, result=1, rule_id="R2", uri="b.py", start_line=2),
    ], repo)

    resp = _post(client, sarif, meta)
    assert resp.status_code == 201, resp.text
    assert resp.json()["finding_count"] == 2
