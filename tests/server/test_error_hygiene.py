"""T-64: error hygiene — nothing internal leaks to the client.

Before this task, several error paths forwarded `str(exc)` (or a raw
`FileNotFoundError` bubbling up unhandled) straight to the HTTP client / SSE
stream:

  - `routers/runs.py`'s `except Exception as exc:` around `ingest()` caught
    ANY parsing failure (AttributeError/TypeError/KeyError/... from deep
    inside `swb_contract.sarif.parser`, not just the SARIF-shaped ones) and
    put `str(exc)` in the 422 body verbatim;
  - `routers/report.py` did the same for PDF generation failures (500);
  - `storage.py::load_blob` raised a bare `FileNotFoundError` with no
    router-level handling, relying on Starlette's default 500 handler.

This file checks the client-visible surface (HTTP body / SSE payload) never
contains a traceback, an absolute filesystem path, or other raw exception
text — those now go to the server log only (`caplog`/`logger.*`), never the
response. `tests/server/test_provider_registry.py` covers the analogous SSE
leak in the AI provider HTTP client (base_url/connection-error text).
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

DATA = Path(__file__).parent.parent / "data"

# Strings that must never appear in a response body — absolute-path and
# traceback fingerprints, deliberately generic so they catch any leak, not
# just the specific one a given test happens to provoke.
_LEAK_MARKERS = ("Traceback", '.py", line', "/Users/", "/home/", str(Path(__file__).resolve().parent))


def _assert_no_internal_details(body: str) -> None:
    for marker in _LEAK_MARKERS:
        assert marker not in body, f"response body leaked internal detail {marker!r}: {body!r}"


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


# ── malformed SARIF (structural, not just malformed JSON) → 422 ────────────


def test_wrong_type_runs_sarif_rejected_with_422_no_internal_details(client):
    """Same fixture as the CLI regression (`wrong_type_runs.sarif`): `runs`
    is a string, not an array. `swb_contract.sarif.parser` raises a bare
    `AttributeError('str' object has no attribute 'get')` for this — before
    the fix, `routers/runs.py`'s broad `except Exception` put that raw text
    in the 422 response body.
    """
    sarif = (DATA / "invalid" / "wrong_type_runs.sarif").read_bytes()
    meta = {
        "schema": "swbmeta/v3",
        "source_sarif": {"sha256": hashlib.sha256(sarif).hexdigest()},
        "provenance": {"repo": _unique_repo()},
        "findings": [],
    }
    resp = client.post(
        "/api/v1/runs",
        files={
            "sarif": ("report.sarif", sarif, "application/json"),
            "meta": ("report.swbmeta.json", json.dumps(meta).encode(), "application/json"),
        },
    )
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_sarif"
    assert "has no attribute" not in resp.text
    _assert_no_internal_details(resp.text)


def test_malformed_json_sarif_rejected_with_422_no_internal_details(client):
    sarif = b"{not json"
    meta = {
        "schema": "swbmeta/v3",
        "source_sarif": {"sha256": hashlib.sha256(sarif).hexdigest()},
        "provenance": {"repo": _unique_repo()},
        "findings": [],
    }
    resp = client.post(
        "/api/v1/runs",
        files={
            "sarif": ("report.sarif", sarif, "application/json"),
            "meta": ("report.swbmeta.json", json.dumps(meta).encode(), "application/json"),
        },
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["error"] == "invalid_sarif"
    _assert_no_internal_details(resp.text)


# ── missing blob on disk → explicit generic 500, not a framework default ───


def test_missing_sarif_blob_returns_generic_500_no_path_leak(client, upload_run):
    run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=_unique_repo(),
    )
    run_id = run["run_id"]
    blob_path = Path(os.environ["DATA_DIR"]) / "blobs" / f"{run_id}/report.sarif"
    assert blob_path.exists()
    blob_path.unlink()

    resp = client.get(f"/api/v1/runs/{run_id}/sarif")
    assert resp.status_code == 500, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "blob_missing"
    assert str(Path(os.environ["DATA_DIR"])) not in resp.text
    assert run.get("run_id", "") == run_id  # sanity: run really was created
    _assert_no_internal_details(resp.text)


# ── PDF generation failure → generic 500, detail server-side only ──────────


def test_report_generation_failure_returns_generic_500_no_leak(client, upload_run, monkeypatch):
    import swb_server.routers.report as report_module  # noqa: PLC0415

    def _boom(run, project, findings):
        raise RuntimeError("cannot open font file /Users/somebody/.fonts/custom.ttf")

    monkeypatch.setattr(report_module, "generate_pdf", _boom)

    run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=_unique_repo(),
    )
    resp = client.get(f"/api/v1/runs/{run['run_id']}/report")
    assert resp.status_code == 500, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "pdf_error"
    assert detail["message"] == "Failed to generate PDF report"
    assert "/Users/somebody" not in resp.text
    assert ".ttf" not in resp.text
    _assert_no_internal_details(resp.text)
