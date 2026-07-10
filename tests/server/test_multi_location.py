"""T-39: multi-location finding storage + API (ADR 0001 §8).

Extra locations (`locations[1:]`), relatedLocations and codeFlows are
payload, not identity — the server stores and serves them as-is from the
(already-validated) swbmeta finding; ingest() doesn't recompute or
cross-check them against the SARIF's own values (same trust boundary as
code/git, see server/swb_server/ingest.py).

Covers:
  (a) full pipeline: swb-cli enrich -> upload -> GET /findings/{id} carries
      extra_locations/related_locations/code_flow through, structured
      (not flattened to strings, not dropped);
  (b) ingest() unit-level: the fields are copied verbatim from the
      validated meta finding into findings_out;
  (c) backward compatibility: a single-location finding still gets empty
      lists (not null) for all three fields via the findings API — existing
      (pre-T-39) single-location findings keep working as before.

Module-level imports of `swb_server.models`/`swb_server.db` are avoided
(see tests/server/test_meta_sarif_reconciliation.py's comment on why) —
`swb_server.ingest` has no such dependency, so it's safe to import at
module level (same as tests/server/test_ingest_via_shared_parser.py does).
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import swb_server.ingest as ingest_mod

DATA = Path(__file__).parent.parent / "data"
VALID = DATA / "valid"


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


class _EnrichArgs:
    """Минимальный объект аргументов для вызова enrich() напрямую (как в tests/cli)."""

    def __init__(self, sarif, out, repo_root=None):
        self.sarif = str(sarif)
        self.out = str(out)
        self.repo_root = str(repo_root) if repo_root else None
        self.context_policy = "lines"
        self.context_lines = 5
        self.no_git = True
        self.fail_on_missing_source = False
        self.log_level = "error"


def _post_run(client, sarif_bytes: bytes, meta_bytes: bytes):
    return client.post(
        "/api/v1/runs",
        files={
            "sarif": ("report.sarif", sarif_bytes, "application/json"),
            "meta": ("report.swbmeta.json", meta_bytes, "application/json"),
        },
    )


# ── (a) full pipeline: enrich -> upload -> API ──────────────────────────────


def test_multi_location_finding_visible_in_api_after_enrich_and_upload(client, tmp_path):
    from swb_cli.commands.enrich import enrich

    repo = _unique_repo()
    root = tmp_path / repo
    root.mkdir()
    sarif_path = root / "report.sarif"
    sarif_path.write_bytes((VALID / "multi_location.sarif").read_bytes())
    out_path = root / "report.sarif.swbmeta.json"

    # repo_root=root -> provenance.repo == root.name == our unique repo
    # (_build_provenance), so project_id resolution doesn't collide with
    # other tests; no source files copied in — snippet extraction degrades
    # to None (T-01/T-02 behavior), irrelevant to what this test checks.
    assert enrich(_EnrichArgs(sarif_path, out_path, repo_root=root)) == 0
    meta = json.loads(out_path.read_text())
    assert meta["schema"] == "swbmeta/v3"
    mf = meta["findings"][0]
    assert len(mf["extra_locations"]) == 1
    assert len(mf["related_locations"]) == 1
    assert len(mf["code_flows"]) == 1

    resp = _post_run(client, sarif_path.read_bytes(), out_path.read_bytes())
    assert resp.status_code == 201, resp.text
    run = resp.json()
    assert run["finding_count"] == 1

    items = client.get(f"/api/v1/runs/{run['run_id']}/findings").json()["items"]
    finding_id = items[0]["id"]

    detail = client.get(f"/api/v1/findings/{finding_id}").json()
    # primary location unaffected — still locations[0] (ADR 0001 §8)
    assert detail["uri"] == "src/sink.py"
    assert detail["start_line"] == 42

    assert detail["extra_locations"] == [
        {"uri": "src/source.py", "region": {"start_line": 10, "end_line": None, "start_column": None}},
    ]
    assert detail["related_locations"] == [
        {
            "uri": "src/helper.py",
            "region": {"start_line": 5, "end_line": None, "start_column": None},
            "message": "Sanitizer bypass here",
        },
    ]
    assert detail["code_flow"] == [
        {
            "thread_flows": [
                {
                    "steps": [
                        {"uri": "src/source.py", "line": 10, "message": "user input enters"},
                        {"uri": "src/transform.py", "line": 20, "message": "passed through transform()"},
                        {"uri": "src/sink.py", "line": 42, "message": "reaches SQL sink"},
                    ],
                },
            ],
        },
    ]


# ── (b) ingest() unit-level: fields copied verbatim from validated meta ─────


def test_ingest_copies_multi_location_fields_from_meta():
    sarif_bytes = (VALID / "multi_location.sarif").read_bytes()
    meta = {
        "schema": "swbmeta/v3",
        "findings": [{
            "swb_id": "sw2:l:aaaaaaaaaaaaaaaaaaaaaaaa:0",
            "occurrence": 0,
            "locator": {
                "run": 0, "result": 0, "rule_id": "CWE-89",
                "uri": "src/sink.py", "norm_uri": "src/sink.py",
                "region": {"start_line": 42, "start_column": 5},
            },
            "fingerprints": {"algo": "swb-fp/2", "level": "legacy", "rule": "CWE-89"},
            "extra_locations": [
                {"uri": "src/source.py", "region": {"start_line": 10}},
            ],
            "related_locations": [
                {"uri": "src/helper.py", "region": {"start_line": 5}, "message": "note"},
            ],
            "code_flows": [
                {"thread_flows": [{"steps": [
                    {"uri": "src/a.py", "line": 1, "message": "step 1"},
                    {"uri": "src/b.py", "line": 2, "message": "step 2"},
                ]}]},
            ],
        }],
    }
    result = ingest_mod.ingest(sarif_bytes, meta)
    fd = result["findings"][0]
    assert fd["extra_locations"] == [
        {"uri": "src/source.py", "region": {"start_line": 10, "end_line": None, "start_column": None}},
    ]
    assert fd["related_locations"] == [
        {
            "uri": "src/helper.py",
            "region": {"start_line": 5, "end_line": None, "start_column": None},
            "message": "note",
        },
    ]
    assert fd["code_flow"] == [
        {"thread_flows": [{"steps": [
            {"uri": "src/a.py", "line": 1, "message": "step 1"},
            {"uri": "src/b.py", "line": 2, "message": "step 2"},
        ]}]},
    ]


def test_ingest_defaults_multi_location_fields_to_empty_lists_when_absent_from_meta():
    # A meta finding that predates T-39 conventions (no extra_locations/
    # related_locations/code_flows keys at all) still validates — the
    # contract schema defaults them to [] (Field(default_factory=list)).
    sarif_bytes = (VALID / "minimal.sarif").read_bytes()
    meta = {
        "schema": "swbmeta/v3",
        "findings": [{
            "swb_id": "sw2:l:bbbbbbbbbbbbbbbbbbbbbbbb:0",
            "occurrence": 0,
            "locator": {
                "run": 0, "result": 0, "rule_id": "CWE-89",
                "uri": "src/db.py", "norm_uri": "src/db.py",
                "region": {"start_line": 42},
            },
            "fingerprints": {"algo": "swb-fp/2", "level": "legacy", "rule": "CWE-89"},
        }],
    }
    result = ingest_mod.ingest(sarif_bytes, meta)
    fd = result["findings"][0]
    assert fd["extra_locations"] == []
    assert fd["related_locations"] == []
    assert fd["code_flow"] == []


# ── (c) backward compatibility: single-location findings get empty lists ────


def test_single_location_finding_has_empty_multi_location_fields_in_api(client, upload_run):
    run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}],
        repo=_unique_repo(),
    )
    items = client.get(f"/api/v1/runs/{run['run_id']}/findings").json()["items"]
    finding_id = items[0]["id"]

    detail = client.get(f"/api/v1/findings/{finding_id}").json()
    assert detail["extra_locations"] == []
    assert detail["related_locations"] == []
    assert detail["code_flow"] == []
