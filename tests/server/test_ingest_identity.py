"""T-15: ingest/API работают со стабильной identity (ADR 0001 §5/§6).

- meta со схемой != swbmeta/v2 отклоняется явной 422 (fallback v1 не проектируется);
- swb_id обязателен для каждой находки meta — без него 422 invalid_meta, ран не создаётся;
- API находок (список и деталь) отдаёт стабильный swb_id, fingerprint_algo и fingerprint_level;
- сквозной путь swb-cli enrich → upload → API сохраняет identity из swbmeta v2.
"""
import hashlib
import json
import shutil
import uuid
from pathlib import Path

from tests.server.conftest import make_meta, make_sarif

DATA = Path(__file__).parent.parent / "data"


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _post_run(client, sarif_bytes: bytes, meta_bytes: bytes):
    return client.post(
        "/api/v1/runs",
        files={
            "sarif": ("report.sarif", sarif_bytes, "application/json"),
            "meta": ("report.swbmeta.json", meta_bytes, "application/json"),
        },
    )


# ── поведение на старом meta (ADR §5: единственная схема — v2, иное → 422) ────


def test_meta_v1_rejected_with_422_unsupported_schema(client):
    spec = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}]
    sarif = make_sarif(spec)
    meta = json.loads(make_meta(sarif, spec, repo=_unique_repo()))
    meta["schema"] = "swbmeta/v1"

    resp = _post_run(client, sarif, json.dumps(meta).encode())
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "unsupported_schema"
    assert "swbmeta/v2" in detail["message"]


# ── swb_id обязателен: без него identity не построить (ADR §1/§6) ─────────────


def test_meta_finding_without_swb_id_rejected_with_422(client, db_session):
    from swb_server.models import Run

    spec = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}]
    sarif = make_sarif(spec)
    meta = json.loads(make_meta(sarif, spec, repo=_unique_repo()))
    del meta["findings"][0]["swb_id"]

    resp = _post_run(client, sarif, json.dumps(meta).encode())
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_meta"
    assert "swb_id" in detail["message"]

    # ран не создан
    sha = hashlib.sha256(sarif).hexdigest()
    assert db_session.query(Run).filter(Run.sarif_sha256 == sha).first() is None


def test_meta_finding_with_empty_swb_id_rejected_with_422(client):
    spec = [
        {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42},
        {"rule_id": "CWE-79", "uri": "src/web.py", "start_line": 7},
    ]
    sarif = make_sarif(spec)
    meta = json.loads(make_meta(sarif, spec, repo=_unique_repo()))
    meta["findings"][1]["swb_id"] = ""  # пустой id схлопнул бы находки в одну identity

    resp = _post_run(client, sarif, json.dumps(meta).encode())
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_meta"
    assert "findings[1]" in detail["message"]


def test_broken_sarif_still_reported_as_invalid_sarif(client):
    """Разделение ошибок meta/SARIF не съело прежнюю ветку invalid_sarif."""
    sarif = b"{not json"
    meta = {
        "schema": "swbmeta/v2",
        "source_sarif": {"sha256": hashlib.sha256(sarif).hexdigest()},
        "provenance": {"repo": _unique_repo()},
        "findings": [],
    }
    resp = _post_run(client, sarif, json.dumps(meta).encode())
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "invalid_sarif"


# ── API находок отдаёт стабильный swb_id и версию алгоритма (ADR §6) ──────────


def test_findings_list_returns_swb_id_algo_and_level(client, upload_run):
    tool_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    content_id = f"sw2:c:{uuid.uuid4().hex[:24]}:0"
    run = upload_run(
        [
            {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": tool_id},
            {"rule_id": "CWE-79", "uri": "src/web.py", "start_line": 7,
             "swb_id": content_id, "fp_level": "content"},
        ],
        repo=_unique_repo(),
    )

    items = client.get(f"/api/v1/runs/{run['run_id']}/findings").json()["items"]
    by_swb = {it["swb_id"]: it for it in items}
    assert set(by_swb) == {tool_id, content_id}
    for it in items:
        assert it["fingerprint_algo"] == "swb-fp/2"
    assert by_swb[tool_id]["fingerprint_level"] == "tool"
    assert by_swb[content_id]["fingerprint_level"] == "content"


def test_finding_detail_returns_swb_id_algo_and_level(client, upload_run):
    swb_id = f"sw2:c:{uuid.uuid4().hex[:24]}:0"
    run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42,
          "swb_id": swb_id, "fp_level": "content"}],
        repo=_unique_repo(),
    )
    finding_id = client.get(f"/api/v1/runs/{run['run_id']}/findings").json()["items"][0]["id"]

    detail = client.get(f"/api/v1/findings/{finding_id}").json()
    assert detail["swb_id"] == swb_id
    assert detail["fingerprint_algo"] == "swb-fp/2"
    assert detail["fingerprint_level"] == "content"


# ── сквозной путь: swb-cli enrich → upload → API ──────────────────────────────


class _EnrichArgs:
    """Минимальный объект аргументов для вызова enrich() напрямую (как в tests/cli)."""

    def __init__(self, sarif, out, repo_root):
        self.sarif = str(sarif)
        self.out = str(out)
        self.repo_root = str(repo_root)
        self.context_policy = "lines"
        self.context_lines = 5
        self.no_git = True
        self.fail_on_missing_source = False
        self.log_level = "error"


def test_enrich_upload_roundtrip_preserves_identity(client, db_session, tmp_path):
    from swb_cli.commands.enrich import enrich

    from swb_server.models import Finding, FindingIdentity

    # уникальный repo_root: имя каталога становится project_id на сервере
    repo = _unique_repo()
    root = tmp_path / repo
    shutil.copytree(DATA / "src", root / "src")
    sarif_path = root / "report.sarif"
    shutil.copy(DATA / "valid" / "with_partial_fingerprints.sarif", sarif_path)
    out_path = root / "report.sarif.swbmeta.json"

    assert enrich(_EnrichArgs(sarif_path, out_path, root)) == 0
    meta = json.loads(out_path.read_text())
    assert meta["schema"] == "swbmeta/v2"
    meta_finding = meta["findings"][0]
    swb_id = meta_finding["swb_id"]
    assert swb_id.startswith("sw2:t:")  # partialFingerprints → уровень tool

    resp = _post_run(client, sarif_path.read_bytes(), out_path.read_bytes())
    assert resp.status_code == 201, resp.text
    run = resp.json()
    assert run["finding_count"] == 1

    # API отдаёт стабильный swb_id и версию алгоритма из swbmeta v2
    items = client.get(f"/api/v1/runs/{run['run_id']}/findings").json()["items"]
    assert len(items) == 1
    assert items[0]["swb_id"] == swb_id
    assert items[0]["fingerprint_algo"] == meta_finding["fingerprints"]["algo"] == "swb-fp/2"
    assert items[0]["fingerprint_level"] == meta_finding["fingerprints"]["level"] == "tool"

    # Finding связан с сущностью вердикта через identity (ADR §6)
    finding = db_session.query(Finding).filter(Finding.id == items[0]["id"]).first()
    identity = db_session.query(FindingIdentity).filter(FindingIdentity.id == finding.identity_id).first()
    assert identity is not None
    assert identity.project_id == run["project_id"]
    assert identity.swb_id == swb_id
    assert identity.algo == "swb-fp/2"
    assert identity.level == "tool"
    assert identity.verdict == "unmarked"
