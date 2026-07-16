"""T-53 — suite «вредоносный вход»: серверная часть.

Явно поименованный, дискаверабельный (`pytest -k malicious`) сборник трёх
сценариев из Done when задачи, читаемых сообразно `inspection/06-tests.md`
§3 ("нет тестов на... раздутый JSON, meta с индексами в пустоту,
sha-mismatch"):

- раздутый JSON → 413 (anchor: `routers/runs.py::_read_limited`, T-02);
- meta с локатором в никуда → 422 (anchor: `ingest.py:111`
  `_reconcile_results_and_meta`, T-36), с фикстурой на диске
  (`tests/data/malicious/broken_locator.{sarif,meta.json}`), а не только
  собранной инлайн, как в `test_meta_sarif_reconciliation.py`;
- sha256-подмена между enrich и upload → отказ загрузки (T-51,
  `routers/runs.py:270`, 409).

Каждый сценарий уже имеет более полное покрытие в своём task-специфичном
файле (`test_upload_limits.py`, `test_meta_sarif_reconciliation.py`,
`test_upload_sha_verification.py`) — они остаются источником истины по
граничным случаям. Этот файл — не замена им, а единая точка входа "вот три
вида недоверенного входа, которые сервер обязан отвергать", которую можно
запустить отдельно по `-k malicious` и на которую может сослаться CI/аудит.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

# `swb_server.models`/`.db`/`.main` — не импортировать на уровне модуля (см.
# комментарий в tests/server/conftest.py и tests/server/test_meta_sarif_reconciliation.py):
# pytest коллектит все тестовые модули до того, как session-scoped фикстура
# `app` выставит DATA_DIR/DATABASE_URL, иначе SQLAlchemy engine привяжется к
# настоящей dev-БД.

DATA = Path(__file__).parent.parent / "data"
MALICIOUS = DATA / "malicious"


def _unique_repo() -> str:
    return f"swb-malicious-{uuid.uuid4().hex[:8]}"


def _post_run(client, sarif_bytes: bytes, meta_bytes: bytes):
    return client.post(
        "/api/v1/runs",
        files={
            "sarif": ("report.sarif", sarif_bytes, "application/json"),
            "meta": ("report.swbmeta.json", meta_bytes, "application/json"),
        },
    )


# ── раздутый JSON → 413 ──────────────────────────────────────────────────────


def test_bloated_sarif_upload_rejected_with_413(client, monkeypatch):
    monkeypatch.setenv("SWB_MAX_UPLOAD_MB", "1")
    bloated = b'{"runs": []}' + b" " * (2 * 1024 * 1024)  # 2 МБ > лимита в 1 МБ
    meta = {
        "schema": "swbmeta/v3",
        "source_sarif": {
            "filename": "report.sarif",
            "sha256": hashlib.sha256(bloated).hexdigest(),
            "size_bytes": len(bloated),
        },
        "provenance": {"repo": _unique_repo()},
        "findings": [],
    }
    resp = _post_run(client, bloated, json.dumps(meta).encode())

    assert resp.status_code == 413
    detail = resp.json()["detail"]
    assert detail["error"] == "payload_too_large"


# ── meta с локатором, указывающим в никуда → 422 ────────────────────────────


def test_meta_locator_pointing_nowhere_rejected_with_422(client, db_session):
    from swb_server.models import Run  # noqa: PLC0415 — см. комментарий выше

    sarif_bytes = (MALICIOUS / "broken_locator.sarif").read_bytes()
    meta_doc = json.loads((MALICIOUS / "broken_locator.meta.json").read_text())
    # фикстура на диске хранит намеренно битый locator.result=999
    # (единственный SARIF-результат имеет индекс 0) — это и есть атака;
    # sha256/size_bytes/repo патчатся здесь, а не хранятся в фикстуре,
    # чтобы не протухать при любой правке SARIF-фикстуры и не сталкиваться
    # с дедупом между запусками (project_id, sarif_sha256 — ADR 0001 §7).
    assert meta_doc["findings"][0]["locator"]["result"] == 999
    meta_doc["source_sarif"]["sha256"] = hashlib.sha256(sarif_bytes).hexdigest()
    meta_doc["source_sarif"]["size_bytes"] = len(sarif_bytes)
    meta_doc["provenance"]["repo"] = _unique_repo()
    meta_bytes = json.dumps(meta_doc).encode()

    resp = _post_run(client, sarif_bytes, meta_bytes)

    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_meta"
    assert "broken locator index" in detail["message"]

    sha = hashlib.sha256(sarif_bytes).hexdigest()
    assert db_session.query(Run).filter(Run.sarif_sha256 == sha).first() is None


# ── sha256 не совпадает с заявленной в meta → отказ загрузки ───────────────


def test_sha256_mismatch_between_sarif_and_meta_rejected(client, db_session):
    from swb_server.models import Project, Run  # noqa: PLC0415 — см. комментарий выше

    sarif_bytes = (MALICIOUS / "broken_locator.sarif").read_bytes()
    repo = _unique_repo()
    meta = {
        "schema": "swbmeta/v3",
        "source_sarif": {
            "filename": "broken_locator.sarif",
            # sha256 заявлен для НЕподменённых байт; в запросе уходят
            # подменённые — имитация повреждения/подмены SARIF между
            # enrich и upload
            "sha256": hashlib.sha256(sarif_bytes).hexdigest(),
            "size_bytes": len(sarif_bytes),
        },
        "provenance": {"repo": repo},
        "findings": [],
    }
    tampered_sarif = sarif_bytes + b" "

    resp = _post_run(client, tampered_sarif, json.dumps(meta).encode())

    assert resp.status_code == 409  # T-51: sha_mismatch — конфликт с заявленным в meta
    detail = resp.json()["detail"]
    assert detail["error"] == "sha_mismatch"

    actual_sha = hashlib.sha256(tampered_sarif).hexdigest()
    assert db_session.query(Run).filter(Run.sarif_sha256 == actual_sha).first() is None
    assert db_session.query(Project).filter(Project.repo == repo).count() == 0
