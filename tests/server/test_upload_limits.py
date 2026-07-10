"""Лимит размера загрузки (T-02): SARIF/meta крупнее лимита → HTTP 413."""
import asyncio
import hashlib
import io
import json
from pathlib import Path

import pytest

DATA = Path(__file__).parent.parent / "data"


def _meta_for(sarif_bytes: bytes, findings: list | None = None) -> bytes:
    meta = {
        "schema": "swbmeta/v3",
        "source_sarif": {
            "filename": "report.sarif",
            "sha256": hashlib.sha256(sarif_bytes).hexdigest(),
            "size_bytes": len(sarif_bytes),
        },
        "provenance": {"repo": "swb-test-repo"},
        "findings": findings if findings is not None else [],
    }
    return json.dumps(meta).encode()


def _post_run(client, sarif_bytes: bytes, meta_bytes: bytes):
    return client.post(
        "/api/v1/runs",
        files={
            "sarif": ("report.sarif", sarif_bytes, "application/json"),
            "meta": ("report.swbmeta.json", meta_bytes, "application/json"),
        },
    )


def test_oversized_sarif_rejected_with_413(client, monkeypatch):
    monkeypatch.setenv("SWB_MAX_UPLOAD_MB", "1")
    big_sarif = b'{"runs": []}' + b" " * (2 * 1024 * 1024)  # 2 МБ > лимита в 1 МБ
    resp = _post_run(client, big_sarif, _meta_for(big_sarif))
    assert resp.status_code == 413
    detail = resp.json()["detail"]
    assert detail["error"] == "payload_too_large"
    # понятный detail: имя поля и лимит, без внутренних путей сервера
    assert "sarif" in detail["message"]
    assert "1 MB" in detail["message"]
    assert "/" not in detail["message"]


def test_oversized_meta_rejected_with_413(client, monkeypatch):
    monkeypatch.setenv("SWB_MAX_UPLOAD_MB", "1")
    sarif_bytes = (DATA / "valid" / "minimal.sarif").read_bytes()
    big_meta = _meta_for(sarif_bytes) + b" " * (2 * 1024 * 1024)
    resp = _post_run(client, sarif_bytes, big_meta)
    assert resp.status_code == 413
    detail = resp.json()["detail"]
    assert detail["error"] == "payload_too_large"
    assert "meta" in detail["message"]


def test_upload_under_limit_accepted_and_stored_intact(client):
    # контроль: с дефолтным лимитом валидная пара проходит,
    # а SARIF после лимитированного чтения хранится байт-в-байт
    sarif_bytes = (DATA / "valid" / "minimal.sarif").read_bytes()
    # T-36: minimal.sarif's one result has a location, so meta must claim it
    # — an empty findings list would now fail strict meta/SARIF reconciliation.
    finding = {
        "swb_id": f"sw2:t:{'a' * 24}:0",
        "occurrence": 0,
        "locator": {
            "run": 0, "result": 0, "rule_id": "CWE-89",
            "uri": "src/db.py", "norm_uri": "src/db.py",
            "region": {"start_line": 42, "start_column": 8},
        },
        "fingerprints": {"algo": "swb-fp/2", "level": "tool", "rule": "CWE-89"},
    }
    resp = _post_run(client, sarif_bytes, _meta_for(sarif_bytes, [finding]))
    assert resp.status_code == 201, resp.text
    run_id = resp.json()["run_id"]
    stored = client.get(f"/api/v1/runs/{run_id}/sarif")
    assert stored.content == sarif_bytes


def test_read_limited_caps_reads_when_size_unknown(app, monkeypatch):
    # fallback-ветка: UploadFile с неизвестным size читается чанками
    # и отклоняется на лимите, не дочитывая файл до конца
    from fastapi import HTTPException, UploadFile

    from swb_server.routers.runs import _read_limited

    monkeypatch.setenv("SWB_MAX_UPLOAD_MB", "1")
    payload = b"\0" * (8 * 1024 * 1024)
    stream = io.BytesIO(payload)
    upload = UploadFile(file=stream)
    assert upload.size is None
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(_read_limited(upload, "sarif"))
    assert exc_info.value.status_code == 413
    assert stream.tell() < len(payload)  # чтение остановлено задолго до конца
