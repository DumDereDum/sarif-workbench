"""Лимит размера загрузки (T-02): SARIF/meta крупнее лимита → HTTP 413."""
import asyncio
import hashlib
import io
import json
from pathlib import Path

import pytest

DATA = Path(__file__).parent.parent / "data"


def _meta_for(sarif_bytes: bytes) -> bytes:
    meta = {
        "schema": "swbmeta/v2",
        "source_sarif": {
            "filename": "report.sarif",
            "sha256": hashlib.sha256(sarif_bytes).hexdigest(),
            "size_bytes": len(sarif_bytes),
        },
        "provenance": {"repo": "swb-test-repo"},
        "findings": [],
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
    resp = _post_run(client, sarif_bytes, _meta_for(sarif_bytes))
    assert resp.status_code == 201
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
