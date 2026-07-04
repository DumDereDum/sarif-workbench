"""Серверный тест-харнесс (T-02, доведён в T-14).

БД и блобы уводятся во временный каталог. Env выставляется ДО импорта
swb_server: db.py создаёт engine на уровне модуля из DATABASE_URL,
поэтому приложение импортируется внутри фикстуры, а не наверху модуля.

БД session-scoped и общая для тестов — тесты не должны предполагать
пустую базу. Фабрики генерируют уникальные SARIF-байты (nonce), чтобы
не попадать в дедуп по sha256.
"""
import hashlib
import json
import os
import uuid

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def app(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("swb-server")
    os.environ["DATA_DIR"] = str(data_dir)
    os.environ["DATABASE_URL"] = f"sqlite:///{data_dir / 'swb.db'}"
    os.environ["LOG_FILE"] = ""  # не писать лог-файл из тестов
    from swb_server.main import app  # noqa: PLC0415 — импорт после установки env

    return app


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db_session(app, client):
    """Сессия SQLAlchemy к той же временной БД, что и приложение.

    Зависимость от client гарантирует, что lifespan (init_db) уже отработал.
    """
    from swb_server.db import SessionLocal  # noqa: PLC0415

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# ── Фабрики SARIF/swbmeta ─────────────────────────────────────────────────────


def make_sarif(findings_spec: list[dict], tool: str = "TestTool") -> bytes:
    """SARIF 2.1.0 c результатами по спецификации; nonce делает байты уникальными."""
    results = [
        {
            "ruleId": spec.get("rule_id", "CWE-89"),
            "level": spec.get("level", "error"),
            "message": {"text": spec.get("message", "test finding")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": spec.get("uri", "src/db.py")},
                        "region": {"startLine": spec.get("start_line", 42)},
                    }
                }
            ],
        }
        for spec in findings_spec
    ]
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool, "version": "1.0.0", "rules": []}},
                "results": results,
            }
        ],
        "properties": {"nonce": uuid.uuid4().hex},
    }
    return json.dumps(sarif).encode()


def make_meta(sarif_bytes: bytes, findings_spec: list[dict], repo: str = "swb-test-repo") -> bytes:
    """swbmeta/v2 для make_sarif: swb_id формата sw2:{t|c|l}:hash:occ (ADR §1)."""
    findings = []
    for i, spec in enumerate(findings_spec):
        swb_id = spec.get("swb_id") or f"sw2:t:{hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:24]}:0"
        findings.append(
            {
                "swb_id": swb_id,
                "occurrence": spec.get("occurrence", 0),
                "locator": {
                    "run": 0,
                    "result": i,
                    "rule_id": spec.get("rule_id", "CWE-89"),
                    "uri": spec.get("uri", "src/db.py"),
                    "norm_uri": spec.get("uri", "src/db.py"),
                    "region": {"start_line": spec.get("start_line", 42)},
                },
                "fingerprints": {
                    "algo": spec.get("algo", "swb-fp/2"),
                    "level": spec.get("fp_level", "tool"),
                    "rule": spec.get("rule_id", "CWE-89"),
                },
            }
        )
    meta = {
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
    return json.dumps(meta).encode()


@pytest.fixture()
def upload_run(client):
    """Фабрика: загрузить ран из спецификации находок, вернуть JSON-ответ сервера.

    Каждая спецификация — dict с необязательными ключами
    rule_id/uri/start_line/message/swb_id/occurrence/algo/fp_level.
    """

    def _upload(findings_spec: list[dict], repo: str = "swb-test-repo", *, sarif_bytes: bytes | None = None):
        sarif = sarif_bytes or make_sarif(findings_spec)
        meta = make_meta(sarif, findings_spec, repo=repo)
        resp = client.post(
            "/api/v1/runs",
            files={
                "sarif": ("report.sarif", sarif, "application/json"),
                "meta": ("report.swbmeta.json", meta, "application/json"),
            },
        )
        assert resp.status_code == 201, resp.text
        return resp.json()

    return _upload
