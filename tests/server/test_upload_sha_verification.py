"""T-51: явное покрытие sha256-сверки при upload (ADR 0001 §7).

`upload_run` (conftest) всегда строит meta с корректным sha256 через
`make_meta`, поэтому успешный путь сверки уже неявно проходит в каждом
существующем upload-тесте, а вот ветка `sha_mismatch` (409) — код,
которым проверяется недоверенный вход клиента — не была покрыта ни одним
тестом. Здесь оба пути явно и рядом: успех документирует инвариант
(Run.sarif_sha256 == sha256 реально загруженных байт), а провал —
что несовпадение отклоняется 409 и не создаёт ни Run, ни Project (сверка
sha в routers/runs.py стоит до резолва проекта).
"""
import hashlib
import json
import uuid

from tests.server.conftest import make_meta, make_sarif


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


def test_upload_with_matching_sha256_succeeds_and_is_recorded(client, db_session):
    from swb_server.models import Run

    repo = _unique_repo()
    spec = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}]
    sarif = make_sarif(spec)
    meta = make_meta(sarif, spec, repo=repo)

    resp = _post_run(client, sarif, meta)
    assert resp.status_code == 201, resp.text
    run_id = resp.json()["run_id"]

    actual_sha = hashlib.sha256(sarif).hexdigest()
    declared_sha = json.loads(meta)["source_sarif"]["sha256"]
    assert declared_sha == actual_sha  # sanity: фикстура действительно даёт совпадение

    stored_run = db_session.query(Run).filter(Run.id == run_id).one()
    assert stored_run.sarif_sha256 == actual_sha


def test_upload_rejects_sha256_mismatch_with_409(client, db_session):
    from swb_server.models import Project, Run

    repo = _unique_repo()
    spec = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}]
    sarif = make_sarif(spec)
    meta = make_meta(sarif, spec, repo=repo)  # meta.source_sarif.sha256 == sha256(sarif)

    # то, что реально уходит в теле запроса, отличается от того, что meta
    # заявляет своим source_sarif.sha256 — как при повреждении/подмене
    # SARIF между enrich и upload.
    tampered_sarif = sarif + b" "

    resp = _post_run(client, tampered_sarif, meta)
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["error"] == "sha_mismatch"

    actual_sha = hashlib.sha256(tampered_sarif).hexdigest()
    declared_sha = hashlib.sha256(sarif).hexdigest()
    assert actual_sha[:8] in detail["message"]
    assert declared_sha[:8] in detail["message"]

    # sha-сверка стоит до резолва/создания проекта в routers/runs.py —
    # провал не должен оставлять ни Run, ни Project.
    assert db_session.query(Run).filter(Run.sarif_sha256 == actual_sha).first() is None
    assert db_session.query(Project).filter(Project.repo == repo).count() == 0
