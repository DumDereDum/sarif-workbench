"""T-51: явное покрытие автосоздания проекта при первом upload (routers/runs.py).

Существующие тесты (test_upload_dedup.py, test_ingest_identity.py и др.)
сравнивают `project_id` в ответах upload между собой (тот же / другой), но
ни один не смотрит на саму строку `projects`: что она реально создаётся,
с какими полями (id/repo/name/team, выведенными из provenance), и что
повторная загрузка в тот же repo переиспользует существующую строку,
а не плодит дубликат.
"""
import json
import uuid

from tests.server.conftest import make_meta, make_sarif


def _post_run(client, sarif_bytes: bytes, meta_bytes: bytes):
    return client.post(
        "/api/v1/runs",
        files={
            "sarif": ("report.sarif", sarif_bytes, "application/json"),
            "meta": ("report.swbmeta.json", meta_bytes, "application/json"),
        },
    )


def test_upload_auto_creates_project_with_fields_from_provenance(client, db_session):
    from swb_server.models import Project

    suffix = uuid.uuid4().hex[:8]
    repo = f"Acme-Corp/Widget-{suffix}"  # смешанный регистр + "/" — проверяем вывод id/name
    team = f"team-{suffix}"

    spec = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}]
    sarif = make_sarif(spec)
    meta = make_meta(sarif, spec, repo=repo)
    meta_data = json.loads(meta)
    meta_data["provenance"]["team"] = team
    meta = json.dumps(meta_data).encode()

    resp = _post_run(client, sarif, meta)
    assert resp.status_code == 201, resp.text
    body = resp.json()

    expected_id = f"acme-corp-widget-{suffix}"  # lower() + [^a-z0-9-] -> "-"; "/" единственный такой символ здесь
    assert body["project_id"] == expected_id

    project = db_session.query(Project).filter(Project.id == expected_id).one()
    assert project.repo == repo  # repo хранится как есть, не lower()
    assert project.name == f"Widget-{suffix}"  # последний сегмент repo после "/"
    assert project.team == team


def test_upload_reuses_existing_project_row_for_second_run_same_repo(client, db_session):
    from swb_server.models import Project, Run

    repo = f"swb-test-{uuid.uuid4().hex[:8]}"
    spec1 = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}]
    spec2 = [{"rule_id": "CWE-79", "uri": "src/web.py", "start_line": 7}]  # другой sha, не дедуп

    sarif1 = make_sarif(spec1)
    resp1 = _post_run(client, sarif1, make_meta(sarif1, spec1, repo=repo))
    assert resp1.status_code == 201, resp1.text
    project_id = resp1.json()["project_id"]

    rows_after_first = db_session.query(Project).filter(Project.id == project_id).all()
    assert len(rows_after_first) == 1
    created_at_first = rows_after_first[0].created_at

    sarif2 = make_sarif(spec2)
    resp2 = _post_run(client, sarif2, make_meta(sarif2, spec2, repo=repo))
    assert resp2.status_code == 201, resp2.text
    body2 = resp2.json()
    assert body2["project_id"] == project_id
    assert body2["deduplicated"] is False
    assert body2["run_id"] != resp1.json()["run_id"]

    rows_after_second = db_session.query(Project).filter(Project.id == project_id).all()
    assert len(rows_after_second) == 1  # ни одной новой строки Project
    assert rows_after_second[0].created_at == created_at_first  # та же строка, не пересоздана

    runs = db_session.query(Run).filter(Run.project_id == project_id).all()
    assert len(runs) == 2  # оба рана привязаны к одному проекту
