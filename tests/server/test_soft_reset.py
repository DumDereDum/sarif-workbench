"""T-26: reset сообщает реальный масштаб операции (сколько вердиктов сброшено),
а не общее число находок в ране.

Регрессия: `reset_verdicts` раньше возвращал {"reset": len(findings)} — общее
число находок рана, даже если реально сброшена была лишь часть (или ни одна)
из них. Здесь — прицельные сценарии на подсчёт.
"""
import uuid


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _findings(client, run_id: str) -> list[dict]:
    return client.get(f"/api/v1/runs/{run_id}/findings").json()["items"]


def test_reset_counts_only_actually_marked_findings(client, upload_run):
    """3 находки, размечены вручную 2 (разными вердиктами), третья осталась unmarked."""
    repo = _unique_repo()
    run = upload_run(
        [
            {"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1},
            {"rule_id": "CWE-79", "uri": "src/b.py", "start_line": 2},
            {"rule_id": "CWE-22", "uri": "src/c.py", "start_line": 3},
        ],
        repo=repo,
    )
    items = _findings(client, run["run_id"])
    assert len(items) == 3

    resp = client.patch(f"/api/v1/findings/{items[0]['id']}/verdict", json={"verdict": "true_positive", "version": 1})
    assert resp.status_code == 200
    resp = client.patch(f"/api/v1/findings/{items[1]['id']}/verdict", json={"verdict": "false_positive", "version": 1})
    assert resp.status_code == 200
    # items[2] остаётся unmarked

    resp = client.post(f"/api/v1/runs/{run['run_id']}/reset")
    assert resp.status_code == 200
    assert resp.json() == {"reset": 2}


def test_reset_counts_zero_when_nothing_marked(client, db_session, upload_run):
    """Ни одна находка не размечена → reset ничего не сбрасывает и не пишет событий."""
    from swb_server.models import VerdictEvent

    repo = _unique_repo()
    run = upload_run(
        [
            {"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1},
            {"rule_id": "CWE-79", "uri": "src/b.py", "start_line": 2},
        ],
        repo=repo,
    )
    items = _findings(client, run["run_id"])
    assert len(items) == 2

    resp = client.post(f"/api/v1/runs/{run['run_id']}/reset")
    assert resp.status_code == 200
    assert resp.json() == {"reset": 0}

    identity_ids = {item["swb_id"] for item in items}  # только чтобы убедиться, что находок 2
    assert len(identity_ids) == 2

    # Ни для одной identity этого рана reset (и вообще никакое) событие не создано
    from swb_server.models import Finding

    findings = db_session.query(Finding).filter(Finding.run_id == run["run_id"]).all()
    for f in findings:
        count = db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == f.identity_id).count()
        assert count == 0


def test_reset_counts_shared_identity_once(client, db_session, upload_run):
    """Две находки одного рана с одинаковым swb_id делят одну identity;
    identity размечена один раз → reset считает её один раз, а не по числу находок.
    """
    from swb_server.models import Finding

    repo = _unique_repo()
    shared_swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    run = upload_run(
        [
            {"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": shared_swb_id, "occurrence": 0},
            {"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": shared_swb_id, "occurrence": 1},
        ],
        repo=repo,
    )
    items = _findings(client, run["run_id"])
    assert len(items) == 2

    # Обе находки действительно делят одну identity
    findings = db_session.query(Finding).filter(Finding.run_id == run["run_id"]).all()
    identity_ids = {f.identity_id for f in findings}
    assert len(identity_ids) == 1

    resp = client.patch(f"/api/v1/findings/{items[0]['id']}/verdict", json={"verdict": "true_positive", "version": 1})
    assert resp.status_code == 200

    resp = client.post(f"/api/v1/runs/{run['run_id']}/reset")
    assert resp.status_code == 200
    assert resp.json() == {"reset": 1}
