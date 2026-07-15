"""T-24: AI-анализ не перезаписывает human-вердикт без явного override.

LLM замокан (monkeypatch call_llm в неймспейсе доменного цикла
`swb_server.ai.analyze_loop`, куда он импортирован для использования в
цикле анализа — см. T-37) — наружу ничего не уходит. Ответ мока — в формате
промпта honest.
"""
import json
import uuid

import pytest


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _first_finding_id(client, run_id: str) -> str:
    items = client.get(f"/api/v1/runs/{run_id}/findings").json()["items"]
    assert items
    return items[0]["id"]


def _sse_events(text: str) -> list[dict]:
    """Разобрать события из тела SSE-ответа (строки `data: {...}`)."""
    return [json.loads(line[len("data: "):]) for line in text.splitlines() if line.startswith("data: ")]


def _analyze(client, run_id: str, **overrides) -> list[dict]:
    payload = {"only_unmarked": False, **overrides}
    resp = client.post(f"/api/v1/runs/{run_id}/analyze", json=payload)
    assert resp.status_code == 200, resp.text
    return _sse_events(resp.text)


def _by_type(events: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for e in events:
        grouped.setdefault(e["type"], []).append(e)
    return grouped


@pytest.fixture()
def mock_llm(monkeypatch):
    """Мок LLM: всегда false_positive, формат под parse_response промпта honest."""

    async def _fake_call_llm(provider, model, system, user):
        return {"content": "Verdict: false_positive\nRationale: замокано", "tokens": 5}

    monkeypatch.setattr("swb_server.ai.analyze_loop.call_llm", _fake_call_llm)


def test_analyze_default_does_not_touch_human_verdict(client, db_session, upload_run, mock_llm):
    from swb_server.models import Finding, VerdictEvent

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    resp = client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "true_positive", "rationale": "проверил руками", "version": 1},
    )
    assert resp.status_code == 200

    events = _analyze(client, run["run_id"])  # без override

    # единственная находка защищена → анализировать нечего, ранний done
    grouped = _by_type(events)
    assert "progress" not in grouped
    done = grouped["done"][0]
    assert done["total"] == 0
    assert done["skipped_human"] == 1
    for start in grouped.get("start", []):
        assert start["skipped_human"] == 1

    # снапшот identity не тронут
    db_session.expire_all()
    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    identity = finding.identity
    assert identity.verdict == "true_positive"
    assert identity.verdict_source == "human"
    assert identity.rationale == "проверил руками"

    # нового события нет: остаётся одно human-событие
    stored = db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == identity.id).all()
    assert len(stored) == 1
    assert stored[0].source == "human"


def test_analyze_override_rewrites_human_verdict_with_history(client, db_session, upload_run, mock_llm):
    from swb_server.models import Finding, VerdictEvent

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    client.patch(f"/api/v1/findings/{finding_id}/verdict", json={"verdict": "true_positive", "version": 1})

    events = _analyze(client, run["run_id"], override=True)

    grouped = _by_type(events)
    assert grouped["start"][0] == {"type": "start", "total": 1, "skipped_human": 0}
    assert grouped["done"][0]["skipped_human"] == 0
    assert grouped["progress"][0]["verdict"] == "false_positive"

    # снапшот перезаписан AI'ем
    db_session.expire_all()
    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    identity = finding.identity
    assert identity.verdict == "false_positive"
    assert identity.verdict_source == "ai"

    # история полная: human-событие + AI-событие с old/new
    stored = db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == identity.id).all()
    assert len(stored) == 2
    ai_events = [e for e in stored if e.source == "ai"]
    assert len(ai_events) == 1
    assert ai_events[0].old_verdict == "true_positive"
    assert ai_events[0].new_verdict == "false_positive"


def test_analyze_mixed_run_skips_only_human_marked(client, db_session, upload_run, mock_llm):
    from swb_server.models import Finding

    repo = _unique_repo()
    run = upload_run(
        [
            {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42},
            {"rule_id": "CWE-79", "uri": "src/web.py", "start_line": 7},
        ],
        repo=repo,
    )
    items = client.get(f"/api/v1/runs/{run['run_id']}/findings").json()["items"]
    assert len(items) == 2
    human_id, other_id = items[0]["id"], items[1]["id"]

    client.patch(f"/api/v1/findings/{human_id}/verdict", json={"verdict": "true_positive", "version": 1})

    events = _analyze(client, run["run_id"])  # без override

    grouped = _by_type(events)
    assert grouped["start"][0]["total"] == 1
    assert grouped["start"][0]["skipped_human"] == 1
    assert grouped["done"][0]["skipped_human"] == 1
    assert [e["finding_id"] for e in grouped["progress"]] == [other_id]

    db_session.expire_all()
    human = db_session.query(Finding).filter(Finding.id == human_id).first()
    assert human.identity.verdict == "true_positive"
    assert human.identity.verdict_source == "human"

    other = db_session.query(Finding).filter(Finding.id == other_id).first()
    assert other.identity.verdict == "false_positive"
    assert other.identity.verdict_source == "ai"


def test_analyze_does_not_protect_human_unmarked(client, db_session, upload_run, mock_llm):
    from swb_server.models import Finding

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    # human поставил unmarked: source=human, но решения нет — не защищаем
    resp = client.patch(f"/api/v1/findings/{finding_id}/verdict", json={"verdict": "unmarked", "version": 1})
    assert resp.status_code == 200
    assert resp.json()["source"] == "human"

    events = _analyze(client, run["run_id"])  # без override

    grouped = _by_type(events)
    assert grouped["start"][0] == {"type": "start", "total": 1, "skipped_human": 0}
    assert grouped["done"][0]["skipped_human"] == 0

    db_session.expire_all()
    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    assert finding.identity.verdict == "false_positive"
    assert finding.identity.verdict_source == "ai"
