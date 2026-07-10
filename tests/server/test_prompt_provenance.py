"""T-25: prompt_id/prompt_version пишутся в вердикт и в событие истории при AI-разметке.

Проверяет, что честный AI-«false_positive» (prompt_id=honest) отличим от
принудительного force_fp по prompt_id, а произвольный custom-промпт,
введённый на лету, не получает версии (не зарегистрирован в PROMPTS).

LLM замокан (monkeypatch call_llm в неймспейсе доменного цикла
swb_server.ai.analyze_loop — см. T-37) — наружу ничего не уходит.
"""
import json
import uuid

import pytest

from swb_server.ai.prompts import PROMPTS


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _first_finding_id(client, run_id: str) -> str:
    items = client.get(f"/api/v1/runs/{run_id}/findings").json()["items"]
    assert items
    return items[0]["id"]


def _sse_events(text: str) -> list[dict]:
    return [json.loads(line[len("data: "):]) for line in text.splitlines() if line.startswith("data: ")]


def _analyze(client, run_id: str, **overrides) -> list[dict]:
    payload = {"api_key": "test-key-not-used", "only_unmarked": False, **overrides}
    resp = client.post(f"/api/v1/runs/{run_id}/analyze", json=payload)
    assert resp.status_code == 200, resp.text
    return _sse_events(resp.text)


@pytest.fixture()
def mock_llm_honest(monkeypatch):
    """Мок LLM в формате парсера honest: всегда false_positive."""

    async def _fake_call_llm(provider, api_key, model, system, user):
        return {"content": "Verdict: false_positive\nRationale: замокано (honest)", "tokens": 5}

    monkeypatch.setattr("swb_server.ai.analyze_loop.call_llm", _fake_call_llm)


@pytest.fixture()
def mock_llm_force_fp(monkeypatch):
    """Мок LLM в формате парсера force_fp (см. ai/prompts.py::_parse_force_fp)."""

    async def _fake_call_llm(provider, api_key, model, system, user):
        return {
            "content": (
                "Marker: False Positive\n"
                "Severity: Minor\n"
                "Правило: CWE-89\n"
                "Комментарий: формально задокументировано (force_fp)"
            ),
            "tokens": 7,
        }

    monkeypatch.setattr("swb_server.ai.analyze_loop.call_llm", _fake_call_llm)


def test_honest_prompt_writes_id_and_version(client, db_session, upload_run, mock_llm_honest):
    from swb_server.models import Finding, VerdictEvent

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    events = _analyze(client, run["run_id"], prompt_id="honest")
    progress = [e for e in events if e["type"] == "progress"]
    assert progress and progress[0]["verdict"] == "false_positive"

    db_session.expire_all()
    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    identity = finding.identity
    assert identity.verdict == "false_positive"
    assert identity.prompt_id == "honest"
    assert identity.prompt_version == PROMPTS["honest"]["version"]

    stored = db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == identity.id).all()
    ai_events = [e for e in stored if e.source == "ai"]
    assert len(ai_events) == 1
    assert ai_events[0].prompt_id == "honest"
    assert ai_events[0].prompt_version == PROMPTS["honest"]["version"]


def test_force_fp_prompt_writes_id_and_version(client, db_session, upload_run, mock_llm_force_fp):
    from swb_server.models import Finding, VerdictEvent

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    events = _analyze(client, run["run_id"], prompt_id="force_fp")
    progress = [e for e in events if e["type"] == "progress"]
    assert progress and progress[0]["verdict"] == "false_positive"

    db_session.expire_all()
    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    identity = finding.identity
    assert identity.verdict == "false_positive"
    assert identity.prompt_id == "force_fp"
    assert identity.prompt_version == PROMPTS["force_fp"]["version"]

    stored = db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == identity.id).all()
    ai_events = [e for e in stored if e.source == "ai"]
    assert len(ai_events) == 1
    assert ai_events[0].prompt_id == "force_fp"
    assert ai_events[0].prompt_version == PROMPTS["force_fp"]["version"]


def test_honest_and_force_fp_false_positive_distinguishable_via_api(client, db_session, upload_run, monkeypatch):
    """Два одинаковых снапшот-вердикта false_positive, но разный prompt_id.

    Мок переключается вручную между ранами (две фикстуры-мока вместе конфликтовали
    бы: monkeypatch.setattr одной перетирал бы другую, так как обе патчат один
    и тот же атрибут).
    """

    async def _fake_honest(provider, api_key, model, system, user):
        return {"content": "Verdict: false_positive\nRationale: замокано (honest)", "tokens": 5}

    async def _fake_force_fp(provider, api_key, model, system, user):
        return {
            "content": (
                "Marker: False Positive\nSeverity: Minor\nПравило: CWE-89\n"
                "Комментарий: формально задокументировано (force_fp)"
            ),
            "tokens": 7,
        }

    repo_honest = _unique_repo()
    run_honest = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo_honest)
    finding_honest_id = _first_finding_id(client, run_honest["run_id"])

    repo_force = _unique_repo()
    run_force = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo_force)
    finding_force_id = _first_finding_id(client, run_force["run_id"])

    monkeypatch.setattr("swb_server.ai.analyze_loop.call_llm", _fake_honest)
    _analyze(client, run_honest["run_id"], prompt_id="honest")

    resp_honest = client.get(f"/api/v1/findings/{finding_honest_id}")
    assert resp_honest.status_code == 200
    vd_honest = resp_honest.json()["verdict"]
    assert vd_honest["verdict"] == "false_positive"
    assert vd_honest["prompt_id"] == "honest"

    monkeypatch.setattr("swb_server.ai.analyze_loop.call_llm", _fake_force_fp)
    _analyze(client, run_force["run_id"], prompt_id="force_fp")

    resp_force = client.get(f"/api/v1/findings/{finding_force_id}")
    assert resp_force.status_code == 200
    vd_force = resp_force.json()["verdict"]
    assert vd_force["verdict"] == "false_positive"
    assert vd_force["prompt_id"] == "force_fp"

    # одинаковый вердикт, разный prompt_id — различимость есть
    assert vd_honest["verdict"] == vd_force["verdict"]
    assert vd_honest["prompt_id"] != vd_force["prompt_id"]


def test_custom_prompt_has_no_version(client, db_session, upload_run, mock_llm_honest):
    from swb_server.models import Finding, VerdictEvent

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    events = _analyze(
        client, run["run_id"],
        prompt_id="custom", custom_system="Ты — эксперт. Отвечай честно.",
    )
    progress = [e for e in events if e["type"] == "progress"]
    assert progress and progress[0]["verdict"] == "false_positive"

    db_session.expire_all()
    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    identity = finding.identity
    assert identity.prompt_id == "custom"
    assert identity.prompt_version is None

    stored = db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == identity.id).all()
    ai_events = [e for e in stored if e.source == "ai"]
    assert len(ai_events) == 1
    assert ai_events[0].prompt_id == "custom"
    assert ai_events[0].prompt_version is None

    resp = client.get(f"/api/v1/findings/{finding_id}")
    assert resp.status_code == 200
    vd = resp.json()["verdict"]
    assert vd["prompt_id"] == "custom"
    assert vd["prompt_version"] is None


def test_finding_history_includes_prompt_fields(client, db_session, upload_run, mock_llm_honest):
    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    _analyze(client, run["run_id"], prompt_id="honest")

    resp = client.get(f"/api/v1/findings/{finding_id}")
    assert resp.status_code == 200
    history = resp.json()["verdict"]["history"]
    ai_history = [h for h in history if h["source"] == "ai"]
    assert len(ai_history) == 1
    assert ai_history[0]["prompt_id"] == "honest"
    assert ai_history[0]["prompt_version"] == PROMPTS["honest"]["version"]
