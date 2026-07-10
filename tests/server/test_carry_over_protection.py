"""T-27: carry-over не маскирует human/ai в verdict_source (ADR 0001 §6).

`write_verdict` больше не перезаписывает денормализованный снапшот
`identity.verdict_source` на "carried" — carry-over лишь подтверждает
прежнее решение в новом скане, полная история по-прежнему видна в
`verdict_events` (там каждое carry-событие честно хранит source="carried").
Это чинит эрозию T-24-защиты (`verdict_source == "human"`) через один или
несколько carry-over подряд.
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
    return [json.loads(line[len("data: "):]) for line in text.splitlines() if line.startswith("data: ")]


def _analyze(client, run_id: str, **overrides) -> list[dict]:
    payload = {"api_key": "test-key-not-used", "only_unmarked": False, **overrides}
    resp = client.post(f"/api/v1/runs/{run_id}/analyze", json=payload)
    assert resp.status_code == 200, resp.text
    return _sse_events(resp.text)


@pytest.fixture()
def mock_llm(monkeypatch):
    """Мок LLM: всегда false_positive, формат под parse_response промпта honest."""

    async def _fake_call_llm(provider, api_key, model, system, user):
        return {"content": "Verdict: false_positive\nRationale: замокано", "tokens": 5}

    monkeypatch.setattr("swb_server.ai.analyze_loop.call_llm", _fake_call_llm)


def test_verdict_source_survives_single_carry_over(client, db_session, upload_run):
    from swb_server.models import FindingIdentity, VerdictEvent

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec = {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}

    run_a = upload_run([spec], repo=repo)
    finding_id = _first_finding_id(client, run_a["run_id"])
    client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "true_positive", "rationale": "confirmed", "version": 1},
    )

    run_b = upload_run([spec], repo=repo)  # carry

    identity = (
        db_session.query(FindingIdentity)
        .filter(FindingIdentity.project_id == run_a["project_id"], FindingIdentity.swb_id == swb_id)
        .first()
    )
    assert identity.verdict == "true_positive"
    assert identity.verdict_source == "human"

    events = (
        db_session.query(VerdictEvent)
        .filter(VerdictEvent.identity_id == identity.id)
        .order_by(VerdictEvent.at, VerdictEvent.id)
        .all()
    )
    assert [e.source for e in events] == ["human", "carried"]
    assert events[1].run_id == run_b["run_id"]


def test_verdict_source_survives_three_carry_overs(client, db_session, upload_run):
    from swb_server.models import FindingIdentity

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec = {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}

    run_a = upload_run([spec], repo=repo)
    finding_id = _first_finding_id(client, run_a["run_id"])
    client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "true_positive", "rationale": "confirmed", "version": 1},
    )

    upload_run([spec], repo=repo)  # carry 1
    run_c = upload_run([spec], repo=repo)  # carry 2

    identity = (
        db_session.query(FindingIdentity)
        .filter(FindingIdentity.project_id == run_a["project_id"], FindingIdentity.swb_id == swb_id)
        .first()
    )
    assert identity.verdict == "true_positive"
    assert identity.verdict_source == "human"

    # тот же результат виден через API находки в ране C
    finding_id_c = _first_finding_id(client, run_c["run_id"])
    resp = client.get(f"/api/v1/findings/{finding_id_c}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"]["verdict"] == "true_positive"
    assert body["verdict"]["source"] == "human"


def test_ai_analyze_does_not_override_human_verdict_after_carry_overs(client, db_session, upload_run, mock_llm):
    from swb_server.models import FindingIdentity, VerdictEvent

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec = {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}

    run_a = upload_run([spec], repo=repo)
    finding_id = _first_finding_id(client, run_a["run_id"])
    client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "true_positive", "rationale": "confirmed", "version": 1},
    )

    upload_run([spec], repo=repo)  # carry 1
    run_c = upload_run([spec], repo=repo)  # carry 2

    events = _analyze(client, run_c["run_id"])  # default: only_unmarked=false, без override

    grouped: dict[str, list[dict]] = {}
    for e in events:
        grouped.setdefault(e["type"], []).append(e)
    done = grouped["done"][0]
    assert done["skipped_human"] >= 1

    identity = (
        db_session.query(FindingIdentity)
        .filter(FindingIdentity.project_id == run_a["project_id"], FindingIdentity.swb_id == swb_id)
        .first()
    )
    assert identity.verdict == "true_positive"
    assert identity.verdict_source == "human"

    stored = (
        db_session.query(VerdictEvent)
        .filter(VerdictEvent.identity_id == identity.id)
        .order_by(VerdictEvent.at, VerdictEvent.id)
        .all()
    )
    assert [e.source for e in stored] == ["human", "carried", "carried"]
    assert not any(e.source == "ai" for e in stored)


def test_verdict_source_survives_carry_over_for_ai_source_too(client, db_session, upload_run, mock_llm):
    """Симметрия: AI-источник тоже не искажается carry-over (не защищён T-24, но снапшот честен)."""
    from swb_server.models import FindingIdentity

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    _analyze(client, run["run_id"])  # без human-вердикта -> AI размечает эту находку

    db_session.expire_all()
    from swb_server.models import Finding

    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    swb_id = finding.swb_id
    identity_id = finding.identity_id
    assert finding.identity.verdict_source == "ai"

    repo2_spec = {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}
    upload_run([repo2_spec], repo=repo)  # carry 1
    upload_run([repo2_spec], repo=repo)  # carry 2

    db_session.expire_all()  # carry-over шёл через сессию приложения, а не через db_session
    identity = db_session.query(FindingIdentity).filter(FindingIdentity.id == identity_id).first()
    assert identity.verdict == "false_positive"
    assert identity.verdict_source == "ai"
