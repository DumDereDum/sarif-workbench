"""T-21: перенос вердиктов при загрузке нового рана (ADR 0001 §6/§7).

Вердикт живёт на identity (T-14/T-15), поэтому "перенос" не копирует данные —
он лишь фиксируется событием `carried` при ingest нового рана для identity,
уже несущей вердикт. Несовпавшие (новые) находки остаются unmarked.
"""
import uuid


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _first_finding_id(client, run_id: str) -> str:
    items = client.get(f"/api/v1/runs/{run_id}/findings").json()["items"]
    assert items
    return items[0]["id"]


def test_carry_over_verdict_survives_new_run(client, db_session, upload_run):
    from swb_server.models import FindingIdentity, VerdictEvent

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec_matched = {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}
    spec_unmatched = {"rule_id": "CWE-79", "uri": "src/web.py", "start_line": 7}

    run_a = upload_run([spec_matched], repo=repo)
    finding_id = _first_finding_id(client, run_a["run_id"])
    client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "true_positive", "rationale": "confirmed"},
    )

    run_b = upload_run([spec_matched, spec_unmatched], repo=repo)

    # Совпавшая находка нового рана видит перенесённый вердикт, несовпавшая — unmarked
    items = client.get(f"/api/v1/runs/{run_b['run_id']}/findings").json()["items"]
    by_swb = {it["swb_id"]: it for it in items}
    assert by_swb[swb_id]["verdict"] == "true_positive"
    assert by_swb[swb_id]["verdict_source"] == "human"
    unmatched = [it for it in items if it["swb_id"] != swb_id]
    assert len(unmatched) == 1
    assert unmatched[0]["verdict"] == "unmarked"

    # counts_by_verdict нового рана корректны
    run_b_json = client.get(f"/api/v1/runs/{run_b['run_id']}").json()
    assert run_b_json["counts_by_verdict"] == {
        "true_positive": 1, "false_positive": 0, "uncertain": 0, "unmarked": 1,
    }

    # История: human-событие из run A + carried-событие из ingest run B
    identity = (
        db_session.query(FindingIdentity)
        .filter(FindingIdentity.project_id == run_a["project_id"], FindingIdentity.swb_id == swb_id)
        .first()
    )
    events = (
        db_session.query(VerdictEvent)
        .filter(VerdictEvent.identity_id == identity.id)
        .order_by(VerdictEvent.at, VerdictEvent.id)
        .all()
    )
    assert len(events) == 2
    assert events[0].source == "human"
    assert events[1].source == "carried"
    assert events[1].actor == "system"
    assert events[1].old_verdict == "true_positive"
    assert events[1].new_verdict == "true_positive"
    assert events[1].run_id == run_b["run_id"]
    # rationale переносится в событие, а не сбрасывается
    assert events[1].rationale == "confirmed"

    # Снапшот identity: rationale не затёрт переносом
    assert identity.rationale == "confirmed"
    assert identity.verdict == "true_positive"
    assert identity.verdict_source == "human"


def test_unmarked_identity_reappearing_gets_no_carried_event(client, db_session, upload_run):
    """Несовпавшие/непомеченные identity не порождают событие carried (ADR §6)."""
    from swb_server.models import FindingIdentity, VerdictEvent

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec = {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}

    run_a = upload_run([spec], repo=repo)
    run_b = upload_run([spec], repo=repo)  # тот же swb_id, вердикт так и не поставлен

    identity = (
        db_session.query(FindingIdentity)
        .filter(FindingIdentity.project_id == run_a["project_id"], FindingIdentity.swb_id == swb_id)
        .first()
    )
    assert identity.verdict == "unmarked"
    assert identity.last_seen_run_id == run_b["run_id"]

    events = db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == identity.id).all()
    assert events == []


def test_carry_over_across_three_runs_appends_one_event_each(client, db_session, upload_run):
    """Каждый новый ран с совпавшей identity дописывает ровно одно carried-событие."""
    from swb_server.models import FindingIdentity, VerdictEvent

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec = {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}

    run_a = upload_run([spec], repo=repo)
    finding_id = _first_finding_id(client, run_a["run_id"])
    client.patch(f"/api/v1/findings/{finding_id}/verdict", json={"verdict": "false_positive"})

    run_b = upload_run([spec], repo=repo)
    run_c = upload_run([spec], repo=repo)

    identity = (
        db_session.query(FindingIdentity)
        .filter(FindingIdentity.project_id == run_a["project_id"], FindingIdentity.swb_id == swb_id)
        .first()
    )
    events = (
        db_session.query(VerdictEvent)
        .filter(VerdictEvent.identity_id == identity.id)
        .order_by(VerdictEvent.at, VerdictEvent.id)
        .all()
    )
    assert [e.source for e in events] == ["human", "carried", "carried"]
    assert events[1].run_id == run_b["run_id"]
    assert events[2].run_id == run_c["run_id"]
    assert identity.verdict == "false_positive"
