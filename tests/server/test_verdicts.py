"""T-14: вердикт как отдельная сущность (finding_identities) + append-only события (verdict_events)."""
import uuid

import pytest
from sqlalchemy.exc import IntegrityError


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _make_project(db_session, repo: str):
    from swb_server.models import Project

    project = Project(id=repo, repo=repo, name=repo)
    db_session.add(project)
    db_session.flush()
    return project


def _make_identity(db_session, project_id: str, swb_id: str | None = None, **kw):
    from swb_server.models import FindingIdentity

    identity = FindingIdentity(
        project_id=project_id,
        swb_id=swb_id or f"sw2:t:{uuid.uuid4().hex[:24]}:0",
        algo="swb-fp/2",
        level="tool",
        **kw,
    )
    db_session.add(identity)
    db_session.flush()
    return identity


# ── writer-одиночка ───────────────────────────────────────────────────────────


def test_write_verdict_updates_snapshot_and_appends_event(db_session):
    from swb_server.models import VerdictEvent
    from swb_server.verdicts import write_verdict

    repo = _unique_repo()
    _make_project(db_session, repo)
    identity = _make_identity(db_session, repo)
    assert identity.verdict == "unmarked"  # default по ADR §6

    event = write_verdict(
        db_session,
        identity,
        new_verdict="true_positive",
        source="human",
        actor="human",
        rationale="реальная инъекция",
    )
    db_session.commit()

    # снапшот на identity обновлён
    assert identity.verdict == "true_positive"
    assert identity.verdict_source == "human"
    assert identity.rationale == "реальная инъекция"

    # событие записано с корректными old/new/source/actor
    stored = db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == identity.id).all()
    assert len(stored) == 1
    ev = stored[0]
    assert ev.id == event.id
    assert ev.id.startswith("ve-")
    assert ev.old_verdict == "unmarked"
    assert ev.new_verdict == "true_positive"
    assert ev.source == "human"
    assert ev.actor == "human"
    assert ev.rationale == "реальная инъекция"
    assert ev.at is not None


def test_second_verdict_appends_second_event_with_previous_old(db_session):
    from swb_server.models import VerdictEvent
    from swb_server.verdicts import write_verdict

    repo = _unique_repo()
    _make_project(db_session, repo)
    identity = _make_identity(db_session, repo)

    write_verdict(db_session, identity, new_verdict="true_positive", source="human", actor="human")
    write_verdict(
        db_session,
        identity,
        new_verdict="false_positive",
        source="ai",
        actor="ai:deepseek/deepseek-chat",
        rationale="looks sanitized",
        provider="deepseek",
        model="deepseek-chat",
    )
    db_session.commit()

    events = (
        db_session.query(VerdictEvent)
        .filter(VerdictEvent.identity_id == identity.id)
        .order_by(VerdictEvent.at, VerdictEvent.id)
        .all()
    )
    assert len(events) == 2
    assert events[0].old_verdict == "unmarked"
    assert events[0].new_verdict == "true_positive"
    # old_verdict второго события = прежний вердикт
    assert events[1].old_verdict == "true_positive"
    assert events[1].new_verdict == "false_positive"
    assert events[1].source == "ai"
    assert events[1].actor == "ai:deepseek/deepseek-chat"
    assert events[1].provider == "deepseek"
    assert events[1].model == "deepseek-chat"
    # prompt_id/prompt_version заполняет T-25 — пока NULL
    assert events[1].prompt_id is None
    assert events[1].prompt_version is None

    # снапшот отражает последнее событие, AI-атрибуты на identity заполнены
    assert identity.verdict == "false_positive"
    assert identity.verdict_source == "ai"
    assert identity.provider == "deepseek"
    assert identity.model == "deepseek-chat"


def test_write_verdict_rejects_unknown_source(db_session):
    from swb_server.verdicts import write_verdict

    repo = _unique_repo()
    _make_project(db_session, repo)
    identity = _make_identity(db_session, repo)
    with pytest.raises(ValueError):
        write_verdict(db_session, identity, new_verdict="true_positive", source="bogus", actor="x")


# ── модель: identity ──────────────────────────────────────────────────────────


def test_unique_project_swb_id_constraint(db_session):
    repo = _unique_repo()
    _make_project(db_session, repo)
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    _make_identity(db_session, repo, swb_id=swb_id)
    with pytest.raises(IntegrityError):
        _make_identity(db_session, repo, swb_id=swb_id)
    db_session.rollback()


def test_findings_with_same_swb_id_share_identity(client, db_session, upload_run):
    from swb_server.models import Finding, FindingIdentity

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec = {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}

    run1 = upload_run([spec], repo=repo)
    run2 = upload_run([spec], repo=repo)  # другой SARIF (nonce), тот же swb_id
    assert run1["run_id"] != run2["run_id"]

    identities = (
        db_session.query(FindingIdentity)
        .filter(FindingIdentity.project_id == run1["project_id"], FindingIdentity.swb_id == swb_id)
        .all()
    )
    assert len(identities) == 1  # два finding'а делят одну identity

    findings = db_session.query(Finding).filter(Finding.identity_id == identities[0].id).all()
    assert len(findings) == 2
    assert {f.run_id for f in findings} == {run1["run_id"], run2["run_id"]}

    # last_seen обновился на второй ран, first_seen остался на первом
    assert identities[0].first_seen_run_id == run1["run_id"]
    assert identities[0].last_seen_run_id == run2["run_id"]


def test_upload_creates_identities(client, db_session, upload_run):
    from swb_server.models import FindingIdentity

    repo = _unique_repo()
    resp = upload_run(
        [
            {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42},
            {"rule_id": "CWE-79", "uri": "src/web.py", "start_line": 7, "fp_level": "content",
             "swb_id": f"sw2:c:{uuid.uuid4().hex[:24]}:0"},
        ],
        repo=repo,
    )
    assert resp["deduplicated"] is False
    assert resp["finding_count"] == 2

    identities = db_session.query(FindingIdentity).filter(FindingIdentity.project_id == resp["project_id"]).all()
    assert len(identities) == 2
    by_level = {i.level: i for i in identities}
    assert set(by_level) == {"tool", "content"}  # level из префикса swb_id
    for identity in identities:
        assert identity.id.startswith("fi-")
        assert identity.algo == "swb-fp/2"
        assert identity.verdict == "unmarked"
        assert identity.first_seen_run_id == resp["run_id"]
        assert identity.last_seen_run_id == resp["run_id"]
        assert identity.first_seen_at is not None
        assert identity.last_seen_at is not None


# ── API-пути ──────────────────────────────────────────────────────────────────


def _first_finding_id(client, run_id: str) -> str:
    items = client.get(f"/api/v1/runs/{run_id}/findings").json()["items"]
    assert items
    return items[0]["id"]


def test_patch_verdict_writes_identity_and_event(client, db_session, upload_run):
    from swb_server.models import Finding, FindingIdentity, VerdictEvent

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    resp = client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "false_positive", "rationale": "sanitized upstream"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "false_positive"
    assert body["source"] == "human"
    assert body["rationale"] == "sanitized upstream"
    assert len(body["history"]) == 1
    assert body["history"][0]["verdict"] == "false_positive"
    assert body["history"][0]["old_verdict"] == "unmarked"
    assert body["history"][0]["source"] == "human"

    # вердикт лежит в таблице finding_identities, не на finding
    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    assert not hasattr(finding, "verdict")
    identity = db_session.query(FindingIdentity).filter(FindingIdentity.id == finding.identity_id).first()
    assert identity.verdict == "false_positive"
    assert identity.verdict_source == "human"

    events = db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == identity.id).all()
    assert len(events) == 1
    assert events[0].actor == "human"

    # counts_by_verdict рана пересчитан через identity
    run_json = client.get(f"/api/v1/runs/{run['run_id']}").json()
    assert run_json["counts_by_verdict"] == {
        "true_positive": 0, "false_positive": 1, "uncertain": 0, "unmarked": 0,
    }


def test_get_finding_serves_verdict_from_identity(client, upload_run):
    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    client.patch(f"/api/v1/findings/{finding_id}/verdict", json={"verdict": "true_positive", "rationale": "r1"})
    client.patch(f"/api/v1/findings/{finding_id}/verdict", json={"verdict": "uncertain", "rationale": "r2"})

    detail = client.get(f"/api/v1/findings/{finding_id}").json()
    vd = detail["verdict"]
    assert vd["verdict"] == "uncertain"
    assert vd["source"] == "human"
    assert vd["rationale"] == "r2"
    # история — события в хронологическом порядке
    assert [h["verdict"] for h in vd["history"]] == ["true_positive", "uncertain"]
    assert [h["old_verdict"] for h in vd["history"]] == ["unmarked", "true_positive"]
    # confidence умер вместе с колонкой (ADR §6)
    assert "confidence" not in vd

    # список находок тоже читает вердикт через identity
    items = client.get(f"/api/v1/runs/{run['run_id']}/findings").json()["items"]
    assert items[0]["verdict"] == "uncertain"
    assert items[0]["verdict_source"] == "human"
    assert "confidence" not in items[0]


def test_reset_unmarks_identities_but_keeps_events(client, db_session, upload_run):
    from swb_server.models import Finding, VerdictEvent

    repo = _unique_repo()
    run = upload_run(
        [
            {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42},
            {"rule_id": "CWE-79", "uri": "src/web.py", "start_line": 7},
        ],
        repo=repo,
    )
    finding_id = _first_finding_id(client, run["run_id"])
    client.patch(f"/api/v1/findings/{finding_id}/verdict", json={"verdict": "true_positive"})

    resp = client.post(f"/api/v1/runs/{run['run_id']}/reset")
    assert resp.status_code == 200
    assert resp.json() == {"reset": 1}

    # снапшоты identity сброшены в unmarked
    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    identity = finding.identity
    assert identity.verdict == "unmarked"
    assert identity.verdict_source == "reset"

    # события живы (append-only): human-событие + reset-событие
    events = (
        db_session.query(VerdictEvent)
        .filter(VerdictEvent.identity_id == identity.id)
        .order_by(VerdictEvent.at, VerdictEvent.id)
        .all()
    )
    assert len(events) == 2
    assert events[0].source == "human"
    assert events[1].source == "reset"
    assert events[1].actor == "system"
    assert events[1].old_verdict == "true_positive"
    assert events[1].new_verdict == "unmarked"
    assert events[1].run_id == run["run_id"]

    # у неразмеченной identity reset события не порождает (ADR §6)
    other = [f for f in db_session.query(Finding).filter(Finding.run_id == run["run_id"]).all() if f.id != finding_id]
    assert other
    other_events = db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == other[0].identity_id).count()
    assert other_events == 0

    run_json = client.get(f"/api/v1/runs/{run['run_id']}").json()
    assert run_json["counts_by_verdict"]["unmarked"] == 2
