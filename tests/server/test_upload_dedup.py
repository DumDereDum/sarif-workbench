"""T-33: дедуп по проекту + идемпотентность загрузки (ADR 0001 §7).

- тот же sarif_sha256 в том же проекте — дубль, ответ идемпотентный;
- тот же sarif, но обновлённая meta (re-enrich) — findings рана
  пересоздаются, вердикт (живёт на identity) не теряется;
- тот же sarif в другом проекте — обычная новая загрузка, не дедуп;
- гонка двух одинаковых загрузок — IntegrityError на UniqueConstraint(project_id,
  sarif_sha256) ловится, ответ идемпотентный, не 500.
"""
import hashlib
import uuid

from tests.server.conftest import make_meta, make_sarif


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _first_finding_id(client, run_id: str) -> str:
    items = client.get(f"/api/v1/runs/{run_id}/findings").json()["items"]
    assert items
    return items[0]["id"]


def _post(client, sarif_bytes: bytes, meta_bytes: bytes):
    return client.post(
        "/api/v1/runs",
        files={
            "sarif": ("report.sarif", sarif_bytes, "application/json"),
            "meta": ("report.swbmeta.json", meta_bytes, "application/json"),
        },
    )


# ── дубль в одном проекте — чистый дедуп, без записи ───────────────────────


def test_reupload_same_sarif_same_meta_is_pure_dedup(client, db_session, upload_run):
    from swb_server.models import Finding, Run

    repo = _unique_repo()
    spec = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}]
    sarif_bytes = make_sarif(spec)

    run1 = upload_run(spec, repo=repo, sarif_bytes=sarif_bytes)
    assert run1["deduplicated"] is False

    runs_before = db_session.query(Run).filter(Run.project_id == run1["project_id"]).count()
    findings_before = db_session.query(Finding).filter(Finding.run_id == run1["run_id"]).count()

    # та же пара sarif+meta байт-в-байт (make_meta детерминирована по входу)
    run2 = upload_run(spec, repo=repo, sarif_bytes=sarif_bytes)

    assert run2["run_id"] == run1["run_id"]
    assert run2["project_id"] == run1["project_id"]
    assert run2["deduplicated"] is True
    assert run2.get("meta_updated") is False

    # БД не растёт: ни новый Run, ни новые Finding не появились
    runs_after = db_session.query(Run).filter(Run.project_id == run1["project_id"]).count()
    findings_after = db_session.query(Finding).filter(Finding.run_id == run1["run_id"]).count()
    assert runs_after == runs_before
    assert findings_after == findings_before


# ── тот же sarif, обновлённая meta — findings пересозданы, вердикт жив ─────


def test_reupload_same_sarif_different_meta_updates_meta_and_findings(client, db_session, upload_run):
    from swb_server.models import Run

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec1 = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}]
    sarif_bytes = make_sarif(spec1)

    run1 = upload_run(spec1, repo=repo, sarif_bytes=sarif_bytes)
    assert run1["deduplicated"] is False

    finding_id = _first_finding_id(client, run1["run_id"])
    patch_resp = client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "true_positive", "rationale": "confirmed", "version": 1},
    )
    assert patch_resp.status_code == 200

    # тот же sarif (байты идентичны), но meta отличается побайтово — как
    # после повторного `swb-cli enrich` с новым fingerprint level; swb_id
    # зафиксирован явно, чтобы identity (и вердикт на ней) не сменилась.
    spec2 = [
        {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id, "fp_level": "content"},
    ]
    meta1 = make_meta(sarif_bytes, spec1, repo=repo)
    meta2 = make_meta(sarif_bytes, spec2, repo=repo)
    assert meta1 != meta2  # контроль: фикстуры действительно дают разные байты

    run2 = upload_run(spec2, repo=repo, sarif_bytes=sarif_bytes)

    assert run2["run_id"] == run1["run_id"]
    assert run2["project_id"] == run1["project_id"]
    assert run2["deduplicated"] is True
    assert run2["meta_updated"] is True

    # ран не задвоился
    runs = db_session.query(Run).filter(Run.project_id == run1["project_id"]).all()
    assert len(runs) == 1
    stored_run = runs[0]

    # исходный SARIF не тронут (инвариант продукта), а meta-блоб реально заменён
    from swb_server.storage import load_blob

    stored_sarif = client.get(f"/api/v1/runs/{run1['run_id']}/sarif")
    assert stored_sarif.content == sarif_bytes
    assert load_blob(stored_run.meta_key) == meta2

    # вердикт не потерян — виден на том же ране после пересоздания находок
    items = client.get(f"/api/v1/runs/{run1['run_id']}/findings").json()["items"]
    assert len(items) == 1
    assert items[0]["swb_id"] == swb_id
    assert items[0]["verdict"] == "true_positive"
    assert items[0]["verdict_source"] == "human"


def test_meta_updated_does_not_write_spurious_carried_event(client, db_session, upload_run):
    """Регрессия: meta_updated переобрабатывает ТОТ ЖЕ run_id, а не новый скан.

    `_create_rules_and_findings` (общий хелпер обычной загрузки и meta_updated)
    пишет событие `carried`, когда find-or-create identity встречает уже
    известную identity с вердиктом — это корректно, когда встречает её НОВЫЙ
    ран (T-21, ADR 0001 §6/§7: "вердикт применён к новому скану"). Но при
    reapply meta для уже существующего рана identity лишь переобрабатывается
    в рамках того же самого run_id — это не новое наблюдение, и `carried` не
    должен появляться (append-only история не должна засоряться ложными
    "перенесено при новом скане" записями). Проверяем количество
    verdict_events на identity до/после одного и после повторного
    meta_updated — оно не должно расти сверх исходного human-события.
    """
    from swb_server.models import FindingIdentity, VerdictEvent

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec1 = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}]
    sarif_bytes = make_sarif(spec1)

    run1 = upload_run(spec1, repo=repo, sarif_bytes=sarif_bytes)
    finding_id = _first_finding_id(client, run1["run_id"])
    patch_resp = client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "true_positive", "rationale": "confirmed", "version": 1},
    )
    assert patch_resp.status_code == 200

    identity = (
        db_session.query(FindingIdentity)
        .filter(FindingIdentity.project_id == run1["project_id"], FindingIdentity.swb_id == swb_id)
        .one()
    )

    def _events():
        return (
            db_session.query(VerdictEvent)
            .filter(VerdictEvent.identity_id == identity.id)
            .all()
        )

    events_after_patch = _events()
    assert len(events_after_patch) == 1
    assert events_after_patch[0].source == "human"

    # первый meta_updated тем же раном — не должен дописать carried
    spec2 = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id, "fp_level": "content"}]
    run2 = upload_run(spec2, repo=repo, sarif_bytes=sarif_bytes)
    assert run2["run_id"] == run1["run_id"]
    assert run2["meta_updated"] is True

    events_after_first_meta_update = _events()
    assert len(events_after_first_meta_update) == 1  # то же единственное human-событие
    assert [e.id for e in events_after_first_meta_update] == [e.id for e in events_after_patch]

    # повторный meta_updated тем же раном — тоже не плодит события
    spec3 = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id, "fp_level": "legacy"}]
    run3 = upload_run(spec3, repo=repo, sarif_bytes=sarif_bytes)
    assert run3["run_id"] == run1["run_id"]
    assert run3["meta_updated"] is True

    events_after_second_meta_update = _events()
    assert len(events_after_second_meta_update) == 1

    # вердикт по-прежнему на identity — не потерян и не перезаписан carry-over
    db_session.expire(identity)
    assert identity.verdict == "true_positive"
    assert identity.verdict_source == "human"


# ── тот же sarif в другом проекте — обычная новая загрузка ─────────────────


def test_same_sarif_different_project_is_new_upload_not_dedup(upload_run):
    spec = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}]
    sarif_bytes = make_sarif(spec)

    repo_a = _unique_repo()
    repo_b = _unique_repo()

    run_a = upload_run(spec, repo=repo_a, sarif_bytes=sarif_bytes)
    run_b = upload_run(spec, repo=repo_b, sarif_bytes=sarif_bytes)

    assert run_a["deduplicated"] is False
    assert run_b["deduplicated"] is False
    assert run_a["run_id"] != run_b["run_id"]
    assert run_a["project_id"] != run_b["project_id"]


# ── гонка двух одинаковых загрузок — IntegrityError пойман, не 500 ─────────


def test_race_duplicate_upload_integrity_error_is_caught_not_500(client, db_session, monkeypatch):
    """Симулирует гонку двух конкурентных upload_run одного и того же файла.

    Настоящую гонку двух HTTP-запросов через `TestClient` воспроизвести
    недетерминированно: starlette прогоняет оба запроса на ОДНОМ event loop
    через blocking portal (кооперативная многозадачность), а между дедуп-select
    и commit'ом в `upload_run` нет ни одной точки `await` — эмпирически ни один
    из пяти прогонов `ThreadPoolExecutor(2) x client.post` не дал коллизии,
    оба запроса каждый раз аккуратно сериализовались.

    Здесь гонка эмулируется явно и детерминированно: у "проигравшего" запроса
    собственная дедуп-проверка форсированно возвращает `None` ровно один раз —
    как если бы конкурент ("победитель") ещё не закоммитил свой Run в момент
    её выполнения. Последующий INSERT ниже реально наталкивается на настоящий
    `UniqueConstraint(project_id, sarif_sha256)` в БД (ран победителя уже там) —
    возникает настоящий `IntegrityError`, а не сымитированный, и код обязан
    его поймать и вернуть идемпотентный ответ, а не дать ему всплыть 500-кой.
    """
    from sqlalchemy.orm import Query

    from swb_server.models import Run

    repo = _unique_repo()
    spec = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}]
    sarif_bytes = make_sarif(spec)
    meta_bytes = make_meta(sarif_bytes, spec, repo=repo)

    winner = _post(client, sarif_bytes, meta_bytes)
    assert winner.status_code == 201, winner.text
    winner_body = winner.json()
    assert winner_body["deduplicated"] is False

    real_first = Query.first
    state = {"skipped": False}

    def patched_first(self):
        if (
            not state["skipped"]
            and self.column_descriptions
            and self.column_descriptions[0]["type"] is Run
        ):
            state["skipped"] = True
            return None
        return real_first(self)

    monkeypatch.setattr(Query, "first", patched_first)

    loser = _post(client, sarif_bytes, meta_bytes)
    assert state["skipped"] is True  # контроль: патч действительно сработал
    assert loser.status_code in (200, 201), loser.text
    loser_body = loser.json()
    assert loser_body["deduplicated"] is True
    assert loser_body["run_id"] == winner_body["run_id"]

    sha = hashlib.sha256(sarif_bytes).hexdigest()
    runs = (
        db_session.query(Run)
        .filter(Run.project_id == winner_body["project_id"], Run.sarif_sha256 == sha)
        .all()
    )
    assert len(runs) == 1
