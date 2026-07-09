"""T-32: единственная реализация `counts_by_verdict`, без гонок.

Четыре сценария:
  - ~20 конкурентных PATCH на разные находки одного рана → итоговый
    `counts_by_verdict` сходится с фактическим распределением вердиктов (не
    теряет инкременты под параллельной записью);
  - reset и analyze используют один и тот же пересчёт → согласованные counts,
    сверенные с независимо посчитанной «истиной» по прямому запросу к БД;
  - regression на TOCTOU-фикс в analyze.py: конкурентный human PATCH,
    случившийся, пока находка ждёт ответ LLM, не перезаписывается AI, когда
    цикл анализа доходит до записи (re-check `verdict_source` перед записью,
    а не только на входе в батч);
  - regression на «голый» recompute (ревью раунд 2, roadmap T-32): вызов
    `recompute_counts_by_verdict` без предшествующей записи в СВОЕЙ транзакции
    (как было в финале analyze.py и в пустой ветке reset_verdicts) не должен
    откатывать конкурентно закоммиченный результат устаревшим снимком —
    воспроизведено детерминированно через управляемое взаимодействие двух
    сессий, а не в расчёте на удачное совпадение по времени.
"""
from __future__ import annotations

import concurrent.futures
import json
import threading
import time
import uuid

import pytest


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _findings(client, run_id: str) -> list[dict]:
    return client.get(f"/api/v1/runs/{run_id}/findings").json()["items"]


def _sse_events(text: str) -> list[dict]:
    return [json.loads(line[len("data: "):]) for line in text.splitlines() if line.startswith("data: ")]


def _by_type(events: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for e in events:
        grouped.setdefault(e["type"], []).append(e)
    return grouped


# ── ~20 конкурентных PATCH на разные находки одного рана ──────────────────────


def test_concurrent_patches_converge_to_actual_verdict_distribution(client, upload_run):
    n = 20
    repo = _unique_repo()
    findings_spec = [
        {"rule_id": "CWE-89", "uri": f"src/f{i}.py", "start_line": i + 1}
        for i in range(n)
    ]
    run = upload_run(findings_spec, repo=repo)
    items = _findings(client, run["run_id"])
    assert len(items) == n

    verdict_cycle = ["true_positive", "false_positive", "uncertain"]
    assigned = {item["id"]: verdict_cycle[i % len(verdict_cycle)] for i, item in enumerate(items)}

    def _patch(finding_id: str, verdict: str):
        resp = client.patch(
            f"/api/v1/findings/{finding_id}/verdict",
            json={"verdict": verdict, "rationale": f"concurrent-{verdict}"},
        )
        assert resp.status_code == 200, resp.text
        return resp

    # 20 отдельных находок одного рана, размечаемых ПАРАЛЛЕЛЬНО из разных
    # потоков — каждый PATCH бьёт по своей identity, но все они пересчитывают
    # и пишут один и тот же run.counts_by_verdict. Именно здесь терялись
    # инкременты в старой реализации read-modify-write.
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_patch, fid, verdict) for fid, verdict in assigned.items()]
        for fut in concurrent.futures.as_completed(futures):
            fut.result()  # re-raise: ни один запрос не должен упасть (500 / database is locked)

    expected = {"true_positive": 0, "false_positive": 0, "uncertain": 0, "unmarked": 0}
    for verdict in assigned.values():
        expected[verdict] += 1

    run_json = client.get(f"/api/v1/runs/{run['run_id']}").json()
    assert run_json["counts_by_verdict"] == expected


# ── reset и analyze дают согласованные counts ──────────────────────────────────


@pytest.fixture()
def mock_llm_cycle(monkeypatch):
    """Мок LLM: вердикт циклически меняется по вызовам — даёт неоднородное распределение."""
    verdicts = ["true_positive", "false_positive", "uncertain"]
    state = {"n": 0}

    async def _fake_call_llm(provider, api_key, model, system, user):
        v = verdicts[state["n"] % len(verdicts)]
        state["n"] += 1
        return {"content": f"Verdict: {v}\nRationale: mock-{v}", "tokens": 1}

    monkeypatch.setattr("swb_server.routers.analyze.call_llm", _fake_call_llm)


def _actual_counts_from_db(db_session, run_id: str) -> dict[str, int]:
    """«Истина», посчитанная независимо от recompute_counts_by_verdict — прямым запросом."""
    from swb_server.models import Finding

    db_session.expire_all()
    findings = db_session.query(Finding).filter(Finding.run_id == run_id).all()
    counts = {"true_positive": 0, "false_positive": 0, "uncertain": 0, "unmarked": 0}
    for f in findings:
        v = (f.identity.verdict if f.identity else None) or "unmarked"
        counts[v] += 1
    return counts


def test_reset_and_analyze_counts_match_independently_computed_truth(
    client, db_session, upload_run, mock_llm_cycle,
):
    repo = _unique_repo()
    findings_spec = [
        {"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1},
        {"rule_id": "CWE-79", "uri": "src/b.py", "start_line": 2},
        {"rule_id": "CWE-22", "uri": "src/c.py", "start_line": 3},
        {"rule_id": "CWE-79", "uri": "src/d.py", "start_line": 4},
    ]
    run = upload_run(findings_spec, repo=repo)
    items = _findings(client, run["run_id"])
    assert len(items) == 4

    client.patch(f"/api/v1/findings/{items[0]['id']}/verdict", json={"verdict": "true_positive"})
    client.patch(f"/api/v1/findings/{items[1]['id']}/verdict", json={"verdict": "false_positive"})

    resp = client.post(f"/api/v1/runs/{run['run_id']}/reset")
    assert resp.status_code == 200

    # reset: counts_by_verdict должен совпасть с независимо посчитанной истиной
    # (все identity этого рана — unmarked)
    run_after_reset = client.get(f"/api/v1/runs/{run['run_id']}").json()
    assert run_after_reset["counts_by_verdict"] == _actual_counts_from_db(db_session, run["run_id"])
    assert run_after_reset["counts_by_verdict"] == {
        "true_positive": 0, "false_positive": 0, "uncertain": 0, "unmarked": 4,
    }

    # analyze по всем находкам (мок даёт неоднородный микс вердиктов)
    resp = client.post(
        f"/api/v1/runs/{run['run_id']}/analyze",
        json={"api_key": "test-key-not-used", "only_unmarked": False},
    )
    assert resp.status_code == 200, resp.text

    run_after_analyze = client.get(f"/api/v1/runs/{run['run_id']}").json()
    assert run_after_analyze["counts_by_verdict"] == _actual_counts_from_db(db_session, run["run_id"])
    # неоднородный микс — не все находки в одном вердикте (мок циклит 3 значения)
    assert sum(run_after_analyze["counts_by_verdict"].values()) == 4
    assert run_after_analyze["counts_by_verdict"]["unmarked"] == 0


# ── TOCTOU regression: human PATCH в разгаре batch-анализа не теряется ────────


def test_analyze_toctou_recheck_protects_finding_patched_mid_batch(client, db_session, upload_run, monkeypatch):
    """Регрессия на остаточный риск T-24 (reviewer, 2026-07-04).

    До фикса verdict_source проверялся один раз оптом на входе в батч —
    human PATCH, случившийся ПОКА конкретная находка ждёт ответ LLM, молча
    перезаписывался AI, когда цикл до неё доходил (TOCTOU). Мок LLM для
    конкретной находки (по её uri в user-сообщении) сначала сам делает
    "конкурентный" human PATCH через отдельную DB-сессию — как если бы
    реальный пользователь успел кликнуть вердикт, пока находка висит на
    сетевом вызове к LLM — и только потом возвращает ответ.
    """
    from swb_server.models import Finding
    from swb_server.verdicts import write_verdict

    repo = _unique_repo()
    run = upload_run(
        [
            {"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1},
            {"rule_id": "CWE-79", "uri": "src/race-target.py", "start_line": 2},
            {"rule_id": "CWE-22", "uri": "src/c.py", "start_line": 3},
        ],
        repo=repo,
    )
    items = _findings(client, run["run_id"])
    assert len(items) == 3
    target = next(i for i in items if i["uri"] == "src/race-target.py")

    async def _fake_call_llm(provider, api_key, model, system, user):
        if "src/race-target.py" in user:
            # "Конкурентный" human PATCH, случившийся, пока эта находка висит
            # на сетевом вызове к LLM — отдельная сессия, как у реального
            # PATCH-запроса на другом потоке/соединении.
            f = db_session.query(Finding).filter(Finding.id == target["id"]).first()
            write_verdict(
                db_session,
                f.identity,
                new_verdict="true_positive",
                source="human",
                actor="human",
                rationale="race: человек успел раньше",
            )
            db_session.commit()
        return {"content": "Verdict: false_positive\nRationale: ai-would-override", "tokens": 3}

    monkeypatch.setattr("swb_server.routers.analyze.call_llm", _fake_call_llm)

    resp = client.post(
        f"/api/v1/runs/{run['run_id']}/analyze",
        json={"api_key": "test-key-not-used", "only_unmarked": False},
    )
    assert resp.status_code == 200, resp.text
    events = _sse_events(resp.text)

    grouped = _by_type(events)
    done = grouped["done"][0]
    # race-target пойман re-check'ом и учтён как skipped_human, а не как AI-запись
    assert done["skipped_human"] == 1

    race_progress = [e for e in grouped["progress"] if e.get("finding_id") == target["id"]]
    assert len(race_progress) == 1
    assert race_progress[0].get("skipped_human") is True

    # снапшот identity — по-прежнему человеческий вердикт, AI его не перезаписал
    db_session.expire_all()
    finding = db_session.query(Finding).filter(Finding.id == target["id"]).first()
    identity = finding.identity
    assert identity.verdict == "true_positive"
    assert identity.verdict_source == "human"

    # никакого AI-события для этой identity не появилось — только human
    from swb_server.models import VerdictEvent

    stored = (
        db_session.query(VerdictEvent)
        .filter(VerdictEvent.identity_id == identity.id)
        .order_by(VerdictEvent.at, VerdictEvent.id)
        .all()
    )
    assert [e.source for e in stored] == ["human"]

    # остальные две находки размечены AI как обычно
    others = [i for i in items if i["id"] != target["id"]]
    for other in others:
        f = db_session.query(Finding).filter(Finding.id == other["id"]).first()
        assert f.identity.verdict == "false_positive"
        assert f.identity.verdict_source == "ai"


# ── regression: «голый» recompute без предшествующей записи в своей транзакции ─


def test_bare_recompute_without_prior_write_does_not_lose_concurrent_commit(client, upload_run):
    """Ревью раунд 2 (roadmap T-32): recompute_counts_by_verdict обязан сам взять
    write-лок ДО агрегатного SELECT, а не полагаться на то, что перед ним уже
    была запись в этой же транзакции.

    До фикса: analyze.py вызывал recompute как ПЕРВУЮ операцию в свежей
    транзакции (после того, как все write_verdict внутри батча уже
    закоммичены по одному) — bare SELECT читает и держит результат в памяти,
    но реально пишет его только отложенным commit(). В эту паузу конкурентный
    писатель мог полностью выполнить write_verdict+recompute+commit, а более
    поздний commit «голого» recompute откатывал его результат устаревшим
    снимком. То же самое — в reset_verdicts, если сбрасывать нечего (ни одна
    identity не изменилась) — цикл ни разу не заходит в write_verdict, и
    recompute становится первой (незащищённой) операцией транзакции.

    Тест не полагается на угаданное окно гонки: два потока управляются
    Event'ами так, что B (конкурентный PATCH) гарантированно исполняется
    между чтением и отложенным commit'ом A — воспроизводит баг детерминированно
    на некорректном коде и не флейкует на исправленном (см. verdicts.py —
    сама recompute_counts_by_verdict теперь форсирует RESERVED-лок ДО SELECT,
    поэтому под фиксом B либо уже успел закоммититься до чтения A, либо
    блокируется на локе A и корректно применяется после его commit — в обоих
    случаях итоговое состояние верное, а не только "не зависает").

    Важная деталь сетапа: если бы `run.counts_by_verdict`, уже лежащий в БД
    ДО recompute A, совпадал с тем, что A вычислит, ORM сочла бы присваивание
    "not dirty" и не эмитила бы UPDATE вообще — тогда тест "проходил" бы и на
    сломанном, и на починенном коде, ничего не проверяя (именно так выглядела
    первая версия этого теста — свежезалитый ран, где A всё равно читает то
    же all-unmarked, что уже лежит в run). Поэтому ПЕРЕД гонкой одна находка
    размечается через `write_verdict` НАПРЯМУЮ, БЕЗ recompute — это ровно та
    ситуация, которую создаёт реальный код внутри цикла analyze.py (запись
    коммитится, а пересчёт счётчика намеренно отложен до конца батча):
    `run.counts_by_verdict` в БД остаётся старым (all-unmarked), хотя
    identity уже другая — и снимок, который вычислит A, будет ОТЛИЧАТЬСЯ от
    persisted-значения, то есть реально дойдёт до UPDATE при commit'е.
    """
    from swb_server.db import SessionLocal
    from swb_server.models import Finding
    from swb_server.verdicts import recompute_counts_by_verdict, write_verdict

    repo = _unique_repo()
    run = upload_run(
        [
            {"rule_id": "CWE-89", "uri": "src/already-committed.py", "start_line": 1},
            {"rule_id": "CWE-79", "uri": "src/race-target.py", "start_line": 2},
        ],
        repo=repo,
    )
    items = _findings(client, run["run_id"])
    already_committed_id = next(i["id"] for i in items if i["uri"] == "src/already-committed.py")
    race_target_id = next(i["id"] for i in items if i["uri"] == "src/race-target.py")

    # Мид-батч analyze.py: write_verdict уже закоммичен для одной находки БЕЗ
    # промежуточного recompute — run.counts_by_verdict в БД ещё старый
    # (all-unmarked), хотя identity уже false_positive.
    setup_session = SessionLocal()
    try:
        f = setup_session.query(Finding).filter(Finding.id == already_committed_id).first()
        write_verdict(setup_session, f.identity, new_verdict="false_positive", source="ai", actor="ai:test")
        setup_session.commit()
    finally:
        setup_session.close()

    a_did_select = threading.Event()
    let_a_commit = threading.Event()
    a_errors: list[Exception] = []

    def _bare_recompute_then_delayed_commit() -> None:
        # Симулирует "голый" финальный recompute в analyze.py / recompute в
        # пустой ветке reset_verdicts: НИКАКОЙ записи в этой сессии до вызова
        # recompute_counts_by_verdict не было.
        session_a = SessionLocal()
        try:
            recompute_counts_by_verdict(session_a, run["run_id"])
            a_did_select.set()
            # Держим транзакцию открытой, не коммитя — как реальный код держит
            # её открытой между SELECT'ом и отложенным commit() в конце.
            if not let_a_commit.wait(timeout=10):
                raise TimeoutError("let_a_commit не выставлен вовремя")
            session_a.commit()
        except Exception as exc:  # noqa: BLE001 — сурфейсим в основном потоке
            a_errors.append(exc)
        finally:
            session_a.close()

    t_a = threading.Thread(target=_bare_recompute_then_delayed_commit)
    t_a.start()
    assert a_did_select.wait(timeout=5), "поток A не дошёл до recompute вовремя"

    b_errors: list[Exception] = []

    def _concurrent_patch() -> None:
        try:
            resp = client.patch(
                f"/api/v1/findings/{race_target_id}/verdict",
                json={"verdict": "true_positive", "rationale": "concurrent commit landing in the gap"},
            )
            assert resp.status_code == 200, resp.text
        except Exception as exc:  # noqa: BLE001
            b_errors.append(exc)

    t_b = threading.Thread(target=_concurrent_patch)
    t_b.start()

    # Даём B шанс либо мгновенно завершиться (баг — recompute A лока не
    # держит), либо начать блокироваться на RESERVED-локе A (фикс) — в обоих
    # случаях дальнейшее поведение детерминировано освобождением A.
    time.sleep(0.3)
    let_a_commit.set()

    t_a.join(timeout=10)
    t_b.join(timeout=10)
    assert not t_a.is_alive(), "поток A завис — commit не завершился"
    assert not t_b.is_alive(), "поток B завис — PATCH не завершился"
    assert not a_errors, a_errors
    assert not b_errors, b_errors

    run_json = client.get(f"/api/v1/runs/{run['run_id']}").json()
    assert run_json["counts_by_verdict"] == {
        "true_positive": 1, "false_positive": 1, "uncertain": 0, "unmarked": 0,
    }
