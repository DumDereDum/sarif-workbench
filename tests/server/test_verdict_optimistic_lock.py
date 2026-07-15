"""T-38: оптимистическая блокировка PATCH /findings/{id}/verdict.

Без версии PATCH был read-modify-write: два клиента, читающие одну и ту же
находку одновременно, оба отправляют свой PATCH — второй молча затирает
решение первого (lost update), без единого сигнала об этом ни одной из
сторон. Здесь identity.version (T-38, инкрементируется в write_verdict на
КАЖДУЮ запись — human/ai/carried/reset) используется как токен версии: PATCH
обязан прислать `version`, прочитанную последним GET; расхождение с текущей
версией identity → 409 с актуальным состоянием находки в теле, чтобы клиент
не падал молча, а мог показать пользователю, что изменилось.

Проверка версии и её инкремент — ОДИН атомарный условный UPDATE внутри
write_verdict (`WHERE id=... AND version=expected_version`), не отдельное
Python-сравнение до записи (review round 2: раунд 1 сравнивал версии в
Python до отдельного вызова write_verdict — под настоящей конкурентностью,
не строго последовательными HTTP-вызовами, это давало TOCTOU-окно, в
котором оба конкурентных PATCH проходили сравнение и оба получали 200,
реинкарнируя исходный lost-update баг). `test_two_concurrent_patches_same_version_only_one_wins`
ниже воспроизводит это настоящей конкурентностью (потоки + barrier), а не
последовательными вызовами, как остальные тесты этого файла.
"""
import concurrent.futures
import threading
import uuid


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _first_finding_id(client, run_id: str) -> str:
    items = client.get(f"/api/v1/runs/{run_id}/findings").json()["items"]
    assert items
    return items[0]["id"]


# ── Настоящая конкурентность: TOCTOU-регрессия review round 2 ──────────────


def test_two_concurrent_patches_same_version_only_one_wins(client, upload_run):
    """Два потока, синхронизированные barrier'ом, шлют PATCH с ОДНОЙ и той же
    version практически одновременно — в отличие от остальных тестов этого
    файла, которые гоняют PATCH строго последовательно через TestClient
    (каждый вызов полностью коммитится до следующего) и поэтому не могут
    поймать TOCTOU-гонку между чтением версии и записью.

    До review round 2 (Python-сравнение `expected_version != identity.version`
    ДО отдельного вызова write_verdict, каждый поток — в своей независимой
    DB-сессии) это воспроизводимо давало ОБА 200: оба потока успевали
    прочитать identity.version=1 и пройти сравнение, пока ни один ещё не
    закоммитил свою запись, — ровно тот lost-update баг, который T-38 должен
    был закрыть. После фикса (атомарный условный UPDATE внутри write_verdict)
    ровно один поток может выиграть гонку за конкретное значение version в
    БД, независимо от того, как ОС планирует потоки — прогоняем несколько
    независимых находок подряд, чтобы не зависеть от везения в конкретном
    прогоне и явно упражнять реальную конкурентность (не один случайный кадр).
    """
    for trial in range(15):
        # ВАЖНО: свежий repo/project на каждый trial, не общий на весь цикл.
        # make_meta вычисляет swb_id детерминированно от (rule_id, uri,
        # start_line) — тот же repo + тот же spec на втором trial означали бы
        # find-or-create той же identity, что и в trial 0 (уже с version > 1
        # и carried-событием от повторного upload_run), и оба потока
        # ЗАКОНОМЕРНО получали бы 409 на "version": 1 — это не гонка, а
        # тестовая ошибка (именно так она сначала и проявилась при отладке).
        repo = _unique_repo()
        run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
        finding_id = _first_finding_id(client, run["run_id"])

        barrier = threading.Barrier(2)

        def _patch(verdict: str, actor: str, _finding_id: str = finding_id) -> object:
            barrier.wait(timeout=5)
            return client.patch(
                f"/api/v1/findings/{_finding_id}/verdict",
                json={"verdict": verdict, "rationale": actor, "version": 1},
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            fut_a = pool.submit(_patch, "true_positive", "thread-A")
            fut_b = pool.submit(_patch, "false_positive", "thread-B")
            resp_a = fut_a.result(timeout=10)
            resp_b = fut_b.result(timeout=10)

        statuses = sorted([resp_a.status_code, resp_b.status_code])
        assert statuses == [200, 409], (
            f"trial {trial}: expected exactly one 200 and one 409, got "
            f"{resp_a.status_code}/{resp_b.status_code} — both-200 is the lost-update regression"
        )

        # Проигравший запрос не оставил в append-only истории событие с
        # несогласованным before/after переходом (review round 2, второе
        # замечание): ровно одно verdict_event на identity, версия ушла
        # ровно на 1 шаг вперёд, а не на 2 (что было бы, если бы оба потока
        # реально записались).
        detail = client.get(f"/api/v1/findings/{finding_id}").json()
        assert len(detail["verdict"]["history"]) == 1, f"trial {trial}: {detail['verdict']['history']}"
        assert detail["verdict"]["version"] == 2, f"trial {trial}: version={detail['verdict']['version']}"


# ── Verify буквально: два PATCH с одинаковой исходной версией ──────────────


def test_two_patches_from_same_version_first_200_second_409(client, upload_run):
    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    # Оба "клиента" читают находку до какой-либо записи — видят одну и ту же
    # версию (свежая identity, ещё не размеченная).
    detail = client.get(f"/api/v1/findings/{finding_id}").json()
    read_version = detail["verdict"]["version"]
    assert read_version == 1

    first = client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "true_positive", "rationale": "client A", "version": read_version},
    )
    assert first.status_code == 200, first.text
    assert first.json()["verdict"] == "true_positive"
    assert first.json()["version"] == 2  # инкремент после первой записи

    # Второй клиент шлёт PATCH с ТОЙ ЖЕ (уже устаревшей) версией.
    second = client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "false_positive", "rationale": "client B", "version": read_version},
    )
    assert second.status_code == 409, second.text
    body = second.json()["detail"]
    assert body["error"] == "version_conflict"

    # решение первого клиента НЕ затёрто вторым PATCH
    current = client.get(f"/api/v1/findings/{finding_id}").json()
    assert current["verdict"]["verdict"] == "true_positive"
    assert current["verdict"]["rationale"] == "client A"


def test_409_body_carries_current_finding_state(client, upload_run):
    """Клиент должен получить актуальное состояние находки в теле 409, а не только код ошибки."""
    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "true_positive", "rationale": "winner", "version": 1},
    )

    stale = client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "false_positive", "rationale": "loser", "version": 1},
    )
    assert stale.status_code == 409
    conflict_finding = stale.json()["detail"]["finding"]
    # то же представление, что отдаёт обычный GET /findings/{id}
    assert conflict_finding["id"] == finding_id
    assert conflict_finding["verdict"]["verdict"] == "true_positive"
    assert conflict_finding["verdict"]["rationale"] == "winner"
    assert conflict_finding["verdict"]["version"] == 2


def test_retry_with_fresh_version_from_conflict_body_succeeds(client, upload_run):
    """После 409 клиент берёт версию из тела ответа и повторяет PATCH — должно пройти."""
    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    client.patch(f"/api/v1/findings/{finding_id}/verdict", json={"verdict": "true_positive", "version": 1})

    stale = client.patch(f"/api/v1/findings/{finding_id}/verdict", json={"verdict": "false_positive", "version": 1})
    assert stale.status_code == 409
    fresh_version = stale.json()["detail"]["finding"]["verdict"]["version"]

    retry = client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "uncertain", "rationale": "re-reviewed after conflict", "version": fresh_version},
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["verdict"] == "uncertain"


def test_missing_version_is_400_not_silent_overwrite(client, upload_run):
    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    resp = client.patch(f"/api/v1/findings/{finding_id}/verdict", json={"verdict": "true_positive"})
    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "bad_request"

    # ничего не записано
    detail = client.get(f"/api/v1/findings/{finding_id}").json()
    assert detail["verdict"]["verdict"] == "unmarked"
    assert detail["verdict"]["version"] == 1


def test_non_integer_version_is_400(client, upload_run):
    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    resp = client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "true_positive", "version": "1"},
    )
    assert resp.status_code == 400


def test_ai_write_between_human_reads_and_patch_causes_conflict(client, upload_run, monkeypatch):
    """Версия бьётся на КАЖДОЙ записи (T-38), не только human — конкурентная
    AI-разметка между чтением человека и его PATCH тоже должна дать 409, а не
    молча перезаписаться человеком поверх свежего AI-решения.
    """
    import json as _json

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    finding_id = _first_finding_id(client, run["run_id"])

    detail = client.get(f"/api/v1/findings/{finding_id}").json()
    human_read_version = detail["verdict"]["version"]
    assert human_read_version == 1

    async def _fake_call_llm(provider, model, system, user):
        return {"content": "Verdict: false_positive\nRationale: ai-first", "tokens": 1}

    monkeypatch.setattr("swb_server.ai.analyze_loop.call_llm", _fake_call_llm)

    analyze_resp = client.post(
        f"/api/v1/runs/{run['run_id']}/analyze",
        json={"only_unmarked": False},
    )
    assert analyze_resp.status_code == 200
    events = [
        _json.loads(line[len("data: "):])
        for line in analyze_resp.text.splitlines()
        if line.startswith("data: ")
    ]
    done = [e for e in events if e["type"] == "done"][0]
    assert done["done"] == 1  # AI успела разметить находку первой

    # человек шлёт свой PATCH с версией, прочитанной ДО AI-записи
    human_patch = client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": "true_positive", "rationale": "human disagrees", "version": human_read_version},
    )
    assert human_patch.status_code == 409
    conflict_finding = human_patch.json()["detail"]["finding"]
    assert conflict_finding["verdict"]["verdict"] == "false_positive"
    assert conflict_finding["verdict"]["source"] == "ai"
