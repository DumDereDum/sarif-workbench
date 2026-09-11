"""Оценки правил: очередь на разбор и запись.

Показатель H задаётся на правило анализатора и хранится глобально —
последствие эксплуатации не зависит от репозитория, в котором находка
нашлась. От системы зависит, насколько это плохо, и это профиль проекта.

Проверяется:
  (а) очередь: правила с числом находок, сортировка по объёму, фильтры;
  (б) ключ (tool, rule_id) едет в теле — идентификаторы содержат слэши,
      названия инструментов пробелы, и путь пришлось бы кодировать;
  (в) значения проверяются по контракту: последствия из таблицы 1, оценка
      CVSS в диапазоне 0-10;
  (г) «не уязвимость» требует обоснования и несовместимо с последствиями;
  (д) запись пересчитывает находки правила во всех проектах;
  (е) массовая запись тем же обработчиком.
"""
from __future__ import annotations

LIST = "/api/v1/fstec/rule-impacts"


def _queue(client, **params):
    return client.get(LIST, params=params).json()


def _row(client, rule_id, **params):
    return next(r for r in _queue(client, **params)["items"] if r["rule_id"] == rule_id)


def _fstec(client, run_id):
    return client.get(f"/api/v1/runs/{run_id}/findings").json()["items"][0]["fstec"]


# ── (а) очередь ────────────────────────────────────────────────────────────


def test_queue_lists_rules_with_finding_counts(upload_run, client):
    upload_run([{"rule_id": "Q-CNT", "uri": f"src/{i}.py"} for i in range(3)],
               repo="fstec-rules-cnt")
    assert _row(client, "Q-CNT")["findings"] == 3


def test_queue_is_sorted_by_volume(upload_run, client):
    """Распределение неравномерное: на замеренном корпусе десять правил
    закрывают две трети находок. Разбирать сверху вниз — короткий путь."""
    upload_run([{"rule_id": "Q-MANY", "uri": f"src/m{i}.py"} for i in range(5)]
               + [{"rule_id": "Q-FEW", "uri": "src/f.py"}], repo="fstec-rules-sort")
    items = [r for r in _queue(client)["items"] if r["rule_id"].startswith("Q-")]
    counts = [r["findings"] for r in items]
    assert counts == sorted(counts, reverse=True)


def test_unassessed_filter_hides_finished_rules(upload_run, client):
    upload_run([{"rule_id": "Q-DONE", "uri": "src/d.py"}], repo="fstec-rules-done")
    assert _row(client, "Q-DONE")["assessed"] is False

    client.put(LIST, json={"tool": "TestTool", "rule_id": "Q-DONE", "impacts": ["dos"]})

    assert _row(client, "Q-DONE")["assessed"] is True
    assert all(r["rule_id"] != "Q-DONE" for r in _queue(client, unassessed=True)["items"])


def test_queue_carries_cwes_for_the_form(upload_run, client):
    """Форма показывает CWE правила — по нему подтягивается подсказка из
    каталога MITRE о том, какие последствия у этой слабости бывают."""
    upload_run([{"rule_id": "CWE-89", "uri": "src/c.py"}], repo="fstec-rules-cwe")
    assert _row(client, "CWE-89")["cwes"] == ["CWE-89"]


def test_tool_filter(upload_run, client):
    upload_run([{"rule_id": "Q-TOOL", "uri": "src/t.py"}], repo="fstec-rules-tool")
    assert _queue(client, tool="НетТакого")["items"] == []


# ── (б)-(в) валидация ──────────────────────────────────────────────────────


def test_rule_id_with_slashes_is_accepted(upload_run, client):
    """`cpp/alloca-in-loop`, `SvEng.CXX.UNINIT.LOCAL_VAR/SvEng.U.29` — ключ
    в пути пришлось бы кодировать на каждом клиенте."""
    r = client.put(LIST, json={"tool": "Semgrep OSS", "rule_id": "cpp/alloca-in-loop",
                               "impacts": ["dos"]})
    assert r.status_code == 200 and r.json()["saved"] == 1


def test_key_is_required(client):
    assert client.put(LIST, json={"impacts": ["dos"]}).status_code == 400


def test_unknown_impact_is_rejected(client):
    r = client.put(LIST, json={"tool": "T", "rule_id": "R", "impacts": ["катастрофа"]})
    assert r.status_code == 400
    assert "недопустимые значения" in r.json()["detail"]["message"]


def test_every_contract_impact_is_accepted(client):
    from swb_contract.fstec import Impact  # noqa: PLC0415

    r = client.put(LIST, json={"tool": "T", "rule_id": "R-ALL",
                               "impacts": [m.value for m in Impact]})
    assert r.status_code == 200


def test_i_cvss_out_of_range_is_rejected(client):
    for bad in (-0.1, 10.1, "много"):
        r = client.put(LIST, json={"tool": "T", "rule_id": "R-CV", "i_cvss": bad})
        assert r.status_code == 400, bad


# ── (г) «не уязвимость» ────────────────────────────────────────────────────


def test_not_applicable_requires_a_reason(client):
    """Решение убирает находки правила из оценки целиком и предъявляется
    аудитору — без обоснования оно непредъявимо."""
    r = client.put(LIST, json={"tool": "T", "rule_id": "R-NA", "not_applicable": True})
    assert r.status_code == 400
    assert "требует note" in r.json()["detail"]["message"]


def test_not_applicable_with_impacts_is_rejected(client):
    r = client.put(LIST, json={"tool": "T", "rule_id": "R-NA2", "not_applicable": True,
                               "note": "проверка качества кода", "impacts": ["dos"]})
    assert r.status_code == 400
    assert "несовместимы" in r.json()["detail"]["message"]


def test_not_applicable_with_reason_is_stored(upload_run, client):
    upload_run([{"rule_id": "R-NA3", "uri": "src/na.py"}], repo="fstec-rules-na")
    client.put(LIST, json={"tool": "TestTool", "rule_id": "R-NA3", "not_applicable": True,
                           "note": "проверка стиля, последствий эксплуатации нет"})
    row = _row(client, "R-NA3")
    assert row["not_applicable"] is True and row["assessed"] is True
    assert "последствий" in row["note"]


# ── (д) пересчёт ───────────────────────────────────────────────────────────


def test_write_recomputes_findings_of_the_rule(upload_run, client):
    run = upload_run([{"rule_id": "R-CALC", "uri": "src/rc.py"}], repo="fstec-rules-calc")
    client.put(f"/api/v1/projects/{run['project_id']}/fstec-profile", json={
        "component_type": "server", "vulnerable_share": "under_10",
        "perimeter_exposure": "not_internet_facing"})
    assert _fstec(client, run["run_id"])["missing"] == ["i_cvss", "H"]

    r = client.put(LIST, json={"tool": "TestTool", "rule_id": "R-CALC",
                               "i_cvss": 9.8, "impacts": ["arbitrary_code_execution"]})
    assert r.json()["recomputed"] == {"assessed": 1}

    fstec = _fstec(client, run["run_id"])
    assert fstec["status"] == "assessed" and fstec["v"] == 3.7


def test_rule_assessment_applies_across_projects(upload_run, client):
    """Таблица глобальная: последствие эксплуатации не зависит от того, в
    каком репозитории слабость нашлась."""
    a = upload_run([{"rule_id": "R-GLOB", "uri": "src/ga.py"}], repo="fstec-rules-glob-a")
    b = upload_run([{"rule_id": "R-GLOB", "uri": "src/gb.py"}], repo="fstec-rules-glob-b")
    for run in (a, b):
        client.put(f"/api/v1/projects/{run['project_id']}/fstec-profile", json={
            "component_type": "server", "vulnerable_share": "under_10",
            "perimeter_exposure": "not_internet_facing"})

    client.put(LIST, json={"tool": "TestTool", "rule_id": "R-GLOB",
                           "i_cvss": 5.0, "impacts": ["dos"]})

    assert _fstec(client, a["run_id"])["status"] == "assessed"
    assert _fstec(client, b["run_id"])["status"] == "assessed"


# ── (е) массовая запись ────────────────────────────────────────────────────


def test_bulk_write(upload_run, client):
    """Тем же обработчиком: таблицу можно заполнить файлом и перенести на
    другую установку, не выдумывая второй формат."""
    upload_run([{"rule_id": f"R-BULK{i}", "uri": f"src/b{i}.py"} for i in range(3)],
               repo="fstec-rules-bulk")
    r = client.put(LIST, json=[
        {"tool": "TestTool", "rule_id": f"R-BULK{i}", "impacts": ["dos"]} for i in range(3)
    ])
    assert r.status_code == 200 and r.json()["saved"] == 3
    assert all(_row(client, f"R-BULK{i}")["assessed"] for i in range(3))


def test_bulk_rejects_the_whole_batch_on_one_bad_item(client):
    """Половина применённой пачки хуже отвергнутой: непонятно, что записалось."""
    r = client.put(LIST, json=[
        {"tool": "T", "rule_id": "R-OK", "impacts": ["dos"]},
        {"tool": "T", "rule_id": "R-BAD", "impacts": ["нет такого"]},
    ])
    assert r.status_code == 400
    assert all(x["rule_id"] != "R-OK" for x in _queue(client)["items"] if x["assessed"])
