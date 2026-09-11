"""Сводка по уровням критичности, фильтр и сортировка.

Проверяется:
  (а) `counts_by_fstec` на ране: сумма сходится с числом находок, а
      «требует оценки» и «не применимо» — полноценные группы, не пропуск;
  (б) счётчики обновляются после записи профиля и оценки правила;
  (в) вердикт «ложное срабатывание» переводит находку в «не применимо»,
      снятие возвращает в расчёт;
  (г) фильтр `?fstec_level=` принимает и уровни, и статусы;
  (д) сортировка `sort=fstec`: посчитанные уровни сверху вниз, затем
      неоценённые — они не уровни, и место между «Средним» и «Низким» им
      не принадлежит.
"""
from __future__ import annotations

PROFILE = {"component_type": "key_processes", "vulnerable_share": "over_70",
           "perimeter_exposure": "internet_facing"}
RULES = "/api/v1/fstec/rule-impacts"


def _counts(client, run_id):
    return client.get(f"/api/v1/runs/{run_id}").json()["counts_by_fstec"]


def _levels(client, run_id, **params):
    items = client.get(f"/api/v1/runs/{run_id}/findings", params=params).json()["items"]
    return [f["fstec"]["level"] or f["fstec"]["status"] for f in items]


def _setup(upload_run, client, repo, specs, rules=()):
    run = upload_run(specs, repo=repo)
    client.put(f"/api/v1/projects/{run['project_id']}/fstec-profile", json=PROFILE)
    if rules:
        client.put(RULES, json=list(rules))
    return run


# ── (а) сводка ─────────────────────────────────────────────────────────────


def test_counts_sum_matches_total(upload_run, client):
    """Сумма обязана сходиться: иначе «требует оценки» выглядит как ноль
    находок, а не как незакрытая работа."""
    run = upload_run([{"rule_id": "C-SUM", "uri": f"src/{i}.py"} for i in range(4)],
                     repo="fstec-counts-sum")
    counts = _counts(client, run["run_id"])
    assert sum(counts.values()) == 4
    assert counts["needs_assessment"] == 4


def test_counts_have_all_keys(upload_run, client):
    run = upload_run([{"rule_id": "C-KEYS", "uri": "src/k.py"}], repo="fstec-counts-keys")
    from swb_server.criticality import COUNTS_KEYS  # noqa: PLC0415

    assert set(_counts(client, run["run_id"])) == set(COUNTS_KEYS)


# ── (б) обновление после записи ────────────────────────────────────────────


def test_counts_follow_profile_and_rule_writes(upload_run, client):
    run = _setup(upload_run, client, "fstec-counts-write",
                 [{"rule_id": "C-W", "uri": "src/w.py"}])
    assert _counts(client, run["run_id"])["needs_assessment"] == 1

    client.put(RULES, json={"tool": "TestTool", "rule_id": "C-W",
                            "i_cvss": 9.8, "impacts": ["arbitrary_code_execution"]})
    counts = _counts(client, run["run_id"])
    assert counts["needs_assessment"] == 0
    # 9.8 × 1.08 × 0.6 = 6.35 — «Высокий»
    assert counts["high"] == 1


def test_not_applicable_rule_lands_in_its_own_group(upload_run, client):
    run = _setup(upload_run, client, "fstec-counts-na",
                 [{"rule_id": "C-NA", "uri": "src/na.py"}])
    client.put(RULES, json={"tool": "TestTool", "rule_id": "C-NA", "not_applicable": True,
                            "note": "проверка стиля"})
    assert _counts(client, run["run_id"])["not_applicable"] == 1


# ── (в) вердикт ────────────────────────────────────────────────────────────


def test_false_positive_moves_finding_out_of_assessment(upload_run, client):
    """Уровень критичности для несуществующей уязвимости бессмыслен."""
    run = _setup(upload_run, client, "fstec-counts-fp",
                 [{"rule_id": "C-FP", "uri": "src/fp.py"}],
                 rules=[{"tool": "TestTool", "rule_id": "C-FP", "i_cvss": 9.8,
                         "impacts": ["arbitrary_code_execution"]}])
    assert _counts(client, run["run_id"])["high"] == 1

    f = client.get(f"/api/v1/runs/{run['run_id']}/findings").json()["items"][0]
    card = client.get(f"/api/v1/findings/{f['id']}").json()
    client.patch(f"/api/v1/findings/{f['id']}/verdict",
                 json={"verdict": "false_positive", "version": card["verdict"]["version"]})

    counts = _counts(client, run["run_id"])
    assert counts["not_applicable"] == 1 and counts["high"] == 0


def test_clearing_false_positive_returns_finding_to_assessment(upload_run, client):
    run = _setup(upload_run, client, "fstec-counts-unfp",
                 [{"rule_id": "C-UNFP", "uri": "src/unfp.py"}],
                 rules=[{"tool": "TestTool", "rule_id": "C-UNFP", "i_cvss": 9.8,
                         "impacts": ["arbitrary_code_execution"]}])
    f = client.get(f"/api/v1/runs/{run['run_id']}/findings").json()["items"][0]

    def _patch(verdict):
        card = client.get(f"/api/v1/findings/{f['id']}").json()
        client.patch(f"/api/v1/findings/{f['id']}/verdict",
                     json={"verdict": verdict, "version": card["verdict"]["version"]})

    _patch("false_positive")
    assert _counts(client, run["run_id"])["not_applicable"] == 1
    _patch("true_positive")
    assert _counts(client, run["run_id"])["high"] == 1


# ── (г) фильтр ─────────────────────────────────────────────────────────────


def test_filter_by_level_and_by_status(upload_run, client):
    run = _setup(upload_run, client, "fstec-filter",
                 [{"rule_id": "F-DONE", "uri": "src/a.py"},
                  {"rule_id": "F-TODO", "uri": "src/b.py"}],
                 rules=[{"tool": "TestTool", "rule_id": "F-DONE", "i_cvss": 9.8,
                         "impacts": ["arbitrary_code_execution"]}])
    assert _levels(client, run["run_id"], fstec_level="high") == ["high"]
    # очередь на разбор надо уметь отфильтровать так же, как посчитанное
    assert _levels(client, run["run_id"], fstec_level="needs_assessment") == \
        ["needs_assessment"]
    assert len(_levels(client, run["run_id"], fstec_level="high,needs_assessment")) == 2


def test_unknown_filter_value_returns_nothing(upload_run, client):
    """Молча проигнорированный фильтр опаснее пустого ответа: пользователь
    решит, что видит отфильтрованное, а увидит весь ран."""
    run = upload_run([{"rule_id": "F-BAD", "uri": "src/x.py"}], repo="fstec-filter-bad")
    assert _levels(client, run["run_id"], fstec_level="кошмарный") == []


# ── (д) сортировка ─────────────────────────────────────────────────────────


def test_sort_puts_assessed_levels_before_unassessed(upload_run, client):
    run = _setup(upload_run, client, "fstec-sort",
                 [{"rule_id": "S-HIGH", "uri": "src/h.py"},
                  {"rule_id": "S-LOW", "uri": "src/l.py"},
                  {"rule_id": "S-TODO", "uri": "src/t.py"}],
                 rules=[
                     {"tool": "TestTool", "rule_id": "S-HIGH", "i_cvss": 9.8,
                      "impacts": ["arbitrary_code_execution"]},
                     {"tool": "TestTool", "rule_id": "S-LOW", "i_cvss": 1.0,
                      "impacts": ["cross_site_scripting"]},
                 ])
    assert _levels(client, run["run_id"], sort="fstec") == \
        ["high", "low", "needs_assessment"]


# ── (е) агрегация ──────────────────────────────────────────────────────────


def _agg(client, run_id):
    groups = client.get(f"/api/v1/runs/{run_id}/aggregations",
                        params={"by": "fstec_level"}).json()["groups"]
    return {g["key"]: g for g in groups}


def test_aggregation_groups_by_level_and_status(upload_run, client):
    run = _setup(upload_run, client, "fstec-agg",
                 [{"rule_id": "A-HI", "uri": "src/hi.py"},
                  {"rule_id": "A-NA", "uri": "src/na.py"},
                  {"rule_id": "A-TODO", "uri": "src/todo.py"}],
                 rules=[
                     {"tool": "TestTool", "rule_id": "A-HI", "i_cvss": 9.8,
                      "impacts": ["arbitrary_code_execution"]},
                     {"tool": "TestTool", "rule_id": "A-NA", "not_applicable": True,
                      "note": "проверка стиля"},
                 ])
    groups = _agg(client, run["run_id"])
    assert groups["high"]["count"] == 1
    assert groups["not_applicable"]["count"] == 1
    assert groups["needs_assessment"]["count"] == 1


def test_aggregation_labels_come_from_the_contract(upload_run, client):
    """Названия уровней — из методики, а не переписаны в роутере."""
    run = _setup(upload_run, client, "fstec-agg-lbl",
                 [{"rule_id": "A-LBL", "uri": "src/l.py"}],
                 rules=[{"tool": "TestTool", "rule_id": "A-LBL", "i_cvss": 9.8,
                         "impacts": ["arbitrary_code_execution"]}])
    from swb_contract.fstec import level_label  # noqa: PLC0415

    assert _agg(client, run["run_id"])["high"]["label"] == level_label("high")


def test_aggregation_labels_the_two_non_levels(upload_run, client):
    """«Требует оценки» и «не применимо» уровнями не являются и своей
    подписи в методике не имеют — она наша."""
    run = upload_run([{"rule_id": "A-NL", "uri": "src/nl.py"}], repo="fstec-agg-nl")
    assert _agg(client, run["run_id"])["needs_assessment"]["label"] == "Требует оценки"
