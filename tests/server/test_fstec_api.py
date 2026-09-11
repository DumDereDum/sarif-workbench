"""Выдача уровня критичности ФСТЭК в API.

Проверяется:
  (а) блок `fstec` есть и в списке находок, и в карточке;
  (б) без профиля ИС и оценки правила находка честно сообщает, чего не
      хватает, и не выглядит как «Низкий»;
  (в) после заполнения профиля и правила уровень появляется, а вместе с ним
      рекомендуемый срок устранения из п. 21;
  (г) карточка несёт полное разложение расчёта: показатели, веса,
      произведения, метку источника I_cvss и значения, отброшенные
      правилом максимума пп. 15-17 — по нему аудитор проверяет арифметику;
  (д) правило, помеченное как «не уязвимость», расчёт не запускает.
"""
from __future__ import annotations

from datetime import datetime


def _profile(db_session, project_id, **kw):
    from swb_server.models import SystemProfile  # noqa: PLC0415 — импорт после env

    db_session.merge(SystemProfile(
        project_id=project_id, updated_at=datetime.utcnow(),
        component_type=kw.get("component_type", "server"),
        vulnerable_share=kw.get("vulnerable_share", "under_10"),
        perimeter_exposure=kw.get("perimeter_exposure", "not_internet_facing"),
    ))
    db_session.commit()


def _rule(db_session, tool, rule_id, **kw):
    from swb_server.models import RuleImpact  # noqa: PLC0415

    db_session.merge(RuleImpact(tool=tool, rule_id=rule_id, updated_at=datetime.utcnow(), **kw))
    db_session.commit()


def _first_finding(client, run_id):
    items = client.get(f"/api/v1/runs/{run_id}/findings").json()["items"]
    return items[0]


# ── (а)-(б) без данных — честный пробел ────────────────────────────────────


def test_list_carries_fstec_block(upload_run, client):
    run = upload_run([{"rule_id": "R-LIST", "uri": "src/a.py", "start_line": 1}])
    f = _first_finding(client, run["run_id"])
    assert f["fstec"]["status"] == "needs_assessment"


def test_missing_lists_every_unset_indicator(upload_run, client):
    """Тестовый SARIF не несёт security-severity — как Svacer и Bandit."""
    run = upload_run([{"rule_id": "R-MISS", "uri": "src/b.py", "start_line": 1}])
    f = _first_finding(client, run["run_id"])
    assert set(f["fstec"]["missing"]) == {"i_cvss", "K", "L", "P", "H"}


def test_unassessed_finding_has_no_level(upload_run, client):
    """Пустая оценка не должна выглядеть как «Низкий»."""
    run = upload_run([{"rule_id": "R-NOLVL", "uri": "src/c.py", "start_line": 1}])
    fstec = _first_finding(client, run["run_id"])["fstec"]
    assert fstec["v"] is None and fstec["level"] is None and fstec["remediation"] is None


# ── (в) после заполнения ───────────────────────────────────────────────────


def test_level_and_deadline_appear_after_profile_and_rule(upload_run, client, db_session):
    run = upload_run([{"rule_id": "R-FULL", "uri": "src/d.py", "start_line": 1}],
                     repo="fstec-api-full")
    _profile(db_session, run["project_id"])
    _rule(db_session, "TestTool", "R-FULL", i_cvss=9.8,
          impacts=["arbitrary_code_execution", "dos"])

    from swb_server.criticality import recompute_run  # noqa: PLC0415

    recompute_run(db_session, run["run_id"])
    db_session.commit()

    fstec = _first_finding(client, run["run_id"])["fstec"]
    assert fstec["status"] == "assessed"
    # 9.8 × (0.5·0.7 + 0.2·0.5 + 0.3·0.6) × (0.1 + 0.5) = 9.8 × 0.63 × 0.6
    assert fstec["v"] == 3.7
    assert fstec["level"] == "medium"
    assert fstec["level_label"] == "Средний"
    # срок устранения п. 21 — текстом, как в методике
    assert fstec["remediation"] == "до 4 недель"


def test_methodology_is_named(upload_run, client):
    """Отчёт предъявляется регулятору: по какому документу считалось,
    должно быть видно рядом с числом."""
    run = upload_run([{"rule_id": "R-METH", "uri": "src/e.py", "start_line": 1}])
    assert "30.06.2025" in _first_finding(client, run["run_id"])["fstec"]["methodology"]


# ── (г) разложение в карточке ──────────────────────────────────────────────


def test_card_carries_breakdown_with_max_rule_candidates(upload_run, client, db_session):
    run = upload_run([{"rule_id": "R-CARD", "uri": "src/f.py", "start_line": 1}],
                     repo="fstec-api-card")
    _profile(db_session, run["project_id"], component_type="key_processes",
             vulnerable_share="over_70", perimeter_exposure="internet_facing")
    _rule(db_session, "TestTool", "R-CARD", i_cvss=8.8,
          impacts=["dos", "arbitrary_code_execution"])

    from swb_server.criticality import recompute_run  # noqa: PLC0415

    recompute_run(db_session, run["run_id"])
    db_session.commit()

    fid = _first_finding(client, run["run_id"])["id"]
    b = client.get(f"/api/v1/findings/{fid}").json()["fstec"]["breakdown"]

    assert b["formula"] == "V = I_cvss × I_infr × (I_at + I_imp)"
    # ручная оценка правила видна как таковая, не выдаётся за оценку анализатора
    assert b["i_cvss"] == {"value": 8.8, "source": "manual_rule"}
    assert [t["symbol"] for t in b["i_infr"]["terms"]] == ["K", "L", "P"]
    assert b["i_infr"]["value"] == 1.08

    # правило максимума п. 17: выбран больший, меньший показан кандидатом
    term = b["i_imp"]["term"]
    assert term["value"] == "arbitrary_code_execution"
    assert {c["value"] for c in term["candidates"]} == {"dos", "arbitrary_code_execution"}


def test_card_of_unassessed_finding_has_no_breakdown(upload_run, client):
    run = upload_run([{"rule_id": "R-NOBD", "uri": "src/g.py", "start_line": 1}])
    fid = _first_finding(client, run["run_id"])["id"]
    fstec = client.get(f"/api/v1/findings/{fid}").json()["fstec"]
    assert fstec["breakdown"] is None
    assert "K" in fstec["missing"]


# ── (д) «не уязвимость» ────────────────────────────────────────────────────


def test_rule_marked_not_applicable_is_not_assessed(upload_run, client, db_session):
    run = upload_run([{"rule_id": "R-NA", "uri": "src/h.py", "start_line": 1}],
                     repo="fstec-api-na")
    _profile(db_session, run["project_id"])
    _rule(db_session, "TestTool", "R-NA", not_applicable=True, i_cvss=9.8,
          impacts=["arbitrary_code_execution"])

    from swb_server.criticality import recompute_run  # noqa: PLC0415

    recompute_run(db_session, run["run_id"])
    db_session.commit()

    fid = _first_finding(client, run["run_id"])["id"]
    fstec = client.get(f"/api/v1/findings/{fid}").json()["fstec"]
    assert fstec["status"] == "not_applicable"
    # перечислять недостающие показатели незачем — оценивать нечего
    assert fstec["missing"] == [] and fstec["v"] is None
