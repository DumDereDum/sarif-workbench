"""Профиль информационной системы: `GET`/`PUT /projects/{id}/fstec-profile`.

Показатели K, L и P описывают систему, а не находку — в SARIF их нет по
природе. Заполняются вручную, один раз на проект.

Проверяется:
  (а) пустой профиль отдаётся с перечнем незаполненных полей, а не 404;
  (б) значения проверяются по перечислениям контракта: неизвестное — 400,
      а не тихая запись, которая уронит расчёт далеко от места ошибки;
  (в) запись запускает пересчёт находок проекта (п. 19);
  (г) профиль можно заполнять частями и очищать явным null;
  (д) пересчёт не задевает соседние проекты.
"""
from __future__ import annotations

URL = "/api/v1/projects/{}/fstec-profile"

FULL = {
    "component_type": "server",
    "vulnerable_share": "under_10",
    "perimeter_exposure": "not_internet_facing",
}


def _fstec(client, run_id):
    return client.get(f"/api/v1/runs/{run_id}/findings").json()["items"][0]["fstec"]


# ── (а) пустой профиль ─────────────────────────────────────────────────────


def test_empty_profile_reports_what_is_missing(upload_run, client):
    run = upload_run([{"rule_id": "P-EMPTY", "uri": "src/a.py"}], repo="fstec-prof-empty")
    body = client.get(URL.format(run["project_id"])).json()
    assert body["complete"] is False
    assert set(body["missing"]) == set(FULL)
    assert body["component_type"] is None


def test_unknown_project_is_404(client):
    assert client.get(URL.format("нет-такого")).status_code == 404


# ── (б) валидация ──────────────────────────────────────────────────────────


def test_unknown_value_is_rejected(upload_run, client):
    """Строка, не совпадающая с перечислением, позже уронила бы расчёт — и
    находка выглядела бы недооценённой без объяснения."""
    run = upload_run([{"rule_id": "P-BAD", "uri": "src/b.py"}], repo="fstec-prof-bad")
    r = client.put(URL.format(run["project_id"]), json={"component_type": "сервер"})
    assert r.status_code == 400
    assert "недопустимое значение" in r.json()["detail"]["message"]


def test_unknown_field_is_rejected(upload_run, client):
    run = upload_run([{"rule_id": "P-FLD", "uri": "src/c.py"}], repo="fstec-prof-field")
    r = client.put(URL.format(run["project_id"]), json={"k": "server"})
    assert r.status_code == 400
    assert "неизвестные поля" in r.json()["detail"]["message"]


def test_updated_by_is_accepted_and_stored(upload_run, client):
    """Подпись под решением приходит тем же телом и показателем не является —
    в список неизвестных полей попадать не должна."""
    run = upload_run([{"rule_id": "P-WHO", "uri": "src/who.py"}], repo="fstec-prof-who")
    r = client.put(URL.format(run["project_id"]), json={**FULL, "updated_by": "И. Специалист"})
    assert r.status_code == 200
    assert client.get(URL.format(run["project_id"])).json()["updated_by"] == "И. Специалист"


def test_every_contract_value_is_accepted(upload_run, client):
    """Отвергнутый вариант — вариант, который специалист не сможет выбрать."""
    from swb_contract.fstec import ComponentType  # noqa: PLC0415

    run = upload_run([{"rule_id": "P-ALL", "uri": "src/d.py"}], repo="fstec-prof-all")
    for member in ComponentType:
        r = client.put(URL.format(run["project_id"]), json={"component_type": member.value})
        assert r.status_code == 200, member


# ── (в) пересчёт ───────────────────────────────────────────────────────────


def test_write_recomputes_project_findings(upload_run, client, db_session):
    run = upload_run([{"rule_id": "P-CALC", "uri": "src/e.py"}], repo="fstec-prof-calc")

    from datetime import datetime  # noqa: PLC0415

    from swb_server.models import RuleImpact  # noqa: PLC0415

    db_session.merge(RuleImpact(tool="TestTool", rule_id="P-CALC", i_cvss=9.8,
                                impacts=["arbitrary_code_execution"],
                                updated_at=datetime.utcnow()))
    db_session.commit()

    assert _fstec(client, run["run_id"])["status"] == "needs_assessment"

    r = client.put(URL.format(run["project_id"]), json=FULL)
    assert r.status_code == 200
    assert r.json()["recomputed"] == {"assessed": 1}

    fstec = _fstec(client, run["run_id"])
    assert fstec["status"] == "assessed"
    # 9.8 × (0.5·0.7 + 0.2·0.5 + 0.3·0.6) × (0.1 + 0.5) = 9.8 × 0.63 × 0.6
    assert fstec["v"] == 3.7 and fstec["level"] == "medium"


def test_changing_perimeter_changes_v(upload_run, client, db_session):
    """П. 19: изменились условия — уровень пересматривается. Вынос компонента
    в интернет поднимает P с 0,6 до 1,1."""
    run = upload_run([{"rule_id": "P-PERIM", "uri": "src/f.py"}], repo="fstec-prof-perim")

    from datetime import datetime  # noqa: PLC0415

    from swb_server.models import RuleImpact  # noqa: PLC0415

    db_session.merge(RuleImpact(tool="TestTool", rule_id="P-PERIM", i_cvss=9.8,
                                impacts=["arbitrary_code_execution"],
                                updated_at=datetime.utcnow()))
    db_session.commit()

    client.put(URL.format(run["project_id"]), json=FULL)
    before = _fstec(client, run["run_id"])["v"]

    client.put(URL.format(run["project_id"]), json={"perimeter_exposure": "internet_facing"})
    after = _fstec(client, run["run_id"])["v"]

    assert after > before


# ── (г) частичное заполнение и очистка ─────────────────────────────────────


def test_partial_write_keeps_other_fields(upload_run, client):
    run = upload_run([{"rule_id": "P-PART", "uri": "src/g.py"}], repo="fstec-prof-part")
    client.put(URL.format(run["project_id"]), json=FULL)
    client.put(URL.format(run["project_id"]), json={"vulnerable_share": "over_70"})
    body = client.get(URL.format(run["project_id"])).json()
    assert body["vulnerable_share"] == "over_70"
    assert body["component_type"] == "server"
    assert body["complete"] is True


def test_explicit_null_clears_a_field(upload_run, client):
    """Профиль можно вернуть в «не заполнено» — например, когда выяснилось,
    что тип компонента был указан ошибочно."""
    run = upload_run([{"rule_id": "P-NULL", "uri": "src/h.py"}], repo="fstec-prof-null")
    client.put(URL.format(run["project_id"]), json=FULL)
    client.put(URL.format(run["project_id"]), json={"component_type": None})
    body = client.get(URL.format(run["project_id"])).json()
    assert body["component_type"] is None and body["missing"] == ["component_type"]


# ── (д) изоляция проектов ──────────────────────────────────────────────────


def test_profile_of_one_project_does_not_touch_another(upload_run, client, db_session):
    a = upload_run([{"rule_id": "P-ISO", "uri": "src/i.py"}], repo="fstec-prof-iso-a")
    b = upload_run([{"rule_id": "P-ISO", "uri": "src/j.py"}], repo="fstec-prof-iso-b")

    from datetime import datetime  # noqa: PLC0415

    from swb_server.models import RuleImpact  # noqa: PLC0415

    db_session.merge(RuleImpact(tool="TestTool", rule_id="P-ISO", i_cvss=9.8,
                                impacts=["dos"], updated_at=datetime.utcnow()))
    db_session.commit()

    client.put(URL.format(a["project_id"]), json=FULL)
    assert _fstec(client, a["run_id"])["status"] == "assessed"
    assert _fstec(client, b["run_id"])["status"] == "needs_assessment"
