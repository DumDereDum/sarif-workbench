"""`GET /fstec/indicators` — таблицы методики для построения форм.

Смысл эндпоинта в том, чтобы веб не переписывал нормативные значения руками.
В проекте уже есть такая ручная копия (`web/src/lib/severity.ts` и
предупреждение в её шапке), и для коэффициентов методики цена расхождения
выше: уровень критичности в отчёте регулятору.

Поэтому тесты сверяют выдачу с контрактом, а не с зашитыми числами — кроме
нескольких значений из самой методики, которые проверяются буквально: если
кто-то поправит `TABLE_1`, тест обязан упасть, а не подстроиться.
"""
from __future__ import annotations

from swb_contract.fstec import LEVELS, TABLE_1


def _body(client):
    r = client.get("/api/v1/fstec/indicators")
    assert r.status_code == 200
    return r.json()


def test_all_five_indicators_are_present(client):
    assert set(_body(client)["indicators"]) == set(TABLE_1)


def test_every_value_of_every_indicator_is_offered(client):
    """Пропущенный вариант — это вариант, который специалист не сможет
    выбрать, и оценка уедет на соседний."""
    body = _body(client)
    for symbol, spec in TABLE_1.items():
        got = {v["value"] for v in body["indicators"][symbol]["values"]}
        assert got == {value.value for value in spec.values}


def test_weights_and_scores_match_the_contract(client):
    body = _body(client)
    for symbol, spec in TABLE_1.items():
        assert body["indicators"][symbol]["weight"] == spec.weight
        for item in body["indicators"][symbol]["values"]:
            value = next(v for v in spec.values if v.value == item["value"])
            assert item["score"] == spec.values[value].score
            assert item["weighted"] == round(spec.weight * spec.values[value].score, 4)


def test_normative_numbers_are_verbatim(client):
    """Несколько значений прямо из таблицы 1 — на случай, если поедет сам
    контракт: тест должен упасть, а не подстроиться под новое значение."""
    ind = _body(client)["indicators"]
    assert ind["K"]["weight"] == 0.5
    assert ind["L"]["weight"] == 0.2
    assert ind["P"]["weight"] == 0.3
    k = {v["value"]: v["score"] for v in ind["K"]["values"]}
    assert k["key_processes"] == 1.1 and k["server"] == 0.7 and k["other"] == 0.1
    h = {v["value"]: v["score"] for v in ind["H"]["values"]}
    assert h["arbitrary_code_execution"] == 0.5 and h["cross_site_scripting"] == 0.1


def test_labels_come_from_the_methodology(client):
    """Подписи — формулировки методики, а не наши пересказы."""
    labels = {v["value"]: v["label"] for v in _body(client)["indicators"]["P"]["values"]}
    assert labels["internet_facing"].startswith("Уязвимое программное")
    assert "Интернет" in labels["not_internet_facing"]


def test_levels_carry_thresholds_and_deadlines(client):
    """Таблица 2 плюс сроки п. 21 — по ним интерфейс рисует плитки."""
    levels = _body(client)["levels"]
    assert [x["key"] for x in levels] == [lv.key for lv in LEVELS]
    by_key = {x["key"]: x for x in levels}
    assert by_key["critical"] == {
        "key": "critical", "label": "Критический", "remediation": "до 24 часов",
        "min_value": 8.0, "min_inclusive": False,
    }
    assert by_key["high"]["remediation"] == "до 7 дней"
    assert by_key["low"]["min_value"] is None


def test_exploitation_default_is_reported(client):
    """Показатель E форма не спрашивает заранее: у него есть умолчание, а
    задаётся он на конкретной находке. Умолчание должно быть видно, а не
    выглядеть пропуском."""
    e = _body(client)["exploitation_default"]
    assert e["value"] == "no_information"
    assert "Отсутствуют сведения" in e["label"]
    assert e["reason"]


def test_methodology_and_formula_are_named(client):
    body = _body(client)
    assert "30.06.2025" in body["methodology"]
    assert body["formula"] == "V = I_cvss × I_infr × (I_at + I_imp)"
