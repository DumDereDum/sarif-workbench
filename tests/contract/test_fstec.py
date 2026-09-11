"""swb_contract.fstec — расчёт уровня критичности по методике ФСТЭК от 30.06.2025.

Проверяется:
  (а) оба примера из приложения к методике воспроизводятся число в число;
  (б) границы таблицы 2 — включая те, где методика разрывает диапазоны
      несимметрично (V > 8,0 критический, но 5,0 ≤ V ≤ 8,0 высокий, то есть
      ровно 8,0 — это «Высокий», а не «Критический»);
  (в) правило максимума для K, L, E, H;
  (г) потолок шкалы при E = «нет сведений об эксплуатации» — 6,48, уровень
      «Критический» недостижим по построению (свойство методики, не баг);
  (д) незаданный показатель → «требует оценки», без подстановки умолчаний;
  (е) I_cvss вне диапазона 0–10 → ошибка, а не тихая нормализация;
  (ж) шкала уровней ФСТЭК отделена от severity-шкалы SARIF.
"""
from __future__ import annotations

import pytest

from swb_contract.fstec import (
    FSTEC_LEVEL_ORDER,
    LEVELS,
    ComponentType,
    CriticalityAssessment,
    CvssSource,
    Exploitation,
    Impact,
    PerimeterExposure,
    VulnerableShare,
    assess,
    level_for,
    level_label,
)
from swb_contract.severity import SEV_ORDER


def _assess(**overrides) -> CriticalityAssessment:
    """Полный набор входных данных примера 2, с точечными подменами."""
    kwargs = dict(
        i_cvss=9.8,
        i_cvss_source=CvssSource.SARIF_SECURITY_SEVERITY,
        component_types=[ComponentType.KEY_PROCESSES],
        vulnerable_share=[VulnerableShare.OVER_70],
        perimeter_exposure=PerimeterExposure.INTERNET_FACING,
        exploitation=[Exploitation.EXPLOIT_AVAILABLE],
        impact=[Impact.ARBITRARY_CODE_EXECUTION],
    )
    kwargs.update(overrides)
    return assess(**kwargs)


# ── (а) примеры из приложения к методике ───────────────────────────────────


def test_appendix_example_1():
    """Пример 1: I_cvss=8,8; I_infr=0,9; I_at+I_imp=0,6 → V=4,75, «Средний»."""
    r = assess(
        i_cvss=8.8,
        i_cvss_source=CvssSource.MANUAL_RULE,
        component_types=[ComponentType.FIREWALL],  # 0,9
        vulnerable_share=[VulnerableShare.FROM_10_TO_50],  # 0,6
        perimeter_exposure=PerimeterExposure.INTERNET_FACING,  # 1,1
        exploitation=[Exploitation.NO_INFORMATION],  # 0,1
        impact=[Impact.ARBITRARY_CODE_EXECUTION],  # 0,5
    )
    assert r.status == "assessed"
    assert r.breakdown["i_infr"]["value"] == 0.9
    assert r.breakdown["i_at"]["value"] == 0.1
    assert r.breakdown["i_imp"]["value"] == 0.5
    assert r.v == 4.75  # 8,8 × 0,9 × 0,6 = 4,752
    assert r.level == "medium"
    assert r.level_label == "Средний"
    assert r.remediation == "до 4 недель"


def test_appendix_example_2():
    """Пример 2: I_cvss=9,8; I_infr=1,08; I_at+I_imp=0,8 → V=8,47, «Критический»."""
    r = assess(
        i_cvss=9.8,
        i_cvss_source=CvssSource.MANUAL_RULE,
        component_types=[ComponentType.KEY_PROCESSES],  # 1,1
        # правило максимума: из четырёх долей уязвимых компонентов берётся большая
        vulnerable_share=[
            VulnerableShare.UNDER_10,
            VulnerableShare.FROM_10_TO_50,
            VulnerableShare.FROM_50_TO_70,
            VulnerableShare.OVER_70,  # 1,0 — максимум
        ],
        perimeter_exposure=PerimeterExposure.INTERNET_FACING,  # 1,1
        exploitation=[Exploitation.EXPLOIT_AVAILABLE],  # 0,3
        impact=[Impact.ARBITRARY_CODE_EXECUTION],  # 0,5
    )
    assert r.status == "assessed"
    assert r.breakdown["i_infr"]["value"] == 1.08
    assert r.breakdown["i_at"]["value"] == 0.3
    assert r.breakdown["i_imp"]["value"] == 0.5
    assert r.v == 8.47  # 9,8 × 1,08 × 0,8 = 8,4672
    assert r.level == "critical"
    assert r.level_label == "Критический"
    assert r.remediation == "до 24 часов"


# ── (б) границы таблицы 2 ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "v,expected",
    [
        (10.0, "critical"),
        (8.01, "critical"),
        (8.0, "high"),  # граница 8,0 принадлежит «Высокому»: V > 8,0 критический
        (7.99, "high"),
        (5.0, "high"),  # 5,0 ≤ V ≤ 8,0
        (4.99, "medium"),
        (2.0, "medium"),  # 2,0 ≤ V < 5,0
        (1.99, "low"),  # V < 2,0
        (0.0, "low"),
    ],
)
def test_level_boundaries(v, expected):
    assert level_for(v).key == expected


def test_levels_table_is_ordered_and_complete():
    assert FSTEC_LEVEL_ORDER == ("critical", "high", "medium", "low")
    assert [lv.key for lv in LEVELS] == list(FSTEC_LEVEL_ORDER)
    # Последний уровень открыт снизу, иначе level_for может не найти уровень.
    assert LEVELS[-1].min_value is None
    assert level_label("high") == "Высокий"


# ── (в) правило максимума ──────────────────────────────────────────────────


def test_max_rule_for_component_type():
    r = _assess(component_types=[ComponentType.OTHER, ComponentType.KEY_PROCESSES])
    term = r.breakdown["i_infr"]["terms"][0]
    assert term["symbol"] == "K"
    assert term["value"] == ComponentType.KEY_PROCESSES.value
    assert term["score"] == 1.1
    # Отброшенные значения остаются в breakdown — иначе из отчёта не видно,
    # что вообще подавалось на вход.
    assert {c["value"] for c in term["candidates"]} == {"other", "key_processes"}


def test_max_rule_for_vulnerable_share():
    r = _assess(
        vulnerable_share=[VulnerableShare.UNDER_10, VulnerableShare.FROM_50_TO_70]
    )
    term = r.breakdown["i_infr"]["terms"][1]
    assert term["symbol"] == "L"
    assert term["value"] == VulnerableShare.FROM_50_TO_70.value
    assert term["score"] == 0.8


def test_max_rule_for_exploitation():
    r = _assess(exploitation=[Exploitation.NO_INFORMATION, Exploitation.IN_THE_WILD])
    term = r.breakdown["i_at"]["term"]
    assert term["value"] == Exploitation.IN_THE_WILD.value
    assert term["score"] == 0.6


def test_max_rule_for_impact():
    r = _assess(
        impact=[
            Impact.CROSS_SITE_SCRIPTING,
            Impact.PRIVILEGE_ESCALATION,
            Impact.DOS,
        ]
    )
    term = r.breakdown["i_imp"]["term"]
    assert term["value"] == Impact.PRIVILEGE_ESCALATION.value
    assert term["score"] == 0.5


def test_max_rule_does_not_depend_on_order():
    forward = _assess(component_types=[ComponentType.OTHER, ComponentType.SERVER])
    backward = _assess(component_types=[ComponentType.SERVER, ComponentType.OTHER])
    assert forward.v == backward.v


# ── (г) потолок шкалы: «Критический» недостижим при E = 0,1 ────────────────


def test_scale_ceiling_without_exploitation_info():
    """Максимум всего по каждому показателю, но без сведений об эксплуатации.

    10 × 1,08 × (0,1 + 0,5) = 6,48 — «Высокий». Это структурное свойство
    методики (она рассчитана на уязвимости с записью в БДУ), а не дефект
    расчёта: для находки SAST в собственном коде E = 0,1 — нормальное
    состояние, и уровень «Критический» при нём недостижим.
    """
    r = assess(
        i_cvss=10.0,
        i_cvss_source=CvssSource.SARIF_SECURITY_SEVERITY,
        component_types=[ComponentType.KEY_PROCESSES],
        vulnerable_share=[VulnerableShare.OVER_70],
        perimeter_exposure=PerimeterExposure.INTERNET_FACING,
        exploitation=[Exploitation.NO_INFORMATION],
        impact=[Impact.ARBITRARY_CODE_EXECUTION],
    )
    assert r.v == 6.48
    assert r.level == "high"


# ── (д) незаданные показатели → «требует оценки» ───────────────────────────


@pytest.mark.parametrize(
    "override,missing",
    [
        ({"i_cvss": None}, "i_cvss"),
        ({"i_cvss_source": None}, "i_cvss_source"),
        ({"component_types": None}, "K"),
        ({"component_types": []}, "K"),  # пустой список — тоже «не задан»
        ({"vulnerable_share": None}, "L"),
        ({"perimeter_exposure": None}, "P"),
        ({"exploitation": []}, "E"),
        ({"impact": None}, "H"),
    ],
)
def test_missing_indicator_needs_assessment(override, missing):
    r = _assess(**override)
    assert r.status == "needs_assessment"
    assert r.missing == (missing,)
    # Ничего не досчитывается и не подставляется по умолчанию.
    assert r.v is None
    assert r.level is None
    assert r.breakdown is None


def test_missing_lists_every_unset_indicator():
    r = assess(
        i_cvss=None,
        i_cvss_source=None,
        component_types=None,
        vulnerable_share=None,
        perimeter_exposure=None,
        exploitation=None,
        impact=None,
    )
    assert r.status == "needs_assessment"
    # i_cvss_source не попадает в список: пока нет самого i_cvss, спрашивать
    # про его источник нечего.
    assert r.missing == ("i_cvss", "K", "L", "P", "E", "H")


# ── (е) валидация I_cvss ───────────────────────────────────────────────────


@pytest.mark.parametrize("bad", [-0.1, 10.1, 100.0, -1.0])
def test_i_cvss_out_of_range_raises(bad):
    with pytest.raises(ValueError, match="i_cvss"):
        _assess(i_cvss=bad)


@pytest.mark.parametrize("ok", [0.0, 10.0, 5.5])
def test_i_cvss_range_bounds_are_inclusive(ok):
    assert _assess(i_cvss=ok).status == "assessed"


@pytest.mark.parametrize("source,expected", [
    (CvssSource.SARIF_SECURITY_SEVERITY, "sarif_security_severity"),
    (CvssSource.MANUAL_RULE, "manual_rule"),
    (CvssSource.MANUAL_FINDING, "manual_finding"),
])
def test_i_cvss_source_is_recorded_in_breakdown(source, expected):
    """Метка источника обязана доехать до разложения: по ней аудитор видит,
    оценка пришла из отчёта, проставлена для класса находок или для этой."""
    r = _assess(i_cvss_source=source)
    assert r.breakdown["i_cvss"] == {"value": 9.8, "source": expected}


def test_cvss_source_has_no_cwe_derived_value():
    """Вывести базовую оценку CVSS из CWE нельзя: внутри одного класса
    оценки в БДУ расходятся от 0,0 до 10,0. Источник, которого не бывает,
    не должен существовать и в перечислении."""
    assert {s.value for s in CvssSource} == {
        "sarif_security_severity", "manual_rule", "manual_finding",
    }


def test_zero_i_cvss_still_computes():
    """V = 0 — это «Низкий», а не «нет оценки»: показатель задан."""
    r = _assess(i_cvss=0.0)
    assert r.status == "assessed"
    assert r.v == 0.0
    assert r.level == "low"


# ── (ж) шкала ФСТЭК не смешивается со шкалой severity ──────────────────────


def test_fstec_levels_are_separate_from_sarif_severity():
    assert FSTEC_LEVEL_ORDER != SEV_ORDER
    assert len(FSTEC_LEVEL_ORDER) == 4
    assert "note" not in FSTEC_LEVEL_ORDER
