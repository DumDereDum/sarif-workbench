"""Сборка показателей методики ФСТЭК и расчёт уровня критичности находки.

`criticality.py` — мост между базой и чистым ядром `swb_contract.fstec`.
Формулы здесь не проверяются, они покрыты `tests/contract/test_fstec.py`;
проверяется то, за что отвечает мост:

  (а) приоритет источников I_cvss: находка → правило → отчёт;
  (б) метка источника едет вместе со значением — по ней аудитор видит,
      кем оценка дана;
  (в) H берётся с правила, переопределение находки главнее;
  (г) E всегда «отсутствуют сведения об эксплуатации»;
  (д) K, L, P берутся из профиля проекта;
  (е) незаданный показатель → «требует оценки» с точным перечнем
      недостающих, без подстановки умолчаний;
  (ж) «не применимо» — только по явному решению человека: помеченное
      правило или разобранное ложное срабатывание. Никогда не из
      отсутствия CWE: так молча выпали бы 944 находки корпуса, включая
      все 124 у Bandit, который CWE не отдаёт вовсе;
  (з) при статусе без расчёта прежние v и level обнуляются.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from swb_contract.fstec import CvssSource
from swb_server.criticality import (
    NOT_APPLICABLE,
    apply_assessment,
    assess_finding,
    is_applicable,
    resolve_indicators,
)


def _finding(security_severity=None, rule_id="R"):
    return SimpleNamespace(security_severity=security_severity, rule_id=rule_id,
                           fstec_v=None, fstec_level=None,
                           fstec_status=None, fstec_missing=None)


def _identity(verdict="unmarked", i_cvss=None, impacts=None):
    return SimpleNamespace(verdict=verdict, fstec_i_cvss=i_cvss, fstec_impacts=impacts)


def _profile(component="server", share="under_10", perimeter="not_internet_facing"):
    return SimpleNamespace(component_type=component, vulnerable_share=share,
                           perimeter_exposure=perimeter)


def _impact(impacts=None, i_cvss=None, not_applicable=False):
    return SimpleNamespace(impacts=impacts, i_cvss=i_cvss, not_applicable=not_applicable)


# ── (а)-(б) приоритет источников I_cvss ────────────────────────────────────


def test_i_cvss_from_report_when_nothing_overrides():
    ind = resolve_indicators(_finding(security_severity=9.3), _identity(), _profile(), _impact())
    assert ind["i_cvss"] == 9.3
    assert ind["i_cvss_source"] is CvssSource.SARIF_SECURITY_SEVERITY


def test_rule_assessment_outranks_report():
    """Специалист оценил правило — его число важнее числа анализатора."""
    ind = resolve_indicators(_finding(security_severity=9.3), _identity(),
                             _profile(), _impact(i_cvss=5.0))
    assert (ind["i_cvss"], ind["i_cvss_source"]) == (5.0, CvssSource.MANUAL_RULE)


def test_finding_override_outranks_rule():
    ind = resolve_indicators(_finding(security_severity=9.3), _identity(i_cvss=7.1),
                             _profile(), _impact(i_cvss=5.0))
    assert (ind["i_cvss"], ind["i_cvss_source"]) == (7.1, CvssSource.MANUAL_FINDING)


def test_no_i_cvss_anywhere_leaves_it_unset():
    """Svacer и Bandit оценки не дают — подставлять нечего и нельзя."""
    ind = resolve_indicators(_finding(), _identity(), _profile(), _impact())
    assert ind["i_cvss"] is None and ind["i_cvss_source"] is None


# ── (в) показатель H ───────────────────────────────────────────────────────


def test_impacts_come_from_rule():
    ind = resolve_indicators(_finding(), _identity(), _profile(),
                             _impact(impacts=["dos", "loss_of_integrity"]))
    assert [i.value for i in ind["impact"]] == ["dos", "loss_of_integrity"]


def test_finding_impacts_override_rule():
    ind = resolve_indicators(_finding(), _identity(impacts=["arbitrary_code_execution"]),
                             _profile(), _impact(impacts=["dos"]))
    assert [i.value for i in ind["impact"]] == ["arbitrary_code_execution"]


# ── (г) показатель E ───────────────────────────────────────────────────────


def test_exploitation_is_always_no_information():
    """Для находки статического анализа в собственном коде записи в БДУ не
    существует — это истинное утверждение, а не умолчание."""
    ind = resolve_indicators(_finding(), _identity(), _profile(), _impact())
    assert [e.value for e in ind["exploitation"]] == ["no_information"]


# ── (д) профиль ИС ─────────────────────────────────────────────────────────


def test_profile_supplies_k_l_p():
    ind = resolve_indicators(_finding(), _identity(),
                             _profile("key_processes", "over_70", "internet_facing"), _impact())
    assert [c.value for c in ind["component_types"]] == ["key_processes"]
    assert [s.value for s in ind["vulnerable_share"]] == ["over_70"]
    assert ind["perimeter_exposure"].value == "internet_facing"


def test_unknown_profile_value_raises_instead_of_silently_dropping():
    """Рассогласование базы с контрактом — ошибка, а не «не задано»: иначе
    показатель исчез бы из расчёта без всякого следа."""
    with pytest.raises(ValueError, match="неизвестное значение"):
        resolve_indicators(_finding(), _identity(), _profile(component="сервер"), _impact())


# ── (е) «требует оценки» ───────────────────────────────────────────────────


def test_full_data_computes():
    status, result = assess_finding(_finding(security_severity=9.8), _identity(),
                                    _profile("key_processes", "over_70", "internet_facing"),
                                    _impact(impacts=["arbitrary_code_execution"]))
    assert status == "assessed"
    # 9.8 × 1.08 × (0.1 + 0.5) = 6.35
    assert result.v == pytest.approx(6.35, abs=0.01)
    assert result.level == "high"


def test_missing_profile_lists_exactly_k_l_p():
    """Отчёт CodeQL: оценка есть, последствия заданы — не хватает только
    сведений о системе."""
    status, result = assess_finding(_finding(security_severity=9.3), _identity(),
                                    None, _impact(impacts=["dos"]))
    assert status == "needs_assessment"
    assert set(result.missing) == {"K", "L", "P"}


def test_svacer_shaped_finding_misses_i_cvss_too():
    """У Svacer security-severity нет ни у одного правила из 66."""
    status, result = assess_finding(_finding(), _identity(), None, _impact())
    assert status == "needs_assessment"
    assert set(result.missing) == {"i_cvss", "K", "L", "P", "H"}


# ── (ж) «не применимо» ─────────────────────────────────────────────────────


def test_rule_marked_not_applicable_is_not_assessed():
    status, result = assess_finding(_finding(security_severity=9.8), _identity(),
                                    _profile(), _impact(impacts=["dos"], not_applicable=True))
    assert status == NOT_APPLICABLE and result is None


def test_false_positive_is_not_assessed():
    """Уязвимости нет — уровень критичности для неё бессмыслен."""
    status, result = assess_finding(_finding(security_severity=9.8),
                                    _identity(verdict="false_positive"),
                                    _profile(), _impact(impacts=["dos"]))
    assert status == NOT_APPLICABLE and result is None


@pytest.mark.parametrize("verdict", ["unmarked", "true_positive", "uncertain"])
def test_other_verdicts_are_assessed(verdict):
    assert is_applicable(_finding(), _identity(verdict=verdict), _impact()) is True


def test_absent_cwe_alone_does_not_make_finding_inapplicable():
    """Ключевое: у Bandit CWE нет ни у одного правила, а он линтер
    безопасности. Отсутствие классификации — не решение о неприменимости."""
    assert is_applicable(_finding(), _identity(), _impact(impacts=None)) is True


# ── (з) запись результата ──────────────────────────────────────────────────


def test_apply_clears_stale_values_when_not_computed():
    """Прежний уровень рядом со статусом «требует оценки» читался бы как
    оценка."""
    f = _finding()
    f.fstec_v, f.fstec_level = 6.35, "high"
    apply_assessment(f, NOT_APPLICABLE, None)
    assert (f.fstec_v, f.fstec_level, f.fstec_status) == (None, None, NOT_APPLICABLE)


def test_apply_writes_missing_list():
    f = _finding()
    status, result = assess_finding(f, _identity(), None, _impact())
    apply_assessment(f, status, result)
    assert f.fstec_status == "needs_assessment"
    assert "K" in f.fstec_missing
