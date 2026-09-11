"""Уровень критичности и срок устранения в PDF-отчёте.

Отчёт предъявляется регулятору, поэтому проверяется не только присутствие
уровня, но и то, без чего документ вводит в заблуждение:

  (а) на обложке названа методика, по которой считалось;
  (б) на обложке видно, заполнен ли профиль ИС — без него расчёт не
      выполнялся ни для одной находки, и сводка «уязвимостей высокого
      уровня нет» была бы неправдой;
  (в) сводка по уровням на обложке;
  (г) на странице находки уровень и рекомендуемый срок устранения (п. 21);
  (д) у находки без оценки колонка срока пуста, а не «Низкий».

Проверяется HTML (`build_html`), а не байты PDF: рендер в PDF — дело
weasyprint, а содержание документа наше.
"""
from __future__ import annotations

from types import SimpleNamespace

from swb_server.report_gen import build_html


def _finding(**kw):
    return SimpleNamespace(
        id="f-1", rule_id="R-1", rule_name="R-1", rule_description="",
        help_uri=None, cwe="CWE-89", severity="high", message="msg",
        uri="src/a.py", start_line=1, end_line=None, scope=None,
        snippet=None, snippet_start=None, snippet_end=None, lang="python",
        code_flow=[], extra_locations=[], related_locations=[], git=None,
        identity=SimpleNamespace(verdict="unmarked", verdict_source=None, rationale=None),
        fstec_status=kw.get("status", "needs_assessment"),
        fstec_level=kw.get("level"), fstec_v=kw.get("v"),
        fstec_missing=kw.get("missing"),
    )


def _run():
    return SimpleNamespace(branch="master", commit="abc1234", tool="TestTool",
                           tool_version="1.0", uploaded_at=None, scanned_at=None,
                           project_id="p")


def _project(profile=None):
    return SimpleNamespace(repo="repo", name="Проект", fstec_profile=profile)


def _full_profile():
    return SimpleNamespace(component_type="server", vulnerable_share="under_10",
                           perimeter_exposure="not_internet_facing")


# ── (а) методика названа ───────────────────────────────────────────────────


def test_cover_names_the_methodology():
    html = build_html(_run(), _project(), [_finding()])
    assert "30.06.2025" in html


# ── (б) отметка о профиле ──────────────────────────────────────────────────


def test_cover_warns_when_profile_is_not_filled():
    """Без профиля расчёт не выполнялся ни для одной находки. Отчёт без этой
    оговорки читался бы как «уязвимостей высокого уровня нет»."""
    html = build_html(_run(), _project(profile=None), [_finding()])
    assert "НЕ ЗАПОЛНЕН" in html


def test_cover_marks_a_filled_profile():
    html = build_html(_run(), _project(_full_profile()), [_finding()])
    assert "НЕ ЗАПОЛНЕН" not in html
    assert "заполнен" in html


def test_partial_profile_counts_as_unfilled():
    """Два поля из трёх — расчёт всё равно не идёт."""
    partial = SimpleNamespace(component_type="server", vulnerable_share="under_10",
                              perimeter_exposure=None)
    assert "НЕ ЗАПОЛНЕН" in build_html(_run(), _project(partial), [_finding()])


# ── (в) сводка по уровням ──────────────────────────────────────────────────


def test_cover_summarises_levels():
    findings = [
        _finding(status="assessed", level="high", v=6.4),
        _finding(status="assessed", level="high", v=5.9),
        _finding(status="assessed", level="low", v=1.2),
        _finding(),
    ]
    html = build_html(_run(), _project(_full_profile()), findings)
    assert "Высокий — 2" in html
    assert "Низкий — 1" in html
    assert "Требует оценки — 1" in html


# ── (г) уровень и срок на странице находки ─────────────────────────────────


def test_finding_page_shows_level_and_deadline():
    html = build_html(_run(), _project(_full_profile()),
                      [_finding(status="assessed", level="medium", v=3.7)])
    assert "Критичность ФСТЭК" in html
    assert "Средний" in html
    assert "V=3.7" in html
    # срок устранения п. 21 — то, ради чего уровень считается
    assert "до 4 недель" in html


def test_deadline_matches_the_level():
    html = build_html(_run(), _project(_full_profile()),
                      [_finding(status="assessed", level="high", v=6.4)])
    assert "до 7 дней" in html


# ── (д) пустая оценка не притворяется уровнем ──────────────────────────────


def test_unassessed_finding_has_no_deadline():
    """Пробел в данных не должен читаться как утверждение о системе."""
    html = build_html(_run(), _project(), [_finding()])
    assert "Требует оценки" in html
    for deadline in ("до 24 часов", "до 7 дней", "до 4 недель", "до 4 месяцев"):
        assert deadline not in html


def test_not_applicable_finding_is_labelled():
    html = build_html(_run(), _project(_full_profile()),
                      [_finding(status="not_applicable")])
    assert "Не применимо" in html
