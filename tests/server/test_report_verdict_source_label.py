"""T-69: PDF-отчёт — колонка автора для всех реальных значений `verdict_source`.

Раньше `src_map` в `report_gen.py` мапила `verdict_source` по ключам
`"ai"`/`"manual"`, но реальные значения снапшота `identity.verdict_source` —
`human`/`ai`/`carried`/`reset` (models.py, ADR 0001 §6). Ключа `"manual"` в
данных никогда не бывает, поэтому для human-, carried- и reset-вердиктов
колонка автора в PDF всегда была пустой строкой.

Тесты покрывают функцию форматирования напрямую (`_verdict_source_label`) и
полную HTML-генерацию (`build_html`) для всех 4 значений, чтобы зафиксировать
и unit-, и сквозное поведение.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from swb_server.report_gen import _verdict_source_label, build_html

# ── Фейковые объекты для build_html (duck typing, как реальные ORM-модели) ──


def _make_identity(verdict: str, verdict_source: str | None) -> SimpleNamespace:
    return SimpleNamespace(
        verdict=verdict,
        verdict_source=verdict_source,
        rationale="Комментарий",
    )


def _make_finding(identity: SimpleNamespace, rule_id: str = "CWE-89") -> SimpleNamespace:
    return SimpleNamespace(
        identity=identity,
        rule_id=rule_id,
        severity="high",
        lang="python",
        cwe="CWE-89",
        uri="src/app.py",
        start_line=42,
        scope="handle_request",
        message="SQL injection",
        snippet=None,
        snippet_start=None,
        verdict_at=None,
    )


def _make_run() -> SimpleNamespace:
    return SimpleNamespace(
        project_id="proj-1",
        branch="main",
        commit="abc123",
        tool="TestTool",
        tool_version="1.0",
        uploaded_at=None,
        scanned_at="2026-07-17",
    )


def _make_project() -> SimpleNamespace:
    return SimpleNamespace(repo="org/repo", name="Test Project")


# ── Unit: функция форматирования ────────────────────────────────────────────


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("human", "Ручная верификация"),
        ("ai", "Автоматическая верификация"),
        ("reset", "Сброс вердикта"),
        ("carried", "Перенесено при рескане"),
    ],
)
def test_verdict_source_label_covers_real_values(source, expected):
    assert _verdict_source_label(source) == expected


def test_verdict_source_label_unknown_and_none_stay_empty():
    # None (никогда не размечено) и незнакомое значение — по-прежнему пустая
    # строка, не выдумываем подпись для того, чего нет в данных.
    assert _verdict_source_label(None) == ""
    assert _verdict_source_label("") == ""
    assert _verdict_source_label("something-else") == ""


def test_manual_key_no_longer_used():
    # Регрессия исходного бага: старый (несуществующий в реальных данных) ключ
    # "manual" не должен внезапно снова стать единственным путём к подписи.
    assert _verdict_source_label("manual") == ""


# ── Сквозной тест: build_html для всех 4 значений verdict_source ───────────


@pytest.mark.parametrize(
    ("verdict", "source", "expected_label"),
    [
        ("true_positive", "human", "Ручная верификация"),
        ("true_positive", "ai", "Автоматическая верификация"),
        ("unmarked", "reset", "Сброс вердикта"),
        ("true_positive", "carried", "Перенесено при рескане"),
    ],
)
def test_build_html_author_column_not_empty(verdict, source, expected_label):
    identity = _make_identity(verdict, source)
    finding = _make_finding(identity)
    html_out = build_html(_make_run(), _make_project(), [finding])

    assert expected_label in html_out
    # Регрессия: до фикса для human/carried/reset автор был пустой строкой —
    # убеждаемся, что колонка "Автор (дата)" реально содержит непустой текст,
    # а не просто что где-то на странице встретилась ожидаемая подпись.
    assert '<td style="white-space:pre-line">' in html_out
    cell_start = html_out.index('<td style="white-space:pre-line">') + len(
        '<td style="white-space:pre-line">'
    )
    cell_end = html_out.index("</td>", cell_start)
    author_cell_content = html_out[cell_start:cell_end]
    assert author_cell_content.strip() != ""
    assert expected_label in author_cell_content


def test_build_html_unmarked_finding_still_has_empty_author():
    # Никогда не размеченная находка (identity=None или verdict_source=None) —
    # по-прежнему пустая колонка автора, это не баг: подписывать нечего.
    identity = _make_identity("unmarked", None)
    finding = _make_finding(identity)
    html_out = build_html(_make_run(), _make_project(), [finding])

    cell_start = html_out.index('<td style="white-space:pre-line">') + len(
        '<td style="white-space:pre-line">'
    )
    cell_end = html_out.index("</td>", cell_start)
    assert html_out[cell_start:cell_end].strip() == ""
