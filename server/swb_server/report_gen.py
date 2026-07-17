"""PDF report generator — точный клон Svacer HTML → weasyprint."""
from __future__ import annotations

import html
from datetime import datetime
from typing import Any

# ── Helpers ───────────────────────────────────────────────────────────────────

_SEV_EN = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Minor",
    "note":     "Note",
}

_VD_LABEL = {
    "true_positive":  "True positive",
    "false_positive": "False positive",
    "uncertain":      "Uncertain",
    "unmarked":       "Не размечено",
}

# Цвет фона ячейки-вердикта (правый верхний угол карточки)
_VD_BG = {
    "true_positive":  "#8b0000",
    "false_positive": "#7b2882",
    "uncertain":      "#7a5c00",
    "unmarked":       "#555555",
}

# Подпись автора по `identity.verdict_source` (T-69). Реальные значения снапшота —
# `human`/`ai`/`reset` (см. models.py, ADR 0001 §6); ключа `"manual"`, который был
# здесь раньше, среди них никогда не бывает, поэтому для human/carried/reset
# колонка автора в PDF всегда была пустой строкой. `"carried"` в этой карте — чисто
# защитный случай: после T-27 `write_verdict` не пишет `"carried"` в снапшот
# identity.verdict_source (пропускает обновление, снапшот остаётся тем, чем был —
# human/ai), так что это значение сюда в норме не долетает; журнал verdict_events
# честно хранит `source="carried"` отдельно и наружу здесь не смотрит (report_gen
# получает только identity-снапшот, не события). Подпись оставлена на случай любых
# иных путей записи (регрессия, прямая правка БД) — не пустая строка вместо неё.
_VERDICT_SOURCE_LABEL = {
    "human":   "Ручная верификация",
    "ai":      "Автоматическая верификация",
    "reset":   "Сброс вердикта",
    "carried": "Перенесено при рескане",
}


def _verdict_source_label(source: str | None) -> str:
    return _VERDICT_SOURCE_LABEL.get(source or "", "")


def _h(s: str | None) -> str:
    return html.escape(str(s or ""))


def _fmt_date(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%d.%m.%Y %H:%M")
    except Exception:
        return iso[:16]


def _short_uri(uri: str | None) -> str:
    if not uri:
        return "—"
    return uri


# ── CSS (точный Svacer) ───────────────────────────────────────────────────────

_CSS = """
@page {
    size: A4;
    margin: 15mm 15mm 20mm 15mm;
    @bottom-right {
        content: counter(page) " из " counter(pages);
        font-family: 'DejaVu Serif', 'Liberation Serif', Times, serif;
        font-size: 8pt;
        color: #666;
    }
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'DejaVu Serif', 'Liberation Serif', Times, serif;
    font-size: 10pt;
    color: #000;
    line-height: 1.4;
}

/* ══ COVER ══ */
.cover {
    page-break-after: always;
    padding: 30pt 0 0;
}
.cover-org {
    font-size: 10pt;
    color: #444;
    margin-bottom: 6pt;
}
.cover-title {
    font-size: 22pt;
    font-weight: bold;
    margin-bottom: 32pt;
    margin-top: 40pt;
    text-align: center;
    text-transform: uppercase;
    letter-spacing: 1.5pt;
}
.cover-meta {
    width: 100%;
    border-collapse: collapse;
    font-size: 10pt;
}
.cover-meta td {
    border: 1px solid #bbb;
    padding: 6pt 10pt;
}
.cover-meta td:first-child {
    width: 38%;
    background: #eef1f5;
    font-weight: bold;
    color: #2a3a4a;
}
.cover-footer {
    margin-top: 40pt;
    font-size: 8.5pt;
    color: #999;
    text-align: center;
    border-top: 1px solid #ccc;
    padding-top: 10pt;
}

/* ══ TOC ══ */
.toc { page-break-after: always; }
.toc-title {
    font-size: 14pt;
    font-weight: bold;
    border-bottom: 2px solid #000;
    padding-bottom: 6pt;
    margin-bottom: 14pt;
}
.toc-row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    padding: 4pt 0;
    border-bottom: 1px dotted #ccc;
    font-size: 9.5pt;
    gap: 8pt;
}
.toc-num  { color: #555; min-width: 18pt; flex-shrink: 0; }
.toc-name { flex: 1; }
.toc-vd   {
    font-size: 8pt; padding: 1pt 7pt; white-space: nowrap;
    flex-shrink: 0; color: #fff; font-weight: bold;
}

/* ══ FINDING PAGE ══ */
.finding { page-break-before: always; }

/* Заголовок: "1. RULE_ID" */
.finding-heading {
    font-size: 13pt;
    font-weight: bold;
    margin-bottom: 10pt;
}

/* Таблица 1: Язык | Серьёзность | Надёжность | CWE */
.t-meta {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 8pt;
    font-size: 10pt;
}
.t-meta th {
    background: #8a9dae;
    color: #fff;
    font-weight: bold;
    text-align: center;
    border: 1px solid #5a7080;
    padding: 5pt 8pt;
}
.t-meta td {
    background: #fff;
    border: 1px solid #5a7080;
    text-align: center;
    padding: 5pt 8pt;
}

/* Таблица 2: детали + код */
.t-details {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 8pt;
    font-size: 10pt;
}
.t-details td {
    border: 1px solid #5a7080;
    vertical-align: top;
    padding: 4pt 6pt;
}

/* Строка «Позиция» + вердикт */
.pos-cell {
    background: #8a9dae;
    color: #000;
    font-style: italic;
    font-weight: bold;
    width: 74%;
    padding: 5pt 8pt;
}
.verdict-cell {
    color: #fff;
    font-weight: bold;
    text-align: center;
    vertical-align: middle;
    width: 26%;
    padding: 5pt 8pt;
    line-height: 1.4;
}

/* Строки полей (Метки, Функция, ...) */
.field-label {
    background: #c8d4de;
    width: 22%;
    padding: 4pt 8pt;
    font-size: 9.5pt;
    vertical-align: top;
}
.field-value {
    background: #fff;
    padding: 4pt 8pt;
    font-size: 9.5pt;
    vertical-align: top;
}

/* Ячейка с кодом (colspan=2) */
.code-cell {
    background: #fff;
    padding: 8pt 4pt 8pt 0;
}

/* Код внутри ячейки */
.code-inner {
    font-family: 'DejaVu Sans Mono', 'Liberation Mono', 'Courier New', monospace;
    font-size: 8.5pt;
    line-height: 1.7;
}
.code-row { display: flex; }
.code-row.hot { background: #ffffc0; }
.code-ln {
    min-width: 36pt;
    text-align: right;
    padding-right: 10pt;
    color: #777;
    flex-shrink: 0;
    font-size: 8.5pt;
}
.code-row.hot .code-ln { color: #555; }
.code-src { white-space: pre; color: #000; }

/* Таблица 3: Автор + Комментарий */
.t-author {
    width: 100%;
    border-collapse: collapse;
    font-size: 10pt;
}
.t-author th {
    background: #8a9dae;
    color: #fff;
    font-weight: bold;
    text-align: center;
    border: 1px solid #5a7080;
    padding: 5pt 8pt;
}
.t-author td {
    border: 1px solid #5a7080;
    padding: 5pt 8pt;
    vertical-align: top;
}
.t-author td:first-child {
    width: 20%;
    white-space: nowrap;
}
"""


# ── Cover ─────────────────────────────────────────────────────────────────────

def _cover(run: Any, project: Any, total: int) -> str:
    repo  = getattr(project, "repo", None) or getattr(run, "project_id", "—")
    name  = getattr(project, "name", None) or repo
    branch   = run.branch or "—"
    commit   = run.commit or "—"
    tool     = run.tool or "SARIF Workbench"
    tool_ver = run.tool_version or ""
    uploaded = _fmt_date(run.uploaded_at.isoformat() if run.uploaded_at else None)
    scanned  = run.scanned_at or "—"

    return f"""
<div class="cover">
  <div class="cover-org">{_h(name)}</div>
  <div class="cover-title">Отчёт о результатах<br>статического анализа кода</div>
  <table class="cover-meta">
    <tr><td>Проект</td><td>{_h(name)}</td></tr>
    <tr><td>Репозиторий</td><td>{_h(repo)}</td></tr>
    <tr><td>Ветка</td><td>{_h(branch)}</td></tr>
    <tr><td>Коммит</td><td>{_h(commit)}</td></tr>
    <tr><td>Инструмент анализа</td><td>{_h(tool)}{(" " + _h(tool_ver)) if tool_ver else ""}</td></tr>
    <tr><td>Дата сканирования</td><td>{_h(str(scanned))}</td></tr>
    <tr><td>Дата создания отчёта</td><td>{_h(uploaded)}</td></tr>
    <tr><td>Всего находок</td><td>{total}</td></tr>
  </table>
  <div class="cover-footer">SARIF Workbench · Конфиденциально · Для служебного пользования</div>
</div>
"""


# ── TOC ───────────────────────────────────────────────────────────────────────

def _toc(findings: list[Any]) -> str:
    rows = ""
    for i, f in enumerate(findings, 1):
        vd  = (f.identity.verdict if f.identity else None) or "unmarked"
        lbl = _VD_LABEL.get(vd, vd)
        bg  = _VD_BG.get(vd, "#555")
        rows += f"""
<div class="toc-row">
  <span class="toc-num">{i}.</span>
  <span class="toc-name">{_h(f.rule_id or "—")}</span>
  <span class="toc-vd" style="background:{bg}">{_h(lbl)}</span>
</div>"""

    return f"""
<div class="toc">
  <div class="toc-title">Содержание</div>
  {rows}
</div>
"""


# ── Code block ────────────────────────────────────────────────────────────────

def _code_rows(f: Any) -> str:
    if not f.snippet:
        return ""
    start   = f.snippet_start or f.start_line or 1
    hot_ln  = f.start_line or start
    lines   = f.snippet.splitlines()

    out = ""
    for idx, line in enumerate(lines):
        lineno = start + idx
        cls    = "code-row hot" if lineno == hot_ln else "code-row"
        out   += f'<div class="{cls}"><span class="code-ln">{lineno}</span><span class="code-src">{_h(line)}</span></div>\n'
    return out


# ── Finding page ──────────────────────────────────────────────────────────────

def _finding_page(f: Any, idx: int, total: int) -> str:
    # --- базовые данные --- (вердикт живёт на identity — T-14)
    identity = f.identity
    vd      = (identity.verdict if identity else None) or "unmarked"
    vd_lbl  = _VD_LABEL.get(vd, vd)
    vd_bg   = _VD_BG.get(vd, "#555555")

    sev_raw = (f.severity or "note").lower()
    sev_lbl = _SEV_EN.get(sev_raw, sev_raw.capitalize())

    lang    = (f.lang or "—").upper()
    cwe     = f.cwe or ""
    uri     = f.uri or "—"
    loc     = f"{uri}:{f.start_line}" if f.start_line else uri
    scope   = f.scope or ""
    message = f.message or "—"

    # verdict + severity в ячейке-вердикте
    vd_cell_text = f"{_h(vd_lbl)}<br>({_h(sev_lbl)})"

    # Автор / дата / источник
    vd_at  = _fmt_date(f.verdict_at.isoformat() if getattr(f, "verdict_at", None) else None)
    author  = _verdict_source_label(identity.verdict_source if identity else None)
    author_cell = author
    if vd_at:
        author_cell += f"\n({vd_at})"

    rationale = (identity.rationale if identity else None) or "—"

    # --- heading ---
    heading = f"{idx}. {_h(f.rule_id or '—')}"

    # --- кодовый блок ---
    code_rows = _code_rows(f)
    code_block = f'<div class="code-inner">{code_rows}</div>' if code_rows else ""

    # --- Строка «Функция» ---
    fn_row = (
        f'<tr><td class="field-label">Функция</td><td class="field-value">{_h(scope)}</td></tr>'
        if scope else ""
    )

    return f"""
<div class="finding">
  <div class="finding-heading">{heading}</div>

  <!-- Таблица 1: Язык | Серьёзность | Надёжность | CWE -->
  <table class="t-meta">
    <thead>
      <tr>
        <th>Язык</th>
        <th>Серьёзность</th>
        <th>Надёжность</th>
        <th>CWE</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>{_h(lang)}</td>
        <td>{_h(sev_lbl)}</td>
        <td>Unknown</td>
        <td>{_h(cwe)}</td>
      </tr>
    </tbody>
  </table>

  <!-- Таблица 2: позиция + поля + код -->
  <table class="t-details">
    <!-- строка: Позиция | Вердикт -->
    <tr>
      <td class="pos-cell">Позиция: {_h(loc)}</td>
      <td class="verdict-cell" style="background:{vd_bg}">{vd_cell_text}</td>
    </tr>
    <!-- Метки -->
    <tr>
      <td class="field-label">Метки</td>
      <td class="field-value"></td>
    </tr>
    {fn_row}
    <!-- Исходная функция -->
    {'<tr><td class="field-label">Исходная функция</td><td class="field-value">' + _h(scope) + '</td></tr>' if scope else ''}
    <!-- Сообщение об ошибке -->
    <tr>
      <td class="field-label">Сообщение об ошибке</td>
      <td class="field-value">{_h(message)}</td>
    </tr>
    <!-- Код -->
    <tr>
      <td class="code-cell" colspan="2">
        {code_block}
      </td>
    </tr>
  </table>

  <!-- Таблица 3: Автор + Комментарий -->
  <table class="t-author">
    <thead>
      <tr>
        <th>Автор (дата)</th>
        <th>Комментарий</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td style="white-space:pre-line">{_h(author_cell.strip())}</td>
        <td>{_h(rationale)}</td>
      </tr>
    </tbody>
  </table>
</div>
"""


# ── Entry points ──────────────────────────────────────────────────────────────

def build_html(run: Any, project: Any, findings: list[Any]) -> str:
    cover = _cover(run, project, len(findings))
    toc   = _toc(findings)
    pages = "".join(
        _finding_page(f, i, len(findings)) for i, f in enumerate(findings, 1)
    )

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<style>
{_CSS}
</style>
</head>
<body>
{cover}
{toc}
{pages}
</body>
</html>"""


def generate_pdf(run: Any, project: Any, findings: list[Any]) -> bytes:
    import weasyprint

    return weasyprint.HTML(string=build_html(run, project, findings)).write_pdf()
