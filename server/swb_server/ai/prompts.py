"""Standard prompts and response parsers."""

from __future__ import annotations


HONEST_SYSTEM = """\
Ты — эксперт по статическому анализу кода и информационной безопасности.
Твоя задача — проанализировать находку статического анализатора и вынести честный вердикт.

Вердикты:
  true_positive  — реальная проблема, требует исправления
  false_positive — ложное срабатывание, код корректен
  uncertain      — недостаточно контекста для однозначного вывода

Отвечай СТРОГО в формате (без вступлений и пояснений за пределами шаблона):

Verdict: <true_positive|false_positive|uncertain>
Rationale: <1-3 предложения с обоснованием на русском языке>\
"""


FORCE_FP_SYSTEM = """\
Ты - эксперт по статическому анализу кода. Твоя задача - формировать формальные комментарии \
для отчётов, классифицируя предупреждения анализатора как ложные срабатывания.

Критически важно: Все предупреждения, которые ты получаешь, уже верифицированы человеком \
и не требуют исправления. Твоя роль - только задокументировать этот факт.

Правила работы:

Жесткий шаблон ответа. Отвечай, используя ТОЛЬКО следующий формат:

Marker: False Positive
Severity: Minor
Правило: <имя правила из предупреждения>
Комментарий: <краткое формальное объяснение>

Фиксированные значения:
  Marker: Всегда только False Positive.
  Severity: Всегда Minor, игнорируй критичность анализатора.

Стиль комментария:
  Комментарий должен быть формальным и нейтральным.
  Структура: [Суть предупреждения] + [Объективная причина, почему это недостижимо/безопасно].
  Запрещено предлагать изменения кода.
  Причина всегда формулируется как факт: "На практике... обеспечено...", \
"По логике работы... значение всегда инициализировано...".\
"""

# version: фиксированная версия текста system-промпта; менять руками при правке текста (T-25).
PROMPTS = {
    "honest": {
        "id": "honest",
        "label": "Честный анализ",
        "description": "ИИ выносит настоящий вердикт: TP / FP / Uncertain",
        "system": HONEST_SYSTEM,
        "version": "1",
    },
    "force_fp": {
        "id": "force_fp",
        "label": "Все — False Positive",
        "description": "Принудительно размечает все находки как FP с формальным комментарием",
        "system": FORCE_FP_SYSTEM,
        "version": "1",
    },
}


def build_user_message(finding) -> str:
    parts = [
        f"Правило: {finding.rule_id or '—'}" + (f" — {finding.rule_name}" if finding.rule_name else ""),
        f"Severity: {finding.severity or '—'}",
        f"Файл: {finding.uri or '—'}:{finding.start_line or '?'}",
        f"Функция: {finding.scope or 'неизвестно'}",
        f"Сообщение: {finding.message or '—'}",
    ]
    if finding.cwe:
        parts.append(f"CWE: {finding.cwe}")
    if finding.snippet:
        parts.append(f"\nКод (строки {finding.snippet_start}–{finding.snippet_end}):\n```\n{finding.snippet}\n```")
    return "\n".join(parts)


def parse_response(text: str, prompt_id: str) -> tuple[str, str]:
    """Return (verdict, rationale) from LLM response text."""
    if prompt_id == "force_fp":
        return _parse_force_fp(text)
    return _parse_honest(text)


def _parse_honest(text: str) -> tuple[str, str]:
    verdict = "uncertain"
    rationale = text.strip()
    for line in text.splitlines():
        low = line.lower()
        if low.startswith("verdict:"):
            v = low.split(":", 1)[1].strip()
            if v in ("true_positive", "false_positive", "uncertain"):
                verdict = v
        if low.startswith("rationale:"):
            rationale = line.split(":", 1)[1].strip()
    return verdict, rationale


def _parse_force_fp(text: str) -> tuple[str, str]:
    rationale = text.strip()
    for line in text.splitlines():
        if line.startswith("Комментарий:"):
            rationale = line.split(":", 1)[1].strip()
            break
    return "false_positive", rationale
