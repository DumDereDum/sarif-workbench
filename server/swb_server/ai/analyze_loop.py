"""T-37: доменный цикл AI-триажа находок.

Выделен из `routers/analyze.py`, чтобы обход находок, вызовы провайдера,
circuit breaker и проверка отмены клиента тестировались напрямую (фейковый
провайдер + фейковый `is_disconnected`), без поднятия HTTP-стека. Модуль не
знает про SSE/HTTP-транспорт и не открывает собственную DB-сессию — `Session`
передаётся вызывающим кодом (`stream()` в `routers/analyze.py`), который также
отвечает за форматирование yield-нутых event-словарей в `data: ...\n\n`.

Инварианты, которые этот модуль обязан сохранять как есть (не переизобретать):
  - T-24: human-вердикт (кроме unmarked) не перезаписывается AI без override;
  - T-32: TOCTOU re-check identity непосредственно перед write_verdict — не
    только на входе в батч, но и после ожидания ответа LLM; единственная
    реализация подсчёта counts_by_verdict — recompute_counts_by_verdict.
"""
from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator, Awaitable, Callable

from sqlalchemy.orm import Session

from ..models import Finding, FindingIdentity
from ..verdicts import recompute_counts_by_verdict, write_verdict
from .prompts import build_user_message, parse_response
from .providers import call_llm

logger = logging.getLogger(__name__)

# T-37: без предохранителя битый ключ провайдера или лежащий провайдер означают
# перебор ВСЕХ находок, каждая — до 120s таймаута (openai_compatible.py::_TIMEOUT) —
# колоссальная трата времени впустую. После стольких подряд идущих ошибок
# провайдера (не любых ошибок вообще — именно подряд, без успеха между ними)
# цикл останавливается сам.
DEFAULT_MAX_CONSECUTIVE_ERRORS = 5


def max_consecutive_errors() -> int:
    """Порог circuit breaker; 0 или отрицательное значение — breaker выключен."""
    return int(os.environ.get("SWB_ANALYZE_MAX_CONSECUTIVE_ERRORS", DEFAULT_MAX_CONSECUTIVE_ERRORS))


# T-66: простой in-memory guard — reset во время анализа (routers/runs.py::
# reset_verdicts) оставлял ран в частично размеченном состоянии, потому что
# ничто не отслеживало "анализ этого рана сейчас идёт". Одна переменная
# модуля достаточна для однопроцессного sqlite-стека проекта (см.
# sarif-workbench-context: "SQLite check_same_thread=False... на конкурентные
# записи не рассчитано" — проект уже принимает single-process допущение);
# персистентность/межпроцессная синхронизация не нужны.
_active_runs: set[str] = set()


def is_analysis_in_progress(run_id: str) -> bool:
    return run_id in _active_runs


def load_findings_for_analysis(
    session: Session,
    run_id: str,
    *,
    only_unmarked: bool,
    override: bool,
) -> tuple[list[Finding], int]:
    """Находки для анализа + число пропущенных из-за защиты human-вердикта (T-24).

    Human-вердикт (кроме unmarked — это отсутствие решения, не защищается)
    исключается из батча, если не передан явный override.
    """
    q = session.query(Finding).filter(Finding.run_id == run_id)
    if only_unmarked:
        q = q.join(FindingIdentity, Finding.identity_id == FindingIdentity.id).filter(
            FindingIdentity.verdict == "unmarked"
        )
    findings = q.all()

    skipped_human = 0
    if not override:
        kept = []
        for f in findings:
            ident = f.identity
            if ident is not None and ident.verdict_source == "human" and ident.verdict != "unmarked":
                skipped_human += 1
            else:
                kept.append(f)
        findings = kept

    return findings, skipped_human


def _stop_message(reason: str, consecutive_errors: int, max_errors: int) -> str:
    if reason == "circuit_breaker":
        return f"Остановлено: {consecutive_errors} ошибок провайдера подряд (порог {max_errors})"
    if reason == "disconnected":
        return "Остановлено: клиент прервал соединение"
    return "Остановлено"


async def run_analysis(
    session: Session,
    run_id: str,
    findings: list[Finding],
    *,
    provider: str,
    model: str,
    system_prompt: str,
    prompt_id: str,
    prompt_version: str | None,
    override: bool,
    skipped_human: int = 0,
    is_disconnected: Callable[[], Awaitable[bool]] | None = None,
    max_errors: int | None = None,
) -> AsyncIterator[dict]:
    """Доменный цикл анализа. Yield-ит event-словари (не SSE-строки):

      start    — {"type": "start", "total": int, "skipped_human": int}
      progress — успешный вердикт по находке (или skip из-за concurrent human)
      error    — провайдер/парсинг упали на этой находке
      done     — финал; при досрочной остановке несёт "stopped_reason"
                 ("circuit_breaker" | "disconnected") и человекочитаемое "message"

    Перед КАЖДЫМ вызовом провайдера проверяется `is_disconnected()` (если
    передан) — отмена анализа клиентом реально прекращает дальнейшие вызовы
    к LLM, а не только скрывает прогресс в браузере.
    """
    # T-66: register this run as "analysis in progress" for the duration of
    # the whole generator body — including the `total == 0` early-return
    # path — so a concurrent reset (routers/runs.py::reset_verdicts) can
    # detect and refuse it (409) instead of racing partially-written
    # verdicts. `finally` runs on normal completion, an exception, AND
    # `.aclose()` (which Python calls when an `async for` consuming this
    # generator exits early, e.g. client disconnect) — the standard
    # async-generator guarantee, no extra plumbing needed.
    _active_runs.add(run_id)
    try:
        total = len(findings)

        if max_errors is None:
            max_errors = max_consecutive_errors()

        if total == 0:
            yield {
                "type": "done", "done": 0, "total": 0, "tokens_total": 0,
                "skipped_human": skipped_human, "message": "Нет находок для анализа",
            }
            return

        yield {"type": "start", "total": total, "skipped_human": skipped_human}

        tokens_total = 0
        processed = 0
        consecutive_errors = 0
        stopped_reason: str | None = None

        for idx, finding in enumerate(findings, start=1):
            if is_disconnected is not None and await is_disconnected():
                stopped_reason = "disconnected"
                logger.info(
                    "[analyze] run_id=%s client disconnected — stopping before finding %d/%d",
                    run_id, idx, total,
                )
                break

            logger.debug(
                "[analyze] [%d/%d] processing finding id=%s  rule=%s  severity=%s  %s:%s",
                idx, total, finding.id, finding.rule_id, finding.severity,
                finding.uri, finding.start_line,
            )
            try:
                user_msg = build_user_message(finding)
                logger.debug("[analyze] [%d/%d] user_message built (%d chars)", idx, total, len(user_msg))

                result = await call_llm(
                    provider=provider,
                    model=model,
                    system=system_prompt,
                    user=user_msg,
                )

                raw_content = result["content"]
                verdict, rationale = parse_response(raw_content, prompt_id)
                tokens_total += result.get("tokens", 0)
                consecutive_errors = 0  # успешный вызов провайдера сбрасывает breaker

                logger.info(
                    "[analyze] [%d/%d] finding=%s  verdict=%s  tokens_this=%d  tokens_total=%d",
                    idx, total, finding.id, verdict, result.get("tokens", 0), tokens_total,
                )
                # T-43: raw_content/rationale are LLM output built from the
                # finding's source snippet (ai/prompts.py) and can quote it back
                # verbatim — log only their length, never the text, at any level.
                logger.debug(
                    "[analyze] [%d/%d] raw_response_len=%d chars", idx, total, len(raw_content),
                )
                logger.debug(
                    "[analyze] [%d/%d] parsed  verdict=%s  rationale_len=%d chars",
                    idx, total, verdict, len(rationale),
                )

                # T-32 (остаточный риск T-24): между постановкой в очередь этой
                # находки и получением ответа LLM прошло сетевое время — за это
                # время человек мог поставить свой вердикт через PATCH. Проверка
                # verdict_source на входе в батч этого не ловит (TOCTOU):
                # перечитываем identity непосредственно перед записью, не
                # полагаясь на объект, загруженный/закэшированный на входе.
                identity = finding.identity
                if not override:
                    session.refresh(identity)
                    if identity.verdict_source == "human" and identity.verdict != "unmarked":
                        skipped_human += 1
                        processed += 1
                        logger.info(
                            "[analyze] [%d/%d] finding=%s SKIPPED — concurrent human verdict "
                            "landed while waiting on LLM response",
                            idx, total, finding.id,
                        )
                        yield {
                            "type": "progress",
                            "done": processed,
                            "total": total,
                            "tokens_total": tokens_total,
                            "finding_id": finding.id,
                            "verdict": identity.verdict,
                            "rationale": identity.rationale,
                            "skipped_human": True,
                        }
                        continue

                write_verdict(
                    session,
                    identity,
                    new_verdict=verdict,
                    source="ai",
                    actor=f"ai:{provider}/{model}",
                    rationale=rationale,
                    provider=provider,
                    model=model,
                    prompt_id=prompt_id,
                    prompt_version=prompt_version,
                    run_id=run_id,
                )

                session.commit()
                processed += 1
                logger.debug("[analyze] [%d/%d] committed to DB", idx, total)

                yield {
                    "type": "progress",
                    "done": processed,
                    "total": total,
                    "tokens_total": tokens_total,
                    "finding_id": finding.id,
                    "verdict": verdict,
                    "rationale": rationale,
                }

            except Exception as exc:
                processed += 1
                consecutive_errors += 1
                msg = str(exc)
                logger.error(
                    "[analyze] [%d/%d] FAILED finding=%s (%s:%s)  error=%s: %s  (consecutive_errors=%d/%d)",
                    idx, total, finding.id, finding.uri, finding.start_line,
                    type(exc).__name__, msg, consecutive_errors, max_errors,
                )
                yield {
                    "type": "error",
                    "done": processed,
                    "total": total,
                    "tokens_total": tokens_total,
                    "finding_id": finding.id,
                    "uri": finding.uri or "",
                    "start_line": finding.start_line or 0,
                    "message": msg,
                }

                if max_errors > 0 and consecutive_errors >= max_errors:
                    stopped_reason = "circuit_breaker"
                    logger.error(
                        "[analyze] run_id=%s circuit breaker tripped: %d consecutive provider "
                        "errors — stopping at finding %d/%d",
                        run_id, consecutive_errors, idx, total,
                    )
                    break

        # T-32: единственная реализация подсчёта — агрегатный SQL, та же транзакция.
        cvd = recompute_counts_by_verdict(session, run_id)
        session.commit()
        logger.info(
            "[analyze] DONE run_id=%s  counts=%s  tokens_total=%d  processed=%d/%d  stopped_reason=%s",
            run_id, cvd, tokens_total, processed, total, stopped_reason,
        )

        done_event: dict = {
            "type": "done",
            "done": processed,
            "total": total,
            "tokens_total": tokens_total,
            "skipped_human": skipped_human,
        }
        if stopped_reason is not None:
            done_event["stopped_reason"] = stopped_reason
            done_event["message"] = _stop_message(stopped_reason, consecutive_errors, max_errors)
        yield done_event
    finally:
        _active_runs.discard(run_id)
