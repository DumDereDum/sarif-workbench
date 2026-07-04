"""Единственная точка записи вердикта (ADR 0001 §6, писатель-одиночка).

Снапшот на FindingIdentity и append-only событие в verdict_events пишутся
только вместе и только здесь. Все пути записи вердикта — PATCH (human),
AI-разметка, carried (T-21) и reset — обязаны идти через write_verdict.
Функция не коммитит: снапшот и событие уходят в БД одной транзакцией
вызывающего кода.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from .models import FindingIdentity, VerdictEvent

VALID_SOURCES = {"human", "ai", "carried", "reset"}


def write_verdict(
    db: Session,
    identity: FindingIdentity,
    *,
    new_verdict: str,
    source: str,
    actor: str,
    rationale: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    prompt_id: str | None = None,
    prompt_version: str | None = None,
    run_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> VerdictEvent:
    """Атомарно обновить снапшот вердикта на identity и дописать событие журнала.

    old_verdict события берётся из текущего снапшота identity. Событие
    append-only: никакой код не изменяет и не удаляет записи verdict_events.
    """
    if source not in VALID_SOURCES:
        raise ValueError(f"source must be one of {sorted(VALID_SOURCES)}, got {source!r}")

    old_verdict = identity.verdict or "unmarked"

    event = VerdictEvent(
        identity_id=identity.id,
        at=datetime.utcnow(),
        source=source,
        actor=actor,
        old_verdict=old_verdict,
        new_verdict=new_verdict,
        rationale=rationale,
        provider=provider,
        model=model,
        prompt_id=prompt_id,
        prompt_version=prompt_version,
        run_id=run_id,
        payload=payload,
    )
    db.add(event)

    # Снапшот текущего состояния (денормализация; источник истины — события)
    identity.verdict = new_verdict
    identity.verdict_source = source
    identity.rationale = rationale
    if source == "ai":
        identity.provider = provider
        identity.model = model
        identity.prompt_id = prompt_id
        identity.prompt_version = prompt_version
        identity.needs_reconfirm = False
    elif source == "reset":
        identity.provider = None
        identity.model = None
        identity.prompt_id = None
        identity.prompt_version = None
        identity.needs_reconfirm = False
    # human/carried: атрибуты последнего AI-вердикта на снапшоте не трогаем

    db.flush()
    return event
