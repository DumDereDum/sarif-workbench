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

from sqlalchemy import func, update
from sqlalchemy.orm import Session

from .models import Finding, FindingIdentity, Run, VerdictEvent

VALID_SOURCES = {"human", "ai", "carried", "reset"}

ALL_VERDICTS = ("true_positive", "false_positive", "uncertain", "unmarked")


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
    # carried не меняет, кто принял решение по существу (T-27, ADR 0001 §6):
    # это лишь подтверждение прежнего вердикта в новом скане, поэтому снапшот
    # verdict_source остаётся тем, чем был (human/ai/reset), не "carried".
    if source != "carried":
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


def recompute_counts_by_verdict(db: Session, run_id: str) -> dict[str, int]:
    """Единственная реализация `run.counts_by_verdict` (T-32, писатель-одиночка для счётчика).

    Один агрегатный SQL-запрос (`Finding JOIN FindingIdentity, GROUP BY verdict`) —
    не Python-цикл по находкам рана. Функция не коммитит — как и `write_verdict`;
    итоговый `run.counts_by_verdict` уходит в БД одним `commit()` вызывающего кода.

    Гонка конкурентных писателей (T-32, ревью раунд 2): под SQLite bare SELECT
    (без предшествующей записи в ЭТОЙ же транзакции) не держит write-лок — он
    берёт SHARED и сразу его отпускает. Если бы агрегатный SELECT шёл первым,
    конкурентный писатель мог бы успеть write_verdict+recompute+commit
    ПОСЛЕ этого чтения, но ДО отложенного commit текущей транзакции — и наш
    поздний commit откатил бы его результат устаревшим снимком (именно так
    ловится баг: «голый» recompute без единой предшествующей записи в analyze.py
    в конце батча и в reset_verdicts на ране без единого фактически изменённого
    вердикта). Поэтому здесь, ПЕРЕД агрегатным SELECT, всегда выполняется
    самодостаточный no-op UPDATE на строку `run` — он ничего не меняет по сути
    (`counts_by_verdict = counts_by_verdict`), но заставляет SQLite сразу
    открыть write-транзакцию и взять RESERVED-лок на этом соединении. С этого
    момента либо конкурентный писатель уже успел закоммититься ДО этой строки
    (и агрегат ниже увидит его результат), либо он будет заблокирован (busy-wait,
    см. `timeout` в `db.py`) и дождётся commit'а ИМЕННО этой транзакции —
    окна для потери его записи устаревшим снимком не остаётся ни при каком
    порядке событий. Тот же приём, что неявно даёт `write_verdict`/`db.flush()`
    вызывающим до recompute (findings.py PATCH, upload_run) — здесь он взят
    самой функцией явно и безусловно, а не как побочный эффект вызывающего кода.
    """
    db.execute(update(Run).where(Run.id == run_id).values(counts_by_verdict=Run.counts_by_verdict))

    counts = {v: 0 for v in ALL_VERDICTS}
    rows = (
        db.query(FindingIdentity.verdict, func.count(Finding.id))
        .select_from(Finding)
        .join(FindingIdentity, Finding.identity_id == FindingIdentity.id)
        .filter(Finding.run_id == run_id)
        .group_by(FindingIdentity.verdict)
        .all()
    )
    for verdict, count in rows:
        counts[verdict or "unmarked"] = count

    run = db.query(Run).filter(Run.id == run_id).first()
    if run is not None:
        run.counts_by_verdict = counts
    return counts
