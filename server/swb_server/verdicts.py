"""Единственная точка записи вердикта (ADR 0001 §6, писатель-одиночка).

Снапшот на FindingIdentity и append-only событие в verdict_events пишутся
только вместе и только здесь. Все пути записи вердикта — PATCH (human),
AI-разметка, carried (T-21) и reset — обязаны идти через write_verdict.
Функция не коммитит: снапшот и событие уходят в БД одной транзакцией
вызывающего кода.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from sqlalchemy import func, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session
from swb_contract.verdict import VERDICT_ORDER

from .models import Finding, FindingIdentity, Run, VerdictEvent

VALID_SOURCES = {"human", "ai", "carried", "reset"}

# Алиас сохранён ради потребителей `verdicts.ALL_VERDICTS` (T-34: единственный
# источник значений — swb_contract.verdict.VERDICT_ORDER).
ALL_VERDICTS = VERDICT_ORDER


class VersionConflict(Exception):
    """T-38 (review round 2): `expected_version` не совпала с текущей версией
    identity В МОМЕНТ атомарного условного UPDATE (не Python-сравнением
    заранее прочитанного значения — см. docstring write_verdict). Кто-то
    другой уже записал сюда что-то своё между тем, как клиент читал версию,
    и этим вызовом. Вызывающий код (PATCH) обязан поймать и вернуть 409 с
    актуальным состоянием, не 500 и не молчаливую перезапись.
    """

    def __init__(self, identity_id: str):
        super().__init__(f"version conflict on FindingIdentity {identity_id}")
        self.identity_id = identity_id


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
    expected_version: int | None = None,
) -> VerdictEvent:
    """Атомарно обновить снапшот вердикта на identity и дописать событие журнала.

    old_verdict события берётся из текущего снапшота identity. Событие
    append-only: никакой код не изменяет и не удаляет записи verdict_events.

    `expected_version` (T-38) — оптимистическая блокировка для клиент-
    инициированной записи (сейчас единственный вызывающий — human PATCH,
    routers/findings.py::update_verdict). Round 1 этой задачи проверял
    версию Python-сравнением ДО вызова write_verdict, отдельно от записи —
    ревью round 2 эмпирически воспроизвёл через настоящую конкурентность
    (два потока, не строго последовательные HTTP-вызовы), что это давало
    TOCTOU-окно: оба потока успевали пройти сравнение, пока ни один ещё не
    закоммитился, и оба получали 200 — ровно тот lost-update баг, который
    T-38 должен был закрыть. Фикс: если `expected_version` передан, версия
    проверяется и инкрементируется ОДНИМ атомарным условным UPDATE
    (`WHERE id=... AND version=expected_version`) здесь, в самом начале, ДО
    того как строится VerdictEvent или меняется любое другое поле снапшота.
    `rowcount == 0` означает, что строка в БД реально была изменена другим
    писателем между моментом, когда клиент прочитал `expected_version`, и
    этим вызовом, — обнаруживается по факту на уровне БД, а не по устаревшей
    Python-переменной. В этом случае выбрасывается VersionConflict и НИЧЕГО
    не пишется (ни снапшот, ни append-only событие) — проигравший запрос не
    оставляет в истории событие с несогласованным before/after переходом.
    Вызовы без `expected_version` (carried/reset/AI-цикл — доверенные
    системные пути, не CAS клиента) инкрементируют версию безусловно, как
    было до этого исправления.
    """
    if source not in VALID_SOURCES:
        raise ValueError(f"source must be one of {sorted(VALID_SOURCES)}, got {source!r}")

    if expected_version is not None:
        # T-38 review round 3 (mypy dependency-aware, `uv run --with mypy
        # --project server mypy server/swb_server`): под bare `uvx mypy` (без
        # установленных зависимостей — команда из SKILL.md) SQLAlchemy-типы
        # резолвятся в Any и маскируют реальные несоответствия; с
        # установленными стабами `Session.execute()` на ORM-enabled UPDATE
        # статически типизируется как `Result[Any]`, а `.rowcount` объявлен
        # только на `CursorResult` (реальный рантайм-тип для DML с курсором —
        # именно он и возвращается здесь). `cast` — не рантайм-конверсия,
        # только подсказка типа для mypy, поведение не меняет.
        result = cast(
            CursorResult,
            db.execute(
                update(FindingIdentity)
                .where(FindingIdentity.id == identity.id, FindingIdentity.version == expected_version)
                .values(version=expected_version + 1)
            ),
        )
        if result.rowcount == 0:
            raise VersionConflict(str(identity.id))
        # CAS прошёл: строка гарантированно была на expected_version вплоть
        # до этого UPDATE (version монотонно растёт и никогда не откатывается
        # назад — см. докстринг выше), поэтому уже загруженный в память
        # identity.verdict/verdict_source/... гарантированно совпадает с тем,
        # что реально лежит в БД прямо сейчас — можно безопасно строить
        # old_verdict и остальной снапшот из него, без дополнительного SELECT.
        #
        # Присваивание int классическому Column[int]-атрибуту (модели этого
        # проекта — Column()-стиль без Mapped[], не типизируются мимо Any) —
        # тот же класс false positive, что и на ~13 других присваиваний
        # identity.* ниже по этому файлу (известный долг, T-54); ТЕ строки
        # существовали на HEAD и не в объёме T-38, поэтому не трогаются. Эта
        # и следующая (в безусловной ветке инкремента ниже) — новые
        # относительно HEAD, поэтому глушатся точечно, а не оставляются
        # half-fixed.
        identity.version = expected_version + 1  # type: ignore[assignment]

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
    # Присваивания identity.* ниже — тот же Column[T]-vs-T false positive, что
    # и на строке 123 выше (см. комментарий там); T-54 глушит их точечно, не
    # трогая рантайм-поведение.
    identity.verdict = new_verdict  # type: ignore[assignment]
    # carried не меняет, кто принял решение по существу (T-27, ADR 0001 §6):
    # это лишь подтверждение прежнего вердикта в новом скане, поэтому снапшот
    # verdict_source остаётся тем, чем был (human/ai/reset), не "carried".
    if source != "carried":
        identity.verdict_source = source  # type: ignore[assignment]
    identity.rationale = rationale  # type: ignore[assignment]
    if source == "ai":
        identity.provider = provider  # type: ignore[assignment]
        identity.model = model  # type: ignore[assignment]
        identity.prompt_id = prompt_id  # type: ignore[assignment]
        identity.prompt_version = prompt_version  # type: ignore[assignment]
        identity.needs_reconfirm = False  # type: ignore[assignment]
    elif source == "reset":
        identity.provider = None  # type: ignore[assignment]
        identity.model = None  # type: ignore[assignment]
        identity.prompt_id = None  # type: ignore[assignment]
        identity.prompt_version = None  # type: ignore[assignment]
        identity.needs_reconfirm = False  # type: ignore[assignment]
    # human/carried: атрибуты последнего AI-вердикта на снапшоте не трогаем

    if expected_version is None:
        # T-38: версия для оптимистической блокировки — бьётся на КАЖДОЙ
        # записи (не только human), чтобы конкурентный PATCH от человека
        # получал 409, если состояние успело измениться под ним хоть по
        # какой причине (в т.ч. AI/carried/reset), а не только от другого
        # человека. Когда expected_version передан, инкремент уже сделан
        # атомарно выше вместе с проверкой — здесь его делать ещё раз нельзя
        # (задвоило бы версию за один вызов).
        #
        # `int(...)` защищает от None (свежая identity до первого flush);
        # # type: ignore[assignment] — тот же Column[int]-vs-int false
        # positive, что и на строке CAS-присваивания выше (review round 3,
        # новая относительно HEAD; см. комментарий там для полного контекста).
        identity.version = int(identity.version or 1) + 1  # type: ignore[assignment]

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
        run.counts_by_verdict = counts  # type: ignore[assignment]
    return counts
