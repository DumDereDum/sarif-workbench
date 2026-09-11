"""Справочные данные методики ФСТЭК для интерфейса.

Интерфейсу нужны варианты выпадающих списков — строки таблицы 1 — и подписи
уровней таблицы 2. Отдавать их из контракта, а не переписывать в вебе руками:
в проекте уже есть ручная синхронизация `web/src/lib/severity.ts` с
`swb_contract/severity.py`, и там же стоит комментарий о том, что ничто не
связывает две копии, кроме внимательности. Второй раз это повторять не надо —
тем более для нормативных значений, расхождение в которых меняет уровень
критичности в отчёте регулятору.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from sqlalchemy import func

from swb_contract.fstec import (
    I_CVSS_MAX,
    I_CVSS_MIN,
    LEVELS,
    METHODOLOGY,
    TABLE_1,
    ComponentType,
    Impact,
    IndicatorSpec,
    PerimeterExposure,
    VulnerableShare,
)

from ..criticality import (
    DEFAULT_EXPLOITATION,
    recompute_counts_by_fstec,
    recompute_project,
    recompute_rule,
)
from ..db import get_db
from ..models import Finding, Project, RuleImpact, Run, SystemProfile

router = APIRouter(prefix="/api/v1")

# Значение E, с которым находка живёт, пока сведений об эксплуатации никто
# не проставил. Отдаётся отдельно от таблицы 1, чтобы форма могла показать,
# что показатель не забыт: у него есть умолчание, и его можно переопределить
# на конкретной находке (PATCH /findings/{id}/exploitation).
_DEFAULT_EXPLOITATION = DEFAULT_EXPLOITATION


def _indicator(spec: IndicatorSpec) -> dict:
    return {
        "symbol": spec.symbol,
        "title": spec.title,
        "weight": spec.weight,
        "values": [
            {
                "value": value.value,
                "label": item.label,
                "score": item.score,
                # произведение из последнего столбца таблицы 1 — показывается
                # рядом с вариантом, чтобы выбор был осознанным
                "weighted": round(spec.weight * item.score, 4),
            }
            for value, item in spec.values.items()
        ],
    }


@router.get("/fstec/indicators")
def get_indicators() -> dict:
    """Таблицы 1 и 2 методики в виде, пригодном для построения форм."""
    return {
        "methodology": METHODOLOGY,
        "formula": "V = I_cvss × I_infr × (I_at + I_imp)",
        "indicators": {symbol: _indicator(spec) for symbol, spec in TABLE_1.items()},
        "levels": [
            {
                "key": level.key,
                "label": level.label,
                # срок устранения п. 21 — текстом, как в методике: перевод
                # «до 4 месяцев» в число дней уже допущение, а не норма
                "remediation": level.remediation,
                "min_value": level.min_value,
                "min_inclusive": level.inclusive,
            }
            for level in LEVELS
        ],
        "exploitation_default": {
            "value": _DEFAULT_EXPLOITATION.value,
            "label": TABLE_1["E"].values[_DEFAULT_EXPLOITATION].label,
            "reason": (
                "Значение по умолчанию: у находки статического анализа в "
                "собственном коде записи об эксплуатации обычно нет. Если "
                "сведения есть — из БДУ, ленты KEV или собственных данных об "
                "инцидентах, — показатель задаётся на находке со ссылкой на "
                "источник."
            ),
        },
    }


# ── Профиль информационной системы ─────────────────────────────────────────
#
# Показатели K, L и P описывают систему, а не находку, и в SARIF их нет по
# природе: анализатор видит исходный код, а не развёрнутый компонент. П. 8в
# методики берёт их из инвентаризации, поэтому заполняются вручную — один раз
# на проект, а не на каждую находку.

# Поле профиля → перечисление контракта, значения которого оно принимает.
_PROFILE_FIELDS: dict[str, type[Enum]] = {
    "component_type": ComponentType,
    "vulnerable_share": VulnerableShare,
    "perimeter_exposure": PerimeterExposure,
}


def _profile_to_dict(profile: SystemProfile | None) -> dict:
    """Профиль плюс перечень незаполненных полей.

    Пустое поле — это «не задано», а не ноль: находка с таким профилем уходит
    в «требует оценки». Список `missing` тут для того, чтобы интерфейс мог
    сказать, чего именно не хватает, не сверяя поля сам.
    """
    values = {
        field: getattr(profile, field, None) if profile else None for field in _PROFILE_FIELDS
    }
    return {
        **values,
        "missing": [field for field, value in values.items() if value is None],
        "complete": all(values.values()),
        "updated_by": profile.updated_by if profile else None,
        "updated_at": profile.updated_at.isoformat() if profile and profile.updated_at else None,
    }


def _validate(body: dict) -> dict[str, str | None]:
    """Значения из тела запроса, проверенные по перечислениям контракта.

    Неизвестное значение — 400, а не тихая запись: строка, не совпадающая с
    перечислением, позже уронит расчёт где-то далеко от места ошибки, и
    находка будет выглядеть недооценённой без объяснения. Явный `null`
    очищает поле — так профиль можно вернуть в «не заполнено».
    """
    # `updated_by` — не показатель методики, а подпись под решением, но
    # приходит тем же телом и в список неизвестных попадать не должен.
    unknown = set(body) - set(_PROFILE_FIELDS) - {"updated_by"}
    if unknown:
        raise HTTPException(400, {
            "error": "bad_request",
            "message": f"неизвестные поля профиля: {sorted(unknown)}",
        })

    cleaned: dict[str, str | None] = {}
    for field, enum_cls in _PROFILE_FIELDS.items():
        if field not in body:
            continue
        value = body[field]
        if value is None:
            cleaned[field] = None
            continue
        allowed = [member.value for member in enum_cls]
        if value not in allowed:
            raise HTTPException(400, {
                "error": "bad_request",
                "message": f"{field}: недопустимое значение {value!r}; допустимы {allowed}",
            })
        cleaned[field] = value
    return cleaned


@router.get("/projects/{project_id}/fstec-profile")
def get_profile(project_id: str, db: Session = Depends(get_db)) -> dict:
    if not db.get(Project, project_id):
        raise HTTPException(404, {"error": "not_found", "message": "Project not found"})
    return _profile_to_dict(db.get(SystemProfile, project_id))


@router.put("/projects/{project_id}/fstec-profile")
def set_profile(project_id: str, body: dict, db: Session = Depends(get_db)) -> dict:
    """Записать профиль и пересчитать находки проекта.

    Пересчёт здесь обязателен по п. 19: K, L и P входят в формулу, и после
    их изменения прежние уровни критичности недействительны.
    """
    if not db.get(Project, project_id):
        raise HTTPException(404, {"error": "not_found", "message": "Project not found"})

    cleaned = _validate(body)
    profile = db.get(SystemProfile, project_id) or SystemProfile(project_id=project_id)
    for field, value in cleaned.items():
        setattr(profile, field, value)
    # Column[T]-vs-T false positive (same class as verdicts.py:123, T-54)
    profile.updated_by = body.get("updated_by") or "human"  # type: ignore[assignment]
    profile.updated_at = datetime.utcnow()  # type: ignore[assignment]
    db.add(profile)
    db.flush()

    stats = recompute_project(db, project_id)
    # Сводка по уровням живёт на ране — пересчитывается вслед за находками,
    # иначе плитки в интерфейсе покажут вчерашнюю картину.
    for (run_id,) in db.query(Run.id).filter(Run.project_id == project_id):
        recompute_counts_by_fstec(db, run_id)
    db.commit()

    return {**_profile_to_dict(profile), "recomputed": stats}


# ── Оценки правил ──────────────────────────────────────────────────────────
#
# Показатель H и, когда анализатор не дал `security-severity`, оценка CVSS
# задаются на правило анализатора и хранятся глобально: последствие
# эксплуатации — свойство слабости, а не репозитория.
#
# Ключ (tool, rule_id) едет в теле, а не в пути: идентификаторы правил
# содержат слэши (`cpp/alloca-in-loop`, `SvEng.CXX.UNINIT.LOCAL_VAR/SvEng.U.29`),
# названия инструментов — пробелы («Semgrep OSS»). Путь пришлось бы кодировать
# на каждом клиенте, и любая ошибка кодирования молча создавала бы оценку не
# того правила. Заодно тот же обработчик принимает массовую запись.

_IMPACT_VALUES = [member.value for member in Impact]


def _rule_row(impact: RuleImpact | None, *, tool: str, rule_id: str,
              findings: int = 0, rule_name: str | None = None,
              cwes: list[str] | None = None) -> dict:
    return {
        "tool": tool,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "cwes": cwes or [],
        "findings": findings,
        "impacts": (impact.impacts if impact else None) or [],
        "not_applicable": bool(impact.not_applicable) if impact else False,
        "i_cvss": impact.i_cvss if impact else None,
        "cvss_vector": impact.cvss_vector if impact else None,
        "note": impact.note if impact else None,
        "updated_by": impact.updated_by if impact else None,
        "updated_at": (
            impact.updated_at.isoformat() if impact and impact.updated_at else None
        ),
        # Правило разобрано, если у него есть последствия либо оно признано
        # не относящимся к безопасности. Пустая оценка — это очередь.
        "assessed": bool(impact and (impact.impacts or impact.not_applicable)),
    }


@router.get("/fstec/rule-impacts")
def list_rule_impacts(
    tool: str | None = None,
    unassessed: bool = False,
    db: Session = Depends(get_db),
) -> dict:
    """Оценки правил с числом находок за каждым.

    `?unassessed=true` даёт очередь на разбор. Сортировка по числу находок:
    распределение крайне неравномерное — на замеренном корпусе десять правил
    закрывают две трети находок, а хвост из семидесяти даёт по одной-две.
    Разбирать сверху вниз — самый короткий путь к покрытию.
    """
    counts = (
        db.query(
            Run.tool.label("tool"),
            Finding.rule_id.label("rule_id"),
            func.count(Finding.id).label("n"),
            func.min(Finding.rule_name).label("rule_name"),
            func.min(Finding.id).label("sample_id"),
        )
        .join(Run, Finding.run_id == Run.id)
        .group_by(Run.tool, Finding.rule_id)
        .all()
    )
    # CWE берутся с одной представительной находки правила, а не собираются по
    # всем: у правила они одни и те же, а запрос на каждую строку очереди
    # превратил бы её открытие в сотню обращений к базе.
    cwes_by_id = {
        row.id: (row.cwes or [])
        for row in db.query(Finding.id, Finding.cwes).filter(
            Finding.id.in_([c.sample_id for c in counts] or [""])
        )
    }
    stats = {(str(c.tool), str(c.rule_id)): c for c in counts}

    impacts = {(str(r.tool), str(r.rule_id)): r for r in db.query(RuleImpact).all()}

    rows = []
    for key in impacts.keys() | stats.keys():
        t, rid = key
        if tool and t != tool:
            continue
        c = stats.get(key)
        row = _rule_row(
            impacts.get(key), tool=t, rule_id=rid,
            findings=int(c.n) if c else 0,
            rule_name=c.rule_name if c else None,
            cwes=cwes_by_id.get(c.sample_id) if c else None,
        )
        if unassessed and row["assessed"]:
            continue
        rows.append(row)

    rows.sort(key=lambda r: (-r["findings"], r["tool"], r["rule_id"]))
    return {
        "total": len(rows),
        "unassessed": sum(1 for r in rows if not r["assessed"]),
        "items": rows,
    }


def _validate_rule_body(item: dict) -> dict:
    """Одна оценка правила, проверенная по контракту."""
    tool, rule_id = item.get("tool"), item.get("rule_id")
    if not tool or not rule_id:
        raise HTTPException(400, {
            "error": "bad_request",
            "message": "tool и rule_id обязательны — это ключ оценки",
        })

    impacts = item.get("impacts") or []
    if not isinstance(impacts, list):
        raise HTTPException(400, {"error": "bad_request", "message": "impacts: ожидается список"})
    bad = [v for v in impacts if v not in _IMPACT_VALUES]
    if bad:
        raise HTTPException(400, {
            "error": "bad_request",
            "message": f"impacts: недопустимые значения {bad}; допустимы {_IMPACT_VALUES}",
        })

    i_cvss = item.get("i_cvss")
    if i_cvss is not None:
        try:
            i_cvss = float(i_cvss)
        except (TypeError, ValueError):
            raise HTTPException(400, {
                "error": "bad_request", "message": "i_cvss: ожидается число 0-10",
            }) from None
        if not (I_CVSS_MIN <= i_cvss <= I_CVSS_MAX):
            raise HTTPException(400, {
                "error": "bad_request",
                "message": f"i_cvss: базовая оценка CVSS лежит в [{I_CVSS_MIN}, {I_CVSS_MAX}]",
            })

    not_applicable = bool(item.get("not_applicable"))
    note = (item.get("note") or "").strip() or None
    # Решение «правило не про уязвимости» убирает его находки из оценки
    # целиком. Оно предъявляется аудитору вместе с обоснованием, поэтому
    # обоснование обязательно именно здесь.
    if not_applicable and not note:
        raise HTTPException(400, {
            "error": "bad_request",
            "message": "not_applicable требует note: решение исключить правило из оценки "
                       "должно быть обосновано",
        })
    if not_applicable and impacts:
        raise HTTPException(400, {
            "error": "bad_request",
            "message": "not_applicable и impacts несовместимы: либо правило не про "
                       "уязвимости, либо у него есть последствия",
        })

    return {
        "tool": str(tool), "rule_id": str(rule_id),
        "impacts": impacts or None, "not_applicable": not_applicable,
        "i_cvss": i_cvss, "cvss_vector": item.get("cvss_vector") or None,
        "note": note, "updated_by": item.get("updated_by") or "human",
    }


@router.put("/fstec/rule-impacts")
def set_rule_impacts(
    # `Any` вместо `dict | list`: FastAPI отвергает объединение как тело
    # запроса с 422 ещё до обработчика, а принимать надо и одну оценку, и
    # пачку — форма и массовый импорт ходят одним путём.
    body: Any = Body(...),
    db: Session = Depends(get_db),
) -> dict:
    """Записать одну оценку или сразу пачку и пересчитать их находки.

    Массовая запись — тем же обработчиком: так таблицу можно заполнить файлом
    и перенести на другую установку, не выдумывая второй формат.

    Пересчёт идёт по всем проектам: `rule_impacts` глобальна, и одна правка
    закрывает правило везде сразу.
    """
    items = body if isinstance(body, list) else [body]
    if not items or not all(isinstance(item, dict) for item in items):
        raise HTTPException(400, {
            "error": "bad_request",
            "message": "ожидается объект оценки или список объектов",
        })

    cleaned = [_validate_rule_body(item) for item in items]

    for data in cleaned:
        impact = db.get(RuleImpact, (data["tool"], data["rule_id"])) or RuleImpact(
            tool=data["tool"], rule_id=data["rule_id"]
        )
        for field in ("impacts", "not_applicable", "i_cvss", "cvss_vector", "note", "updated_by"):
            setattr(impact, field, data[field])
        impact.updated_at = datetime.utcnow()  # type: ignore[assignment]
        db.add(impact)
    db.flush()

    stats: dict[str, int] = {}
    touched: set[str] = set()
    for data in cleaned:
        for status, n in recompute_rule(db, data["tool"], data["rule_id"]).items():
            stats[status] = stats.get(status, 0) + n
        touched.update(
            run_id
            for (run_id,) in db.query(Finding.run_id)
            .join(Run, Finding.run_id == Run.id)
            .filter(Finding.rule_id == data["rule_id"], Run.tool == data["tool"])
            .distinct()
        )
    for run_id in touched:
        recompute_counts_by_fstec(db, run_id)
    db.commit()

    return {"saved": len(cleaned), "recomputed": stats}
