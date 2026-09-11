"""Расчёт уровня критичности находки по методике ФСТЭК от 30.06.2025.

Мост между находкой в базе и чистым ядром `swb_contract.fstec`: собирает
шесть показателей из трёх источников и зовёт `assess()`. Формулы, таблицы и
пороги здесь не дублируются — они целиком в контракте.

Откуда берётся каждый показатель
--------------------------------
    I_cvss  переопределение на identity → RuleImpact.i_cvss → Finding.security_severity
    H       переопределение на identity → RuleImpact.impacts
    E       FindingIdentity.fstec_exploitation → «отсутствуют сведения»
    K,L,P   SystemProfile проекта

`I_cvss` приходит из отчёта только там, где анализатор дал
`security-severity`: CodeQL проставляет его своим security-запросам, Svacer
и Bandit не дают никогда, у реестровых правил Semgrep его нет. Остальным
оценку задаёт специалист на правиле.

`E` задаётся на находке и по умолчанию равен «отсутствуют сведения об
эксплуатации в реальных атаках (наличии эксплойта)». Это не подстановка, а
строка таблицы 1: для находки статического анализа в собственном коде записи
об эксплуатации обычно нет нигде. Но она бывает — у организации с подпиской
на БДУ, лентой KEV или собственными данными об инцидентах, — и тогда
показатель проставляется вручную со ссылкой на источник. Значение живёт на
identity: оно относится к уязвимости и переживает повторный скан так же, как
вердикт.

Три статуса
-----------
    assessed          расчёт выполнен
    needs_assessment  какого-то показателя нет; какого именно — в `missing`
    not_applicable    правило помечено человеком как «не уязвимость», либо
                      находка признана ложным срабатыванием

Первые два — из контракта, они про достаточность данных. Третий серверный:
контракт про применимость правил не знает.

Статус `not_applicable` ставится ТОЛЬКО по явному решению человека. Вывести
его из отсутствия CWE нельзя — измерено: так молча выпали бы 944 находки
корпуса, включая все 124 у Bandit, который CWE не отдаёт вовсе, оставаясь
при этом линтером безопасности.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import func, update
from sqlalchemy.orm import Session

from swb_contract.fstec import (
    FSTEC_LEVEL_ORDER,
    METHODOLOGY,
    ComponentType,
    CriticalityAssessment,
    CvssSource,
    Exploitation,
    Impact,
    PerimeterExposure,
    VulnerableShare,
    assess,
    level_for,
)

# Умолчание для находки, которой сведений об эксплуатации не проставляли.
# Не пропуск и не заглушка: «отсутствуют сведения» — законное значение
# таблицы 1, и для находки в собственном коде оно обычно истинно.
DEFAULT_EXPLOITATION = Exploitation.NO_INFORMATION

NOT_APPLICABLE = "not_applicable"

# Вердикт, при котором уязвимости нет, а значит нечего и оценивать.
_FALSE_POSITIVE = "false_positive"


def _enum_or_none(cls: type, value: str | None) -> Any:
    """Значение перечисления контракта по строке из базы.

    Неизвестная строка — это не «не задано», а рассогласование базы с
    контрактом, и молча превращать её в None нельзя: показатель исчез бы из
    расчёта, а находка выглядела бы недооценённой без всякого следа.
    """
    if value is None:
        return None
    try:
        return cls(value)
    except ValueError as exc:
        raise ValueError(f"{cls.__name__}: неизвестное значение {value!r} в базе") from exc


def resolve_indicators(
    finding: Any,
    identity: Any,
    profile: Any,
    rule_impact: Any,
) -> dict:
    """Собрать аргументы `assess()` из находки, профиля ИС и оценки правила.

    Порядок источников `I_cvss` — от частного к общему: оценка, выставленная
    для этой находки, важнее оценки правила, а та важнее числа из отчёта.
    Метка источника едет вместе со значением: в отчёте регулятору должно
    быть видно, кем оценка дана.
    """
    i_cvss: float | None = None
    source: CvssSource | None = None

    override = getattr(identity, "fstec_i_cvss", None) if identity is not None else None
    if override is not None:
        i_cvss, source = float(override), CvssSource.MANUAL_FINDING
    elif rule_impact is not None and rule_impact.i_cvss is not None:
        i_cvss, source = float(rule_impact.i_cvss), CvssSource.MANUAL_RULE
    elif finding.security_severity is not None:
        i_cvss, source = float(finding.security_severity), CvssSource.SARIF_SECURITY_SEVERITY

    impacts: list[Impact] | None = None
    raw_impacts = getattr(identity, "fstec_impacts", None) if identity is not None else None
    if not raw_impacts and rule_impact is not None:
        raw_impacts = rule_impact.impacts
    if raw_impacts:
        impacts = [_enum_or_none(Impact, v) for v in raw_impacts]

    # E: проставленное человеком значение важнее умолчания. Правило максимума
    # (п. 16) методика применяет к списку сведений; источник у нас один, но
    # список сохраняем — так же, как для K и L.
    raw_exploitation = getattr(identity, "fstec_exploitation", None) if identity is not None else None
    exploitation = _enum_or_none(Exploitation, raw_exploitation) or DEFAULT_EXPLOITATION

    component = _enum_or_none(ComponentType, getattr(profile, "component_type", None))
    share = _enum_or_none(VulnerableShare, getattr(profile, "vulnerable_share", None))
    perimeter = _enum_or_none(PerimeterExposure, getattr(profile, "perimeter_exposure", None))

    return {
        "i_cvss": i_cvss,
        "i_cvss_source": source,
        # K и L методика принимает списками (правило максимума пп. 15, 2.8),
        # но профиль задаёт по одному значению на проект: разбиение системы
        # на компоненты — отдельная задача, и до неё список из одного
        # элемента честнее, чем выдуманные несколько.
        "component_types": [component] if component else None,
        "vulnerable_share": [share] if share else None,
        "perimeter_exposure": perimeter,
        "exploitation": [exploitation],
        "impact": impacts,
    }


def is_applicable(finding: Any, identity: Any, rule_impact: Any) -> bool:
    """Есть ли вообще что оценивать.

    Оценивается уязвимость. Если правило признано не относящимся к
    безопасности или находка разобрана как ложное срабатывание, уровень
    критичности для неё бессмыслен — и «Низкий» здесь был бы неправдой.
    """
    if rule_impact is not None and rule_impact.not_applicable:
        return False
    verdict = getattr(identity, "verdict", None) if identity is not None else None
    return verdict != _FALSE_POSITIVE


def assess_finding(
    finding: Any,
    identity: Any,
    profile: Any,
    rule_impact: Any,
) -> tuple[str, CriticalityAssessment | None]:
    """Статус находки и результат расчёта, если он выполнялся.

    Возвращает `(NOT_APPLICABLE, None)`, когда оценивать нечего, — тогда
    вызывающий обнуляет `fstec_v` и `fstec_level`, а не оставляет прежние.
    """
    if not is_applicable(finding, identity, rule_impact):
        return NOT_APPLICABLE, None
    result = assess(**resolve_indicators(finding, identity, profile, rule_impact))
    return result.status, result


def apply_assessment(finding: Any, status: str, result: CriticalityAssessment | None) -> None:
    """Записать результат в колонки находки.

    `v` и `level` обнуляются, когда расчёт не выполнялся: устаревшее
    значение рядом со статусом «требует оценки» читалось бы как оценка.
    """
    finding.fstec_status = status
    finding.fstec_v = result.v if result else None
    finding.fstec_level = result.level if result else None
    finding.fstec_missing = list(result.missing) if result and result.missing else None


# ── Пересчёт ───────────────────────────────────────────────────────────────
#
# Пункт 19 методики требует пересчитывать уровень критичности при появлении
# новых сведений об уязвимости. Входов три, и каждый меняется в своей точке:
# профиль ИС, оценка правила, загрузка нового прогона. Функции ниже не
# коммитят — как `write_verdict` и `recompute_counts_by_verdict`; коммитит
# вызывающий код, одной транзакцией со своей записью.
#
# `swb_server.models` импортируется внутри функций, а не наверху модуля:
# `models` тянет за собой `db`, а тот создаёт engine прямо при импорте, из
# переменных окружения. Модульный импорт зафиксировал бы движок на этапе
# сбора тестов, до того как харнесс уведёт базу во временный каталог (та же
# причина, по которой отложены импорты в `tests/server/conftest.py`).
# Побочная польза: половина модуля, собирающая показатели, остаётся чистой
# и импортируется без базы вовсе.


def _recompute(db: Session, findings: Sequence[Any]) -> dict[str, int]:
    """Пересчитать переданные находки.

    Справочники читаются один раз на всю пачку: на прогоне в 1339 находок
    запрос на каждую был бы заметен.
    """
    from .models import RuleImpact, Run, SystemProfile  # noqa: PLC0415 — см. выше

    if not findings:
        return {}

    runs = {
        str(r.id): (str(r.project_id), r.tool or "unknown")
        for r in db.query(Run.id, Run.project_id, Run.tool).all()
    }
    profiles = {
        str(r.project_id): r
        for r in db.query(SystemProfile)
        .filter(SystemProfile.project_id.in_({p for p, _ in runs.values()} or [""]))
        .all()
    }
    impacts = {(str(r.tool), str(r.rule_id)): r for r in db.query(RuleImpact).all()}

    stats: dict[str, int] = {}
    for f in findings:
        project_id, tool = runs.get(str(f.run_id), ("", "unknown"))
        rule_impact = impacts.get((tool, str(f.rule_id or "")))
        status, result = assess_finding(f, f.identity, profiles.get(project_id), rule_impact)
        apply_assessment(f, status, result)
        stats[status] = stats.get(status, 0) + 1
    return stats


def recompute_finding(db: Session, finding: Any) -> dict[str, int]:
    """После смены вердикта — только эта находка.

    Вердикт «ложное срабатывание» переводит находку в «не применимо»: уровень
    критичности для несуществующей уязвимости бессмыслен. Обратная смена
    возвращает её в расчёт.
    """
    return _recompute(db, [finding])


def recompute_identity(db: Session, identity_id: str) -> dict[str, int]:
    """После правки показателя на находке — все её наблюдения в проекте.

    Одна identity живёт во всех прогонах проекта, где находка встретилась
    (ADR 0001 §6). Пересчитать только открытую в карточке строку значило бы
    оставить в прошлых прогонах прежний уровень при том же самом показателе.
    """
    from .models import Finding  # noqa: PLC0415 — см. выше

    return _recompute(db, db.query(Finding).filter(Finding.identity_id == identity_id).all())


def recompute_run(db: Session, run_id: str) -> dict[str, int]:
    """После загрузки прогона — его находки."""
    from .models import Finding  # noqa: PLC0415 — см. выше

    return _recompute(db, db.query(Finding).filter(Finding.run_id == run_id).all())


def recompute_project(db: Session, project_id: str) -> dict[str, int]:
    """После записи профиля ИС — все находки проекта: K, L и P у них общие."""
    from .models import Finding, Run  # noqa: PLC0415 — см. выше

    findings = (
        db.query(Finding)
        .join(Run, Finding.run_id == Run.id)
        .filter(Run.project_id == project_id)
        .all()
    )
    return _recompute(db, findings)


def recompute_rule(db: Session, tool: str, rule_id: str) -> dict[str, int]:
    """После записи оценки правила — его находки во ВСЕХ проектах.

    `rule_impacts` глобальна: последствие эксплуатации не зависит от
    репозитория, поэтому одна правка закрывает правило везде сразу.
    """
    from .models import Finding, Run  # noqa: PLC0415 — см. выше

    findings = (
        db.query(Finding)
        .join(Run, Finding.run_id == Run.id)
        .filter(Finding.rule_id == rule_id, Run.tool == tool)
        .all()
    )
    return _recompute(db, findings)


# ── Выдача ─────────────────────────────────────────────────────────────────


def summary(finding: Any) -> dict:
    """Краткий блок для списка находок — из сохранённых колонок, без расчёта.

    Уровень и срок берутся из `level_for(v)`, а не хранятся отдельно: они
    производные от V, и вторая копия в базе разошлась бы с ним при первом же
    изменении порогов методики.
    """
    v = finding.fstec_v
    level = level_for(v) if v is not None else None
    return {
        "status": finding.fstec_status or "needs_assessment",
        "v": v,
        "level": level.key if level else None,
        "level_label": level.label if level else None,
        # Рекомендуемый срок устранения (п. 21) — текстом, как в методике.
        "remediation": level.remediation if level else None,
        "missing": list(finding.fstec_missing or ()),
        "methodology": METHODOLOGY,
    }


def describe(db: Session, finding: Any) -> dict:
    """Полный блок для карточки находки — с разложением расчёта.

    Разложение считается заново, а не читается из базы: это чистая функция
    от входов, и сохранённая копия разошлась бы с ними при первом же
    пересчёте. Стоит один вызов `assess()` на открытие карточки.

    По разложению аудитор видит не только итог, но и каждый показатель, его
    вес, произведение и — для K, L, E, H — какие значения отброшены правилом
    максимума пп. 15-17. Плюс метку источника I_cvss: пришла оценка из
    отчёта, проставлена для правила или для этой находки.
    """
    from .models import RuleImpact, Run, SystemProfile  # noqa: PLC0415 — см. выше

    block = summary(finding)

    run = db.get(Run, finding.run_id)
    profile = db.get(SystemProfile, run.project_id) if run else None
    rule_impact = (
        db.get(RuleImpact, ((run.tool or "unknown"), finding.rule_id or ""))
        if run
        else None
    )

    status, result = assess_finding(finding, finding.identity, profile, rule_impact)
    block["status"] = status
    block["breakdown"] = result.breakdown if result else None
    if result is not None:
        block["missing"] = list(result.missing)
    # Правило признано не относящимся к безопасности или находка разобрана
    # как ложное срабатывание — перечислять недостающие показатели незачем.
    if status == NOT_APPLICABLE:
        block["missing"] = []
    return block


# ── Счётчики ───────────────────────────────────────────────────────────────


# Порядок сводки: уровни методики сверху вниз, затем две группы находок, по
# которым расчёта не было.
COUNTS_KEYS: tuple[str, ...] = (*FSTEC_LEVEL_ORDER, "needs_assessment", NOT_APPLICABLE)


def recompute_counts_by_fstec(db: Session, run_id: str) -> dict[str, int]:
    """Единственная реализация `run.counts_by_fstec`.

    Один агрегатный SQL-запрос, не Python-цикл по находкам рана. Функция не
    коммитит — коммитит вызывающий, одной транзакцией со своей записью.

    Перед агрегатом выполняется самодостаточный no-op UPDATE строки `run` —
    тот же приём и по той же причине, что подробно разобрана в
    `verdicts.recompute_counts_by_verdict`: под SQLite голый SELECT не держит
    write-лок, и без этого UPDATE конкурентный писатель мог бы закоммититься
    между нашим чтением и нашим отложенным commit, а мы затёрли бы его
    результат устаревшим снимком.

    Находка без уровня попадает в группу своего статуса, а не пропадает:
    сумма по сводке обязана сходиться с общим числом находок рана, иначе
    «требует оценки» выглядит как ноль находок, а не как незакрытая работа.
    """
    from .models import Finding, Run  # noqa: PLC0415 — см. выше

    # Сессия живёт с `autoflush=False` (db.py), а `_recompute` меняет находки
    # в памяти — без сброса агрегат ниже прочитал бы состояние до пересчёта и
    # сводка отстала бы ровно на одну запись.
    db.flush()
    db.execute(update(Run).where(Run.id == run_id).values(counts_by_fstec=Run.counts_by_fstec))

    counts = dict.fromkeys(COUNTS_KEYS, 0)
    rows = (
        db.query(Finding.fstec_status, Finding.fstec_level, func.count(Finding.id))
        .filter(Finding.run_id == run_id)
        .group_by(Finding.fstec_status, Finding.fstec_level)
        .all()
    )
    for status, level, count in rows:
        key = level if status == "assessed" and level else (status or "needs_assessment")
        counts[key] = counts.get(key, 0) + count

    run = db.query(Run).filter(Run.id == run_id).first()
    if run is not None:
        run.counts_by_fstec = counts  # type: ignore[assignment]
    return counts
