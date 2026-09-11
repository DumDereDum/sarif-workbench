"""Расчёт уровня критичности уязвимости по методике ФСТЭК от 30.06.2025.

Формула (п. 12):

    V = I_cvss × I_infr × (I_at + I_imp)

    I_infr = k·K + l·L + p·P   (п. 14)
    I_at   = e·E               (п. 16)
    I_imp  = h·H               (п. 17)

ВАЖНО: шкала уровней здесь — своя, четырёхуровневая (`FSTEC_LEVEL_ORDER`), и
она НЕ связана с пятиуровневой `SEV_ORDER` из `severity.py`. Это разные вещи:
severity — оценка правила SAST-инструментом, уровень критичности ФСТЭК —
оценка уязвимости применительно к конкретной информационной системе.

Свойство шкалы: при E = «отсутствуют сведения об
эксплуатации» (0,1 — нормальное состояние находки в собственном коде,
на которую нет записи в БДУ) потолок V равен

    10 × 1,08 × (0,1 + 0,5) = 6,48

то есть уровень «Критический» (V > 8,0) недостижим по построению. Методика
рассчитана на уязвимости со сведениями об эксплуатации, а не на результаты
статического анализа. Это фиксируется тестом; подгонять коэффициенты под
ожидаемое распределение нельзя — они нормативные.

Методика обновляется (редакция от 28.10.2022 отменена этой, п. 6), поэтому
все числа заведены как данные в `TABLE_1` / `LEVELS` и правятся там, не
затрагивая логику расчёта.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal, Mapping, Sequence

METHODOLOGY = "Методика оценки уровня критичности уязвимостей ПО, ФСТЭК России, 30.06.2025"

# Знаков после запятой для промежуточных значений в breakdown. Служит ровно
# одной цели — убрать шум двоичного представления float (0,5 × 1,1 в Python
# даёт 0.55000000000000004), чтобы разложение расчёта было предъявимо
# аудитору. Все произведения из таблицы 1 укладываются максимум в 3 знака,
# так что округление до 4 для них не теряет ничего. Итоговое V считается по
# НЕокруглённым значениям и округляется отдельно, до 2 знаков (см. `assess`).
_BREAKDOWN_PRECISION = 4

# Знаков после запятой для итоговой оценки V. Сравнение с порогами таблицы 2
# выполняется по округлённому значению.
_V_PRECISION = 2


# ── Показатели: перечисления значений (таблица 1) ───────────────────────────


class ComponentType(Enum):
    """K — тип компонента ИС, подверженного уязвимости (таблица 1, строка 1)."""

    KEY_PROCESSES = "key_processes"
    FIREWALL = "firewall"
    NETWORK_DEVICE = "network_device"
    TELECOM = "telecom"
    SERVER = "server"
    WORKSTATION = "workstation"
    STORAGE = "storage"
    OTHER = "other"


class VulnerableShare(Enum):
    """L — количество уязвимых компонентов ИС (таблица 1, строка 2)."""

    OVER_70 = "over_70"
    FROM_50_TO_70 = "from_50_to_70"
    FROM_10_TO_50 = "from_10_to_50"
    UNDER_10 = "under_10"


class PerimeterExposure(Enum):
    """P — влияние на эффективность защиты периметра ИС (таблица 1, строка 3)."""

    INTERNET_FACING = "internet_facing"
    NOT_INTERNET_FACING = "not_internet_facing"


class Exploitation(Enum):
    """E — эксплуатация уязвимости (таблица 1, строка 4)."""

    IN_THE_WILD = "in_the_wild"
    EXPLOIT_AVAILABLE = "exploit_available"
    NO_INFORMATION = "no_information"


class Impact(Enum):
    """H — последствия воздействий при эксплуатации уязвимости (таблица 1, строка 5)."""

    ARBITRARY_CODE_EXECUTION = "arbitrary_code_execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SECURITY_BYPASS = "security_bypass"
    CODE_INJECTION = "code_injection"
    OBTAIN_SENSITIVE_INFORMATION = "obtain_sensitive_information"
    LOSS_OF_INTEGRITY = "loss_of_integrity"
    DOS = "dos"
    OVERWRITE_ARBITRARY_FILES = "overwrite_arbitrary_files"
    WRITE_LOCAL_FILES = "write_local_files"
    READ_LOCAL_FILES = "read_local_files"
    SPOOF_USER_INTERFACE = "spoof_user_interface"
    CROSS_SITE_SCRIPTING = "cross_site_scripting"


class CvssSource(Enum):
    """Происхождение значения I_cvss.

    Модуль не вычисляет I_cvss сам (п. 13 — базовая оценка CVSS 3.1 берётся из
    БДУ/иных баз либо определяется специалистом), но обязан перенести метку
    источника в breakdown: без неё непонятно, откуда взялась цифра в отчёте.

    Ручная оценка разделена на две: аудитору важно, дана она для класса
    находок или для этой конкретной. Оценка правила — приближение того же
    рода, что и `security-severity` (он тоже константа правила: все находки
    одного запроса CodeQL получают одно число); оценка находки — точная.

    Источника «вывести из CWE» здесь нет намеренно. Проверено на выгрузке
    БДУ: внутри одного CWE базовые оценки разбросаны от 0,0 до 10,0 при
    стандартном отклонении 1,0-1,6 балла, и медиана по классу — статистика,
    а не «значение, рассчитанное разработчиком по базовым метрикам», которого
    требует п. 13.
    """

    SARIF_SECURITY_SEVERITY = "sarif_security_severity"
    MANUAL_RULE = "manual_rule"
    MANUAL_FINDING = "manual_finding"


# ── Таблица 1: весовые коэффициенты и оценки показателей ────────────────────


@dataclass(frozen=True)
class IndicatorValue:
    """Одна строка-значение показателя: числовая оценка + название из методики."""

    score: float
    label: str


@dataclass(frozen=True)
class IndicatorSpec:
    """Показатель целиком: обозначение, весовой коэффициент и его значения."""

    symbol: str
    title: str
    weight: float
    values: Mapping[Enum, IndicatorValue]

    def score(self, value: Enum) -> float:
        return self.values[value].score

    def label(self, value: Enum) -> str:
        return self.values[value].label

    def weighted(self, value: Enum) -> float:
        return self.weight * self.values[value].score


K = IndicatorSpec(
    symbol="K",
    title="Тип компонента информационной системы, подверженного уязвимости",
    weight=0.5,  # k
    values={
        ComponentType.KEY_PROCESSES: IndicatorValue(
            1.1,
            "Уязвимости подвержены компоненты системы, обеспечивающие реализацию "
            "важных процессов (бизнес-процессов), функций, полномочий",
        ),
        ComponentType.FIREWALL: IndicatorValue(0.9, "Уязвимости подвержены межсетевые экраны"),
        ComponentType.NETWORK_DEVICE: IndicatorValue(
            0.9, "Уязвимости подвержены сетевые устройства и шлюзы"
        ),
        ComponentType.TELECOM: IndicatorValue(
            0.8,
            "Уязвимости подвержены телекоммуникационное оборудование, система "
            "управления сетью передачи данных",
        ),
        ComponentType.SERVER: IndicatorValue(
            0.7, "Уязвимости подвержены серверы (центральные вычислительные узлы)"
        ),
        ComponentType.WORKSTATION: IndicatorValue(
            0.5,
            "Уязвимости подвержены пользовательские устройства "
            "(автоматизированные рабочие места)",
        ),
        ComponentType.STORAGE: IndicatorValue(
            0.4, "Уязвимости подвержены системы хранения данных"
        ),
        ComponentType.OTHER: IndicatorValue(0.1, "Уязвимости подвержены другие компоненты"),
    },
)

L = IndicatorSpec(
    symbol="L",
    title="Количество уязвимых компонентов информационной системы",
    weight=0.2,  # l
    values={
        VulnerableShare.OVER_70: IndicatorValue(
            1.0, "Более 70% компонентов от общего числа компонентов в информационной системе"
        ),
        VulnerableShare.FROM_50_TO_70: IndicatorValue(
            0.8, "50-70% компонентов от общего числа компонентов в информационной системе"
        ),
        VulnerableShare.FROM_10_TO_50: IndicatorValue(
            0.6, "10-50% компонентов от общего числа компонентов в информационной системе"
        ),
        VulnerableShare.UNDER_10: IndicatorValue(
            0.5, "Менее 10% компонентов от общего числа компонентов в информационной системе"
        ),
    },
)

P = IndicatorSpec(
    symbol="P",
    title="Влияние на эффективность защиты периметра информационной системы",
    weight=0.3,  # p
    values={
        PerimeterExposure.INTERNET_FACING: IndicatorValue(
            1.1, "Уязвимое программное, программно-аппаратное средство доступно из сети «Интернет»"
        ),
        PerimeterExposure.NOT_INTERNET_FACING: IndicatorValue(
            0.6,
            "Уязвимое программное, программно-аппаратное средство недоступно из сети «Интернет»",
        ),
    },
)

E = IndicatorSpec(
    symbol="E",
    title="Эксплуатация уязвимости",
    weight=1.0,  # e
    values={
        Exploitation.IN_THE_WILD: IndicatorValue(0.6, "Эксплуатируется в реальных атаках"),
        Exploitation.EXPLOIT_AVAILABLE: IndicatorValue(
            0.3, "Имеются сведения о наличии средств эксплуатации (эксплойта) уязвимости"
        ),
        Exploitation.NO_INFORMATION: IndicatorValue(
            0.1, "Отсутствуют сведения об эксплуатации в реальных атаках (наличии эксплойта)"
        ),
    },
)

H = IndicatorSpec(
    symbol="H",
    title="Последствия воздействий, которым подвергается информационная система "
    "при эксплуатации уязвимости",
    weight=1.0,  # h
    values={
        Impact.ARBITRARY_CODE_EXECUTION: IndicatorValue(
            0.5, "Выполнение произвольного кода (Arbitrary Code Execution)"
        ),
        Impact.PRIVILEGE_ESCALATION: IndicatorValue(
            0.5, "Повышение привилегий (Privilege Escalation)"
        ),
        Impact.SECURITY_BYPASS: IndicatorValue(
            0.4, "Обход механизмов безопасности (Security Bypass)"
        ),
        Impact.CODE_INJECTION: IndicatorValue(0.34, "Внедрение кода (Code Injection)"),
        Impact.OBTAIN_SENSITIVE_INFORMATION: IndicatorValue(
            0.3, "Получение конфиденциальной информации (Obtain Sensitive Information)"
        ),
        Impact.LOSS_OF_INTEGRITY: IndicatorValue(
            0.3, "Нарушение целостности данных (Loss of Integrity)"
        ),
        Impact.DOS: IndicatorValue(0.26, "Отказ в обслуживании (DoS)"),
        Impact.OVERWRITE_ARBITRARY_FILES: IndicatorValue(
            0.22, "Перезапись произвольных файлов (Overwrite Arbitrary Files)"
        ),
        Impact.WRITE_LOCAL_FILES: IndicatorValue(0.2, "Запись локальных файлов (Write Local Files)"),
        Impact.READ_LOCAL_FILES: IndicatorValue(
            0.18, "Чтение локальных файлов (Read Local Files)"
        ),
        Impact.SPOOF_USER_INTERFACE: IndicatorValue(
            0.12, "Поддельный пользовательский интерфейс (Spoof User Interface)"
        ),
        Impact.CROSS_SITE_SCRIPTING: IndicatorValue(
            0.1, "Межсайтовый скриптинг (Cross Site Scripting)"
        ),
    },
)

TABLE_1: Mapping[str, IndicatorSpec] = {spec.symbol: spec for spec in (K, L, P, E, H)}


# ── Таблица 2: пороги уровней критичности ──────────────────────────────────


@dataclass(frozen=True)
class LevelSpec:
    """Уровень критичности: порог по V, название и рекомендуемый срок устранения.

    `min_value` — нижняя граница диапазона, `inclusive` — входит ли она в него.
    Записано ровно так, как в таблице 2: V > 8,0 критический (граница НЕ
    включается), 5,0 ≤ V ≤ 8,0 высокий, 2,0 ≤ V < 5,0 средний, V < 2,0 низкий.
    Значение ровно 8,0 попадает в «Высокий», ровно 5,0 — в «Высокий»,
    ровно 2,0 — в «Средний».
    """

    key: str
    label: str
    # Рекомендуемый срок устранения (п. 21). Хранится текстом, как в методике:
    # переводить «до 4 месяцев» в число дней — уже допущение, а не норма.
    remediation: str
    min_value: float | None
    inclusive: bool


# Порядок важен: перебирается сверху вниз, первый подошедший уровень выигрывает.
LEVELS: tuple[LevelSpec, ...] = (
    LevelSpec("critical", "Критический", "до 24 часов", 8.0, inclusive=False),
    LevelSpec("high", "Высокий", "до 7 дней", 5.0, inclusive=True),
    LevelSpec("medium", "Средний", "до 4 недель", 2.0, inclusive=True),
    LevelSpec("low", "Низкий", "до 4 месяцев", None, inclusive=True),
)

FSTEC_LEVEL_ORDER: tuple[str, ...] = tuple(level.key for level in LEVELS)

_LEVELS_BY_KEY: Mapping[str, LevelSpec] = {level.key: level for level in LEVELS}


def level_for(v: float) -> LevelSpec:
    """Уровень критичности по итоговой оценке V (таблица 2).

    Ожидает V, уже округлённое до `_V_PRECISION` знаков — см. `assess`.
    """
    for level in LEVELS:
        if level.min_value is None:
            return level
        if v > level.min_value or (level.inclusive and v == level.min_value):
            return level
    # Недостижимо: последний уровень таблицы всегда имеет min_value=None.
    raise AssertionError("LEVELS must end with an open-ended (min_value=None) level")


# ── Расчёт ─────────────────────────────────────────────────────────────────

I_CVSS_MIN = 0.0
I_CVSS_MAX = 10.0

Status = Literal["assessed", "needs_assessment"]


@dataclass(frozen=True)
class CriticalityAssessment:
    """Результат оценки.

    `status="assessed"` — расчёт выполнен, заполнены `v`, `level`, `breakdown`.
    `status="needs_assessment"` — какой-то из показателей не задан, расчёт НЕ
    выполнялся, заполнен `missing`. Значения по умолчанию не подставляются ни
    при каких условиях: показатель, взятый с потолка, попадёт в отчёт как
    факт, а он им не является.
    """

    status: Status
    v: float | None = None
    level: str | None = None
    level_label: str | None = None
    remediation: str | None = None
    missing: tuple[str, ...] = ()
    breakdown: dict | None = None


def _round(value: float) -> float:
    return round(value, _BREAKDOWN_PRECISION)


def _pick_max(spec: IndicatorSpec, values: Sequence[Enum]) -> Enum:
    """Правило максимума: из нескольких значений показателя берётся наибольшее.

    Для K, E и H правило закреплено нормативно — пункты 15, 16 и 17
    соответственно. Для L прямой нормы в тексте нет: оно следует только из
    примера 2 приложения, где расчёт берёт максимум из четырёх долей со
    ссылкой на «подпункт 2.8 настоящей Методики» — пункта с таким номером в
    документе не существует. Реализуем для L так же, как для остальных
    (это единственное прочтение, согласующееся с приведённым расчётом), но
    расхождение отмечаем здесь, чтобы при обновлении методики его перепроверили.
    """
    return max(values, key=spec.score)


def _term(spec: IndicatorSpec, chosen: Enum, candidates: Sequence[Enum]) -> dict:
    """Разложение одного слагаемого для breakdown, включая правило максимума."""
    return {
        "symbol": spec.symbol,
        "title": spec.title,
        "weight": spec.weight,
        "value": chosen.value,
        "value_label": spec.label(chosen),
        "score": spec.score(chosen),
        "weighted": _round(spec.weighted(chosen)),
        # Все переданные значения — чтобы из отчёта было видно, что именно
        # отбрасывалось правилом максимума, а не только что победило.
        "candidates": [
            {"value": c.value, "value_label": spec.label(c), "score": spec.score(c)}
            for c in candidates
        ],
    }


def assess(
    *,
    i_cvss: float | None,
    i_cvss_source: CvssSource | None,
    component_types: Sequence[ComponentType] | None,
    vulnerable_share: Sequence[VulnerableShare] | None,
    perimeter_exposure: PerimeterExposure | None,
    exploitation: Sequence[Exploitation] | None,
    impact: Sequence[Impact] | None,
) -> CriticalityAssessment:
    """Оценить уровень критичности уязвимости применительно к системе (п. 12).

    K, L, E, H принимаются списками — к ним применяется правило максимума
    (см. `_pick_max`). P — единственное значение: правила максимума для него
    методика не устанавливает, и додумывать его здесь нельзя.

    Любой незаданный показатель (None или пустой список) → расчёт не
    выполняется, возвращается `status="needs_assessment"` с перечнем
    недостающих. `i_cvss` вне диапазона 0–10 — это не «не задан», а ошибка
    входных данных, поэтому ValueError.
    """
    if i_cvss is not None and not (I_CVSS_MIN <= i_cvss <= I_CVSS_MAX):
        raise ValueError(
            f"i_cvss must be within [{I_CVSS_MIN}, {I_CVSS_MAX}] (базовая оценка CVSS 3.1), "
            f"got {i_cvss}"
        )

    missing: list[str] = []
    if i_cvss is None:
        missing.append("i_cvss")
    elif i_cvss_source is None:
        # Значение без метки источника непроверяемо в отчёте — требуем оба.
        missing.append("i_cvss_source")
    if not component_types:
        missing.append("K")
    if not vulnerable_share:
        missing.append("L")
    if perimeter_exposure is None:
        missing.append("P")
    if not exploitation:
        missing.append("E")
    if not impact:
        missing.append("H")

    if missing:
        return CriticalityAssessment(status="needs_assessment", missing=tuple(missing))

    # Здесь все показатели заданы — проверки выше это гарантируют; asserts для
    # сужения Optional-типов, а не для валидации.
    assert i_cvss is not None and i_cvss_source is not None
    assert component_types and vulnerable_share and exploitation and impact
    assert perimeter_exposure is not None

    k_value = _pick_max(K, component_types)
    l_value = _pick_max(L, vulnerable_share)
    e_value = _pick_max(E, exploitation)
    h_value = _pick_max(H, impact)

    i_infr = K.weighted(k_value) + L.weighted(l_value) + P.weighted(perimeter_exposure)
    i_at = E.weighted(e_value)
    i_imp = H.weighted(h_value)

    # V считается по неокруглённым значениям; округляется только результат.
    v = round(i_cvss * i_infr * (i_at + i_imp), _V_PRECISION)
    level = level_for(v)

    breakdown = {
        "methodology": METHODOLOGY,
        "formula": "V = I_cvss × I_infr × (I_at + I_imp)",
        "i_cvss": {
            "value": i_cvss,
            "source": i_cvss_source.value,
        },
        "i_infr": {
            "value": _round(i_infr),
            "formula": "I_infr = k·K + l·L + p·P",
            "terms": [
                _term(K, k_value, component_types),
                _term(L, l_value, vulnerable_share),
                _term(P, perimeter_exposure, [perimeter_exposure]),
            ],
        },
        "i_at": {
            "value": _round(i_at),
            "formula": "I_at = e·E",
            "term": _term(E, e_value, exploitation),
        },
        "i_imp": {
            "value": _round(i_imp),
            "formula": "I_imp = h·H",
            "term": _term(H, h_value, impact),
        },
        "v": v,
        "level": level.key,
        "level_label": level.label,
        "remediation": level.remediation,
    }

    return CriticalityAssessment(
        status="assessed",
        v=v,
        level=level.key,
        level_label=level.label,
        remediation=level.remediation,
        breakdown=breakdown,
    )


def level_label(key: str) -> str:
    """Человекочитаемое название уровня по его ключу."""
    return _LEVELS_BY_KEY[key].label


__all__ = [
    "METHODOLOGY",
    "ComponentType",
    "VulnerableShare",
    "PerimeterExposure",
    "Exploitation",
    "Impact",
    "CvssSource",
    "IndicatorValue",
    "IndicatorSpec",
    "K",
    "L",
    "P",
    "E",
    "H",
    "TABLE_1",
    "LevelSpec",
    "LEVELS",
    "FSTEC_LEVEL_ORDER",
    "level_for",
    "level_label",
    "I_CVSS_MIN",
    "I_CVSS_MAX",
    "CriticalityAssessment",
    "assess",
]
