from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.types import JSON
from sqlalchemy.orm import relationship

from .db import Base


def _uid(prefix: str = "") -> str:
    return prefix + uuid.uuid4().hex[:12]


class Project(Base):
    __tablename__ = "projects"
    __allow_unmapped__ = True

    id = Column(String, primary_key=True)
    repo = Column(String, nullable=False)
    name = Column(String, nullable=False)
    team = Column(String)
    baseline_run_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    runs = relationship(
        "Run",
        primaryjoin="Project.id == Run.project_id",
        foreign_keys="Run.project_id",
        back_populates="project",
        order_by="Run.uploaded_at",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    findings_identities = relationship(
        "FindingIdentity",
        back_populates="project",
        order_by="FindingIdentity.last_seen_at",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    fstec_profile = relationship(
        "SystemProfile",
        back_populates="project",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Run(Base):
    __tablename__ = "runs"
    __table_args__ = (UniqueConstraint("project_id", "sarif_sha256", name="uq_run_project_sha256"),)
    __allow_unmapped__ = True

    id = Column(String, primary_key=True, default=lambda: _uid("r-"))
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    commit = Column(String, nullable=False, default="unknown")
    branch = Column(String, default="unknown")
    tool = Column(String)
    tool_version = Column(String)
    # Версия конфигурации анализатора из property bag отчёта — не то же
    # самое, что версия драйвера: у Svacer драйвер это svacer, а сканирует
    # Svace, и его версия лежит только здесь. Для отчёта регулятору важно,
    # чем и в какой конфигурации сканировали.
    analyzer_config = Column(String)
    scanned_at = Column(String)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    sarif_key = Column(String)
    meta_key = Column(String)
    # дедуп скопирован на проект (ADR 0001 §7) — уникальность составная, не
    # глобальная: тот же SARIF в другом проекте — обычная новая загрузка.
    sarif_sha256 = Column(String)
    counts = Column(JSON)
    counts_by_verdict = Column(JSON)
    # Сводка по уровням критичности ФСТЭК: ключи FSTEC_LEVEL_ORDER плюс
    # `needs_assessment` и `not_applicable`. Последние два — полноценные
    # группы, а не пропуск: находка без данных и находка, которую решили не
    # оценивать, должны быть видны в сводке, иначе их «не хватает» в сумме.
    counts_by_fstec = Column(JSON)

    project = relationship(
        "Project",
        primaryjoin="Run.project_id == Project.id",
        foreign_keys=[project_id],
        back_populates="runs",
    )
    findings = relationship(
        "Finding", 
        back_populates="run", 
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    rules = relationship(
        "Rule",
        back_populates="run", 
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class FindingIdentity(Base):
    """ADR 0001 §6 — стабильная идентичность находки в рамках проекта + снапшот вердикта.

    Снапшот (verdict/…) — денормализация; источник истины по изменениям —
    verdict_events. Снапшот и событие пишутся только вместе, через
    `verdicts.write_verdict` (писатель-одиночка).
    """
    __tablename__ = "finding_identities"
    __table_args__ = (UniqueConstraint("project_id", "swb_id", name="uq_identity_project_swb"),)
    __allow_unmapped__ = True

    id = Column(String, primary_key=True, default=lambda: _uid("fi-"))
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    swb_id = Column(String, nullable=False)
    algo = Column(String, nullable=False, default="swb-fp/2")
    level = Column(String, nullable=False, default="legacy")  # tool / content / legacy

    verdict = Column(String, nullable=False, default="unmarked")  # текущее значение
    verdict_source = Column(String, nullable=True)  # human / ai / carried / reset
    rationale = Column(Text, nullable=True)
    needs_reconfirm = Column(Boolean, nullable=False, default=False)
    # T-38: оптимистическая блокировка вердикта — инкрементируется в write_verdict
    # на КАЖДЫЙ вызов (human/ai/carried/reset), не только human. PATCH-клиент
    # присылает версию, прочитанную своим последним GET; расхождение с текущей
    # версией identity → 409 (см. routers/findings.py::update_verdict).
    version = Column(Integer, nullable=False, default=1)
    # E методики — сведения об эксплуатации уязвимости (таблица 1, строка 4).
    # Живёт на identity, а не на находке: показатель относится к уязвимости и
    # обязан пережить повторный скан так же, как вердикт. NULL — значение по
    # умолчанию «отсутствуют сведения»: это строка таблицы 1, а не пропуск.
    #
    # Ссылка обязательна для всего, кроме умолчания: показатель сокращает
    # срок устранения с недель до суток (п. 21), и предъявить аудитору нужно
    # не только значение, но и откуда оно взято — номер БДУ, CVE, бюллетень,
    # запись об инциденте.
    fstec_exploitation = Column(String, nullable=True)
    fstec_exploitation_ref = Column(Text, nullable=True)
    fstec_exploitation_by = Column(String, nullable=True)
    fstec_exploitation_at = Column(DateTime, nullable=True)
    # атрибуты последнего AI-вердикта (prompt_id/prompt_version заполняет T-25)
    provider = Column(String, nullable=True)
    model = Column(String, nullable=True)
    prompt_id = Column(String, nullable=True)
    prompt_version = Column(String, nullable=True)

    first_seen_run_id = Column(String, ForeignKey("runs.id", ondelete="SET NULL"), nullable=True)
    first_seen_at = Column(DateTime, nullable=True)
    last_seen_run_id = Column(String, ForeignKey("runs.id", ondelete="SET NULL"), nullable=True)
    last_seen_at = Column(DateTime, nullable=True)  # обновляются при каждом ingest

    project = relationship(
        "Project",
        primaryjoin="FindingIdentity.project_id == Project.id",
        foreign_keys=[project_id],
        back_populates="findings_identities",
    )

    findings = relationship(
        "Finding", 
        back_populates="identity",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    events = relationship(
        "VerdictEvent",
        back_populates="identity",
        order_by="VerdictEvent.at",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class VerdictEvent(Base):
    """ADR 0001 §6 — append-only журнал вердиктов: события не изменяются и не удаляются."""
    __tablename__ = "verdict_events"
    __allow_unmapped__ = True

    id = Column(String, primary_key=True, default=lambda: _uid("ve-"))
    identity_id = Column(String, ForeignKey("finding_identities.id", ondelete="CASCADE"), nullable=False)
    at = Column(DateTime, nullable=False, default=datetime.utcnow)  # UTC
    source = Column(String, nullable=False)  # human | ai | carried | reset
    actor = Column(String, nullable=False)  # human / ai:{provider}/{model} / system
    old_verdict = Column(String, nullable=False)  # всегда заполняется, в т.ч. unmarked
    new_verdict = Column(String, nullable=False)
    rationale = Column(Text, nullable=True)
    provider = Column(String, nullable=True)
    model = Column(String, nullable=True)
    prompt_id = Column(String, nullable=True)      # заполняет T-25
    prompt_version = Column(String, nullable=True)  # заполняет T-25
    run_id = Column(String, ForeignKey("runs.id", ondelete="SET NULL"),nullable=True)
    payload = Column(JSON, nullable=True)  # расширение без миграции

    identity = relationship("FindingIdentity", back_populates="events")


class Finding(Base):
    __tablename__ = "findings"
    __allow_unmapped__ = True

    id = Column(String, primary_key=True, default=lambda: _uid("f-"))
    run_id = Column(String, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    identity_id = Column(String, ForeignKey("finding_identities.id", ondelete="CASCADE"), nullable=False)
    # swb_id/occurrence — денормализация для выдачи; вердикт живёт на identity
    swb_id = Column(String, nullable=False, default="")
    occurrence = Column(Integer, default=0)
    rule_id = Column(String)
    rule_name = Column(String)
    rule_description = Column(Text)
    help_uri = Column(String)
    # cwe — основной CWE правила (первый из перечисленных анализатором):
    # на нём держатся фильтр `?cwe=` и агрегация `by=cwe`. cwes — весь
    # список: CodeQL перечисляет по 2-5 штук на правило, и терять их нельзя.
    cwe = Column(String)
    cwes = Column(JSON)
    # Базовая оценка CVSS из отчёта (`properties["security-severity"]`, 0-10).
    # Единственный автоматический источник показателя I_cvss методики ФСТЭК;
    # до этой колонки число вычислялось при загрузке и выбрасывалось.
    # Есть не у всех: CodeQL проставляет его своим security-запросам, Svacer
    # и Bandit не дают никогда, у реестровых правил Semgrep его нет.
    security_severity = Column(Float)
    severity = Column(String, default="note")
    # Уровень критичности по методике ФСТЭК от 30.06.2025 — результат
    # `criticality.assess_finding`. Хранится, а не считается на лету: фильтры,
    # сортировка и агрегации сделаны на SQL (см. `_severity_order_expr`), и
    # расчёт в Python потребовал бы вычитывать весь прогон в память.
    # Пересчитывается при изменении любого входа (п. 19 методики): профиля ИС,
    # оценки правила, загрузки нового прогона.
    fstec_v = Column(Float, nullable=True)
    fstec_level = Column(String, nullable=True)  # ключ из FSTEC_LEVEL_ORDER
    # assessed | needs_assessment | not_applicable. Первые два — из контракта
    # (`fstec.Status`), они отвечают на вопрос «хватило ли данных для расчёта».
    # Третий — серверный: правило помечено как «не уязвимость», и считать
    # нечего. Контракт про применимость правил не знает и знать не должен.
    fstec_status = Column(String, nullable=False, default="needs_assessment")
    fstec_missing = Column(JSON, nullable=True)  # незаданные показатели
    # Разложение расчёта не хранится: это чистая функция от входов, и
    # сохранённая копия разойдётся с ними при первом же пересчёте.
    message = Column(Text)
    uri = Column(String)
    start_line = Column(Integer)
    end_line = Column(Integer)
    scope = Column(String)
    snippet = Column(Text)
    snippet_start = Column(Integer)
    snippet_end = Column(Integer)
    lang = Column(String)
    # T-39 (ADR 0001 §8): multi-location payload, not identity material.
    # code_flow stores the structured codeFlows -> threadFlows -> steps
    # (list, possibly empty) — the column existed before T-39 but was always
    # None (never written by ingest); extra_locations/related_locations are new.
    code_flow = Column(JSON)
    extra_locations = Column(JSON)
    related_locations = Column(JSON)
    git = Column(JSON)

    run = relationship("Run", back_populates="findings")
    identity = relationship("FindingIdentity", back_populates="findings")


class Rule(Base):
    __tablename__ = "rules"
    __allow_unmapped__ = True

    id = Column(String, primary_key=True, default=lambda: _uid("rl-"))
    run_id = Column(String, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(String)
    name = Column(String)
    description = Column(Text)
    help_uri = Column(String)
    default_severity = Column(String)

    run = relationship("Run", back_populates="rules")


class RuleImpact(Base):
    """Оценка правила анализатора для методики ФСТЭК — показатель H и,
    когда анализатор не дал `security-severity`, базовая оценка CVSS.

    Таблица **глобальная**, не привязана к проекту: «что произойдёт, если
    проэксплуатировать разыменование NULL» — свойство слабости, а не
    репозитория. От информационной системы зависит, насколько это плохо, и
    это показатели K, L, P из `SystemProfile`.

    Заполняется вручную. Автоматического источника у H нет: проверено на
    выгрузке БДУ (ФСТЭК проставляет последствие каждой уязвимости отдельно,
    и внутри одного CWE значения расходятся) и на каталоге MITRE (там
    перечислено всё, что когда-либо наблюдалось, — при правиле максимума
    п. 17 больше половины CWE корпуса получили бы 0,5).

    Гранулярность «на правило» выбрана потому, что правило анализатора у́же
    CWE и описывает один конкретный дефект: `DEREF_OF_NULL.RET.STAT` — это
    разыменование NULL, а CWE-119, под который попадают его соседи,
    покрывает всё от чтения за границей буфера до выполнения кода. Тем же
    свойством обладает и `security-severity`: он тоже константа правила.
    """
    __tablename__ = "rule_impacts"
    __allow_unmapped__ = True

    # Идентификаторы правил у анализаторов независимы и могут совпасть,
    # поэтому ключ составной.
    tool = Column(String, primary_key=True)
    rule_id = Column(String, primary_key=True)

    impacts = Column(JSON, nullable=True)  # значения Impact из таблицы 1
    # «Посмотрели и решили, что это не уязвимость» — отдельное состояние, не
    # то же самое, что пустой impacts («ещё не смотрели»). Ставится только
    # человеком: вывести это из отсутствия CWE нельзя — у Bandit его нет ни
    # у одного правила, а он линтер безопасности.
    not_applicable = Column(Boolean, nullable=False, default=False)
    i_cvss = Column(Float, nullable=True)  # 0-10, если анализатор не дал
    cvss_vector = Column(String, nullable=True)  # чем обоснована оценка

    note = Column(Text, nullable=True)  # обоснование, идёт в отчёт аудитору
    updated_by = Column(String, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class SystemProfile(Base):
    """Показатели K, L, P — свойства информационной системы, а не находки.

    В SARIF их нет и быть не может: анализатор видит исходный код, а не
    развёрнутый компонент. Методика берёт их из инвентаризации (п. 8в,
    п. 11.2), поэтому заполняются вручную — один раз на проект.

    Хранятся строковые `.value` перечислений контракта, а не числа:
    коэффициенты нормативные и живут в `fstec.TABLE_1`. Число в базе
    пришлось бы мигрировать при уточнении методики.

    Незаполненное поле — None, и находка уходит в «требует оценки».
    Умолчаний нет: подставленный тип компонента попадёт в отчёт регулятору
    как факт, а он им не является.
    """
    __tablename__ = "system_profiles"
    __allow_unmapped__ = True

    project_id = Column(
        String, ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )
    component_type = Column(String, nullable=True)      # ComponentType.value
    vulnerable_share = Column(String, nullable=True)    # VulnerableShare.value
    perimeter_exposure = Column(String, nullable=True)  # PerimeterExposure.value

    updated_by = Column(String, nullable=True)
    updated_at = Column(DateTime, nullable=True)

    project = relationship(
        "Project",
        primaryjoin="SystemProfile.project_id == Project.id",
        foreign_keys=[project_id],
        back_populates="fstec_profile",
    )
