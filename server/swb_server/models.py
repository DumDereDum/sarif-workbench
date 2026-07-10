from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
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
    )


class Run(Base):
    __tablename__ = "runs"
    __table_args__ = (UniqueConstraint("project_id", "sarif_sha256", name="uq_run_project_sha256"),)
    __allow_unmapped__ = True

    id = Column(String, primary_key=True, default=lambda: _uid("r-"))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    commit = Column(String, nullable=False, default="unknown")
    branch = Column(String, default="unknown")
    tool = Column(String)
    tool_version = Column(String)
    scanned_at = Column(String)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    sarif_key = Column(String)
    meta_key = Column(String)
    # дедуп скопирован на проект (ADR 0001 §7) — уникальность составная, не
    # глобальная: тот же SARIF в другом проекте — обычная новая загрузка.
    sarif_sha256 = Column(String)
    counts = Column(JSON)
    counts_by_verdict = Column(JSON)

    project = relationship(
        "Project",
        primaryjoin="Run.project_id == Project.id",
        foreign_keys=[project_id],
        back_populates="runs",
    )
    findings = relationship("Finding", back_populates="run")
    rules = relationship("Rule", back_populates="run")


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
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    swb_id = Column(String, nullable=False)
    algo = Column(String, nullable=False, default="swb-fp/2")
    level = Column(String, nullable=False, default="legacy")  # tool / content / legacy

    verdict = Column(String, nullable=False, default="unmarked")  # текущее значение
    verdict_source = Column(String, nullable=True)  # human / ai / carried / reset
    rationale = Column(Text, nullable=True)
    needs_reconfirm = Column(Boolean, nullable=False, default=False)
    # атрибуты последнего AI-вердикта (prompt_id/prompt_version заполняет T-25)
    provider = Column(String, nullable=True)
    model = Column(String, nullable=True)
    prompt_id = Column(String, nullable=True)
    prompt_version = Column(String, nullable=True)

    first_seen_run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    first_seen_at = Column(DateTime, nullable=True)
    last_seen_run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    last_seen_at = Column(DateTime, nullable=True)  # обновляются при каждом ingest

    findings = relationship("Finding", back_populates="identity")
    events = relationship(
        "VerdictEvent",
        back_populates="identity",
        order_by="VerdictEvent.at",
    )


class VerdictEvent(Base):
    """ADR 0001 §6 — append-only журнал вердиктов: события не изменяются и не удаляются."""
    __tablename__ = "verdict_events"
    __allow_unmapped__ = True

    id = Column(String, primary_key=True, default=lambda: _uid("ve-"))
    identity_id = Column(String, ForeignKey("finding_identities.id"), nullable=False)
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
    run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    payload = Column(JSON, nullable=True)  # расширение без миграции

    identity = relationship("FindingIdentity", back_populates="events")


class Finding(Base):
    __tablename__ = "findings"
    __allow_unmapped__ = True

    id = Column(String, primary_key=True, default=lambda: _uid("f-"))
    run_id = Column(String, ForeignKey("runs.id"), nullable=False)
    identity_id = Column(String, ForeignKey("finding_identities.id"), nullable=False)
    # swb_id/occurrence — денормализация для выдачи; вердикт живёт на identity
    swb_id = Column(String, nullable=False, default="")
    occurrence = Column(Integer, default=0)
    rule_id = Column(String)
    rule_name = Column(String)
    rule_description = Column(Text)
    help_uri = Column(String)
    cwe = Column(String)
    severity = Column(String, default="note")
    message = Column(Text)
    uri = Column(String)
    start_line = Column(Integer)
    end_line = Column(Integer)
    scope = Column(String)
    snippet = Column(Text)
    snippet_start = Column(Integer)
    snippet_end = Column(Integer)
    lang = Column(String)
    code_flow = Column(JSON)
    git = Column(JSON)

    run = relationship("Run", back_populates="findings")
    identity = relationship("FindingIdentity", back_populates="findings")


class Rule(Base):
    __tablename__ = "rules"
    __allow_unmapped__ = True

    id = Column(String, primary_key=True, default=lambda: _uid("rl-"))
    run_id = Column(String, ForeignKey("runs.id"), nullable=False)
    rule_id = Column(String)
    name = Column(String)
    description = Column(Text)
    help_uri = Column(String)
    default_severity = Column(String)

    run = relationship("Run", back_populates="rules")
