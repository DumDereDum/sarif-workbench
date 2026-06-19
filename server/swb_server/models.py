from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
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
    sarif_sha256 = Column(String, unique=True)
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


class Finding(Base):
    __tablename__ = "findings"
    __allow_unmapped__ = True

    id = Column(String, primary_key=True, default=lambda: _uid("f-"))
    run_id = Column(String, ForeignKey("runs.id"), nullable=False)
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

    verdict = Column(String, default="unmarked")
    verdict_source = Column(String)
    confidence = Column(Integer)
    rationale = Column(Text)
    provider = Column(String)
    model_version = Column(String)
    prompt_version = Column(String)
    needs_reconfirm = Column(Boolean, default=False)
    verdict_history = Column(JSON)

    run = relationship("Run", back_populates="findings")


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
