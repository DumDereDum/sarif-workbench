from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SarifRegion:
    start_line: int
    end_line: int | None = None
    start_column: int | None = None


@dataclass
class SarifLocation:
    uri: str
    region: SarifRegion


@dataclass
class SarifResult:
    run_index: int
    result_index: int
    rule_id: str
    level: str           # error | warning | note | none
    message: str
    locations: list[SarifLocation] = field(default_factory=list)
    code_flow_steps: list[str] = field(default_factory=list)


@dataclass
class SarifRule:
    rule_id: str
    name: str | None = None
    full_description: str | None = None
    help_uri: str | None = None
    security_severity: float | None = None  # from properties["security-severity"]


@dataclass
class SarifTool:
    name: str
    version: str | None
    rules: list[SarifRule] = field(default_factory=list)


@dataclass
class SarifRun:
    index: int
    tool: SarifTool
    results: list[SarifResult] = field(default_factory=list)
