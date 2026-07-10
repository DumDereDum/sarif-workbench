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
    uri_base_id: str | None = None


@dataclass
class SarifRelatedLocation:
    """`result.relatedLocations[]` — same physicalLocation shape as
    `locations[]`, plus an optional message (T-39). Payload, not identity
    (ADR 0001 §8)."""
    uri: str
    region: SarifRegion
    uri_base_id: str | None = None
    message: str = ""


@dataclass
class CodeFlowStep:
    """One `threadFlows[].locations[]` entry of a SARIF codeFlow (T-39)."""
    uri: str
    line: int | None
    message: str


@dataclass
class SarifThreadFlow:
    steps: list[CodeFlowStep] = field(default_factory=list)


@dataclass
class SarifCodeFlow:
    thread_flows: list[SarifThreadFlow] = field(default_factory=list)


@dataclass
class SarifResult:
    run_index: int
    result_index: int
    rule_id: str
    level: str           # error | warning | note | none
    message: str
    locations: list[SarifLocation] = field(default_factory=list)
    related_locations: list[SarifRelatedLocation] = field(default_factory=list)
    code_flows: list[SarifCodeFlow] = field(default_factory=list)
    fingerprints: dict[str, str] = field(default_factory=dict)
    partial_fingerprints: dict[str, str] = field(default_factory=dict)


@dataclass
class SarifRule:
    rule_id: str
    name: str | None = None
    full_description: str | None = None
    help_uri: str | None = None
    security_severity: float | None = None  # from properties["security-severity"]
    # T-35: needed by server ingest (was read from the raw SARIF dict there,
    # not previously modeled by the typed CLI parser).
    tags: list[str] = field(default_factory=list)  # from properties["tags"]
    default_level: str = "warning"  # from defaultConfiguration.level


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
    # Raw `originalUriBaseIds` mapping: base id -> artifactLocation dict
    # ({"uri": ..., "uriBaseId": ...}); used to resolve location uriBaseId.
    original_uri_base_ids: dict = field(default_factory=dict)
