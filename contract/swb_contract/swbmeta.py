from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class SourceSarif(BaseModel):
    filename: str
    sha256: str
    size_bytes: int


class Provenance(BaseModel):
    repo: str
    branch: str
    commit: str
    commit_short: str
    is_dirty: bool
    tool: str
    tool_version: str
    scanned_at: str  # ISO-8601 UTC


class ContextPolicy(BaseModel):
    mode: Literal["none", "line", "lines", "function"]
    lines: Optional[int] = None


class Region(BaseModel):
    start_line: int
    end_line: Optional[int] = None
    start_column: Optional[int] = None


class Locator(BaseModel):
    run: int
    result: int
    rule_id: str
    uri: str                        # as in the SARIF file — for navigation/cross-checks
    norm_uri: str                   # normalized per ADR 0001 §3
    region: Region


class Fingerprints(BaseModel):
    # ADR 0001 §1/§5 — fingerprint chain, algorithm version swb-fp/2
    algo: Literal["swb-fp/2"] = "swb-fp/2"
    level: Literal["tool", "content", "legacy"]  # level that feeds swb_id (T-13)
    rule: str
    tool: Optional[dict[str, str]] = None        # passthrough fingerprints/partialFingerprints
    tool_kind: Optional[Literal["fingerprints", "partialFingerprints"]] = None
    content: Optional[str] = None   # sha256 of level-2 material, when source is readable
    context: Optional[str] = None   # same hash for the ±2-line window — diagnostics only
    scope: Optional[str] = None     # reserved (tree-sitter, Later)
    flow: Optional[str] = None      # reserved (T-39, not part of identity)


class GitInfo(BaseModel):
    blob_sha: Optional[str] = None
    blame_commit: Optional[str] = None
    last_changed: Optional[str] = None


class CodeSnippet(BaseModel):
    lang: Optional[str] = None
    start_line: int
    end_line: int
    snippet: str


class ExtraLocation(BaseModel):
    """T-39: `result.locations[1:]` from SARIF — additional locations beyond
    the primary one (`locator`). Payload only: per ADR 0001 §8, identity is
    built from `locations[0]` alone, these never feed swb_id."""
    uri: str
    region: Region


class RelatedLocation(BaseModel):
    """T-39: `result.relatedLocations[]` from SARIF. Payload only, same as
    `ExtraLocation` (ADR 0001 §8) — not part of identity."""
    uri: str
    region: Region
    message: Optional[str] = None


class CodeFlowStep(BaseModel):
    """T-39: one `threadFlows[].locations[]` entry of a SARIF codeFlow."""
    uri: str
    line: Optional[int] = None
    message: Optional[str] = None


class ThreadFlow(BaseModel):
    steps: list[CodeFlowStep] = Field(default_factory=list)


class CodeFlow(BaseModel):
    thread_flows: list[ThreadFlow] = Field(default_factory=list)


class Finding(BaseModel):
    swb_id: str
    occurrence: int
    locator: Locator
    fingerprints: Fingerprints
    git: Optional[GitInfo] = None
    code: Optional[CodeSnippet] = None
    # T-39: multi-location payload (ADR 0001 §8) — stored/shown, not identity
    # material. Defaults to empty so single-location findings (the common
    # case) don't need to set anything.
    extra_locations: list[ExtraLocation] = Field(default_factory=list)
    related_locations: list[RelatedLocation] = Field(default_factory=list)
    code_flows: list[CodeFlow] = Field(default_factory=list)


class SwbMeta(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    # T-39: multi-location findings (extra_locations/related_locations/
    # code_flows on Finding) are a format change -> new schema version, no
    # v2 compatibility (same precedent as the v1->v2 transition in ADR 0001
    # §5/§9 — no real installations to migrate).
    schema_: Literal["swbmeta/v3"] = Field("swbmeta/v3", alias="schema")
    generated_by: str
    generated_at: str  # ISO-8601 UTC
    source_sarif: SourceSarif
    provenance: Provenance
    context_policy: ContextPolicy
    findings: list[Finding]
