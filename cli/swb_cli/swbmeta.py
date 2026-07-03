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


class Finding(BaseModel):
    swb_id: str
    occurrence: int
    locator: Locator
    fingerprints: Fingerprints
    git: Optional[GitInfo] = None
    code: Optional[CodeSnippet] = None


class SwbMeta(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_: Literal["swbmeta/v2"] = Field("swbmeta/v2", alias="schema")
    generated_by: str
    generated_at: str  # ISO-8601 UTC
    source_sarif: SourceSarif
    provenance: Provenance
    context_policy: ContextPolicy
    findings: list[Finding]
