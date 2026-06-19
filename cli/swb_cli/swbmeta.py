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
    uri: str
    region: Region


class Fingerprints(BaseModel):
    rule: str
    scope: Optional[str] = None     # tree-sitter — not yet implemented
    content: Optional[str] = None   # normalized code hash — not yet implemented
    context: Optional[str] = None   # surrounding lines hash — not yet implemented
    flow: Optional[str] = None      # codeFlow hash — not yet implemented


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

    schema_: Literal["swbmeta/v1"] = Field("swbmeta/v1", alias="schema")
    generated_by: str
    generated_at: str  # ISO-8601 UTC
    source_sarif: SourceSarif
    provenance: Provenance
    context_policy: ContextPolicy
    findings: list[Finding]
