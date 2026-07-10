"""swbmeta/v3 pydantic schema — re-exported from the shared contract package.

The schema itself lives in `swb_contract.swbmeta` (T-34, single source of
truth shared with the server). This module stays as a thin re-export so
existing CLI imports (`from swb_cli.swbmeta import ...`) keep working
unchanged.
"""
from __future__ import annotations

from swb_contract.swbmeta import (
    CodeFlow,
    CodeFlowStep,
    CodeSnippet,
    ContextPolicy,
    ExtraLocation,
    Finding,
    Fingerprints,
    GitInfo,
    Locator,
    Provenance,
    RelatedLocation,
    Region,
    SourceSarif,
    SwbMeta,
    ThreadFlow,
)

__all__ = [
    "CodeFlow",
    "CodeFlowStep",
    "CodeSnippet",
    "ContextPolicy",
    "ExtraLocation",
    "Finding",
    "Fingerprints",
    "GitInfo",
    "Locator",
    "Provenance",
    "RelatedLocation",
    "Region",
    "SourceSarif",
    "SwbMeta",
    "ThreadFlow",
]
