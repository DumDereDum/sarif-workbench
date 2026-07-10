"""swbmeta/v2 pydantic schema — re-exported from the shared contract package.

The schema itself lives in `swb_contract.swbmeta` (T-34, single source of
truth shared with the server). This module stays as a thin re-export so
existing CLI imports (`from swb_cli.swbmeta import ...`) keep working
unchanged.
"""
from __future__ import annotations

from swb_contract.swbmeta import (
    CodeSnippet,
    ContextPolicy,
    Finding,
    Fingerprints,
    GitInfo,
    Locator,
    Provenance,
    Region,
    SourceSarif,
    SwbMeta,
)

__all__ = [
    "CodeSnippet",
    "ContextPolicy",
    "Finding",
    "Fingerprints",
    "GitInfo",
    "Locator",
    "Provenance",
    "Region",
    "SourceSarif",
    "SwbMeta",
]
