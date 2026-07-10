"""SARIF 2.1.0 parser — re-exported from the shared contract package.

The parsing logic itself lives in `swb_contract.sarif.parser` (T-35, single
source of truth shared with the server, which used to keep its own
raw-dict SARIF traversal in `ingest.py`). This module stays as a thin
re-export so existing CLI imports (`from swb_cli.sarif.parser import ...`),
including the private `_extract_text` helper used directly by
`tests/cli/test_parser.py`, keep working unchanged.
"""
from __future__ import annotations

from swb_contract.sarif.parser import (
    _extract_text,
    parse_sarif,
    parse_sarif_data,
)

__all__ = [
    "parse_sarif",
    "parse_sarif_data",
    "_extract_text",
]
