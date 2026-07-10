"""Typed SARIF 2.1.0 dataclasses — re-exported from the shared contract package.

The models themselves live in `swb_contract.sarif.models` (T-35, single
source of truth shared with the server). This module stays as a thin
re-export so existing CLI imports (`from swb_cli.sarif.models import ...`)
keep working unchanged.
"""
from __future__ import annotations

from swb_contract.sarif.models import (
    SarifLocation,
    SarifRegion,
    SarifResult,
    SarifRule,
    SarifRun,
    SarifTool,
)

__all__ = [
    "SarifLocation",
    "SarifRegion",
    "SarifResult",
    "SarifRule",
    "SarifRun",
    "SarifTool",
]
