"""Single source of truth for the verdict enum and its canonical order.

Consolidates what used to be three independent copies (T-34):
`server/swb_server/routers/runs.py::_VERDICT_ORDER`,
`server/swb_server/routers/findings.py::_VALID_VERDICTS`,
`server/swb_server/verdicts.py::ALL_VERDICTS`.
"""
from __future__ import annotations

VERDICT_ORDER: tuple[str, ...] = ("true_positive", "false_positive", "uncertain", "unmarked")
