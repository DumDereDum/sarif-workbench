"""T-34: swb_contract — единый источник схемы swbmeta и энумов severity/verdict.

Три вещи проверяются:
  (а) severity: SEV_ORDER/map_severity доступны в swb_contract и корректны
      на нескольких примерах SARIF level / security-severity;
  (б) verdict: VERDICT_ORDER содержит ровно 4 ожидаемых значения в порядке;
  (в) CLI и сервер действительно ИМПОРТИРУЮТ эти объекты из swb_contract, а
      не переопределяют локальные копии — identity-проверки (`is`), не
      просто равенство значений.
"""
from __future__ import annotations

import pytest

from swb_contract.severity import SEV_ORDER, map_severity
from swb_contract.verdict import VERDICT_ORDER


# ── (а) severity ────────────────────────────────────────────────────────────


def test_sev_order_values_and_type():
    assert SEV_ORDER == ("critical", "high", "medium", "low", "note")
    assert isinstance(SEV_ORDER, tuple)


@pytest.mark.parametrize(
    "security_severity,level,expected",
    [
        # no security-severity → falls back to SARIF level map
        (None, "error", "high"),
        (None, "warning", "medium"),
        (None, "note", "low"),
        (None, "none", "note"),
        (None, "totally-unknown-level", "note"),  # unknown level → default note
        # security-severity present → overrides level entirely
        (9.5, "warning", "critical"),
        (9.0, "note", "critical"),
        (7.0, "note", "high"),
        (8.9, "error", "high"),
        (4.0, "none", "medium"),
        (6.9, "none", "medium"),
        (0.1, "none", "low"),
        (3.9, "none", "low"),
        (0, "error", "note"),  # score not > 0 → note, even though level is "error"
        # unparseable security-severity → falls back to level map, doesn't raise
        ("not-a-number", "error", "high"),
        (None, None, "note"),
    ],
)
def test_map_severity(security_severity, level, expected):
    assert map_severity(security_severity, level) == expected


# ── (б) verdict ─────────────────────────────────────────────────────────────


def test_verdict_order_values_and_type():
    assert VERDICT_ORDER == ("true_positive", "false_positive", "uncertain", "unmarked")
    assert len(VERDICT_ORDER) == 4
    assert isinstance(VERDICT_ORDER, tuple)


# ── (в) CLI импортирует swbmeta-схему из contract, не копирует ─────────────


def test_cli_swbmeta_is_contract_swbmeta():
    import swb_cli.swbmeta as cli_swbmeta
    import swb_contract.swbmeta as contract_swbmeta

    for name in (
        "SourceSarif",
        "Provenance",
        "ContextPolicy",
        "Region",
        "Locator",
        "Fingerprints",
        "GitInfo",
        "CodeSnippet",
        "Finding",
        "SwbMeta",
    ):
        assert getattr(cli_swbmeta, name) is getattr(contract_swbmeta, name), (
            f"swb_cli.swbmeta.{name} is not the same object as swb_contract.swbmeta.{name} "
            "— looks like a local copy, not a re-export"
        )


# ── (в) сервер импортирует severity/verdict константы из contract ──────────


def test_server_ingest_imports_severity_from_contract():
    import swb_contract.severity as severity_mod
    import swb_server.ingest as ingest_mod

    assert ingest_mod.SEV_ORDER is severity_mod.SEV_ORDER
    assert ingest_mod.map_severity is severity_mod.map_severity


def test_server_runs_router_imports_severity_and_verdict_from_contract():
    import swb_contract.severity as severity_mod
    import swb_contract.verdict as verdict_mod
    import swb_server.routers.runs as runs_mod

    assert runs_mod.SEV_ORDER is severity_mod.SEV_ORDER
    assert runs_mod.VERDICT_ORDER is verdict_mod.VERDICT_ORDER


def test_server_verdicts_module_imports_verdict_order_from_contract():
    import swb_contract.verdict as verdict_mod
    import swb_server.verdicts as verdicts_mod

    assert verdicts_mod.ALL_VERDICTS is verdict_mod.VERDICT_ORDER


def test_server_findings_router_valid_verdicts_match_contract():
    import swb_contract.verdict as verdict_mod
    import swb_server.routers.findings as findings_mod

    assert findings_mod._VALID_VERDICTS == set(verdict_mod.VERDICT_ORDER)
