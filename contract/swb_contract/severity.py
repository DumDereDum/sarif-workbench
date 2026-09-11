"""Single source of truth for the severity enum, its display order, and the
mapping from SARIF `level`/`security-severity` to it.

Moved here verbatim from `server/swb_server/ingest.py` (T-34) — CLI and
server must import these instead of keeping local copies that can drift.
"""
from __future__ import annotations

from typing import Any

SEV_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "note")

LEVEL_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "note",
}


# Собственная качественная шкала анализатора, когда он её отдаёт.
#
# В SARIF для уровня есть только `level` с четырьмя значениями, и шкалы
# точнее в него не помещаются: Svacer различает Critical / Major / Normal /
# Minor, но Major и Normal у него оба становятся `warning` — на двух реальных
# отчётах так схлопываются 278 находок из 424. Исходная градация при этом
# никуда не девается, она лежит в property bag результата.
#
# Ключи распознаются без учёта регистра. Незнакомое значение игнорируется:
# додумывать чужую шкалу нельзя, лучше опереться на `level`.
TOOL_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "major": "high",
    "normal": "medium",
    "minor": "low",
}


def sec_sev_to_enum(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "note"


def map_severity(security_severity: Any, level: str, tool_severity: Any = None) -> str:
    """Пятиуровневая severity находки из того, что дал анализатор.

    Порядок источников — от точного к грубому:

      1. `security-severity` — базовая оценка CVSS, число 0-10;
      2. собственная шкала анализатора, если он её отдал: она по построению
         не грубее `level`, иначе инструменту незачем было бы её вести;
      3. `level` из SARIF.

    Незнакомое значение в любом из источников не роняет разбор и не
    угадывается — управление переходит следующему источнику.
    """
    if security_severity is not None:
        try:
            return sec_sev_to_enum(float(security_severity))
        except (TypeError, ValueError):
            pass
    if tool_severity is not None:
        mapped = TOOL_SEVERITY_MAP.get(str(tool_severity).strip().lower())
        if mapped:
            return mapped
    return LEVEL_MAP.get(str(level).lower(), "note")
