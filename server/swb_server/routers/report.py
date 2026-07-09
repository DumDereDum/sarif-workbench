from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Finding, FindingIdentity, Run
from ..report_gen import generate_pdf

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")

# PDF-отчёт рендерит весь список находок постранично в одном HTML-документе
# (report_gen.py не умеет стримить weasyprint), поэтому единственный способ не
# грузить в память безлимитный ран — жёсткий потолок на число находок в отчёте.
_DEFAULT_REPORT_MAX_FINDINGS = 2000


def _report_max_findings() -> int:
    return int(os.environ.get("SWB_REPORT_MAX_FINDINGS", _DEFAULT_REPORT_MAX_FINDINGS))


@router.get("/runs/{run_id}/report")
def get_report(
    run_id: str,
    verdict: str | None = None,   # фильтр: true_positive,false_positive,...
    db: Session = Depends(get_db),
):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(404, {"error": "not_found", "message": "Run not found"})

    project = run.project

    q = db.query(Finding).filter(Finding.run_id == run_id)
    if verdict:
        verdicts = [v.strip() for v in verdict.split(",")]
        q = q.join(FindingIdentity, Finding.identity_id == FindingIdentity.id).filter(
            FindingIdentity.verdict.in_(verdicts)
        )
    q = q.order_by(Finding.severity, Finding.uri, Finding.start_line)

    limit = _report_max_findings()
    # limit+1 достаточно, чтобы понять, что находок больше лимита, не вычитывая
    # весь (потенциально огромный) ран в память.
    findings = q.limit(limit + 1).all()

    if not findings:
        raise HTTPException(404, {"error": "no_findings", "message": "Нет находок для отчёта"})

    if len(findings) > limit:
        raise HTTPException(
            413,
            {
                "error": "report_too_large",
                "message": (
                    f"В ране больше {limit} находок под текущим фильтром — "
                    f"PDF-отчёт ограничен SWB_REPORT_MAX_FINDINGS ({limit})"
                ),
            },
        )

    logger.info("[report] generating PDF run=%s findings=%d", run_id, len(findings))
    try:
        pdf_bytes = generate_pdf(run, project, findings)
    except Exception as exc:
        logger.error("[report] PDF generation failed: %s", exc)
        raise HTTPException(500, {"error": "pdf_error", "message": str(exc)})

    filename = f"report-{run_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
