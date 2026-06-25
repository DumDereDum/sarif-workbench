from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Finding, Run
from ..report_gen_pdf import generate_pdf

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")


@router.get("/runs/{run_id}/report-pdf")
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
        q = q.filter(Finding.verdict.in_(verdicts))
    findings = q.order_by(Finding.severity, Finding.uri, Finding.start_line).all()

    if not findings:
        raise HTTPException(404, {"error": "no_findings", "message": "Нет находок для отчёта"})

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
