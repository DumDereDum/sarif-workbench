import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Finding, Run
from ..storage import load_blob

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")


@router.get("/runs/{run_id}/report-sarif")
def get_sarif(run_id: str, db: Session = Depends(get_db)):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(404)

    data = load_blob(run.sarif_key)

    return Response(
        content=data,
        media_type="application/sarif+json",
        headers={
            "Content-Disposition":
                f'attachment; filename="{run_id}.sarif"'
        },
    )