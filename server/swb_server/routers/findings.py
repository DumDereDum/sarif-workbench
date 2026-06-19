from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Finding, Run

router = APIRouter(prefix="/api/v1")

_VALID_VERDICTS = {"true_positive", "false_positive", "uncertain", "unmarked"}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, {"error": "not_found", "message": "Finding not found"})

    snippet_obj = None
    if f.snippet is not None:
        lines = f.snippet.split("\n")
        snippet_obj = {
            "start_line": f.snippet_start or f.start_line,
            "end_line": f.snippet_end,
            "lines": lines,
            "hot_line": f.start_line,
        }

    return {
        "id": f.id,
        "swb_id": f.swb_id,
        "occurrence": f.occurrence,
        "severity": f.severity,
        "rule_id": f.rule_id,
        "rule_name": f.rule_name,
        "rule_description": f.rule_description,
        "help_uri": f.help_uri,
        "cwe": f.cwe,
        "uri": f.uri,
        "start_line": f.start_line,
        "end_line": f.end_line,
        "scope": f.scope,
        "snippet": snippet_obj,
        "lang": f.lang,
        "code_flow": f.code_flow,
        "git": f.git,
        "verdict": {
            "verdict": f.verdict,
            "source": f.verdict_source,
            "confidence": f.confidence,
            "rationale": f.rationale,
            "provider": f.provider,
            "model_version": f.model_version,
            "prompt_version": f.prompt_version,
            "needs_reconfirm": f.needs_reconfirm or False,
            "history": f.verdict_history or [],
        },
    }


@router.patch("/findings/{finding_id}/verdict")
def update_verdict(finding_id: str, body: dict, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, {"error": "not_found", "message": "Finding not found"})

    verdict = body.get("verdict")
    if verdict not in _VALID_VERDICTS:
        raise HTTPException(400, {"error": "bad_request", "message": f"verdict must be one of {_VALID_VERDICTS}"})

    rationale = body.get("rationale", "")

    # Append old verdict to history
    history = list(f.verdict_history or [])
    if f.verdict and f.verdict != "unmarked":
        history.append({
            "verdict": f.verdict,
            "source": f.verdict_source,
            "at": datetime.now(timezone.utc).isoformat(),
        })

    f.verdict = verdict
    f.verdict_source = "human"
    f.rationale = rationale
    f.confidence = None
    f.verdict_history = history

    # Recount counts_by_verdict on the run
    run = db.query(Run).filter(Run.id == f.run_id).first()
    if run:
        cvd = {"true_positive": 0, "false_positive": 0, "uncertain": 0, "unmarked": 0}
        for ff in db.query(Finding).filter(Finding.run_id == run.id).all():
            v = verdict if ff.id == finding_id else (ff.verdict or "unmarked")
            cvd[v] = cvd.get(v, 0) + 1
        run.counts_by_verdict = cvd

    db.commit()
    return {
        "verdict": f.verdict,
        "source": f.verdict_source,
        "rationale": f.rationale,
        "history": f.verdict_history,
    }
