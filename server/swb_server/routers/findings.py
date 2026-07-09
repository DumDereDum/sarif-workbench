from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Finding, FindingIdentity, VerdictEvent
from ..verdicts import recompute_counts_by_verdict, write_verdict

router = APIRouter(prefix="/api/v1")

_VALID_VERDICTS = {"true_positive", "false_positive", "uncertain", "unmarked"}


def _history(db: Session, identity: FindingIdentity | None) -> list[dict]:
    """События identity в хронологическом порядке, в прежней форме ответа."""
    if identity is None:
        return []
    events = (
        db.query(VerdictEvent)
        .filter(VerdictEvent.identity_id == identity.id)
        .order_by(VerdictEvent.at, VerdictEvent.id)
        .all()
    )
    return [
        {
            "verdict": e.new_verdict,
            "old_verdict": e.old_verdict,
            "source": e.source,
            "actor": e.actor,
            "rationale": e.rationale,
            "provider": e.provider,
            "model": e.model,
            "prompt_id": e.prompt_id,
            "prompt_version": e.prompt_version,
            "run_id": e.run_id,
            "at": e.at.isoformat() if e.at else None,
        }
        for e in events
    ]


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

    identity = f.identity
    return {
        "id": f.id,
        "swb_id": f.swb_id,
        "occurrence": f.occurrence,
        # версия алгоритма и уровень отпечатка — с identity (ADR 0001 §6, T-15)
        "fingerprint_algo": identity.algo if identity else None,
        "fingerprint_level": identity.level if identity else None,
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
            "verdict": identity.verdict if identity else "unmarked",
            "source": identity.verdict_source if identity else None,
            "rationale": identity.rationale if identity else None,
            "provider": identity.provider if identity else None,
            "model_version": identity.model if identity else None,
            "prompt_id": identity.prompt_id if identity else None,
            "prompt_version": identity.prompt_version if identity else None,
            "needs_reconfirm": (identity.needs_reconfirm if identity else False) or False,
            "history": _history(db, identity),
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

    identity = f.identity
    write_verdict(
        db,
        identity,
        new_verdict=verdict,
        source="human",
        actor="human",
        rationale=rationale,
    )

    # T-32: единственная реализация подсчёта — агрегатный SQL, та же транзакция.
    recompute_counts_by_verdict(db, f.run_id)

    db.commit()
    return {
        "verdict": identity.verdict,
        "source": identity.verdict_source,
        "rationale": identity.rationale,
        "history": _history(db, identity),
    }
