from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Project, Run

router = APIRouter(prefix="/api/v1")


def _run_to_dict(r: Run) -> dict:
    return {
        "id": r.id,
        "commit": r.commit,
        "branch": r.branch,
        "tool": r.tool,
        "tool_version": r.tool_version,
        "scanned_at": r.scanned_at,
        "uploaded_at": r.uploaded_at.isoformat() if r.uploaded_at else None,
        "counts": r.counts or {},
        "counts_by_verdict": r.counts_by_verdict or {},
    }


@router.get("/projects")
def list_projects(db: Session = Depends(get_db)):
    projects = db.query(Project).order_by(Project.created_at).all()
    result = []
    for p in projects:
        last_run = (
            db.query(Run)
            .filter(Run.project_id == p.id)
            .order_by(Run.uploaded_at.desc())
            .first()
        )
        result.append({
            "id": p.id,
            "name": p.name,
            "repo": p.repo,
            "team": p.team,
            "baseline_run_id": p.baseline_run_id,
            "last_run": _run_to_dict(last_run) if last_run else None,
            "counts": last_run.counts if last_run else {},
            "counts_by_verdict": last_run.counts_by_verdict if last_run else {},
        })
    return {"projects": result}


@router.get("/projects/{project_id}/runs")
def list_runs(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, {"error": "not_found", "message": "Project not found"})

    runs = (
        db.query(Run)
        .filter(Run.project_id == project_id)
        .order_by(Run.uploaded_at.asc())
        .all()
    )
    return {
        "project": {
            "id": project.id,
            "name": project.name,
            "repo": project.repo,
            "team": project.team,
            "baseline_run_id": project.baseline_run_id,
        },
        "runs": [_run_to_dict(r) for r in runs],
    }


@router.put("/projects/{project_id}/baseline")
def set_baseline(project_id: str, body: dict, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, {"error": "not_found", "message": "Project not found"})

    baseline_run_id = body.get("baseline_run_id")
    if baseline_run_id:
        run = db.query(Run).filter(Run.id == baseline_run_id, Run.project_id == project_id).first()
        if not run:
            raise HTTPException(404, {"error": "not_found", "message": "Run not found"})

    project.baseline_run_id = baseline_run_id  # type: ignore[assignment]
    db.commit()
    return {"baseline_run_id": baseline_run_id}
