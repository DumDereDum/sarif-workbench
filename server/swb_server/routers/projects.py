from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from ..models import Project, Run
import logging

from ..db import get_db
from ..storage import delete_blob
from ..ai.analyze_loop import is_analysis_in_progress

router = APIRouter(prefix="/api/v1")
logger = logging.getLogger(__name__)


def _run_to_dict(r: Run) -> dict:
    return {
        "id": r.id,
        "commit": r.commit,
        "branch": r.branch,
        "tool": r.tool,
        "tool_version": r.tool_version,
        "analyzer_config": r.analyzer_config,
        "scanned_at": r.scanned_at,
        "uploaded_at": r.uploaded_at.isoformat() if r.uploaded_at else None,
        "counts": r.counts or {},
        "counts_by_verdict": r.counts_by_verdict or {},
        "counts_by_fstec": r.counts_by_fstec or {},
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
            "counts_by_fstec": last_run.counts_by_fstec if last_run else {},
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


@router.delete("/projects/{project_id}", status_code=204)
def delete_project(project_id: str, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, {"error": "not_found", "message": "Project not found"})

    run_ids = [run_id[0] for run_id in db.query(Run.id).filter(Run.project_id == project.id).all()]

    if any(is_analysis_in_progress(run_id) for run_id in run_ids):
        raise HTTPException(
            409,
            {
                "error": "analysis_in_progress",
                "message": "Cannot delete the project while AI analysis is running for any his run",
            },
        )

    # Удаляем проект - остальные данные удалятся каскадно
    db.delete(project)
    db.commit()

    try:
        for run_id in run_ids:
            delete_blob(run_id)
        logger.info("All blobs of the project were deleted successfully")
    except Exception as exp:
        logger.warning("Failed to delete blobs of project=%s: %s", project_id, exp)

    return Response(status_code=204) 