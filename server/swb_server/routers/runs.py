from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..db import get_db
from ..ingest import MetaValidationError, ingest
from ..models import Finding, FindingIdentity, Project, Rule, Run
from ..storage import load_blob, save_blob
from ..verdicts import write_verdict

router = APIRouter(prefix="/api/v1")

_SEV_ORDER = ["critical", "high", "medium", "low", "note"]

_DEFAULT_MAX_UPLOAD_MB = 50
_UPLOAD_CHUNK_SIZE = 1024 * 1024


def _max_upload_mb() -> int:
    return int(os.environ.get("SWB_MAX_UPLOAD_MB", _DEFAULT_MAX_UPLOAD_MB))


async def _read_limited(upload: UploadFile, field: str) -> bytes:
    """Read an uploaded file, rejecting it with 413 before buffering past the limit.

    The multipart parser has already spooled the part to a temp file, so its
    ``size`` is normally known and oversized uploads are rejected without
    reading a single byte into memory. The chunked loop is a fallback for the
    case when the size is unknown — it stops as soon as the cap is crossed
    instead of loading the whole file.
    """
    limit_mb = _max_upload_mb()
    limit = limit_mb * 1024 * 1024
    detail = {
        "error": "payload_too_large",
        "message": f"{field} file exceeds the upload limit of {limit_mb} MB (SWB_MAX_UPLOAD_MB)",
    }
    if upload.size is not None and upload.size > limit:
        raise HTTPException(413, detail)
    chunks: list[bytes] = []
    total = 0
    while chunk := await upload.read(_UPLOAD_CHUNK_SIZE):
        total += len(chunk)
        if total > limit:
            raise HTTPException(413, detail)
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/runs", status_code=201)
async def upload_run(
    sarif: UploadFile = File(...),
    meta: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    sarif_bytes = await _read_limited(sarif, "sarif")
    meta_bytes = await _read_limited(meta, "meta")

    try:
        meta_data = json.loads(meta_bytes)
    except json.JSONDecodeError as exc:
        raise HTTPException(422, {"error": "invalid_meta", "message": str(exc)})

    if meta_data.get("schema") != "swbmeta/v2":
        raise HTTPException(422, {"error": "unsupported_schema", "message": "Only swbmeta/v2 is supported"})

    actual_sha = hashlib.sha256(sarif_bytes).hexdigest()
    expected_sha = meta_data.get("source_sarif", {}).get("sha256", "")
    if actual_sha != expected_sha:
        raise HTTPException(
            409,
            {"error": "sha_mismatch", "message": f"SARIF sha256 mismatch: got {actual_sha[:8]}…, expected {expected_sha[:8]}…"},
        )

    # Idempotency — same SARIF sha256 means the run is already in the DB
    existing = db.query(Run).filter(Run.sarif_sha256 == actual_sha).first()
    if existing:
        return {
            "run_id": existing.id,
            "project_id": existing.project_id,
            "deduplicated": True,
            "uploaded_at": existing.uploaded_at.isoformat() if existing.uploaded_at else None,
            "finding_count": (existing.counts or {}).get("all", 0),
            "counts": existing.counts or {},
        }

    # Resolve / create project
    provenance = meta_data.get("provenance", {})
    repo: str = provenance.get("repo", "unknown")
    project_id = re.sub(r"[^a-z0-9-]", "-", repo.lower()) if repo else "unknown"

    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        project = Project(
            id=project_id,
            repo=repo,
            name=repo.split("/")[-1] if "/" in repo else repo,
            team=provenance.get("team"),
        )
        db.add(project)
        db.flush()

    # Parse SARIF + meta
    try:
        ingested = ingest(sarif_bytes, meta_data)
    except MetaValidationError as exc:
        raise HTTPException(422, {"error": "invalid_meta", "message": str(exc)})
    except Exception as exc:
        raise HTTPException(422, {"error": "invalid_sarif", "message": str(exc)})

    # Save blobs
    run_id = "r-" + uuid.uuid4().hex[:10]
    sarif_key = f"{run_id}/report.sarif"
    meta_key = f"{run_id}/report.swbmeta.json"
    save_blob(sarif_key, sarif_bytes)
    save_blob(meta_key, meta_bytes)

    # Create run
    run = Run(
        id=run_id,
        project_id=project_id,
        commit=provenance.get("commit_short") or provenance.get("commit", "unknown"),
        branch=provenance.get("branch", "unknown"),
        tool=ingested["tool"],
        tool_version=ingested["tool_version"],
        scanned_at=provenance.get("scanned_at"),
        sarif_key=sarif_key,
        meta_key=meta_key,
        sarif_sha256=actual_sha,
        counts=ingested["counts"],
    )
    db.add(run)
    db.flush()

    # Rules
    for rule_id, info in ingested["rules"].items():
        db.add(Rule(
            run_id=run_id,
            rule_id=rule_id,
            name=info["name"],
            description=info["description"],
            help_uri=info["help_uri"],
            default_severity=info["default_severity"],
        ))

    # Findings: find-or-create identity по (project_id, swb_id) — ADR 0001 §6
    now = datetime.utcnow()
    identities: dict[str, FindingIdentity] = {}
    cvd = {"true_positive": 0, "false_positive": 0, "uncertain": 0, "unmarked": 0}
    for fd in ingested["findings"]:
        algo = fd.pop("fingerprint_algo")
        level = fd.pop("fingerprint_level")
        swb_id = fd["swb_id"]
        identity = identities.get(swb_id)
        if identity is None:
            identity = (
                db.query(FindingIdentity)
                .filter(FindingIdentity.project_id == project_id, FindingIdentity.swb_id == swb_id)
                .first()
            )
            if identity is None:
                identity = FindingIdentity(
                    project_id=project_id,
                    swb_id=swb_id,
                    algo=algo,
                    level=level,
                    first_seen_run_id=run_id,
                    first_seen_at=now,
                )
                db.add(identity)
                db.flush()
            identities[swb_id] = identity
        identity.last_seen_run_id = run_id
        identity.last_seen_at = now
        v = identity.verdict or "unmarked"
        cvd[v] = cvd.get(v, 0) + 1
        db.add(Finding(run_id=run_id, identity_id=identity.id, **fd))

    run.counts_by_verdict = cvd
    db.commit()

    return {
        "run_id": run_id,
        "project_id": project_id,
        "deduplicated": False,
        "finding_count": ingested["counts"].get("all", 0),
        "counts": ingested["counts"],
    }


@router.get("/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db)):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(404, {"error": "not_found", "message": "Run not found"})
    p = run.project
    return {
        "id": run.id,
        "project_id": run.project_id,
        "project_name": p.name if p else None,
        "project_repo": p.repo if p else None,
        "commit": run.commit,
        "branch": run.branch,
        "tool": run.tool,
        "tool_version": run.tool_version,
        "scanned_at": run.scanned_at,
        "uploaded_at": run.uploaded_at.isoformat() if run.uploaded_at else None,
        "counts": run.counts or {},
        "counts_by_verdict": run.counts_by_verdict or {},
        "baseline_run_id": p.baseline_run_id if p else None,
    }


@router.get("/runs/{run_id}/findings")
def list_findings(
    run_id: str,
    severity: str | None = None,
    verdict: str | None = None,
    rule: str | None = None,
    cwe: str | None = None,
    file: str | None = None,
    q: str | None = None,
    sort: str = "severity",
    dir: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
):
    if not db.query(Run).filter(Run.id == run_id).first():
        raise HTTPException(404, {"error": "not_found", "message": "Run not found"})

    query = db.query(Finding).filter(Finding.run_id == run_id)

    if severity:
        query = query.filter(Finding.severity.in_([s.strip() for s in severity.split(",")]))
    if verdict:
        query = query.join(FindingIdentity, Finding.identity_id == FindingIdentity.id).filter(
            FindingIdentity.verdict.in_([v.strip() for v in verdict.split(",")])
        )
    if rule:
        query = query.filter(Finding.rule_id.contains(rule))
    if cwe:
        query = query.filter(Finding.cwe.contains(cwe))
    if file:
        query = query.filter(Finding.uri.contains(file))
    if q:
        like = f"%{q}%"
        query = query.filter(
            Finding.uri.like(like)
            | Finding.rule_id.like(like)
            | Finding.message.like(like)
            | Finding.scope.like(like)
        )

    all_findings = query.all()

    # Sort
    def sort_key(f: Finding):
        if sort == "severity":
            return _SEV_ORDER.index(f.severity) if f.severity in _SEV_ORDER else 99
        if sort == "verdict":
            order = ["true_positive", "false_positive", "uncertain", "unmarked"]
            v = f.identity.verdict if f.identity else "unmarked"
            return order.index(v) if v in order else 99
        if sort == "file":
            return f.uri or ""
        return getattr(f, sort, "") or ""

    reverse = dir == "desc"
    all_findings.sort(key=sort_key, reverse=reverse)

    total = len(all_findings)
    offset = (page - 1) * page_size
    page_findings = all_findings[offset : offset + page_size]

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": f.id,
                "swb_id": f.swb_id,
                "occurrence": f.occurrence,
                # версия алгоритма и уровень отпечатка — с identity (ADR 0001 §6, T-15)
                "fingerprint_algo": (f.identity.algo if f.identity else None),
                "fingerprint_level": (f.identity.level if f.identity else None),
                "severity": f.severity,
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "cwe": f.cwe,
                "uri": f.uri,
                "start_line": f.start_line,
                "scope": f.scope,
                "message": f.message,
                "verdict": (f.identity.verdict if f.identity else "unmarked"),
                "verdict_source": (f.identity.verdict_source if f.identity else None),
                "lang": f.lang,
            }
            for f in page_findings
        ],
    }


@router.get("/runs/{run_id}/aggregations")
def get_aggregations(run_id: str, by: str = "severity", db: Session = Depends(get_db)):
    if not db.query(Run).filter(Run.id == run_id).first():
        raise HTTPException(404, {"error": "not_found", "message": "Run not found"})

    findings = db.query(Finding).filter(Finding.run_id == run_id).all()
    counts: dict[str, dict] = {}

    for f in findings:
        if by == "severity":
            key = f.severity or "note"
            label = key.capitalize()
        elif by == "verdict":
            key = (f.identity.verdict if f.identity else None) or "unmarked"
            label = key
        elif by == "rule":
            key = f.rule_id or ""
            label = f"{key} {f.rule_name or ''}".strip()
        elif by == "file":
            key = f.uri or ""
            label = key
        elif by == "cwe":
            key = f.cwe or f.rule_id or ""
            label = key
        else:
            key = f.severity or "note"
            label = key

        if key not in counts:
            counts[key] = {"key": key, "label": label, "count": 0}
        counts[key]["count"] += 1

    groups = sorted(counts.values(), key=lambda x: -x["count"])
    return {"by": by, "groups": groups}


@router.post("/runs/{run_id}/reset")
def reset_verdicts(run_id: str, db: Session = Depends(get_db)):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(404, {"error": "not_found", "message": "Run not found"})

    findings = db.query(Finding).filter(Finding.run_id == run_id).all()
    # Сброс снапшотов identity, встречающихся в ране, через writer-одиночку;
    # события journal'а append-only — не удаляются (ADR 0001 §6)
    seen: set[str] = set()
    for f in findings:
        identity = f.identity
        if identity is None or identity.id in seen:
            continue
        seen.add(identity.id)
        if (identity.verdict or "unmarked") != "unmarked":
            write_verdict(
                db,
                identity,
                new_verdict="unmarked",
                source="reset",
                actor="system",
                run_id=run_id,
            )

    total = len(findings)
    run.counts_by_verdict = {
        "true_positive": 0,
        "false_positive": 0,
        "uncertain": 0,
        "unmarked": total,
    }
    db.commit()
    return {"reset": total}


@router.get("/runs/{run_id}/sarif")
def get_sarif(run_id: str, db: Session = Depends(get_db)):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(404, {"error": "not_found", "message": "Run not found"})
    data = load_blob(run.sarif_key)
    return Response(content=data, media_type="application/json")


