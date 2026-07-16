from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy import case, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from swb_contract.severity import SEV_ORDER
from swb_contract.verdict import VERDICT_ORDER

from ..db import get_db
from ..ingest import MetaValidationError, ingest
from ..models import Finding, FindingIdentity, Project, Rule, Run
from ..storage import load_blob, save_blob
from ..verdicts import recompute_counts_by_verdict, write_verdict

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")

# Колонки находки, по которым можно сортировать напрямую (белый список — не
# пропускаем произвольные имена полей в ORDER BY). "file" — алиас uri, как и
# раньше в python-реализации.
_SORT_COLUMNS: dict[str, ColumnElement] = {
    "rule_id": Finding.rule_id,
    "rule_name": Finding.rule_name,
    "cwe": Finding.cwe,
    "uri": Finding.uri,
    "file": Finding.uri,
    "start_line": Finding.start_line,
    "end_line": Finding.end_line,
    "message": Finding.message,
    "scope": Finding.scope,
    "lang": Finding.lang,
    "swb_id": Finding.swb_id,
    "occurrence": Finding.occurrence,
}

_DEFAULT_MAX_UPLOAD_MB = 50
_UPLOAD_CHUNK_SIZE = 1024 * 1024


def _severity_order_expr() -> ColumnElement:
    """CASE, эмулирующий смысловой порядок SEV_ORDER (critical>...>note) в SQL."""
    return case(
        *[(Finding.severity == s, i) for i, s in enumerate(SEV_ORDER)],
        else_=len(SEV_ORDER),
    )


def _verdict_order_expr() -> ColumnElement:
    """CASE, эмулирующий порядок VERDICT_ORDER в SQL (требует join с FindingIdentity)."""
    return case(
        *[(FindingIdentity.verdict == v, i) for i, v in enumerate(VERDICT_ORDER)],
        else_=len(VERDICT_ORDER),
    )


def _max_upload_mb() -> int:
    return int(os.environ.get("SWB_MAX_UPLOAD_MB", _DEFAULT_MAX_UPLOAD_MB))


def _serialize_finding(f: Finding) -> dict:
    return {
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


def _create_rules_and_findings(db: Session, *, run_id: str, project_id: str, ingested: dict) -> None:
    """Пишет Rule/Finding рана из ingest(); find-or-create identity по
    (project_id, swb_id) — ADR 0001 §6. Общая для обычной загрузки и ветки
    meta_updated (T-33, ADR §7) — та же логика для обеих.
    """
    for rule_id, info in ingested["rules"].items():
        db.add(Rule(
            run_id=run_id,
            rule_id=rule_id,
            name=info["name"],
            description=info["description"],
            help_uri=info["help_uri"],
            default_severity=info["default_severity"],
        ))

    now = datetime.utcnow()
    identities: dict[str, FindingIdentity] = {}
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
            elif (identity.verdict or "unmarked") != "unmarked" and identity.last_seen_run_id != run_id:
                # Совпадение с уже известной identity, несущей вердикт (T-21,
                # ADR 0001 §6/§7): переносить нечего — вердикт уже лежит на
                # identity и виден автоматически через join. Здесь только
                # фиксируем событием, что он был применён к новому скану;
                # old = new, rationale сохраняем как есть (не сбрасываем).
                #
                # `identity.last_seen_run_id != run_id` отсекает ложное
                # срабатывание в ветке meta_updated (T-33, ADR §7): там
                # тот же самый run_id повторно прогоняется через ingest после
                # правки meta (свежие сниппеты/отпечатки) — это не новый скан,
                # а переобработка уже виденного этим раном наблюдения, поэтому
                # писать "перенесено при новом скане" было бы ложью в
                # append-only истории. Для обычной загрузки run_id всегда
                # свежий (строка runs ещё не существует), так что ни одна
                # identity не может иметь last_seen_run_id == run_id заранее —
                # проверка не меняет поведение carry-over между разными ранами.
                write_verdict(
                    db,
                    identity,
                    new_verdict=identity.verdict,  # type: ignore[arg-type]
                    source="carried",
                    actor="system",
                    rationale=identity.rationale,  # type: ignore[arg-type]
                    run_id=run_id,
                )
            identities[swb_id] = identity
        # Column[T]-vs-T false positive (same class as verdicts.py:123, T-54)
        identity.last_seen_run_id = run_id  # type: ignore[assignment]
        identity.last_seen_at = now  # type: ignore[assignment]
        db.add(Finding(run_id=run_id, identity_id=identity.id, **fd))


def _dedup_response(
    db: Session,
    existing: Run,
    sarif_bytes: bytes,
    meta_bytes: bytes,
    meta_data: dict,
) -> dict:
    """Идемпотентный ответ на повторную загрузку (project_id, sarif_sha256) — ADR 0001 §7.

    Если сохранённая meta байтово совпадает с новой — чистый дедуп, без записи.
    Если отличается (re-enrich со свежими сниппетами/отпечатками) — meta-блоб
    заменяется, Rule/Finding рана пересоздаются в этой же транзакции повторным
    ingest'ом с той же find-or-create identity логикой, что и обычная загрузка;
    вердикты не теряются — они живут на identity, не на Finding.
    """
    try:
        saved_meta_bytes = load_blob(str(existing.meta_key))
    except FileNotFoundError:
        logger.error("[runs] meta blob missing for run=%s key=%s", existing.id, existing.meta_key)
        raise HTTPException(500, {"error": "blob_missing", "message": "Stored meta file is missing"})
    if saved_meta_bytes == meta_bytes:
        return {
            "run_id": existing.id,
            "project_id": existing.project_id,
            "deduplicated": True,
            "meta_updated": False,
            "uploaded_at": existing.uploaded_at.isoformat() if existing.uploaded_at else None,
            "finding_count": (existing.counts or {}).get("all", 0),  # type: ignore[call-overload]
            "counts": existing.counts or {},
        }

    try:
        ingested = ingest(sarif_bytes, meta_data)
    except MetaValidationError as exc:
        raise HTTPException(422, {"error": "invalid_meta", "message": str(exc)})
    except Exception as exc:
        logger.warning("[runs] SARIF parse failed during re-ingest: %s: %s", type(exc).__name__, exc)
        raise HTTPException(422, {"error": "invalid_sarif", "message": "Malformed SARIF file"})

    save_blob(str(existing.meta_key), meta_bytes)
    db.query(Finding).filter(Finding.run_id == existing.id).delete()
    db.query(Rule).filter(Rule.run_id == existing.id).delete()

    _create_rules_and_findings(db, run_id=str(existing.id), project_id=str(existing.project_id), ingested=ingested)

    existing.tool = ingested["tool"]
    existing.tool_version = ingested["tool_version"]
    existing.counts = ingested["counts"]

    # T-32: единственная реализация подсчёта — агрегатный SQL, та же транзакция.
    db.flush()
    recompute_counts_by_verdict(db, str(existing.id))
    db.commit()

    return {
        "run_id": existing.id,
        "project_id": existing.project_id,
        "deduplicated": True,
        "meta_updated": True,
        "uploaded_at": existing.uploaded_at.isoformat() if existing.uploaded_at else None,
        "finding_count": ingested["counts"].get("all", 0),
        "counts": ingested["counts"],
    }


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

    if meta_data.get("schema") != "swbmeta/v3":
        raise HTTPException(422, {"error": "unsupported_schema", "message": "Only swbmeta/v3 is supported"})

    actual_sha = hashlib.sha256(sarif_bytes).hexdigest()
    expected_sha = meta_data.get("source_sarif", {}).get("sha256", "")
    if actual_sha != expected_sha:
        raise HTTPException(
            409,
            {"error": "sha_mismatch", "message": f"SARIF sha256 mismatch: got {actual_sha[:8]}…, expected {expected_sha[:8]}…"},
        )

    # Resolve / create project — до дедуп-проверки: дедуп скопирован на
    # проект (ADR 0001 §7, UNIQUE(project_id, sarif_sha256)), не глобальный —
    # тот же SARIF в другом проекте это обычная новая загрузка, не молчаливый
    # дубль. Определение проекта — из provenance.repo meta, как и раньше.
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

    # Idempotency — тот же sarif_sha256 в том же проекте (ADR 0001 §7)
    existing = (
        db.query(Run)
        .filter(Run.project_id == project_id, Run.sarif_sha256 == actual_sha)
        .first()
    )
    if existing:
        return _dedup_response(db, existing, sarif_bytes, meta_bytes, meta_data)

    # Parse SARIF + meta
    try:
        ingested = ingest(sarif_bytes, meta_data)
    except MetaValidationError as exc:
        raise HTTPException(422, {"error": "invalid_meta", "message": str(exc)})
    except Exception as exc:
        logger.warning("[runs] SARIF parse failed: %s: %s", type(exc).__name__, exc)
        raise HTTPException(422, {"error": "invalid_sarif", "message": "Malformed SARIF file"})

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
    try:
        db.flush()
    except IntegrityError:
        # Гонка двух одинаковых загрузок (ADR 0001 §7): конкурент уже
        # закоммитил тот же (project_id, sarif_sha256) между нашей
        # дедуп-проверкой выше и этим flush — откатываем и отдаём тот же
        # идемпотентный ответ, что и обычный дедуп, а не 500 (T-33).
        db.rollback()
        raced = (
            db.query(Run)
            .filter(Run.project_id == project_id, Run.sarif_sha256 == actual_sha)
            .first()
        )
        if raced is None:
            raise
        return _dedup_response(db, raced, sarif_bytes, meta_bytes, meta_data)

    _create_rules_and_findings(db, run_id=run_id, project_id=project_id, ingested=ingested)

    # T-32: единственная реализация подсчёта — агрегатный SQL, та же транзакция.
    # flush() нужен явно: Finding-строки выше только добавлены в сессию
    # (autoflush=False), а агрегатный запрос читает из БД напрямую.
    db.flush()
    recompute_counts_by_verdict(db, run_id)
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

    # join с FindingIdentity нужен и для фильтра по вердикту, и для сортировки
    # по нему — делаем один раз, не дублируя join.
    needs_identity_join = bool(verdict) or sort == "verdict"
    if needs_identity_join:
        query = query.join(FindingIdentity, Finding.identity_id == FindingIdentity.id)

    if severity:
        query = query.filter(Finding.severity.in_([s.strip() for s in severity.split(",")]))
    if verdict:
        query = query.filter(FindingIdentity.verdict.in_([v.strip() for v in verdict.split(",")]))
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

    # total считается SQL COUNT по тому же (отфильтрованному) запросу — до
    # сортировки/пагинации, чтобы не грузить находки в Python ради счёта.
    total = query.count()

    if sort == "severity":
        order_expr = _severity_order_expr()
    elif sort == "verdict":
        order_expr = _verdict_order_expr()
    else:
        # Неизвестное имя сортировки не должно превращаться в SQL-инъекцию —
        # только из белого списка; иначе — детерминированный fallback на id.
        order_expr = _SORT_COLUMNS.get(sort, Finding.id)

    order_expr = order_expr.desc() if dir == "desc" else order_expr.asc()
    # Finding.id — вторичный тай-брейкер: без него страницы могут
    # пересекаться/терять записи при равных значениях основного поля сортировки
    # (LIMIT/OFFSET без детерминированного порядка не гарантирует стабильность).
    query = query.order_by(order_expr, Finding.id.asc())

    page = max(page, 1)
    page_size = max(page_size, 1)
    offset = (page - 1) * page_size
    page_findings = query.offset(offset).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [_serialize_finding(f) for f in page_findings],
    }


@router.get("/runs/{run_id}/aggregations")
def get_aggregations(run_id: str, by: str = "severity", db: Session = Depends(get_db)):
    if not db.query(Run).filter(Run.id == run_id).first():
        raise HTTPException(404, {"error": "not_found", "message": "Run not found"})

    base = db.query(Finding).filter(Finding.run_id == run_id)
    count_expr = func.count(Finding.id)
    groups: list[dict]
    # аннотация нужна явно: ветки ниже возвращают Row разной формы (2- и
    # 3-колоночные) — без неё mypy сузил бы тип rows по первой ветке.
    rows: list[Any]

    if by == "verdict":
        key_expr = func.coalesce(FindingIdentity.verdict, "unmarked")
        rows = (
            base.join(FindingIdentity, Finding.identity_id == FindingIdentity.id)
            .with_entities(key_expr.label("key"), count_expr.label("count"))
            .group_by(key_expr)
            .all()
        )
        groups = [{"key": key, "label": key, "count": count} for key, count in rows]
    elif by == "rule":
        key_expr = func.coalesce(Finding.rule_id, "")
        name_expr = func.min(Finding.rule_name)
        rows = (
            base.with_entities(key_expr.label("key"), name_expr.label("name"), count_expr.label("count"))
            .group_by(key_expr)
            .all()
        )
        groups = [
            {"key": key, "label": f"{key} {name or ''}".strip(), "count": count}
            for key, name, count in rows
        ]
    elif by == "file":
        key_expr = func.coalesce(Finding.uri, "")
        rows = (
            base.with_entities(key_expr.label("key"), count_expr.label("count"))
            .group_by(key_expr)
            .all()
        )
        groups = [{"key": key, "label": key, "count": count} for key, count in rows]
    elif by == "cwe":
        key_expr = func.coalesce(Finding.cwe, Finding.rule_id, "")
        rows = (
            base.with_entities(key_expr.label("key"), count_expr.label("count"))
            .group_by(key_expr)
            .all()
        )
        groups = [{"key": key, "label": key, "count": count} for key, count in rows]
    else:
        # "severity" и любое нераспознанное значение `by` — прежнее поведение.
        key_expr = func.coalesce(Finding.severity, "note")
        rows = (
            base.with_entities(key_expr.label("key"), count_expr.label("count"))
            .group_by(key_expr)
            .all()
        )
        label_fn = (lambda k: k.capitalize()) if by == "severity" else (lambda k: k)
        groups = [{"key": key, "label": label_fn(key), "count": count} for key, count in rows]

    groups.sort(key=lambda x: -x["count"])
    return {"by": by, "groups": groups}


@router.get("/runs/{run_id}/diff")
def diff_run(run_id: str, baseline: str | None = None, db: Session = Depends(get_db)):
    """new/closed/unchanged между `run_id` (target) и `baseline`, сравнение по identity (ADR 0001 §6).

    `baseline` — id рана-опоры; если не передан, берётся `project.baseline_run_id`
    (T-22, вторая половина ценности identity после переноса вердиктов T-21).
    """
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(404, {"error": "not_found", "message": "Run not found"})

    baseline_run_id = baseline or (run.project.baseline_run_id if run.project else None)
    if not baseline_run_id:
        raise HTTPException(
            400,
            {
                "error": "no_baseline",
                "message": "No baseline query param given and the project has no baseline_run_id set",
            },
        )

    baseline_run = db.query(Run).filter(Run.id == baseline_run_id).first()
    if not baseline_run:
        raise HTTPException(404, {"error": "not_found", "message": "Baseline run not found"})

    if baseline_run.project_id != run.project_id:
        raise HTTPException(
            400,
            {
                "error": "baseline_project_mismatch",
                "message": "Baseline run belongs to a different project",
            },
        )

    target_findings = db.query(Finding).filter(Finding.run_id == run_id).all()
    baseline_findings = db.query(Finding).filter(Finding.run_id == baseline_run_id).all()

    target_identity_ids = {f.identity_id for f in target_findings}
    baseline_identity_ids = {f.identity_id for f in baseline_findings}

    new = [f for f in target_findings if f.identity_id not in baseline_identity_ids]
    unchanged = [f for f in target_findings if f.identity_id in baseline_identity_ids]
    closed = [f for f in baseline_findings if f.identity_id not in target_identity_ids]

    return {
        "run_id": run_id,
        "baseline_run_id": baseline_run_id,
        "new": [_serialize_finding(f) for f in new],
        "closed": [_serialize_finding(f) for f in closed],
        "unchanged": [_serialize_finding(f) for f in unchanged],
        "counts": {"new": len(new), "closed": len(closed), "unchanged": len(unchanged)},
    }


@router.post("/runs/{run_id}/reset")
def reset_verdicts(run_id: str, db: Session = Depends(get_db)):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(404, {"error": "not_found", "message": "Run not found"})

    findings = db.query(Finding).filter(Finding.run_id == run_id).all()
    # Сброс снапшотов identity, встречающихся в ране, через writer-одиночку;
    # события journal'а append-only — не удаляются (ADR 0001 §6)
    seen: set[str] = set()
    reset_count = 0
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
            reset_count += 1

    # T-32: единственная реализация подсчёта — агрегатный SQL, та же транзакция.
    recompute_counts_by_verdict(db, run_id)
    db.commit()
    return {"reset": reset_count}


@router.get("/runs/{run_id}/sarif")
def get_sarif(run_id: str, db: Session = Depends(get_db)):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(404, {"error": "not_found", "message": "Run not found"})
    try:
        data = load_blob(run.sarif_key)  # type: ignore[arg-type]
    except FileNotFoundError:
        logger.error("[runs] SARIF blob missing for run=%s key=%s", run_id, run.sarif_key)
        raise HTTPException(500, {"error": "blob_missing", "message": "Stored SARIF file is missing"})
    return Response(content=data, media_type="application/json")


