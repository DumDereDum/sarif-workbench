from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from swb_contract.verdict import VERDICT_ORDER

from ..db import get_db
from ..models import Finding, FindingIdentity, VerdictEvent
from ..verdicts import VersionConflict, recompute_counts_by_verdict, write_verdict

router = APIRouter(prefix="/api/v1")

_VALID_VERDICTS = set(VERDICT_ORDER)


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


def _serialize_finding(db: Session, f: Finding) -> dict:
    """Полная сериализация находки, как отдаёт GET /findings/{id}.

    Вынесена в helper (T-38), чтобы 409 version_conflict мог вернуть в теле
    ровно то же представление актуального состояния находки, что и обычный
    GET — без дублирования полей.
    """
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
            # T-38: версия identity для оптимистической блокировки — клиент
            # обязан прислать её обратно в PATCH .../verdict как "version".
            "version": identity.version if identity else None,
            "history": _history(db, identity),
        },
    }


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, {"error": "not_found", "message": "Finding not found"})
    return _serialize_finding(db, f)


@router.patch("/findings/{finding_id}/verdict")
def update_verdict(finding_id: str, body: dict, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, {"error": "not_found", "message": "Finding not found"})

    verdict = body.get("verdict")
    if verdict not in _VALID_VERDICTS:
        raise HTTPException(400, {"error": "bad_request", "message": f"verdict must be one of {_VALID_VERDICTS}"})

    # T-38: оптимистическая блокировка — read-modify-write без версии молча
    # затирал чужое решение при параллельном редактировании (lost update).
    # Клиент обязан прислать версию identity, прочитанную своим последним GET.
    expected_version = body.get("version")
    if not isinstance(expected_version, int) or isinstance(expected_version, bool):
        raise HTTPException(
            400,
            {
                "error": "bad_request",
                "message": "version (integer, from a prior GET /findings/{id}) is required",
            },
        )

    rationale = body.get("rationale", "")

    identity = f.identity
    try:
        # T-38 (review round 2): проверка версии и её инкремент — ОДИН
        # атомарный условный UPDATE внутри write_verdict, не отдельное
        # Python-сравнение здесь заранее. Раунд 1 сравнивал
        # `expected_version != identity.version` в Python до вызова
        # write_verdict — под настоящей конкурентностью (не строго
        # последовательными запросами) это давало TOCTOU-окно: два потока
        # оба успевали пройти сравнение, пока ни один не закоммитился, и оба
        # получали 200 (см. test_two_concurrent_patches_same_version_only_one_wins).
        # Теперь конфликт обнаруживается по rowcount UPDATE'а на уровне БД.
        write_verdict(
            db,
            identity,
            new_verdict=verdict,
            source="human",
            actor="human",
            rationale=rationale,
            expected_version=expected_version,
        )
    except VersionConflict:
        # Ничего не записано (ни снапшот, ни append-only событие) — сессию
        # откатываем (снимает любые локи от наших SELECT'ов, expire'ит кэш)
        # и перечитываем находку заново, чтобы 409 нёс действительно текущее
        # состояние победившей записи, а не наш устаревший in-memory снапшот.
        db.rollback()
        fresh = db.query(Finding).filter(Finding.id == finding_id).first()
        raise HTTPException(
            409,
            {
                "error": "version_conflict",
                "message": "Finding was modified concurrently; refresh and retry",
                "finding": _serialize_finding(db, fresh) if fresh else None,
            },
        )

    # T-32: единственная реализация подсчёта — агрегатный SQL, та же транзакция.
    recompute_counts_by_verdict(db, f.run_id)

    db.commit()
    return {
        "verdict": identity.verdict,
        "source": identity.verdict_source,
        "rationale": identity.rationale,
        "version": identity.version,
        "history": _history(db, identity),
    }
