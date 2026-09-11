from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from swb_contract.fstec import TABLE_1, Exploitation
from swb_contract.verdict import VERDICT_ORDER

from .. import criticality
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
        # T-66: normalize line endings before splitting. The CLI's own
        # snippet builder (cli/swb_cli/code.py) never leaves a `\r` in the
        # stored text (Path.read_text uses universal-newline translation,
        # and the snippet is re-joined with plain "\n"), but `f.snippet` is
        # untrusted at this boundary — it can come from any tool/upload that
        # produces a valid swbmeta payload, not just our CLI. Normalizing
        # here (rather than trusting `.split("\n")`) keeps a stray `\r` from
        # a CRLF-authored file out of the API response.
        lines = f.snippet.replace("\r\n", "\n").replace("\r", "\n").split("\n")
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
        # Текст самой находки. В списке он есть с самого начала, а в карточке
        # его не было: она читала поле, которого в ответе не было, и рамка
        # «Сообщение анализатора» пустовала у всех инструментов.
        "message": f.message,
        "help_uri": f.help_uri,
        "cwe": f.cwe,
        # всегда список (возможно пустой), даже у находок, загруженных до
        # появления колонки — клиенту не нужна проверка на null
        "cwes": f.cwes or [],
        # базовая оценка CVSS из отчёта; None — анализатор её не дал
        "security_severity": f.security_severity,
        # уровень критичности ФСТЭК с полным разложением расчёта: показатели,
        # веса, произведения и значения, отброшенные правилом максимума
        "fstec": criticality.describe(db, f),
        # Сведения об эксплуатации (E): что стоит сейчас и откуда это взято.
        # Отдаётся отдельно от разложения — разложение показывает значение,
        # попавшее в формулу, а здесь видно, задавал ли его человек.
        "exploitation": _exploitation_block(identity),
        "uri": f.uri,
        "start_line": f.start_line,
        "end_line": f.end_line,
        "scope": f.scope,
        "snippet": snippet_obj,
        "lang": f.lang,
        # T-39 (ADR 0001 §8): multi-location payload — always a list
        # (possibly empty), never None, even for findings ingested before
        # this column existed (SQLAlchemy JSON column default is NULL).
        "code_flow": f.code_flow or [],
        "extra_locations": f.extra_locations or [],
        "related_locations": f.related_locations or [],
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


def _exploitation_block(identity: FindingIdentity | None) -> dict:
    """Текущее значение E с меткой источника.

    `set_by_human = False` означает умолчание — «отсутствуют сведения». Это
    законное значение таблицы 1, а не пропуск, поэтому оно отдаётся с той же
    подписью, что и заданное вручную, и отличается только меткой.
    """
    raw = getattr(identity, "fstec_exploitation", None) if identity is not None else None
    value = Exploitation(raw) if raw else criticality.DEFAULT_EXPLOITATION
    at = getattr(identity, "fstec_exploitation_at", None) if identity is not None else None
    return {
        "value": value.value,
        "label": TABLE_1["E"].values[value].label,
        "score": TABLE_1["E"].values[value].score,
        "set_by_human": bool(raw),
        "ref": getattr(identity, "fstec_exploitation_ref", None) if identity is not None else None,
        "by": getattr(identity, "fstec_exploitation_by", None) if identity is not None else None,
        "at": at.isoformat() if at else None,
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
    recompute_counts_by_verdict(db, f.run_id)  # type: ignore[arg-type]
    # Вердикт «ложное срабатывание» убирает находку из оценки по методике, а
    # снятие возвращает — статус и сводка по уровням обязаны это отразить.
    criticality.recompute_finding(db, f)
    criticality.recompute_counts_by_fstec(db, f.run_id)  # type: ignore[arg-type]

    db.commit()
    return {
        "verdict": identity.verdict,
        "source": identity.verdict_source,
        "rationale": identity.rationale,
        "version": identity.version,
        "history": _history(db, identity),
    }


@router.patch("/findings/{finding_id}/exploitation")
def update_exploitation(finding_id: str, body: dict, db: Session = Depends(get_db)):
    """Показатель E методики — сведения об эксплуатации уязвимости (п. 16).

    Задаётся на находке, а не на правиле и не на проекте: правило описывает
    класс слабости, проект — систему, а «опубликован ли эксплойт и ходят ли с
    ним в атаки» — факт о конкретной уязвимости. Источник таких сведений
    внешний: БДУ, лента KEV, бюллетень поставщика, запись об инциденте.

    `value: null` возвращает находку к умолчанию «отсутствуют сведения».
    Любое другое значение требует ссылки: показатель сокращает срок
    устранения с недель до суток (п. 21), и аудитору предъявляется не только
    выбор, но и на чём он основан.
    """
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, {"error": "not_found", "message": "Finding not found"})

    identity = f.identity
    if identity is None:
        raise HTTPException(
            409,
            {"error": "no_identity", "message": "Finding has no identity to attach the indicator to"},
        )

    value = body.get("value")
    ref = (body.get("ref") or "").strip()
    actor = (body.get("actor") or "human").strip() or "human"

    if value is not None:
        try:
            exploitation = Exploitation(value)
        except ValueError:
            allowed = [e.value for e in Exploitation]
            raise HTTPException(
                400,
                {"error": "bad_request", "message": f"value must be null or one of {allowed}"},
            ) from None
        # Умолчание ссылки не требует: «сведений нет» — это отсутствие данных,
        # а не утверждение о внешнем мире, которое нужно чем-то подкреплять.
        if exploitation is not criticality.DEFAULT_EXPLOITATION and not ref:
            raise HTTPException(
                400,
                {
                    "error": "ref_required",
                    "message": (
                        "ref is required: cite the source of the exploitation data "
                        "(BDU/CVE id, advisory, incident record)"
                    ),
                },
            )
        identity.fstec_exploitation = exploitation.value  # type: ignore[assignment]
        identity.fstec_exploitation_ref = ref or None  # type: ignore[assignment]
        identity.fstec_exploitation_by = actor  # type: ignore[assignment]
        identity.fstec_exploitation_at = datetime.utcnow()  # type: ignore[assignment]
    else:
        identity.fstec_exploitation = None  # type: ignore[assignment]
        identity.fstec_exploitation_ref = None  # type: ignore[assignment]
        identity.fstec_exploitation_by = None  # type: ignore[assignment]
        identity.fstec_exploitation_at = None  # type: ignore[assignment]

    # П. 19: пересчёт при появлении новых сведений. Показатель живёт на
    # identity, поэтому пересчитываются все наблюдения находки в проекте, а
    # сводка — у каждого затронутого прогона.
    criticality.recompute_identity(db, str(identity.id))
    for run_id in {str(row[0]) for row in db.query(Finding.run_id).filter(Finding.identity_id == identity.id)}:
        criticality.recompute_counts_by_fstec(db, run_id)

    db.commit()
    return {
        "exploitation": _exploitation_block(identity),
        "fstec": criticality.describe(db, f),
    }
