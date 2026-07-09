from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException

logger = logging.getLogger(__name__)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import SessionLocal, get_db
from ..models import Finding, FindingIdentity, Run
from ..verdicts import recompute_counts_by_verdict, write_verdict
from ..ai.prompts import PROMPTS, build_user_message, parse_response
from ..ai.providers import call_llm

router = APIRouter(prefix="/api/v1")


class AnalyzeRequest(BaseModel):
    provider: str = "deepseek"
    api_key: str
    model: str = "deepseek-chat"
    prompt_id: str = "honest"          # honest | force_fp | custom
    custom_system: str | None = None   # used when prompt_id == "custom"
    only_unmarked: bool = True
    override: bool = False             # T-24: перезаписывать human-вердикты только явно


@router.get("/prompts")
def list_prompts():
    return {"prompts": list(PROMPTS.values())}


@router.post("/runs/{run_id}/analyze")
async def analyze_run(
    run_id: str,
    req: AnalyzeRequest,
    db: Session = Depends(get_db),
):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(404, {"error": "not_found", "message": "Run not found"})

    if req.prompt_id == "custom":
        if not req.custom_system:
            raise HTTPException(422, {"error": "missing_prompt", "message": "custom_system is required when prompt_id=custom"})
        system_prompt = req.custom_system
        # T-25: произвольный промпт с лёту не зарегистрирован — у него нет и не может быть версии.
        prompt_version = None
    elif req.prompt_id in PROMPTS:
        system_prompt = PROMPTS[req.prompt_id]["system"]
        prompt_version = PROMPTS[req.prompt_id]["version"]
    else:
        raise HTTPException(422, {"error": "unknown_prompt", "message": f"Unknown prompt_id: {req.prompt_id!r}"})

    async def stream():
        with SessionLocal() as session:
            q = session.query(Finding).filter(Finding.run_id == run_id)
            if req.only_unmarked:
                q = q.join(FindingIdentity, Finding.identity_id == FindingIdentity.id).filter(
                    FindingIdentity.verdict == "unmarked"
                )
            findings = q.all()

            # T-24: human-вердикт по умолчанию неприкосновенен — AI-анализ
            # пропускает такие находки, если не передан явный override.
            # Human-«unmarked» не защищается: это отсутствие решения.
            skipped_human = 0
            if not req.override:
                kept = []
                for f in findings:
                    ident = f.identity
                    if ident is not None and ident.verdict_source == "human" and ident.verdict != "unmarked":
                        skipped_human += 1
                    else:
                        kept.append(f)
                findings = kept

            total = len(findings)
            tokens_total = 0

            logger.info(
                "[analyze] START run_id=%s  provider=%s  model=%s  prompt=%s  only_unmarked=%s  override=%s  findings=%d  skipped_human=%d",
                run_id, req.provider, req.model, req.prompt_id, req.only_unmarked, req.override, total, skipped_human,
            )

            if total == 0:
                logger.info("[analyze] no findings to process, exiting early")
                yield _event({
                    "type": "done", "done": 0, "total": 0, "tokens_total": 0,
                    "skipped_human": skipped_human, "message": "Нет находок для анализа",
                })
                return

            yield _event({"type": "start", "total": total, "skipped_human": skipped_human})

            for i, finding in enumerate(findings):
                logger.debug(
                    "[analyze] [%d/%d] processing finding id=%s  rule=%s  severity=%s  %s:%s",
                    i + 1, total, finding.id, finding.rule_id, finding.severity,
                    finding.uri, finding.start_line,
                )
                try:
                    user_msg = build_user_message(finding)
                    logger.debug("[analyze] [%d/%d] user_message built (%d chars)", i + 1, total, len(user_msg))

                    result = await call_llm(
                        provider=req.provider,
                        api_key=req.api_key,
                        model=req.model,
                        system=system_prompt,
                        user=user_msg,
                    )

                    raw_content = result["content"]
                    verdict, rationale = parse_response(raw_content, req.prompt_id)
                    tokens_total += result.get("tokens", 0)

                    logger.info(
                        "[analyze] [%d/%d] finding=%s  verdict=%s  tokens_this=%d  tokens_total=%d",
                        i + 1, total, finding.id, verdict, result.get("tokens", 0), tokens_total,
                    )
                    logger.debug(
                        "[analyze] [%d/%d] raw_response:\n%s",
                        i + 1, total, raw_content,
                    )
                    logger.debug(
                        "[analyze] [%d/%d] parsed  verdict=%s  rationale=%s",
                        i + 1, total, verdict, rationale,
                    )

                    # T-32 (остаточный риск T-24): между постановкой в очередь этой
                    # находки и получением ответа LLM прошло сетевое время — за это
                    # время человек мог поставить свой вердикт через PATCH. Проверка
                    # verdict_source на входе в батч (выше) этого не ловит (TOCTOU):
                    # перечитываем identity непосредственно перед записью, не
                    # полагаясь на объект, загруженный/закэшированный на входе.
                    identity = finding.identity
                    if not req.override:
                        session.refresh(identity)
                        if identity.verdict_source == "human" and identity.verdict != "unmarked":
                            skipped_human += 1
                            logger.info(
                                "[analyze] [%d/%d] finding=%s SKIPPED — concurrent human verdict "
                                "landed while waiting on LLM response",
                                i + 1, total, finding.id,
                            )
                            yield _event({
                                "type": "progress",
                                "done": i + 1,
                                "total": total,
                                "tokens_total": tokens_total,
                                "finding_id": finding.id,
                                "verdict": identity.verdict,
                                "rationale": identity.rationale,
                                "skipped_human": True,
                            })
                            continue

                    write_verdict(
                        session,
                        identity,
                        new_verdict=verdict,
                        source="ai",
                        actor=f"ai:{req.provider}/{req.model}",
                        rationale=rationale,
                        provider=req.provider,
                        model=req.model,
                        prompt_id=req.prompt_id,
                        prompt_version=prompt_version,
                        run_id=run_id,
                    )

                    session.commit()
                    logger.debug("[analyze] [%d/%d] committed to DB", i + 1, total)

                    yield _event({
                        "type": "progress",
                        "done": i + 1,
                        "total": total,
                        "tokens_total": tokens_total,
                        "finding_id": finding.id,
                        "verdict": verdict,
                        "rationale": rationale,
                    })

                except Exception as exc:
                    msg = str(exc)
                    logger.error(
                        "[analyze] [%d/%d] FAILED finding=%s (%s:%s)  error=%s: %s",
                        i + 1, total, finding.id, finding.uri, finding.start_line,
                        type(exc).__name__, msg,
                    )
                    yield _event({
                        "type": "error",
                        "done": i + 1,
                        "total": total,
                        "tokens_total": tokens_total,
                        "finding_id": finding.id,
                        "uri": finding.uri or "",
                        "start_line": finding.start_line or 0,
                        "message": msg,
                    })

            # T-32: единственная реализация подсчёта — агрегатный SQL, та же транзакция.
            cvd = recompute_counts_by_verdict(session, run_id)
            session.commit()
            logger.info("[analyze] DONE run_id=%s  counts=%s  tokens_total=%d", run_id, cvd, tokens_total)

            yield _event({
                "type": "done", "done": total, "total": total,
                "tokens_total": tokens_total, "skipped_human": skipped_human,
            })

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})


def _event(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
