from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request

logger = logging.getLogger(__name__)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..ai.analyze_loop import load_findings_for_analysis, max_consecutive_errors, run_analysis
from ..ai.prompts import PROMPTS
from ..db import SessionLocal, get_db
from ..models import Run

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
    request: Request,
    db: Session = Depends(get_db),
):
    """Транспортный слой (SSE): валидация запроса, StreamingResponse.

    Доменный цикл — `ai.analyze_loop.run_analysis()` — вынесен отдельно (T-37)
    и тестируется без HTTP. Здесь только: разбор промпта, own DB-сессия для
    генератора (см. комментарий в `stream()`), форматирование событий в SSE.
    """
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
        # Своя сессия (не Depends(get_db)): тело этого генератора исполняется
        # StreamingResponse ПОСЛЕ того, как analyze_run() вернул ответ — сессия
        # из request-scoped get_db к этому моменту уже была бы закрыта.
        with SessionLocal() as session:
            findings, skipped_human = load_findings_for_analysis(
                session, run_id, only_unmarked=req.only_unmarked, override=req.override,
            )
            logger.info(
                "[analyze] START run_id=%s  provider=%s  model=%s  prompt=%s  only_unmarked=%s  "
                "override=%s  findings=%d  skipped_human=%d",
                run_id, req.provider, req.model, req.prompt_id, req.only_unmarked, req.override,
                len(findings), skipped_human,
            )

            async for event in run_analysis(
                session,
                run_id,
                findings,
                provider=req.provider,
                api_key=req.api_key,
                model=req.model,
                system_prompt=system_prompt,
                prompt_id=req.prompt_id,
                prompt_version=prompt_version,
                override=req.override,
                skipped_human=skipped_human,
                # T-37: проверяется перед каждым вызовом провайдера в run_analysis —
                # отмена анализа в UI (fetch AbortController) реально прекращает
                # дальнейшие LLM-вызовы на сервере, а не только прячет прогресс в браузере.
                is_disconnected=request.is_disconnected,
                # T-37: circuit breaker — N подряд ошибок провайдера останавливает
                # цикл вместо перебора всех находок с таймаутами (битый ключ и т.п.).
                max_errors=max_consecutive_errors(),
            ):
                yield _event(event)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})


def _event(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
