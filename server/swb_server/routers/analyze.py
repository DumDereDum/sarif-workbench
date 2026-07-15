from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..ai.analyze_loop import load_findings_for_analysis, max_consecutive_errors, run_analysis
from ..ai.prompts import PROMPTS
from ..ai.providers import load_registry, visible_providers
from ..db import SessionLocal, get_db
from ..models import Run

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")


class AnalyzeRequest(BaseModel):
    # T-44: no api_key field — the client never holds or sends one, the
    # server resolves it from the chosen provider's own config
    # (ai/providers.py::_resolve_api_key). provider/model default to `None`
    # rather than a hardcoded literal (the old "deepseek"/"deepseek-chat"
    # defaults drifted out of sync with the registry after T-42) — an
    # unset value resolves to the live registry's default at request time,
    # see `_resolve_provider_and_model` below, so there is nothing here that
    # can go stale if the registry changes.
    provider: str | None = None
    model: str | None = None
    prompt_id: str = "honest"          # honest | force_fp | custom
    custom_system: str | None = None   # used when prompt_id == "custom"
    only_unmarked: bool = True
    override: bool = False             # T-24: перезаписывать human-вердикты только явно


@router.get("/prompts")
def list_prompts():
    return {"prompts": list(PROMPTS.values())}


@router.get("/providers")
def list_providers():
    """T-44: single source of truth for the web UI's provider/model choices —
    replaces the hardcoded `PROVIDERS` list that used to live in
    AnalyzeModal.tsx and could name a provider not actually in the registry.
    Only providers currently usable (T-42 gates applied — a disabled remote
    provider is omitted, same rule `get_provider()` enforces) are listed.
    """
    configs = visible_providers()
    return {
        "providers": [
            {"name": c.name, "local": c.local, "default_model": c.default_model}
            for c in configs
        ],
        "default_provider": configs[0].name if configs else None,
    }


def _resolve_provider_and_model(req: AnalyzeRequest) -> tuple[str, str]:
    """T-44: fill in an unset provider/model from the live registry default
    rather than a literal hardcoded here — see AnalyzeRequest docstring.

    An explicitly named provider is passed through untouched, even if it
    turns out to be unknown or currently blocked (T-42) — that already has
    a specific, well-tested error path (`get_provider()`'s `ValueError`/
    `PermissionError`, surfaced per-finding by `run_analysis`). The 422
    below is only for the "nothing to fall back to at all" case, when the
    caller didn't name a provider and there isn't a usable default either —
    it must not mask a more specific error for a provider the caller did
    name explicitly.
    """
    if req.provider:
        model_name = req.model
        if not model_name:
            cfg = load_registry().get(req.provider)
            model_name = (cfg.default_model if cfg else None) or ""
        return req.provider, model_name

    visible = visible_providers()
    if not visible:
        raise HTTPException(
            422,
            {
                "error": "no_provider",
                "message": "Нет доступного AI-провайдера: настройте SWB_AI_PROVIDERS "
                "или разрешите удалённый провайдер (SWB_ALLOW_REMOTE_PROVIDERS)",
            },
        )
    default_cfg = visible[0]
    model_name = req.model or default_cfg.default_model or ""
    return default_cfg.name, model_name


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

    provider_name, model_name = _resolve_provider_and_model(req)

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
                run_id, provider_name, model_name, req.prompt_id, req.only_unmarked, req.override,
                len(findings), skipped_human,
            )

            async for event in run_analysis(
                session,
                run_id,
                findings,
                provider=provider_name,
                model=model_name,
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
