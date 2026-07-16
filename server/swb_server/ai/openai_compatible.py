"""OpenAI-compatible `/chat/completions` HTTP client (T-41).

One implementation serves every provider that speaks this protocol —
DeepSeek, vLLM, Ollama, etc. A provider differs from another purely by its
`base_url` (and whether a real API key is required), both of which come
from the registry in `providers.py`. There is no per-provider branch here.
"""

from __future__ import annotations

import logging
import time

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = 120.0


def _mask_key(key: str) -> str:
    if len(key) <= 8:
        return "***"
    return key[:4] + "..." + key[-4:]


def _extract_error_message(response: httpx.Response) -> str:
    """Human-readable text for the RuntimeError raised on a non-200 response.

    T-43: this message is not just logged here — it flows *out* of this
    function inside the exception, into `analyze_loop.py`'s generic
    `except Exception` handler, which both logs it at ERROR level (via
    `str(exc)`) and forwards it verbatim to the client in the SSE `error`
    event's `"message"` field. So it must never carry raw, unvetted
    response-body text — only a provider's own well-formed
    `{"error": {"message": ...}}` field (the OpenAI-compatible error
    contract every provider in the registry speaks) is trusted enough to
    surface as-is. Anything else — a non-JSON body, or JSON missing that
    field — collapses to a length-only placeholder instead of being sliced
    and included verbatim.
    """
    try:
        data = response.json()
    except Exception:
        return f"(non-JSON error body, {len(response.text)} chars)"
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            message = err.get("message")
            if isinstance(message, str) and message:
                return message
    return f"(error body without 'error.message', {len(response.text)} chars)"


async def call_openai_compatible(
    base_url: str,
    api_key: str,
    model: str,
    system: str,
    user: str,
    *,
    provider_name: str = "openai_compatible",
) -> dict:
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.1,
        "max_tokens": 512,
        "stream": False,
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key.strip()}",
    }

    # T-43: only metadata is ever logged here — id/lengths/latency/status/
    # tokens/provider — never prompt or response *content*. The prompt
    # carries the finding's source snippet (see ai/prompts.py) and the
    # response can quote it back, so neither may reach the log file, not
    # even at DEBUG. `_mask_key` keeps the api_key itself out too.
    logger.debug(
        "[%s] REQUEST  url=%s  model=%s  api_key=%s  temperature=0.1  max_tokens=512  "
        "system_len=%d  user_len=%d",
        provider_name, url, model, _mask_key(api_key), len(system), len(user),
    )

    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(url, json=payload, headers=headers)
    except httpx.ConnectError as exc:
        elapsed = time.monotonic() - t0
        logger.error(
            "[%s] CONNECT FAILED after %.2fs  model=%s  url=%s  error=%s",
            provider_name, elapsed, model, url, exc,
        )
        # T-64: the client-facing message must not carry the provider's
        # base_url or the raw httpx connection error text — both are server
        # infra details (e.g. an internal host/port for a self-hosted
        # provider), not something the browser SSE consumer needs. Full
        # detail stays in the log line above.
        raise RuntimeError(f"Не удалось подключиться к провайдеру {provider_name}") from exc
    except httpx.TimeoutException as exc:
        elapsed = time.monotonic() - t0
        logger.error(
            "[%s] TIMEOUT after %.2fs  model=%s  url=%s",
            provider_name, elapsed, model, url,
        )
        raise RuntimeError(f"Провайдер {provider_name} не ответил за {_TIMEOUT}s") from exc
    except Exception as exc:
        elapsed = time.monotonic() - t0
        logger.error(
            "[%s] HTTP ERROR after %.2fs  model=%s  error=%s: %s",
            provider_name, elapsed, model, type(exc).__name__, exc,
        )
        raise

    elapsed = time.monotonic() - t0

    # T-43: response headers/body are metadata-only here (length, not text).
    # Headers in particular are skipped rather than dumped wholesale — a
    # provider echoing `Authorization` back would otherwise leak the api_key
    # into the log even though the request-side log already masks it.
    logger.debug(
        "[%s] HTTP %d  elapsed=%.2fs  body_len=%d",
        provider_name, response.status_code, elapsed, len(response.text),
    )

    if response.status_code != 200:
        logger.error(
            "[%s] API ERROR  status=%d  model=%s  body_len=%d",
            provider_name, response.status_code, model, len(response.text),
        )
        msg = _extract_error_message(response)
        raise RuntimeError(f"Провайдер {provider_name} вернул {response.status_code}: {msg}")

    data = response.json()
    content = (data["choices"][0]["message"].get("content") or "").strip()
    usage = data.get("usage", {})
    tokens_prompt = usage.get("prompt_tokens", 0)
    tokens_completion = usage.get("completion_tokens", 0)
    tokens_total = usage.get("total_tokens", 0)

    logger.info(
        "[%s] OK  model=%s  elapsed=%.2fs  tokens=prompt:%d+completion:%d=%d",
        provider_name, model, elapsed, tokens_prompt, tokens_completion, tokens_total,
    )
    logger.debug("[%s] response_content_len=%d chars", provider_name, len(content))

    return {"content": content, "tokens": tokens_total}
