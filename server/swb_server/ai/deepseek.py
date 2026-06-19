"""DeepSeek provider — прямой HTTP-запрос через httpx (без openai SDK)."""

from __future__ import annotations

import logging
import time

import httpx

logger = logging.getLogger(__name__)

_API_URL = "https://api.deepseek.com/chat/completions"
_TIMEOUT = 120.0


def _mask_key(key: str) -> str:
    if len(key) <= 8:
        return "***"
    return key[:4] + "..." + key[-4:]


async def call_deepseek(api_key: str, model: str, system: str, user: str) -> dict:
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

    logger.debug(
        "[deepseek] REQUEST  url=%s  model=%s  api_key=%s  temperature=0.1  max_tokens=512",
        _API_URL, model, _mask_key(api_key),
    )
    logger.debug("[deepseek] system_prompt (%d chars):\n%s", len(system), system)
    logger.debug("[deepseek] user_message  (%d chars):\n%s", len(user), user)

    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(_API_URL, json=payload, headers=headers)
    except httpx.ConnectError as exc:
        elapsed = time.monotonic() - t0
        logger.error(
            "[deepseek] CONNECT FAILED after %.2fs  model=%s  url=%s  error=%s",
            elapsed, model, _API_URL, exc,
        )
        raise RuntimeError(f"Не удалось подключиться к DeepSeek API ({_API_URL}): {exc}") from exc
    except httpx.TimeoutException as exc:
        elapsed = time.monotonic() - t0
        logger.error(
            "[deepseek] TIMEOUT after %.2fs  model=%s  url=%s",
            elapsed, model, _API_URL,
        )
        raise RuntimeError(f"DeepSeek API не ответил за {_TIMEOUT}s") from exc
    except Exception as exc:
        elapsed = time.monotonic() - t0
        logger.error(
            "[deepseek] HTTP ERROR after %.2fs  model=%s  error=%s: %s",
            elapsed, model, type(exc).__name__, exc,
        )
        raise

    elapsed = time.monotonic() - t0

    logger.debug(
        "[deepseek] HTTP %d  elapsed=%.2fs  headers=%s",
        response.status_code, elapsed, dict(response.headers),
    )
    logger.debug("[deepseek] response_body:\n%s", response.text[:2000])

    if response.status_code != 200:
        logger.error(
            "[deepseek] API ERROR  status=%d  model=%s  body=%s",
            response.status_code, model, response.text[:500],
        )
        try:
            err = response.json().get("error", {})
            msg = err.get("message", response.text[:200])
        except Exception:
            msg = response.text[:200]
        raise RuntimeError(f"DeepSeek API вернул {response.status_code}: {msg}")

    data = response.json()
    content = (data["choices"][0]["message"].get("content") or "").strip()
    usage = data.get("usage", {})
    tokens_prompt = usage.get("prompt_tokens", 0)
    tokens_completion = usage.get("completion_tokens", 0)
    tokens_total = usage.get("total_tokens", 0)

    logger.info(
        "[deepseek] OK  model=%s  elapsed=%.2fs  tokens=prompt:%d+completion:%d=%d",
        model, elapsed, tokens_prompt, tokens_completion, tokens_total,
    )
    logger.debug("[deepseek] response_content (%d chars):\n%s", len(content), content)

    return {"content": content, "tokens": tokens_total}
