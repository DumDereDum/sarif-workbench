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

    logger.debug(
        "[%s] REQUEST  url=%s  model=%s  api_key=%s  temperature=0.1  max_tokens=512",
        provider_name, url, model, _mask_key(api_key),
    )
    logger.debug("[%s] system_prompt (%d chars):\n%s", provider_name, len(system), system)
    logger.debug("[%s] user_message  (%d chars):\n%s", provider_name, len(user), user)

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
        raise RuntimeError(f"Не удалось подключиться к провайдеру {provider_name} ({url}): {exc}") from exc
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

    logger.debug(
        "[%s] HTTP %d  elapsed=%.2fs  headers=%s",
        provider_name, response.status_code, elapsed, dict(response.headers),
    )
    logger.debug("[%s] response_body:\n%s", provider_name, response.text[:2000])

    if response.status_code != 200:
        logger.error(
            "[%s] API ERROR  status=%d  model=%s  body=%s",
            provider_name, response.status_code, model, response.text[:500],
        )
        try:
            err = response.json().get("error", {})
            msg = err.get("message", response.text[:200])
        except Exception:
            msg = response.text[:200]
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
    logger.debug("[%s] response_content (%d chars):\n%s", provider_name, len(content), content)

    return {"content": content, "tokens": tokens_total}
