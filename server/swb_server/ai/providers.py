"""LLM provider dispatcher.

Supported providers:
  deepseek  — DeepSeek API via httpx (https://api.deepseek.com/chat/completions)

To add a new provider:
  1. Create server/swb_server/ai/<name>.py with async call_<name>(...) -> dict
  2. Add a branch in call_llm() below
"""

from __future__ import annotations

import logging
from typing import Any

from .deepseek import call_deepseek

logger = logging.getLogger(__name__)


async def call_llm(provider: str, api_key: str, model: str, system: str, user: str) -> dict[str, Any]:
    """Dispatch to the right provider. Returns {"content": str, "tokens": int}."""
    logger.debug("[providers] dispatching  provider=%s  model=%s", provider, model)

    if provider == "deepseek":
        return await call_deepseek(api_key, model, system, user)

    raise ValueError(f"Unknown provider: {provider!r}. Supported: deepseek")
