"""LLM provider registry + dispatcher (T-41).

A "provider" is just a named OpenAI-compatible endpoint config — DeepSeek,
vLLM, Ollama, and friends are all reachable through the single HTTP client
in `openai_compatible.py`; what makes them different is data (`base_url`,
`local`), not code. Adding a provider means adding a registry entry, not a
new module or a new branch here.

The registry is built from config (env var or file), not hardcoded:

  SWB_AI_PROVIDERS       JSON array of provider entries (inline), e.g.:
                         [{"name": "deepseek", "base_url": "https://api.deepseek.com",
                           "local": false, "default_model": "deepseek-chat"},
                          {"name": "ollama", "base_url": "http://localhost:11434/v1",
                           "local": true, "default_model": "llama3"}]

  SWB_AI_PROVIDERS_FILE  Path to a JSON file with the same array shape.
                         Takes precedence over SWB_AI_PROVIDERS if both are set.

If neither is set, the registry falls back to a single built-in entry
(DeepSeek's cloud API) — this preserves today's behavior unchanged for
anyone who hasn't configured anything. Making the *default* a local
provider and gating remote providers behind an opt-in flag is T-42, not
this task.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

from .openai_compatible import call_openai_compatible

logger = logging.getLogger(__name__)

_ENV_PROVIDERS = "SWB_AI_PROVIDERS"
_ENV_PROVIDERS_FILE = "SWB_AI_PROVIDERS_FILE"


@dataclass(frozen=True)
class ProviderConfig:
    """Provider interface: what `call_llm` needs to reach a provider.

    `local` is descriptive metadata in this task (surfaced for a future
    "local providers only" enforcement, T-42) — T-41 does not act on it.
    """

    name: str
    base_url: str
    local: bool = False
    default_model: str | None = None


_DEFAULT_REGISTRY: dict[str, ProviderConfig] = {
    "deepseek": ProviderConfig(
        name="deepseek",
        base_url="https://api.deepseek.com",
        local=False,
        default_model="deepseek-chat",
    ),
}


def _parse_registry(raw: str, *, source: str) -> dict[str, ProviderConfig]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {source}: {exc}") from exc

    registry: dict[str, ProviderConfig] = {}
    for entry in data:
        try:
            cfg = ProviderConfig(
                name=entry["name"],
                base_url=entry["base_url"],
                local=bool(entry.get("local", False)),
                default_model=entry.get("default_model"),
            )
        except KeyError as exc:
            raise ValueError(f"{source}: provider entry missing required field {exc}") from exc
        registry[cfg.name] = cfg
    return registry


def load_registry() -> dict[str, ProviderConfig]:
    """Build the provider registry from config (env var or file).

    Read fresh on every call rather than cached at import time — same
    pattern as `analyze_loop.max_consecutive_errors()` — so config changes
    (and tests using monkeypatch/env) take effect without reloading the
    module.
    """
    file_path = os.environ.get(_ENV_PROVIDERS_FILE, "").strip()
    if file_path:
        with open(file_path, encoding="utf-8") as fh:
            return _parse_registry(fh.read(), source=_ENV_PROVIDERS_FILE)

    raw = os.environ.get(_ENV_PROVIDERS, "").strip()
    if raw:
        return _parse_registry(raw, source=_ENV_PROVIDERS)

    return dict(_DEFAULT_REGISTRY)


def get_provider(name: str) -> ProviderConfig:
    registry = load_registry()
    try:
        return registry[name]
    except KeyError:
        available = ", ".join(sorted(registry)) or "(none configured)"
        raise ValueError(f"Unknown provider: {name!r}. Available: {available}") from None


async def call_llm(provider: str, api_key: str, model: str, system: str, user: str) -> dict[str, Any]:
    """Dispatch to the configured provider. Returns {"content": str, "tokens": int}."""
    config = get_provider(provider)
    logger.debug(
        "[providers] dispatching  provider=%s  base_url=%s  model=%s  local=%s",
        provider, config.base_url, model, config.local,
    )
    return await call_openai_compatible(config.base_url, api_key, model, system, user, provider_name=provider)
