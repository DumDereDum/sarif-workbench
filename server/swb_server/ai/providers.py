"""LLM provider registry + dispatcher (T-41, T-42).

A "provider" is just a named OpenAI-compatible endpoint config — DeepSeek,
vLLM, Ollama, and friends are all reachable through the single HTTP client
in `openai_compatible.py`; what makes them different is data (`base_url`,
`local`), not code. Adding a provider means adding a registry entry, not a
new module or a new branch here.

The registry is built from config (env var or file), not hardcoded:

  SWB_AI_PROVIDERS       JSON array of provider entries (inline), e.g.:
                         [{"name": "ollama", "base_url": "http://localhost:11434/v1",
                           "local": true, "default_model": "llama3"},
                          {"name": "deepseek", "base_url": "https://api.deepseek.com",
                           "local": false, "default_model": "deepseek-chat"}]

  SWB_AI_PROVIDERS_FILE  Path to a JSON file with the same array shape.
                         Takes precedence over SWB_AI_PROVIDERS if both are set.

If neither is set, the registry falls back to a single built-in entry — a
local Ollama endpoint (`_DEFAULT_REGISTRY`). Unlike T-41, this is now an
*enforced* invariant, not just a convention: code must not leave the
perimeter by default (product invariant #2/#3), so the out-of-the-box
provider is local, and remote (`local=False`) providers are inert unless
explicitly turned on.

T-42 — remote providers are opt-in, gated by two independent controls
checked in `get_provider()` (the single choke point every LLM call goes
through, via `call_llm()`):

  SWB_ALLOW_REMOTE_PROVIDERS   Default "false". Must be truthy
                                ("1"/"true"/"yes"/"on", case-insensitive)
                                for ANY remote provider to be usable at all.

  SWB_REMOTE_PROVIDER_ALLOWLIST
                                Comma-separated list of hostnames a remote
                                provider's `base_url` is allowed to point at
                                (e.g. "api.deepseek.com,api.openai.com").
                                Empty/unset = nothing is allowlisted, so
                                remote providers stay unusable even with the
                                flag on. This is the SSRF guard for a
                                configurable `base_url`
                                (inspection/03-security.md §2, §5): the flag
                                says whether remote calls happen at all, the
                                allowlist says which hosts they may reach.

A remote provider that fails either check is not just refused when called —
it is also excluded from the "available providers" list surfaced in error
messages, so a disabled remote provider is neither visible nor callable.
Local providers (`local=True`) are never subject to these two checks.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .openai_compatible import call_openai_compatible

logger = logging.getLogger(__name__)

_ENV_PROVIDERS = "SWB_AI_PROVIDERS"
_ENV_PROVIDERS_FILE = "SWB_AI_PROVIDERS_FILE"
_ENV_ALLOW_REMOTE = "SWB_ALLOW_REMOTE_PROVIDERS"
_ENV_REMOTE_ALLOWLIST = "SWB_REMOTE_PROVIDER_ALLOWLIST"

_TRUTHY = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class ProviderConfig:
    """Provider interface: what `call_llm` needs to reach a provider.

    `local` gates enforcement (T-42): remote (`local=False`) providers are
    only reachable when `SWB_ALLOW_REMOTE_PROVIDERS` is on AND their
    `base_url` host is in `SWB_REMOTE_PROVIDER_ALLOWLIST`, checked in
    `get_provider()`. Local providers bypass both checks.
    """

    name: str
    base_url: str
    local: bool = False
    default_model: str | None = None


_DEFAULT_REGISTRY: dict[str, ProviderConfig] = {
    "ollama": ProviderConfig(
        name="ollama",
        base_url="http://localhost:11434/v1",
        local=True,
        default_model="llama3",
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


def remote_providers_allowed() -> bool:
    """T-42: master switch. False unless explicitly turned on."""
    return os.environ.get(_ENV_ALLOW_REMOTE, "").strip().lower() in _TRUTHY


def _remote_allowlist() -> set[str]:
    raw = os.environ.get(_ENV_REMOTE_ALLOWLIST, "").strip()
    if not raw:
        return set()
    return {host.strip().lower() for host in raw.split(",") if host.strip()}


def _host_of(base_url: str) -> str:
    return (urlsplit(base_url).hostname or "").lower()


def _remote_denied_reason(config: ProviderConfig) -> str | None:
    """None if this remote provider is usable right now, else why not.

    Only meaningful for `config.local is False` — callers must check that
    first. Two independent gates (T-42, see module docstring): the flag
    (any remote at all) and the allowlist (which hosts).
    """
    if not remote_providers_allowed():
        return (
            f"remote providers are disabled — set {_ENV_ALLOW_REMOTE}=true to allow "
            f"non-local providers such as {config.name!r}"
        )
    host = _host_of(config.base_url)
    allowlist = _remote_allowlist()
    if not host or host not in allowlist:
        return (
            f"host {host or config.base_url!r} is not in the remote provider allowlist — "
            f"add it to {_ENV_REMOTE_ALLOWLIST} (comma-separated hostnames) to allow {config.name!r}"
        )
    return None


def _is_usable(config: ProviderConfig) -> bool:
    return config.local or _remote_denied_reason(config) is None


def _visible_names(registry: dict[str, ProviderConfig]) -> list[str]:
    """Names of providers that are actually usable right now — a
    remote provider blocked by the flag/allowlist is not "visible"."""
    return sorted(name for name, cfg in registry.items() if _is_usable(cfg))


def get_provider(name: str) -> ProviderConfig:
    """Resolve a provider by name, enforcing the T-42 remote gate.

    This is the single choke point every LLM call goes through
    (`call_llm` below) — enforcing here means analyze.py, analyze_loop.py,
    and any future caller all get it for free.
    """
    registry = load_registry()
    config = registry.get(name)
    if config is None:
        available = ", ".join(_visible_names(registry)) or "(none configured)"
        raise ValueError(f"Unknown provider: {name!r}. Available: {available}")

    if not config.local:
        reason = _remote_denied_reason(config)
        if reason is not None:
            available = ", ".join(_visible_names(registry)) or "(none configured)"
            raise PermissionError(
                f"Remote provider {name!r} is not available: {reason}. Available: {available}"
            )

    return config


async def call_llm(provider: str, api_key: str, model: str, system: str, user: str) -> dict[str, Any]:
    """Dispatch to the configured provider. Returns {"content": str, "tokens": int}."""
    config = get_provider(provider)
    logger.debug(
        "[providers] dispatching  provider=%s  base_url=%s  model=%s  local=%s",
        provider, config.base_url, model, config.local,
    )
    return await call_openai_compatible(config.base_url, api_key, model, system, user, provider_name=provider)
