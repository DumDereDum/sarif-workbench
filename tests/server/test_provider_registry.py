"""T-41: Provider-интерфейс — конфигурируемый реестр провайдеров вместо
`if provider == "deepseek"`, и единая OpenAI-совместимая реализация HTTP-клиента
(DeepSeek/vLLM/Ollama различаются данными в реестре, не кодом).

T-42: локальный дефолт + remote-провайдеры — opt-in за двумя независимыми
воротами (`SWB_ALLOW_REMOTE_PROVIDERS` + `SWB_REMOTE_PROVIDER_ALLOWLIST`),
проверяемыми в `get_provider()` — единственной точке входа, через которую
проходит `call_llm`.

HTTP замокан через `httpx.MockTransport`, подставленный вместо
`httpx.AsyncClient` в `openai_compatible.py` — ни один настоящий сетевой
вызов наружу не уходит.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from swb_server.ai import openai_compatible, providers


def _install_mock_transport(monkeypatch, handler):
    """Подменить httpx.AsyncClient в openai_compatible.py фейковым транспортом."""
    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    class _MockAsyncClient(real_async_client):  # type: ignore[misc, valid-type]
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(openai_compatible.httpx, "AsyncClient", _MockAsyncClient)


def _ok_response(content: str = "Verdict: uncertain\nRationale: r") -> dict:
    return {
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


@pytest.fixture(autouse=True)
def _clean_provider_env(monkeypatch):
    """Реестр читается из env на каждый вызов (T-41/T-42) — не даём тестам
    наследовать конфиг друг от друга или от окружения запуска."""
    monkeypatch.delenv("SWB_AI_PROVIDERS", raising=False)
    monkeypatch.delenv("SWB_AI_PROVIDERS_FILE", raising=False)
    monkeypatch.delenv("SWB_ALLOW_REMOTE_PROVIDERS", raising=False)
    monkeypatch.delenv("SWB_REMOTE_PROVIDER_ALLOWLIST", raising=False)


# ── реестр строится из конфига (env/файл), а не хардкода ──────────────────


def test_default_registry_is_local_only():
    """T-42: дефолтный сконфигурированный провайдер — локальный, не облачный."""
    registry = providers.load_registry()

    assert set(registry) == {"ollama"}
    assert registry["ollama"].base_url == "http://localhost:11434/v1"
    assert registry["ollama"].local is True


def test_registry_from_env_json(monkeypatch):
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps(
            [
                {"name": "ollama-local", "base_url": "http://localhost:11434/v1", "local": True},
                {"name": "deepseek", "base_url": "https://api.deepseek.com", "local": False},
            ]
        ),
    )

    registry = providers.load_registry()

    assert set(registry) == {"ollama-local", "deepseek"}
    assert registry["ollama-local"].base_url == "http://localhost:11434/v1"
    assert registry["ollama-local"].local is True


def test_registry_from_file_takes_precedence_over_env(tmp_path, monkeypatch):
    cfg_file = tmp_path / "providers.json"
    cfg_file.write_text(
        json.dumps([{"name": "vllm-local", "base_url": "http://localhost:8000/v1", "local": True}])
    )

    monkeypatch.setenv("SWB_AI_PROVIDERS", json.dumps([{"name": "deepseek", "base_url": "https://x"}]))
    monkeypatch.setenv("SWB_AI_PROVIDERS_FILE", str(cfg_file))

    registry = providers.load_registry()

    assert set(registry) == {"vllm-local"}
    assert registry["vllm-local"].base_url == "http://localhost:8000/v1"


def test_get_provider_unknown_raises_with_available_list(monkeypatch):
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps([{"name": "only-one", "base_url": "http://x", "local": True}]),
    )

    with pytest.raises(ValueError, match="only-one"):
        providers.get_provider("does-not-exist")


# ── HTTP уходит на настроенный base_url, ответ парсится единообразно ──────


def test_call_llm_hits_configured_base_url_local_provider(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json=_ok_response())

    _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps([{"name": "local-llm", "base_url": "http://localhost:11434/v1", "local": True}]),
    )

    result = asyncio.run(providers.call_llm("local-llm", "unused-key", "llama3", "sys", "user"))

    assert captured["url"] == "http://localhost:11434/v1/chat/completions"
    assert result == {"content": "Verdict: uncertain\nRationale: r", "tokens": 15}


def test_call_llm_hits_configured_base_url_remote_deepseek_when_allowed(monkeypatch):
    """T-42: remote provider is reachable once BOTH the flag and the
    allowlist explicitly permit it — not just because it's in the registry."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=_ok_response("Verdict: true_positive\nRationale: ok"))

    _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps(
            [{"name": "deepseek", "base_url": "https://api.deepseek.com", "local": False, "default_model": "deepseek-chat"}]
        ),
    )
    monkeypatch.setenv("SWB_ALLOW_REMOTE_PROVIDERS", "true")
    monkeypatch.setenv("SWB_REMOTE_PROVIDER_ALLOWLIST", "api.deepseek.com")

    result = asyncio.run(providers.call_llm("deepseek", "sk-test", "deepseek-chat", "sys", "user"))

    assert captured["url"] == "https://api.deepseek.com/chat/completions"
    assert captured["auth"] == "Bearer sk-test"
    assert result == {"content": "Verdict: true_positive\nRationale: ok", "tokens": 15}


def test_call_llm_parses_identically_across_two_configured_providers(monkeypatch):
    """Verify T-41: локальный (localhost) и облачный провайдер конфигурируются
    как данные и проходят через один и тот же HTTP-код — различается только URL.
    T-42: облачный провайдер требует явного opt-in (флаг + allowlist), иначе
    этот тест сам по себе проверял бы поведение, которое T-42 запрещает."""

    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(200, json=_ok_response("Verdict: false_positive\nRationale: same-code"))

    _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps(
            [
                {"name": "vllm-local", "base_url": "http://localhost:8000/v1", "local": True},
                {"name": "cloud-x", "base_url": "https://api.example.com", "local": False},
            ]
        ),
    )
    monkeypatch.setenv("SWB_ALLOW_REMOTE_PROVIDERS", "true")
    monkeypatch.setenv("SWB_REMOTE_PROVIDER_ALLOWLIST", "api.example.com")

    r1 = asyncio.run(providers.call_llm("vllm-local", "k", "m", "s", "u"))
    r2 = asyncio.run(providers.call_llm("cloud-x", "k", "m", "s", "u"))

    expected = {"content": "Verdict: false_positive\nRationale: same-code", "tokens": 15}
    assert r1 == expected
    assert r2 == expected
    assert seen_urls == [
        "http://localhost:8000/v1/chat/completions",
        "https://api.example.com/chat/completions",
    ]


# ── T-42: remote providers are opt-in, gated by flag + host allowlist ─────


def test_remote_provider_blocked_by_default_no_network_call(monkeypatch):
    """Flag off (default) → remote provider call raises before any HTTP
    request is attempted, even though it exists in the registry."""
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200, json=_ok_response())

    _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps([{"name": "cloud-x", "base_url": "https://api.example.com", "local": False}]),
    )
    # SWB_ALLOW_REMOTE_PROVIDERS not set — default false (see _clean_provider_env).

    with pytest.raises(PermissionError, match="cloud-x"):
        asyncio.run(providers.call_llm("cloud-x", "k", "m", "s", "u"))

    assert called["count"] == 0, "remote call must not reach the network when disabled"


def test_remote_provider_blocked_when_flag_on_but_host_not_allowlisted(monkeypatch):
    """Flag on but allowlist empty/mismatched → still blocked (SSRF guard)."""
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200, json=_ok_response())

    _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps([{"name": "cloud-x", "base_url": "https://api.example.com", "local": False}]),
    )
    monkeypatch.setenv("SWB_ALLOW_REMOTE_PROVIDERS", "true")
    monkeypatch.setenv("SWB_REMOTE_PROVIDER_ALLOWLIST", "some-other-host.example")

    with pytest.raises(PermissionError, match="allowlist"):
        asyncio.run(providers.call_llm("cloud-x", "k", "m", "s", "u"))

    assert called["count"] == 0


def test_remote_provider_not_in_available_list_when_disabled(monkeypatch):
    """Disabled remote provider is not just uncallable — it's also not
    offered as an "available" option to a caller who names the wrong provider."""
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps(
            [
                {"name": "ollama", "base_url": "http://localhost:11434/v1", "local": True},
                {"name": "cloud-x", "base_url": "https://api.example.com", "local": False},
            ]
        ),
    )
    # remote disabled by default

    with pytest.raises(ValueError) as excinfo:
        providers.get_provider("does-not-exist")

    assert "ollama" in str(excinfo.value)
    assert "cloud-x" not in str(excinfo.value)


def test_local_provider_unaffected_by_remote_gate(monkeypatch):
    """Local providers bypass the flag/allowlist entirely."""
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps([{"name": "ollama", "base_url": "http://localhost:11434/v1", "local": True}]),
    )
    # SWB_ALLOW_REMOTE_PROVIDERS / allowlist both unset.

    config = providers.get_provider("ollama")

    assert config.name == "ollama"


def test_call_openai_compatible_strips_trailing_slash_in_base_url(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json=_ok_response())

    _install_mock_transport(monkeypatch, handler)

    asyncio.run(
        openai_compatible.call_openai_compatible(
            "http://localhost:11434/v1/", "key", "model", "sys", "user", provider_name="local-llm"
        )
    )

    assert captured["url"] == "http://localhost:11434/v1/chat/completions"


def test_call_openai_compatible_raises_on_non_200(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "bad key"}})

    _install_mock_transport(monkeypatch, handler)

    with pytest.raises(RuntimeError, match="bad key"):
        asyncio.run(
            openai_compatible.call_openai_compatible(
                "https://api.deepseek.com", "bad-key", "deepseek-chat", "sys", "user"
            )
        )
