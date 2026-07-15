"""T-44: ключи живут на сервере, `GET /api/v1/providers` — единый источник
провайдеров/моделей/дефолтов для web UI (заменяет хардкод `PROVIDERS` в
AnalyzeModal.tsx, который после T-42 указывал на несуществующего провайдера
"deepseek" — любой AI-анализ из UI падал).

`AnalyzeRequest` (routers/analyze.py) больше не принимает `api_key` вообще —
ключ резолвится сервером из конфига провайдера (ai/providers.py::_resolve_api_key),
клиент никогда его не видит и не передаёт.

LLM замокан (monkeypatch call_llm в неймспейсе доменного цикла
swb_server.ai.analyze_loop — см. T-37) — наружу ничего не уходит.

`swb_server.routers.analyze` НЕ импортируется на уровне модуля: тот же риск,
что описан в test_analyze_loop.py — импорт тянет `..db`/`..models`, и если это
случится во время СБОРА тестов (до того как session-scoped фикстура `app` в
conftest.py выставит DATA_DIR/DATABASE_URL), SQLAlchemy engine молча привяжется
к реальному дефолтному пути на диске вместо временной БД теста. Поэтому
`AnalyzeRequest` тянется лениво через фикстуру, зависящую от `app`.
"""
from __future__ import annotations

import json
import uuid

import pytest


@pytest.fixture()
def AnalyzeRequestCls(app):
    from swb_server.routers.analyze import AnalyzeRequest  # noqa: PLC0415

    return AnalyzeRequest


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _sse_events(text: str) -> list[dict]:
    return [json.loads(line[len("data: "):]) for line in text.splitlines() if line.startswith("data: ")]


@pytest.fixture(autouse=True)
def _clean_provider_env(monkeypatch):
    """Реестр читается из env на каждый вызов (T-41/T-42) — не даём тестам
    наследовать конфиг друг от друга или от окружения запуска (тот же
    паттерн, что в test_provider_registry.py)."""
    monkeypatch.delenv("SWB_AI_PROVIDERS", raising=False)
    monkeypatch.delenv("SWB_AI_PROVIDERS_FILE", raising=False)
    monkeypatch.delenv("SWB_ALLOW_REMOTE_PROVIDERS", raising=False)
    monkeypatch.delenv("SWB_REMOTE_PROVIDER_ALLOWLIST", raising=False)


# ── AnalyzeRequest не принимает ключ ────────────────────────────────────────


def test_analyze_request_has_no_api_key_field(AnalyzeRequestCls):
    """Done when T-44: клиент не хранит и не передаёт ключ — контракт
    запроса даже не может принять его как значимое поле модели."""
    assert "api_key" not in AnalyzeRequestCls.model_fields


# ── GET /api/v1/providers ────────────────────────────────────────────────


def test_list_providers_default_registry_is_ollama_only(client):
    resp = client.get("/api/v1/providers")
    assert resp.status_code == 200
    body = resp.json()
    assert body["providers"] == [{"name": "ollama", "local": True, "default_model": "llama3"}]
    assert body["default_provider"] == "ollama"


def test_list_providers_excludes_blocked_remote(client, monkeypatch):
    """T-42 gate applied: cloud-x is registered but not allowed -> invisible."""
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps(
            [
                {"name": "ollama", "base_url": "http://localhost:11434/v1", "local": True, "default_model": "llama3"},
                {"name": "cloud-x", "base_url": "https://api.example.com", "local": False, "default_model": "x-1"},
            ]
        ),
    )
    # SWB_ALLOW_REMOTE_PROVIDERS unset -> cloud-x blocked by default

    resp = client.get("/api/v1/providers")
    assert resp.status_code == 200
    body = resp.json()
    assert [p["name"] for p in body["providers"]] == ["ollama"]
    assert body["default_provider"] == "ollama"


def test_list_providers_empty_when_nothing_visible(client, monkeypatch):
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps([{"name": "cloud-x", "base_url": "https://api.example.com", "local": False}]),
    )
    # remote-only registry, remote disabled by default -> nothing visible at all

    resp = client.get("/api/v1/providers")
    assert resp.status_code == 200
    body = resp.json()
    assert body["providers"] == []
    assert body["default_provider"] is None


# ── POST /runs/{id}/analyze без api_key ────────────────────────────────────


def test_analyze_request_body_has_no_api_key_and_still_works(client, upload_run, monkeypatch):
    """Regression: до T-44 клиент всегда слал `api_key` в теле; теперь тело
    запроса реально не несёт никакого секрета, и анализ всё равно проходит
    end-to-end (клиенту достаточно указать/оставить дефолтным provider/model)."""

    async def _fake_call_llm(provider, model, system, user):
        return {"content": "Verdict: true_positive\nRationale: ok", "tokens": 1}

    monkeypatch.setattr("swb_server.ai.analyze_loop.call_llm", _fake_call_llm)

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)

    payload = {"only_unmarked": False}
    assert "api_key" not in payload  # sanity: this literally is the request body below

    resp = client.post(f"/api/v1/runs/{run['run_id']}/analyze", json=payload)
    assert resp.status_code == 200, resp.text
    progress = [e for e in _sse_events(resp.text) if e["type"] == "progress"]
    assert progress and progress[0]["verdict"] == "true_positive"


def test_analyze_without_provider_field_uses_registry_default(client, upload_run, monkeypatch):
    """rassinhron models bug (T-44 Why): a caller that doesn't name a
    provider/model at all gets the *actual* registry default — not a dead
    literal that can drift out of sync with it."""
    captured: dict = {}

    async def _fake_call_llm(provider, model, system, user):
        captured["provider"] = provider
        captured["model"] = model
        return {"content": "Verdict: uncertain\nRationale: ok", "tokens": 1}

    monkeypatch.setattr("swb_server.ai.analyze_loop.call_llm", _fake_call_llm)

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)

    resp = client.post(f"/api/v1/runs/{run['run_id']}/analyze", json={"only_unmarked": False})
    assert resp.status_code == 200, resp.text
    assert captured["provider"] == "ollama"
    assert captured["model"] == "llama3"


def test_analyze_explicit_provider_overrides_default_and_picks_its_own_model(client, upload_run, monkeypatch):
    captured: dict = {}

    async def _fake_call_llm(provider, model, system, user):
        captured["provider"] = provider
        captured["model"] = model
        return {"content": "Verdict: uncertain\nRationale: ok", "tokens": 1}

    monkeypatch.setattr("swb_server.ai.analyze_loop.call_llm", _fake_call_llm)
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps(
            [
                {"name": "ollama", "base_url": "http://localhost:11434/v1", "local": True, "default_model": "llama3"},
                {"name": "vllm-local", "base_url": "http://localhost:8000/v1", "local": True, "default_model": "mistral"},
            ]
        ),
    )

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)

    resp = client.post(
        f"/api/v1/runs/{run['run_id']}/analyze",
        json={"only_unmarked": False, "provider": "vllm-local"},
    )
    assert resp.status_code == 200, resp.text
    assert captured["provider"] == "vllm-local"
    assert captured["model"] == "mistral"


def test_analyze_returns_422_when_no_provider_available(client, upload_run, monkeypatch):
    """Deny-all edge (remote-only registry, remote disabled): a clear 422,
    not an opaque failure deep inside the analyze loop."""
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps([{"name": "cloud-x", "base_url": "https://api.example.com", "local": False}]),
    )

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)

    resp = client.post(f"/api/v1/runs/{run['run_id']}/analyze", json={"only_unmarked": False})
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "no_provider"


def test_analyze_explicit_blocked_provider_is_not_masked_by_no_provider_422(client, upload_run, monkeypatch):
    """An explicitly named provider that turns out blocked/unknown gets its
    own specific error, surfaced per-finding inside the SSE stream by the
    existing get_provider()/call_llm() error path — the top-level 422 guard
    in _resolve_provider_and_model only applies when nothing was named at
    all, it must not swallow a more specific error for a name the caller
    did provide."""
    monkeypatch.setenv(
        "SWB_AI_PROVIDERS",
        json.dumps([{"name": "cloud-x", "base_url": "https://api.example.com", "local": False}]),
    )
    # remote disabled by default -> nothing "visible", but the request names
    # a provider explicitly, so the 422 guard must not fire at all.

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)

    resp = client.post(
        f"/api/v1/runs/{run['run_id']}/analyze",
        json={"only_unmarked": False, "provider": "cloud-x", "model": "x"},
    )
    assert resp.status_code == 200, resp.text  # not masked by the 422 guard
    error_events = [e for e in _sse_events(resp.text) if e["type"] == "error"]
    assert error_events, "expected the blocked-provider failure to surface as a per-finding error"
    assert "cloud-x" in error_events[0]["message"]
