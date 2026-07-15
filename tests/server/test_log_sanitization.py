"""T-43: log sanitization — prompt/response content and the raw api_key must
never reach the log output, at any log level, from either of the two places
that talk to an LLM provider or handle its answer:

  - `ai/openai_compatible.py::call_openai_compatible` — the HTTP client that
    builds the request (system/user messages) and reads the response;
  - `ai/analyze_loop.py::run_analysis` — the domain loop that logs around
    the parsed verdict/rationale for each finding.

Before T-43 both modules logged full prompt/response text at DEBUG (the
system prompt carries the finding's source snippet, see `ai/prompts.py`,
and the LLM's rationale can quote it back) — a code/secret leak onto disk
via `LOG_LEVEL=DEBUG`, independent of the "data doesn't leave the perimeter"
invariant since it's a *local* leak, but just as real for anyone who can
read the server's log file.

Verified by injecting a marker string standing in for "source code from a
finding's snippet" into the system prompt, the user message, and the mocked
provider response, plus a marker api_key standing in for a real secret, and
asserting neither marker appears anywhere in the captured log text — only
`_mask_key`'s masked form of the api_key may.
"""
from __future__ import annotations

import asyncio
import logging
import uuid

import httpx
import pytest

from swb_server.ai import openai_compatible

CODE_MARKER = "UNIQUE_SECRET_CODE_MARKER_12345"
KEY_MARKER = "sk-VERYSECRETKEY000111"


def _install_mock_transport(monkeypatch, handler):
    """Substitute httpx.AsyncClient in openai_compatible.py with a fake
    transport — no real network call ever leaves the process."""
    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    class _MockAsyncClient(real_async_client):  # type: ignore[misc, valid-type]
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(openai_compatible.httpx, "AsyncClient", _MockAsyncClient)


def _ok_response(content: str) -> dict:
    return {
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


# ── ai/openai_compatible.py ─────────────────────────────────────────────────


def test_call_openai_compatible_never_logs_prompt_or_response_content(monkeypatch, caplog):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok_response(f"Verdict: true_positive\nRationale: {CODE_MARKER}"))

    _install_mock_transport(monkeypatch, handler)

    system_prompt = f"You are a reviewer.\n```\n{CODE_MARKER}\n```"
    user_message = f"Finding context:\n```\n{CODE_MARKER}\n```"

    with caplog.at_level(logging.DEBUG, logger="swb_server.ai.openai_compatible"):
        result = asyncio.run(
            openai_compatible.call_openai_compatible(
                "https://api.example.com", KEY_MARKER, "test-model",
                system_prompt, user_message, provider_name="test-provider",
            )
        )

    assert CODE_MARKER in result["content"]  # sanity: the marker really was in the response
    assert CODE_MARKER not in caplog.text, "prompt/response content leaked into logs"
    assert KEY_MARKER not in caplog.text, "raw api_key leaked into logs"
    # Sanity: logging still happened (and the masked key form made it through)
    # — the absence above isn't just because nothing got logged at all.
    assert "test-provider" in caplog.text
    assert openai_compatible._mask_key(KEY_MARKER) in caplog.text


def test_call_openai_compatible_never_logs_error_body_content(monkeypatch, caplog):
    """Non-200 branch, non-JSON body: the raw error body is metadata-only
    (length) in the direct log call here — AND, since the exception message
    itself is what ultimately reaches the log/SSE downstream (see
    `test_call_openai_compatible_error_message_never_contains_raw_body`
    below), it must not carry the raw body text either."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text=f"unauthorized, saw: {CODE_MARKER}")

    _install_mock_transport(monkeypatch, handler)

    with (
        caplog.at_level(logging.DEBUG, logger="swb_server.ai.openai_compatible"),
        pytest.raises(RuntimeError) as excinfo,
    ):
        asyncio.run(
            openai_compatible.call_openai_compatible(
                "https://api.example.com", KEY_MARKER, "test-model", "sys", "user",
                provider_name="test-provider",
            )
        )

    assert CODE_MARKER not in caplog.text
    assert KEY_MARKER not in caplog.text
    assert CODE_MARKER not in str(excinfo.value), (
        "raw error body leaked into the exception message — this message is "
        "what analyze_loop.py later logs at ERROR *and* sends to the client "
        "over SSE, so a non-200 response body is not just a logging concern"
    )


def test_call_openai_compatible_error_message_never_contains_json_body_without_message_field(monkeypatch):
    """Non-200 branch, valid JSON but missing the OpenAI-compatible
    `error.message` field: falling back to raw response text was the bug —
    the exception message must fall back to a length-only placeholder
    instead, not to `response.text[:200]`."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"code": "bad_request", "details": CODE_MARKER}})

    _install_mock_transport(monkeypatch, handler)

    with pytest.raises(RuntimeError) as excinfo:
        asyncio.run(
            openai_compatible.call_openai_compatible(
                "https://api.example.com", KEY_MARKER, "test-model", "sys", "user",
            )
        )

    assert CODE_MARKER not in str(excinfo.value)


def test_call_openai_compatible_never_logs_response_headers(monkeypatch, caplog):
    """A provider that (mis)echoes Authorization back in response headers
    must not leak the api_key via a wholesale headers dump."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_ok_response("Verdict: uncertain\nRationale: ok"),
            headers={"Authorization": request.headers["authorization"]},
        )

    _install_mock_transport(monkeypatch, handler)

    with caplog.at_level(logging.DEBUG, logger="swb_server.ai.openai_compatible"):
        asyncio.run(
            openai_compatible.call_openai_compatible(
                "https://api.example.com", KEY_MARKER, "test-model", "sys", "user",
                provider_name="test-provider",
            )
        )

    assert KEY_MARKER not in caplog.text


# ── ai/analyze_loop.py ──────────────────────────────────────────────────────


@pytest.fixture()
def analyze_loop(app):
    from swb_server.ai import analyze_loop as module  # noqa: PLC0415

    return module


def _collect(agen):
    async def _run():
        return [e async for e in agen]

    return asyncio.run(_run())


def test_analyze_loop_never_logs_raw_response_or_rationale(db_session, upload_run, monkeypatch, caplog, analyze_loop):
    from swb_server.models import Finding  # noqa: PLC0415

    run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/f.py", "start_line": 1}],
        repo=f"swb-test-{uuid.uuid4().hex[:8]}",
    )
    findings = db_session.query(Finding).filter(Finding.run_id == run["run_id"]).all()
    assert len(findings) == 1

    async def _fake_call_llm(**kwargs):
        return {"content": f"Verdict: false_positive\nRationale: {CODE_MARKER}", "tokens": 1}

    monkeypatch.setattr(analyze_loop, "call_llm", _fake_call_llm)

    with caplog.at_level(logging.DEBUG):
        events = _collect(
            analyze_loop.run_analysis(
                db_session, run["run_id"], findings,
                provider="deepseek",
                model="deepseek-chat",
                system_prompt=f"sys prompt with {CODE_MARKER}",
                prompt_id="honest",
                prompt_version="1",
                override=False,
            )
        )

    assert any(e["type"] == "progress" for e in events)
    assert CODE_MARKER not in caplog.text, "raw LLM response / rationale leaked into logs"
    assert KEY_MARKER not in caplog.text, "raw api_key leaked into logs"


def test_analyze_loop_error_path_never_leaks_raw_provider_error_body(
    db_session, upload_run, monkeypatch, caplog, analyze_loop,
):
    """End-to-end regression for the leak reviewer found: a non-200 provider
    response with a non-standard error body (not `{"error": {"message": ...}}`)
    must not leak its raw text into EITHER of the two downstream consumers of
    the resulting exception message — analyze_loop.py's ERROR-level log line
    (`except Exception as exc: ... logger.error(..., msg, ...)`) and the SSE
    `error` event's `"message"` field sent to the client.

    Wires `analyze_loop.call_llm` straight to the real
    `openai_compatible.call_openai_compatible` (mocked HTTP transport only)
    so the exception actually flows through both files, not just one."""
    from swb_server.models import Finding  # noqa: PLC0415

    run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/f.py", "start_line": 1}],
        repo=f"swb-test-{uuid.uuid4().hex[:8]}",
    )
    findings = db_session.query(Finding).filter(Finding.run_id == run["run_id"]).all()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text=f"upstream blew up: {CODE_MARKER}")

    _install_mock_transport(monkeypatch, handler)

    # T-44: analyze_loop.call_llm no longer receives api_key (it's resolved
    # server-side inside providers.call_llm from the provider's own config,
    # not passed down from the caller) — the stand-in below hardcodes the
    # marker key itself, standing in for whatever `_resolve_api_key` would
    # have produced, so this test still exercises "a real secret flowing
    # through call_openai_compatible must never leak into logs/SSE".
    async def _real_call_llm(*, provider, model, system, user):
        return await openai_compatible.call_openai_compatible(
            "https://api.example.com", KEY_MARKER, model, system, user, provider_name=provider,
        )

    monkeypatch.setattr(analyze_loop, "call_llm", _real_call_llm)

    with caplog.at_level(logging.DEBUG):
        events = _collect(
            analyze_loop.run_analysis(
                db_session, run["run_id"], findings,
                provider="deepseek",
                model="deepseek-chat",
                system_prompt="sys",
                prompt_id="honest",
                prompt_version="1",
                override=False,
                max_errors=1,
            )
        )

    error_events = [e for e in events if e["type"] == "error"]
    assert error_events, "expected the provider failure to surface as an 'error' event"
    assert CODE_MARKER not in error_events[0]["message"], "raw provider error body leaked into the SSE event"
    assert CODE_MARKER not in caplog.text, "raw provider error body leaked into the ERROR log line"
    assert KEY_MARKER not in caplog.text
    assert KEY_MARKER not in error_events[0]["message"]
