"""T-37: доменный цикл AI-триажа (`ai.analyze_loop.run_analysis`) тестируется
напрямую, без HTTP-стека — вызываем генератор с фейковым провайдером и
фейковым `is_disconnected`. `call_llm` подменяется в неймспейсе
`swb_server.ai.analyze_loop` (там, куда он импортирован для использования
циклом), поэтому сеть наружу не используется.

`swb_server.ai.analyze_loop` НЕ импортируется на уровне модуля: он тянет за
собой `..models`/`..verdicts`, которые импортируют `swb_server.db` — если это
случится во время СБОРА тестов (до того как session-scoped фикстура `app` в
conftest.py успеет выставить DATA_DIR/DATABASE_URL на временный каталог),
SQLAlchemy engine молча привяжется к реальному дефолтному пути на диске
(`server/data/swb.db`) вместо временной БД теста — тот самый риск, от
которого `tests/contract/conftest.py` защищается явным `setdefault`. Поэтому
модуль импортируется лениво через фикстуру `analyze_loop`, которая зависит от
`app` и тем самым гарантирует правильный порядок.
"""
import asyncio
import uuid

import pytest


@pytest.fixture()
def analyze_loop(app):
    from swb_server.ai import analyze_loop as module  # noqa: PLC0415

    return module


def _collect(agen):
    async def _run():
        return [e async for e in agen]

    return asyncio.run(_run())


def _findings_for_run(db_session, run_id):
    from swb_server.models import Finding  # noqa: PLC0415

    return db_session.query(Finding).filter(Finding.run_id == run_id).all()


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _make_run(upload_run, n: int):
    return upload_run(
        [{"rule_id": "CWE-89", "uri": f"src/f{i}.py", "start_line": i + 1} for i in range(n)],
        repo=_unique_repo(),
    )


def _run_kwargs(**overrides):
    base = dict(
        provider="deepseek",
        model="deepseek-chat",
        system_prompt="sys",
        prompt_id="honest",
        prompt_version="1",
        override=False,
    )
    base.update(overrides)
    return base


# ── Circuit breaker ─────────────────────────────────────────────────────────


def test_circuit_breaker_stops_after_n_consecutive_errors(db_session, upload_run, monkeypatch, analyze_loop):
    run = _make_run(upload_run, 10)
    findings = _findings_for_run(db_session, run["run_id"])
    assert len(findings) == 10

    calls = []

    async def _always_fails(**kwargs):
        calls.append(1)
        raise RuntimeError("simulated provider outage (bad api key)")

    monkeypatch.setattr(analyze_loop, "call_llm", _always_fails)

    events = _collect(
        analyze_loop.run_analysis(
            db_session, run["run_id"], findings, max_errors=3, **_run_kwargs()
        )
    )

    # breaker остановил цикл после 3 ошибок подряд, а не перебрал все 10 находок
    assert len(calls) == 3

    error_events = [e for e in events if e["type"] == "error"]
    assert len(error_events) == 3

    done_events = [e for e in events if e["type"] == "done"]
    assert len(done_events) == 1
    done = done_events[0]
    assert done["stopped_reason"] == "circuit_breaker"
    assert done["done"] == 3
    assert done["total"] == 10
    assert done["message"]  # человекочитаемая причина остановки для клиента


def test_circuit_breaker_default_threshold_is_five(monkeypatch, analyze_loop):
    monkeypatch.delenv("SWB_ANALYZE_MAX_CONSECUTIVE_ERRORS", raising=False)
    assert analyze_loop.max_consecutive_errors() == analyze_loop.DEFAULT_MAX_CONSECUTIVE_ERRORS == 5


def test_circuit_breaker_threshold_configurable_via_env(monkeypatch, analyze_loop):
    monkeypatch.setenv("SWB_ANALYZE_MAX_CONSECUTIVE_ERRORS", "2")
    assert analyze_loop.max_consecutive_errors() == 2


def test_circuit_breaker_does_not_trip_on_non_consecutive_errors(db_session, upload_run, monkeypatch, analyze_loop):
    """Ошибка, ошибка, успех (сброс), ошибка, ошибка, успех — макс. 2 подряд,
    порог 3 — breaker не должен сработать, весь батч обрабатывается."""
    run = _make_run(upload_run, 6)
    findings = _findings_for_run(db_session, run["run_id"])

    calls = {"n": 0}

    async def _flaky(**kwargs):
        calls["n"] += 1
        if calls["n"] % 3 == 0:
            return {"content": "Verdict: false_positive\nRationale: ok", "tokens": 1}
        raise RuntimeError("transient")

    monkeypatch.setattr(analyze_loop, "call_llm", _flaky)

    events = _collect(
        analyze_loop.run_analysis(
            db_session, run["run_id"], findings, max_errors=3, **_run_kwargs()
        )
    )

    assert calls["n"] == 6  # весь батч дошёл до провайдера, breaker не сработал
    done = [e for e in events if e["type"] == "done"][0]
    assert "stopped_reason" not in done
    assert done["done"] == 6
    assert done["total"] == 6


# ── Disconnect ───────────────────────────────────────────────────────────────


def test_disconnect_stops_further_provider_calls(db_session, upload_run, monkeypatch, analyze_loop):
    run = _make_run(upload_run, 5)
    findings = _findings_for_run(db_session, run["run_id"])

    calls = []

    async def _ok(**kwargs):
        calls.append(1)
        return {"content": "Verdict: false_positive\nRationale: ok", "tokens": 1}

    monkeypatch.setattr(analyze_loop, "call_llm", _ok)

    checks = {"n": 0}

    async def _fake_is_disconnected():
        checks["n"] += 1
        # первые 2 находки успевают обработаться до того, как клиент "отменил"
        return checks["n"] > 2

    events = _collect(
        analyze_loop.run_analysis(
            db_session, run["run_id"], findings,
            is_disconnected=_fake_is_disconnected,
            **_run_kwargs(),
        )
    )

    # только 2 находки реально дошли до провайдера — дальше LLM не вызывается
    assert len(calls) == 2

    done_events = [e for e in events if e["type"] == "done"]
    assert len(done_events) == 1
    done = done_events[0]
    assert done["stopped_reason"] == "disconnected"
    assert done["done"] == 2
    assert done["total"] == 5
    assert done["message"]


def test_disconnect_checked_before_first_provider_call(db_session, upload_run, monkeypatch, analyze_loop):
    """Клиент отменил анализ ещё до первой находки — к провайдеру не идёт ни одного вызова."""
    run = _make_run(upload_run, 3)
    findings = _findings_for_run(db_session, run["run_id"])

    calls = []

    async def _ok(**kwargs):
        calls.append(1)
        return {"content": "Verdict: false_positive\nRationale: ok", "tokens": 1}

    monkeypatch.setattr(analyze_loop, "call_llm", _ok)

    async def _already_disconnected():
        return True

    events = _collect(
        analyze_loop.run_analysis(
            db_session, run["run_id"], findings,
            is_disconnected=_already_disconnected,
            **_run_kwargs(),
        )
    )

    assert calls == []
    done = [e for e in events if e["type"] == "done"][0]
    assert done["stopped_reason"] == "disconnected"
    assert done["done"] == 0
    assert done["total"] == 3


# ── In-progress guard (T-66) ──────────────────────────────────────────────────
#
# reset во время analyze (routers/runs.py::reset_verdicts) раньше оставлял ран
# в частично размеченном состоянии — ничто не отслеживало, что анализ этого
# рана ещё идёт. `is_analysis_in_progress` — простой in-memory guard,
# выставляемый на весь async-generator body `run_analysis` через try/finally.


def test_in_progress_guard_true_during_analysis_false_after(db_session, upload_run, monkeypatch, analyze_loop):
    """Guard is set before the first yield and cleared once the generator
    runs to completion.

    NOTE: the whole scenario runs inside a single `asyncio.run()` call, not
    one `asyncio.run()` per `__anext__()` — `asyncio.run()` calls
    `loop.shutdown_asyncgens()` on exit, which force-closes (`aclose()`s)
    any async generator created during that run and not yet exhausted. A
    separate `asyncio.run()` per step would therefore close (and clear the
    guard on) this generator after the very first step, before the test
    could observe the "in progress" state at all.
    """
    run = _make_run(upload_run, 3)
    findings = _findings_for_run(db_session, run["run_id"])
    run_id = run["run_id"]

    async def _ok(**kwargs):
        return {"content": "Verdict: false_positive\nRationale: ok", "tokens": 1}

    monkeypatch.setattr(analyze_loop, "call_llm", _ok)

    assert analyze_loop.is_analysis_in_progress(run_id) is False

    async def scenario():
        agen = analyze_loop.run_analysis(db_session, run_id, findings, **_run_kwargs())
        first_event = await agen.__anext__()
        assert first_event["type"] == "start"
        # guard is set for the whole generator body, before the first "start" yield
        assert analyze_loop.is_analysis_in_progress(run_id) is True

        remaining = [e async for e in agen]
        assert remaining[-1]["type"] == "done"
        # generator ran to completion -> finally cleared the guard
        assert analyze_loop.is_analysis_in_progress(run_id) is False

    asyncio.run(scenario())
    assert analyze_loop.is_analysis_in_progress(run_id) is False


def test_in_progress_guard_cleared_on_early_close(db_session, upload_run, monkeypatch, analyze_loop):
    """Генератор не доведён до конца (aclose — как при отмене клиента через
    `async for ... break`/`.aclose()`) — guard всё равно снимается через finally.

    See NOTE above the previous test for why this runs inside one
    `asyncio.run()` call rather than one per step.
    """
    run = _make_run(upload_run, 3)
    findings = _findings_for_run(db_session, run["run_id"])
    run_id = run["run_id"]

    async def _ok(**kwargs):
        return {"content": "Verdict: false_positive\nRationale: ok", "tokens": 1}

    monkeypatch.setattr(analyze_loop, "call_llm", _ok)

    async def scenario():
        agen = analyze_loop.run_analysis(db_session, run_id, findings, **_run_kwargs())
        await agen.__anext__()
        assert analyze_loop.is_analysis_in_progress(run_id) is True

        await agen.aclose()
        assert analyze_loop.is_analysis_in_progress(run_id) is False

    asyncio.run(scenario())
    assert analyze_loop.is_analysis_in_progress(run_id) is False


def test_in_progress_guard_cleared_when_total_is_zero(db_session, upload_run, monkeypatch, analyze_loop):
    """total == 0 — the early-return path (`return` right after the first
    yield) must also go through the `finally` cleanup, not bypass it."""
    run_id = "r-nonexistent-empty"

    events = _collect(analyze_loop.run_analysis(db_session, run_id, [], **_run_kwargs()))
    assert events[0]["type"] == "done"
    assert analyze_loop.is_analysis_in_progress(run_id) is False
