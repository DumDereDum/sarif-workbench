"""T-66: reset отвергается (409), пока по рану идёт AI-анализ.

`test_analyze_loop.py::test_in_progress_guard_*` уже покрывает жизненный цикл
guard'а (`ai.analyze_loop.is_analysis_in_progress`) на доменном уровне —
выставляется при входе в `run_analysis`, снимается в `finally` (нормальное
завершение, ранний `return`, `.aclose()`). Здесь — только wiring в
`routers/runs.py::reset_verdicts`: раз guard says "в процессе", эндпоинт
должен ответить 409, а не выполнить сброс.
"""
import uuid


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def test_reset_rejected_with_409_while_analysis_in_progress(client, upload_run):
    from swb_server.ai import analyze_loop

    run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1}],
        repo=_unique_repo(),
    )
    run_id = run["run_id"]

    analyze_loop._active_runs.add(run_id)
    try:
        resp = client.post(f"/api/v1/runs/{run_id}/reset")
    finally:
        analyze_loop._active_runs.discard(run_id)

    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["error"] == "analysis_in_progress"


def test_reset_succeeds_when_no_analysis_in_progress(client, upload_run):
    from swb_server.ai import analyze_loop

    run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1}],
        repo=_unique_repo(),
    )
    run_id = run["run_id"]

    assert analyze_loop.is_analysis_in_progress(run_id) is False
    resp = client.post(f"/api/v1/runs/{run_id}/reset")
    assert resp.status_code == 200


def test_reset_allowed_again_after_guard_cleared(client, upload_run):
    """Guard снят (аналог: analyze завершился) — reset снова доступен для
    того же run_id, который до этого был отвергнут 409."""
    from swb_server.ai import analyze_loop

    run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1}],
        repo=_unique_repo(),
    )
    run_id = run["run_id"]

    analyze_loop._active_runs.add(run_id)
    blocked = client.post(f"/api/v1/runs/{run_id}/reset")
    assert blocked.status_code == 409

    analyze_loop._active_runs.discard(run_id)
    allowed = client.post(f"/api/v1/runs/{run_id}/reset")
    assert allowed.status_code == 200
