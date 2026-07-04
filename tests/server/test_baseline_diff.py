"""T-22: baseline-дифф new/closed/unchanged по identity (ADR 0001 §6, вторая половина
ценности identity после переноса вердиктов T-21).

Вердикт живёт на identity (T-14/T-15), а дифф сравнивает множества identity_id,
встречающихся в Finding-строках target-рана и baseline-рана:
- new — identity есть в target, но не в baseline;
- closed — identity есть в baseline, но не в target (сама Finding-строка берётся
  из baseline-рана, т.к. в target её физически нет);
- unchanged — identity есть в обоих.
"""
import uuid


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _swb_id() -> str:
    return f"sw2:t:{uuid.uuid4().hex[:24]}:0"


def test_diff_partial_overlap_categorizes_correctly(client, upload_run):
    repo = _unique_repo()
    shared_id = _swb_id()
    closed_id = _swb_id()
    new_id = _swb_id()

    shared_spec = {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": shared_id}
    closed_spec = {"rule_id": "CWE-79", "uri": "src/web.py", "start_line": 7, "swb_id": closed_id}
    new_spec = {"rule_id": "CWE-22", "uri": "src/fs.py", "start_line": 13, "swb_id": new_id}

    baseline_run = upload_run([shared_spec, closed_spec], repo=repo)
    target_run = upload_run([shared_spec, new_spec], repo=repo)

    resp = client.get(
        f"/api/v1/runs/{target_run['run_id']}/diff",
        params={"baseline": baseline_run["run_id"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["run_id"] == target_run["run_id"]
    assert body["baseline_run_id"] == baseline_run["run_id"]

    assert {f["swb_id"] for f in body["new"]} == {new_id}
    assert {f["swb_id"] for f in body["closed"]} == {closed_id}
    assert {f["swb_id"] for f in body["unchanged"]} == {shared_id}

    assert body["counts"] == {"new": 1, "closed": 1, "unchanged": 1}


def test_diff_empty_baseline_everything_is_new(client, upload_run):
    """Пустой baseline (0 находок) — все находки target-рана попадают в new."""
    repo = _unique_repo()
    baseline_run = upload_run([], repo=repo)
    target_run = upload_run(
        [
            {"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": _swb_id()},
            {"rule_id": "CWE-79", "uri": "src/b.py", "start_line": 2, "swb_id": _swb_id()},
        ],
        repo=repo,
    )

    resp = client.get(
        f"/api/v1/runs/{target_run['run_id']}/diff",
        params={"baseline": baseline_run["run_id"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert len(body["new"]) == 2
    assert body["closed"] == []
    assert body["unchanged"] == []
    assert body["counts"] == {"new": 2, "closed": 0, "unchanged": 0}


def test_diff_full_match_everything_unchanged(client, upload_run):
    """Полное совпадение identity между ранами — всё unchanged, new/closed пусты."""
    repo = _unique_repo()
    specs = [
        {"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": _swb_id()},
        {"rule_id": "CWE-79", "uri": "src/b.py", "start_line": 2, "swb_id": _swb_id()},
    ]

    baseline_run = upload_run(specs, repo=repo)
    target_run = upload_run(specs, repo=repo)

    resp = client.get(
        f"/api/v1/runs/{target_run['run_id']}/diff",
        params={"baseline": baseline_run["run_id"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert len(body["unchanged"]) == 2
    assert body["new"] == []
    assert body["closed"] == []
    assert body["counts"] == {"new": 0, "closed": 0, "unchanged": 2}


def test_diff_full_mismatch_everything_new_and_closed(client, upload_run):
    """Нет общих identity — всё target попадает в new, всё baseline — в closed."""
    repo = _unique_repo()
    baseline_run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": _swb_id()}],
        repo=repo,
    )
    target_run = upload_run(
        [{"rule_id": "CWE-79", "uri": "src/b.py", "start_line": 2, "swb_id": _swb_id()}],
        repo=repo,
    )

    resp = client.get(
        f"/api/v1/runs/{target_run['run_id']}/diff",
        params={"baseline": baseline_run["run_id"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert len(body["new"]) == 1
    assert len(body["closed"]) == 1
    assert body["unchanged"] == []
    assert body["counts"] == {"new": 1, "closed": 1, "unchanged": 0}


def test_diff_uses_project_baseline_when_query_param_omitted(client, upload_run):
    repo = _unique_repo()
    shared_id = _swb_id()
    baseline_run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": shared_id}],
        repo=repo,
    )
    target_run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": shared_id}],
        repo=repo,
    )

    project_id = target_run["project_id"]
    set_resp = client.put(
        f"/api/v1/projects/{project_id}/baseline",
        json={"baseline_run_id": baseline_run["run_id"]},
    )
    assert set_resp.status_code == 200, set_resp.text

    resp = client.get(f"/api/v1/runs/{target_run['run_id']}/diff")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["baseline_run_id"] == baseline_run["run_id"]
    assert len(body["unchanged"]) == 1
    assert body["new"] == []
    assert body["closed"] == []


def test_diff_explicit_baseline_overrides_project_baseline(client, upload_run):
    """Явный query-параметр baseline имеет приоритет над project.baseline_run_id."""
    repo = _unique_repo()
    project_baseline_run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": _swb_id()}],
        repo=repo,
    )
    explicit_id = _swb_id()
    explicit_baseline_run = upload_run(
        [{"rule_id": "CWE-79", "uri": "src/b.py", "start_line": 2, "swb_id": explicit_id}],
        repo=repo,
    )
    target_run = upload_run(
        [{"rule_id": "CWE-79", "uri": "src/b.py", "start_line": 2, "swb_id": explicit_id}],
        repo=repo,
    )

    project_id = target_run["project_id"]
    client.put(
        f"/api/v1/projects/{project_id}/baseline",
        json={"baseline_run_id": project_baseline_run["run_id"]},
    )

    resp = client.get(
        f"/api/v1/runs/{target_run['run_id']}/diff",
        params={"baseline": explicit_baseline_run["run_id"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["baseline_run_id"] == explicit_baseline_run["run_id"]
    assert len(body["unchanged"]) == 1


def test_diff_no_baseline_available_returns_4xx(client, upload_run):
    repo = _unique_repo()
    target_run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": _swb_id()}],
        repo=repo,
    )

    resp = client.get(f"/api/v1/runs/{target_run['run_id']}/diff")
    assert 400 <= resp.status_code < 500, resp.text
    body = resp.json()["detail"]
    assert "error" in body
    assert "message" in body


def test_diff_target_run_not_found(client, upload_run):
    repo = _unique_repo()
    baseline_run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": _swb_id()}],
        repo=repo,
    )

    resp = client.get(
        "/api/v1/runs/r-does-not-exist/diff",
        params={"baseline": baseline_run["run_id"]},
    )
    assert resp.status_code == 404
    body = resp.json()["detail"]
    assert body["error"] == "not_found"


def test_diff_baseline_run_not_found(client, upload_run):
    repo = _unique_repo()
    target_run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": _swb_id()}],
        repo=repo,
    )

    resp = client.get(
        f"/api/v1/runs/{target_run['run_id']}/diff",
        params={"baseline": "r-does-not-exist"},
    )
    assert resp.status_code == 404
    body = resp.json()["detail"]
    assert body["error"] == "not_found"


def test_diff_baseline_from_different_project_rejected(client, upload_run):
    other_repo = _unique_repo()
    own_repo = _unique_repo()

    other_project_run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": _swb_id()}],
        repo=other_repo,
    )
    target_run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1, "swb_id": _swb_id()}],
        repo=own_repo,
    )

    resp = client.get(
        f"/api/v1/runs/{target_run['run_id']}/diff",
        params={"baseline": other_project_run["run_id"]},
    )
    assert 400 <= resp.status_code < 500, resp.text
    body = resp.json()["detail"]
    assert body["error"] == "baseline_project_mismatch"
