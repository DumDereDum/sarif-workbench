"""T-31: пагинация/фильтры/сортировка находок и агрегации в SQL, не в Python.

Раньше `list_findings`/`get_aggregations` делали `query.all()` и сортировали/
резали/группировали в Python — на больших ранах это O(N) по каждому запросу
списка. Тесты здесь бьют по контракту (`total`/`page`/`page_size`/`items`),
не по реализации: несколько страниц не должны пересекаться и не терять
записи, сортировка по severity/verdict должна быть смысловой (не
алфавитной — CASE-эмуляция _SEV_ORDER/_VERDICT_ORDER), фильтры должны давать
корректный `total`.
"""
import uuid


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _set_verdict(client, finding_id: str, verdict: str) -> None:
    resp = client.patch(f"/api/v1/findings/{finding_id}/verdict", json={"verdict": verdict})
    assert resp.status_code == 200, resp.text


# ── Пагинация ──────────────────────────────────────────────────────────────


def test_three_pages_no_overlap_no_loss(client, upload_run):
    repo = _unique_repo()
    levels = ["error", "warning", "note", "none"]
    specs = [
        {"rule_id": "CWE-89", "uri": f"src/f{i}.py", "start_line": i, "level": levels[i % 4]}
        for i in range(250)
    ]
    run = upload_run(specs, repo=repo)
    run_id = run["run_id"]

    page_size = 100
    seen_ids: list[str] = []
    total = None
    page = 1
    while True:
        resp = client.get(
            f"/api/v1/runs/{run_id}/findings",
            params={"page": page, "page_size": page_size},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["page"] == page
        assert body["page_size"] == page_size
        total = body["total"]
        seen_ids.extend(it["id"] for it in body["items"])
        if len(body["items"]) < page_size:
            break
        page += 1
        assert page <= 10, "safety cap — не должно быть бесконечного цикла"

    assert total == 250
    assert page == 3  # 100 + 100 + 50
    assert len(seen_ids) == 250
    # Ни пересечений, ни потерь записей между страницами
    assert len(set(seen_ids)) == 250


def test_page_zero_or_negative_is_clamped_not_a_500(client, upload_run):
    repo = _unique_repo()
    specs = [{"rule_id": "CWE-89", "uri": f"src/z{i}.py", "start_line": i} for i in range(5)]
    run = upload_run(specs, repo=repo)

    resp = client.get(f"/api/v1/runs/{run['run_id']}/findings", params={"page": 0})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["page"] == 1
    assert len(body["items"]) == 5

    resp_neg = client.get(f"/api/v1/runs/{run['run_id']}/findings", params={"page": -3})
    assert resp_neg.status_code == 200, resp_neg.text
    assert resp_neg.json()["page"] == 1


# ── Сортировка ────────────────────────────────────────────────────────────


def test_sort_by_severity_is_semantic_not_alphabetical(client, upload_run):
    """Алфавитный порядок был бы high < low < medium < note; смысловой (_SEV_ORDER)
    — critical > high > medium > low > note. Различаются местом low/medium —
    это и отличает CASE-based SQL-сортировку от наивного ORDER BY severity."""
    repo = _unique_repo()
    specs = [
        {"rule_id": "CWE-1", "uri": "src/a.py", "start_line": 1, "level": "note"},     # -> low
        {"rule_id": "CWE-2", "uri": "src/b.py", "start_line": 2, "level": "error"},    # -> high
        {"rule_id": "CWE-3", "uri": "src/c.py", "start_line": 3, "level": "none"},     # -> note
        {"rule_id": "CWE-4", "uri": "src/d.py", "start_line": 4, "level": "warning"},  # -> medium
    ]
    run = upload_run(specs, repo=repo)
    run_id = run["run_id"]

    resp_asc = client.get(
        f"/api/v1/runs/{run_id}/findings",
        params={"sort": "severity", "dir": "asc", "page_size": 10},
    )
    assert [it["severity"] for it in resp_asc.json()["items"]] == ["high", "medium", "low", "note"]

    resp_desc = client.get(
        f"/api/v1/runs/{run_id}/findings",
        params={"sort": "severity", "dir": "desc", "page_size": 10},
    )
    assert [it["severity"] for it in resp_desc.json()["items"]] == ["note", "low", "medium", "high"]


def test_sort_by_verdict_uses_semantic_order(client, upload_run):
    repo = _unique_repo()
    specs = [{"rule_id": "CWE-1", "uri": f"src/sv{i}.py", "start_line": i} for i in range(4)]
    run = upload_run(specs, repo=repo)
    run_id = run["run_id"]

    items = client.get(f"/api/v1/runs/{run_id}/findings", params={"page_size": 100}).json()["items"]
    by_uri = {it["uri"]: it["id"] for it in items}
    _set_verdict(client, by_uri["src/sv1.py"], "uncertain")
    _set_verdict(client, by_uri["src/sv2.py"], "false_positive")
    _set_verdict(client, by_uri["src/sv3.py"], "true_positive")
    # src/sv0.py остаётся unmarked

    resp = client.get(
        f"/api/v1/runs/{run_id}/findings",
        params={"sort": "verdict", "dir": "asc", "page_size": 100},
    )
    order = [it["verdict"] for it in resp.json()["items"]]
    assert order == ["true_positive", "false_positive", "uncertain", "unmarked"]


# ── Фильтры ───────────────────────────────────────────────────────────────


def test_filter_by_severity_gives_correct_total_and_items(client, upload_run):
    repo = _unique_repo()
    specs = (
        [{"rule_id": "CWE-1", "uri": f"src/h{i}.py", "start_line": i, "level": "error"} for i in range(5)]
        + [{"rule_id": "CWE-2", "uri": f"src/m{i}.py", "start_line": i, "level": "warning"} for i in range(7)]
        # level "none" -> severity "note" (см. _LEVEL_MAP в ingest.py; level "note" -> "low")
        + [{"rule_id": "CWE-3", "uri": f"src/n{i}.py", "start_line": i, "level": "none"} for i in range(3)]
    )
    run = upload_run(specs, repo=repo)
    run_id = run["run_id"]

    resp = client.get(f"/api/v1/runs/{run_id}/findings", params={"severity": "high", "page_size": 100})
    body = resp.json()
    assert body["total"] == 5
    assert len(body["items"]) == 5
    assert all(it["severity"] == "high" for it in body["items"])

    resp2 = client.get(
        f"/api/v1/runs/{run_id}/findings",
        params={"severity": "medium,note", "page_size": 100},
    )
    body2 = resp2.json()
    assert body2["total"] == 10
    assert {it["severity"] for it in body2["items"]} == {"medium", "note"}


def test_filter_by_verdict_gives_correct_total_and_items(client, upload_run):
    repo = _unique_repo()
    specs = [{"rule_id": "CWE-1", "uri": f"src/v{i}.py", "start_line": i} for i in range(4)]
    run = upload_run(specs, repo=repo)
    run_id = run["run_id"]

    items = client.get(f"/api/v1/runs/{run_id}/findings", params={"page_size": 100}).json()["items"]
    _set_verdict(client, items[0]["id"], "true_positive")
    _set_verdict(client, items[1]["id"], "true_positive")
    _set_verdict(client, items[2]["id"], "false_positive")
    # items[3] остаётся unmarked

    resp = client.get(
        f"/api/v1/runs/{run_id}/findings",
        params={"verdict": "true_positive", "page_size": 100},
    )
    body = resp.json()
    assert body["total"] == 2
    assert all(it["verdict"] == "true_positive" for it in body["items"])


# ── Агрегации: SQL GROUP BY/COUNT ────────────────────────────────────────


def test_aggregations_by_severity_group_by_sql(client, upload_run):
    repo = _unique_repo()
    specs = [
        {"rule_id": "CWE-1", "uri": "src/a.py", "start_line": 1, "level": "error"},
        {"rule_id": "CWE-1", "uri": "src/b.py", "start_line": 2, "level": "error"},
        {"rule_id": "CWE-2", "uri": "src/c.py", "start_line": 3, "level": "warning"},
    ]
    run = upload_run(specs, repo=repo)

    resp = client.get(f"/api/v1/runs/{run['run_id']}/aggregations", params={"by": "severity"})
    assert resp.status_code == 200, resp.text
    groups = {g["key"]: g["count"] for g in resp.json()["groups"]}
    assert groups == {"high": 2, "medium": 1}


def test_aggregations_by_verdict_group_by_sql(client, upload_run):
    repo = _unique_repo()
    specs = [{"rule_id": "CWE-1", "uri": f"src/agv{i}.py", "start_line": i} for i in range(3)]
    run = upload_run(specs, repo=repo)
    run_id = run["run_id"]

    items = client.get(f"/api/v1/runs/{run_id}/findings", params={"page_size": 100}).json()["items"]
    _set_verdict(client, items[0]["id"], "true_positive")
    _set_verdict(client, items[1]["id"], "true_positive")
    # items[2] остаётся unmarked

    resp = client.get(f"/api/v1/runs/{run_id}/aggregations", params={"by": "verdict"})
    groups = {g["key"]: g["count"] for g in resp.json()["groups"]}
    assert groups == {"true_positive": 2, "unmarked": 1}


def test_aggregations_totals_match_findings_total(client, upload_run):
    """Сумма count по группам агрегации должна совпадать с total списка находок."""
    repo = _unique_repo()
    levels = ["error", "warning", "note", "none"]
    specs = [
        {"rule_id": f"CWE-{i % 5}", "uri": f"src/agg{i}.py", "start_line": i, "level": levels[i % 4]}
        for i in range(37)
    ]
    run = upload_run(specs, repo=repo)
    run_id = run["run_id"]

    total = client.get(f"/api/v1/runs/{run_id}/findings", params={"page_size": 1}).json()["total"]
    assert total == 37

    for by in ("severity", "rule", "file", "cwe"):
        resp = client.get(f"/api/v1/runs/{run_id}/aggregations", params={"by": by})
        groups = resp.json()["groups"]
        assert sum(g["count"] for g in groups) == 37, f"by={by}"
