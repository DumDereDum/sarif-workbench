"""T-31: PDF-отчёт не должен грузить неограниченный ран в память.

`report_gen.py` собирает одну большую HTML-строку для weasyprint — потоковой
генерации нет, поэтому единственная защита от неограниченно большого рана —
жёсткий потолок числа находок (`SWB_REPORT_MAX_FINDINGS`), проверяемый до
того, как весь ран вычитан из БД (limit+1, не query.all()).
"""
import uuid


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def test_report_over_limit_rejected_with_413(client, upload_run, monkeypatch):
    monkeypatch.setenv("SWB_REPORT_MAX_FINDINGS", "3")
    repo = _unique_repo()
    specs = [{"rule_id": "CWE-89", "uri": f"src/big{i}.py", "start_line": i} for i in range(5)]
    run = upload_run(specs, repo=repo)

    resp = client.get(f"/api/v1/runs/{run['run_id']}/report")
    assert resp.status_code == 413, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "report_too_large"
    assert "3" in detail["message"]


def test_report_under_limit_still_generates_pdf(client, upload_run, monkeypatch):
    monkeypatch.setenv("SWB_REPORT_MAX_FINDINGS", "10")
    repo = _unique_repo()
    specs = [{"rule_id": "CWE-89", "uri": f"src/ok{i}.py", "start_line": i} for i in range(3)]
    run = upload_run(specs, repo=repo)

    resp = client.get(f"/api/v1/runs/{run['run_id']}/report")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"


def test_report_exactly_at_limit_still_generates(client, upload_run, monkeypatch):
    """limit+1-запрос не должен ложно отклонять ран ровно на границе лимита."""
    monkeypatch.setenv("SWB_REPORT_MAX_FINDINGS", "4")
    repo = _unique_repo()
    specs = [{"rule_id": "CWE-89", "uri": f"src/edge{i}.py", "start_line": i} for i in range(4)]
    run = upload_run(specs, repo=repo)

    resp = client.get(f"/api/v1/runs/{run['run_id']}/report")
    assert resp.status_code == 200, resp.text
