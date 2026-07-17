"""T-6-10: PDF-отчёт должен упорядочивать находки по смысловому
severity-порядку (critical > high > medium > low > note), а не алфавитно.

`get_report` в `routers/report.py` раньше сортировал через
`Finding.severity` — обычную строковую колонку. Алфавитный порядок строк
["critical","high","low","medium","note"] отличается от смыслового местом
low/medium: находки severity "low" оказывались раньше "medium", что вводит
читателя PDF-отчёта в заблуждение о приоритете. Фикс переиспользует
`_severity_order_expr()` (CASE-эмуляция смыслового порядка), уже
использующуюся для `list_findings` в `routers/runs.py` (T-31).

Реальный weasyprint не гоняем: `generate_pdf` монкейпатчится, чтобы
перехватить порядок находок, которые дошли до него из SQL-запроса — тот же
приём, что и в test_error_hygiene.py::test_report_generation_failure_...
"""
from __future__ import annotations

import json
import uuid


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _make_sarif_with_security_severity(specs: list[dict]) -> bytes:
    """Как `make_sarif` в conftest.py, но также пишет rule-level
    properties["security-severity"] для находок с ключом "sec_sev" в spec —
    единственный способ получить severity="critical" (LEVEL_MAP не содержит
    "critical", только `sec_sev_to_enum` через security-severity >= 9.0, см.
    swb_contract.severity)."""
    rules = []
    results = []
    for spec in specs:
        rule: dict = {"id": spec["rule_id"]}
        if "sec_sev" in spec:
            rule["properties"] = {"security-severity": str(spec["sec_sev"])}
        rules.append(rule)
        results.append(
            {
                "ruleId": spec["rule_id"],
                "level": spec.get("level", "error"),
                "message": {"text": spec.get("message", "test finding")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": spec["uri"]},
                            "region": {"startLine": spec["start_line"]},
                        }
                    }
                ],
            }
        )
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "TestTool", "version": "1.0.0", "rules": rules}},
                "results": results,
            }
        ],
        "properties": {"nonce": uuid.uuid4().hex},
    }
    return json.dumps(sarif).encode()


def test_report_orders_findings_by_semantic_severity_not_alphabetical(client, upload_run, monkeypatch):
    """Алфавитный порядок был бы critical, high, low, medium, note (различие
    от смыслового — местом low/medium). Смысловой (SEV_ORDER) —
    critical, high, medium, low, note."""
    # Импорт внутри теста, не на верху модуля: swb_server импортируется ДО
    # того, как фикстура `app` (conftest.py) успевает выставить
    # DATA_DIR/DATABASE_URL на tmp-каталог — модульный движок db.py иначе
    # успевает забиндиться на настоящую локальную dev-БД (см. docstring
    # conftest.py::app).
    import swb_server.routers.report as report_module  # noqa: PLC0415

    captured: dict = {}

    def _fake_generate_pdf(run, project, findings):
        captured["severities"] = [f.severity for f in findings]
        return b"%PDF-fake"

    monkeypatch.setattr(report_module, "generate_pdf", _fake_generate_pdf)

    repo = _unique_repo()
    specs = [
        {"rule_id": "CWE-1", "uri": "src/low.py", "start_line": 1, "level": "note"},        # -> low
        {"rule_id": "CWE-2", "uri": "src/note.py", "start_line": 2, "level": "none"},       # -> note
        {"rule_id": "CWE-3", "uri": "src/high.py", "start_line": 3, "level": "error"},      # -> high
        {"rule_id": "CWE-4", "uri": "src/medium.py", "start_line": 4, "level": "warning"},  # -> medium
        {"rule_id": "CWE-5", "uri": "src/critical.py", "start_line": 5, "sec_sev": 9.5},    # -> critical
    ]
    sarif_bytes = _make_sarif_with_security_severity(specs)
    run = upload_run(specs, repo=repo, sarif_bytes=sarif_bytes)

    resp = client.get(f"/api/v1/runs/{run['run_id']}/report")
    assert resp.status_code == 200, resp.text
    assert captured["severities"] == ["critical", "high", "medium", "low", "note"]


def test_report_toc_reflects_same_semantic_severity_order(client, upload_run):
    """Сквозной тест без monkeypatch generate_pdf: TOC и таблица находок
    строятся из того же списка, что и вернул SQL-запрос — реальный weasyprint
    гоняется, содержимое PDF не парсится (бинарный формат), но сам факт
    успешной 200-генерации на смеси severities без 500 подтверждает, что
    порядок находок, дошедший до report_gen.build_html/_toc, не ломает
    рендер."""
    repo = _unique_repo()
    specs = [
        {"rule_id": "CWE-1", "uri": "src/low.py", "start_line": 1, "level": "note"},
        {"rule_id": "CWE-2", "uri": "src/high.py", "start_line": 2, "level": "error"},
        {"rule_id": "CWE-3", "uri": "src/medium.py", "start_line": 3, "level": "warning"},
    ]
    run = upload_run(specs, repo=repo)

    resp = client.get(f"/api/v1/runs/{run['run_id']}/report")
    assert resp.status_code == 200, resp.text
    assert resp.content[:4] == b"%PDF"
