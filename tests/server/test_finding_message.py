"""Текст находки в карточке.

`result.message.text` — единственное, что объясняет конкретное срабатывание:
у Svace описания правила нет вовсе (`shortDescription` повторяет имя правила),
и сообщение остаётся единственным содержательным текстом. В списке находок оно
было с самого начала, а деталь его не отдавала — карточка читала поле, которого
в ответе не существовало.

Импорт `swb_server.models` на уровне модуля не делаем (см. комментарий в
tests/server/test_meta_sarif_reconciliation.py).
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

DATA = Path(__file__).parent.parent / "data"
VALID = DATA / "valid"


class _EnrichArgs:
    def __init__(self, sarif, out, repo_root=None):
        self.sarif = str(sarif)
        self.out = str(out)
        self.repo_root = str(repo_root) if repo_root else None
        self.source_root = None
        self.context_policy = "lines"
        self.context_lines = 5
        self.no_git = True
        self.fail_on_missing_source = False
        self.log_level = "error"


def _upload(client, tmp_path, sarif_name="minimal.sarif"):
    from swb_cli.commands.enrich import enrich

    root = tmp_path / f"swb-test-{uuid.uuid4().hex[:8]}"
    root.mkdir()
    sarif_path = root / "report.sarif"
    sarif_path.write_bytes((VALID / sarif_name).read_bytes())
    out_path = root / "report.sarif.swbmeta.json"
    assert enrich(_EnrichArgs(sarif_path, out_path, repo_root=root)) == 0

    resp = client.post(
        "/api/v1/runs",
        files={
            "sarif": ("report.sarif", sarif_path.read_bytes(), "application/json"),
            "meta": ("report.swbmeta.json", out_path.read_bytes(), "application/json"),
        },
    )
    assert resp.status_code == 201, resp.text
    run_id = resp.json()["run_id"]
    items = client.get(f"/api/v1/runs/{run_id}/findings").json()["items"]
    # Текст берётся из самого отчёта, а не из sidecar: в swbmeta его нет —
    # enrich хранит идентичность и код, сообщение остаётся в SARIF.
    sarif = json.loads(sarif_path.read_text())
    return items, sarif["runs"][0]["results"][0]["message"]["text"]


def test_detail_returns_the_analyzer_message(client, tmp_path):
    items, text = _upload(client, tmp_path)
    detail = client.get(f"/api/v1/findings/{items[0]['id']}").json()
    assert detail["message"] == text
    assert detail["message"]


def test_detail_message_matches_the_list(client, tmp_path):
    # список и карточка показывают один и тот же текст — расхождение здесь
    # выглядело бы как потеря данных при открытии находки
    items, _ = _upload(client, tmp_path)
    detail = client.get(f"/api/v1/findings/{items[0]['id']}").json()
    assert detail["message"] == items[0]["message"]
