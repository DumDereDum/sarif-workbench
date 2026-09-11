"""Сведения о прогоне из property bag документа SARIF.

Спецификация отводит под них свободный мешок, и ключи у каждого инструмента
свои. Svacer пишет туда имя проекта, ветку, снимок и версию конфигурации
анализатора — без их чтения оба его отчёта легли в проект по имени каталога,
из которого запускался CLI, с коммитом `0000000` и без ветки.

Проверяется:
  (а) разбор: ключи документа и прогона, терпимость к чужому мусору;
  (б) данные CLI важнее данных отчёта — он знает git-репозиторий, в котором
      работал, и его сведения точнее;
  (в) имя проекта из отчёта берётся только когда CLI репозиторий не определил;
  (г) версия конфигурации анализатора — не версия драйвера — доезжает до
      выдачи и до PDF.
"""
from __future__ import annotations

import hashlib
import json
import uuid

import pytest

from swb_contract.sarif.parser import parse_document_info


def _doc(props=None, run_props=None):
    d = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Svacer"}}, "results": []}]}
    if props is not None:
        d["properties"] = props
    if run_props is not None:
        d["runs"][0]["properties"] = run_props
    return d


# ── (а) разбор ─────────────────────────────────────────────────────────────


def test_reads_svacer_document_properties():
    info = parse_document_info(_doc({
        "project_name": "chrony",
        "branch_name": "master",
        "checkers_config_version": "Svace version 4.0.251120 (git rev e036810)",
    }))
    assert info.project == "chrony"
    assert info.branch == "master"
    assert "Svace version 4.0.251120" in info.analyzer_config


def test_falls_back_to_run_level_properties():
    """Спецификация допускает оба места, и часть инструментов пишет на
    уровень прогона."""
    assert parse_document_info(_doc(run_props={"project_name": "ndpi"})).project == "ndpi"


def test_document_properties_win_over_run_properties():
    info = parse_document_info(_doc({"project_name": "doc"}, {"project_name": "run"}))
    assert info.project == "doc"


@pytest.mark.parametrize("props", [
    None, {}, {"project_name": ""}, {"project_name": "   "},
    {"project_name": 42}, {"project_name": None}, "не словарь",
])
def test_malformed_bag_gives_none_and_does_not_raise(props):
    """Мешок свободный: чужие ключи и кривые значения не должны ронять
    загрузку и не должны подставляться выдумкой."""
    assert parse_document_info(_doc(props)).project is None


def test_empty_document_is_safe():
    assert parse_document_info({}).project is None


# ── (б)-(в) приоритет источников ───────────────────────────────────────────


def _sarif_with_properties(props: dict, tool: str = "Svacer") -> bytes:
    return json.dumps({
        "version": "2.1.0",
        "properties": props,
        "runs": [{
            "tool": {"driver": {"name": tool, "version": "1.0", "rules": []}},
            "results": [{
                "ruleId": "R-DOC", "level": "warning", "message": {"text": "f"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/a.c"},
                    "region": {"startLine": 1}}}],
            }],
        }],
    }).encode()


def _meta(sarif_bytes: bytes, provenance: dict) -> bytes:
    return json.dumps({
        "schema": "swbmeta/v3",
        # sha сверяется загрузкой: meta и SARIF должны быть одной парой
        "source_sarif": {
            "filename": "r.sarif",
            "sha256": hashlib.sha256(sarif_bytes).hexdigest(),
            "size_bytes": len(sarif_bytes),
        },
        "provenance": provenance,
        "findings": [{
            "swb_id": "sw2:t:docinfo1:0", "occurrence": 0,
            "locator": {"run": 0, "result": 0, "rule_id": "R-DOC", "uri": "src/a.c",
                        "norm_uri": "src/a.c", "region": {"start_line": 1}},
            "fingerprints": {"algo": "swb-fp/2", "level": "tool", "rule": "R-DOC"},
        }],
    }).encode()


def _upload(client, props, provenance):
    # nonce делает байты уникальными: дедуп идёт по sha256 в рамках проекта
    sarif = _sarif_with_properties({**props, "nonce": uuid.uuid4().hex})
    r = client.post("/api/v1/runs", files={
        "sarif": ("r.sarif", sarif, "application/json"),
        "meta": ("r.swbmeta.json", _meta(sarif, provenance), "application/json"),
    })
    assert r.status_code == 201, r.text
    return r.json()


def test_project_comes_from_report_when_cli_had_no_repo(client):
    """Отчёт выгружен с сервера анализатора, исходников рядом нет — без этого
    проект назывался бы по каталогу, в котором запускали enrich."""
    run = _upload(client, {"project_name": "chrony-doc"}, {"repo": "unknown"})
    assert run["project_id"] == "chrony-doc"


def test_cli_repo_wins_when_git_data_is_real(client):
    """Настоящий прогон в CI: CLI работал внутри сканированного репозитория,
    и его сведения точнее имени проекта на сервере анализатора."""
    run = _upload(client, {"project_name": "from-report"},
                  {"repo": "from-cli", "branch": "main", "commit": "a" * 40})
    assert run["project_id"] == "from-cli"


def test_explicit_project_beats_the_report(client):
    """`enrich --project` — решение человека, и его не перебивает ничто.
    Без признака `repo_explicit` сервер не отличил бы его от имени каталога:
    git-данных при выгрузке с сервера анализатора нет в обоих случаях."""
    run = _upload(client, {"project_name": "from-report"},
                  {"repo": "explicit-name", "repo_explicit": True,
                   "branch": "unknown", "commit": "0" * 40})
    assert run["project_id"] == "explicit-name"


def test_report_wins_when_cli_had_no_git(client):
    """`enrich --no-git` всё равно пишет `repo` — имя каталога, из которого
    запускали. Ветка и коммит при этом заглушки, и это единственный признак,
    по которому видно, что репозитория CLI не видел."""
    run = _upload(client, {"project_name": "from-report"},
                  {"repo": "sarif-workbench", "branch": "unknown", "commit": "0" * 40})
    assert run["project_id"] == "from-report"


def test_non_latin_project_name_is_slugified(client):
    """Идентификатор проекта собирается по прежнему правилу — только латиница,
    цифры и дефис. Кириллическое имя из отчёта Svacer превратится в дефисы:
    поведение существующее, но теперь оно достижимо и через отчёт, а не только
    через `--project`. Имя проекта при этом сохраняется как есть."""
    run = _upload(client, {"project_name": "Ядро"}, {"repo": "unknown"})
    assert run["project_id"] == "----"
    assert client.get("/api/v1/projects").json()  # выдача не падает


def test_branch_fills_the_gap(client):
    run = _upload(client, {"project_name": "docinfo-branch", "branch_name": "master"},
                  {"repo": "unknown"})
    assert client.get(f"/api/v1/runs/{run['run_id']}").json()["branch"] == "master"


def test_cli_branch_wins(client):
    run = _upload(client, {"branch_name": "из-отчёта"},
                  {"repo": "docinfo-cli-branch", "branch": "из-cli"})
    assert client.get(f"/api/v1/runs/{run['run_id']}").json()["branch"] == "из-cli"


# ── (г) версия конфигурации анализатора ────────────────────────────────────


def test_analyzer_config_reaches_the_api(client):
    """Это не версия драйвера: у Svacer драйвер — svacer, а сканирует Svace."""
    run = _upload(client, {
        "project_name": "docinfo-config",
        "checkers_config_version": "Svace version 4.0.251120",
    }, {"repo": "unknown"})
    body = client.get(f"/api/v1/runs/{run['run_id']}").json()
    assert body["analyzer_config"] == "Svace version 4.0.251120"
    assert body["tool_version"] == "1.0"  # версия драйвера осталась своей


def test_analyzer_config_appears_on_the_report_cover(client, db_session):
    from swb_server.models import Finding, Run  # noqa: PLC0415
    from swb_server.report_gen import build_html  # noqa: PLC0415

    run = _upload(client, {
        "project_name": "docinfo-pdf",
        "checkers_config_version": "Svace version 4.0.251120",
    }, {"repo": "unknown"})
    row = db_session.get(Run, run["run_id"])
    findings = db_session.query(Finding).filter(Finding.run_id == run["run_id"]).all()
    html = build_html(row, row.project, findings)
    assert "Конфигурация анализатора" in html
    assert "Svace version 4.0.251120" in html
