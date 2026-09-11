"""Имя проекта в провенансе: явное указание против выведенного.

До флага `--project` имя проекта было **всегда именем каталога**:
`repo = repo_root.name`. Git даёт ветку и коммит, но имени репозитория не
даёт, поэтому даже прогон в CI назывался по каталогу, куда сделан checkout.
А отчёт, выгруженный с сервера анализатора, приходилось класть в каталог с
нужным именем — исходников рядом нет вовсе.

Проверяется:
  (а) без флага поведение прежнее — имя каталога;
  (б) флаг задаёт имя и поднимает признак `repo_explicit`;
  (в) признак нужен серверу, чтобы отличить решение человека от догадки по
      месту запуска: без него явное имя проиграло бы имени проекта из
      отчёта Svacer;
  (г) пустая строка и пробелы флагом не считаются.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from swb_cli.commands.enrich import _build_provenance


def _prov(tmp_path: Path, project=None, name="workspace"):
    root = tmp_path / name
    root.mkdir(exist_ok=True)
    return _build_provenance(
        tool_name="TestTool", tool_version="1.0",
        repo_root=root, no_git=True, project=project,
    )


# ── (а) прежнее поведение ──────────────────────────────────────────────────


def test_without_flag_repo_is_the_directory_name(tmp_path):
    p = _prov(tmp_path)
    assert p.repo == "workspace"
    assert p.repo_explicit is False


def test_without_repo_root_repo_is_unknown():
    p = _build_provenance("TestTool", "1.0", repo_root=None, no_git=True)
    assert p.repo == "unknown" and p.repo_explicit is False


# ── (б)-(в) явное имя ──────────────────────────────────────────────────────


def test_flag_sets_the_name(tmp_path):
    p = _prov(tmp_path, project="chrony")
    assert p.repo == "chrony"


def test_flag_marks_the_name_as_explicit(tmp_path):
    """Признак нужен серверу: без него он не отличит решение человека от
    имени каталога и предпочёл бы имя проекта из отчёта."""
    assert _prov(tmp_path, project="chrony").repo_explicit is True


def test_flag_beats_the_directory_name(tmp_path):
    assert _prov(tmp_path, project="chrony", name="sarif-workbench").repo == "chrony"


def test_name_is_trimmed(tmp_path):
    assert _prov(tmp_path, project="  chrony  ").repo == "chrony"


# ── (г) пустое значение флагом не считается ────────────────────────────────


@pytest.mark.parametrize("blank", ["", "   ", None])
def test_blank_project_falls_back_to_the_directory(tmp_path, blank):
    p = _prov(tmp_path, project=blank)
    assert p.repo == "workspace" and p.repo_explicit is False


# ── совместимость схемы ────────────────────────────────────────────────────


def test_old_sidecars_without_the_field_still_parse():
    """Поле необязательное со значением по умолчанию — версию схемы
    поднимать не пришлось, и sidecar, созданные до флага, читаются."""
    from swb_contract.swbmeta import Provenance  # noqa: PLC0415

    p = Provenance(repo="r", branch="main", commit="a" * 40, commit_short="aaaaaaa",
                   is_dirty=False, tool="T", tool_version="1", scanned_at="2026-01-01T00:00:00Z")
    assert p.repo_explicit is False
