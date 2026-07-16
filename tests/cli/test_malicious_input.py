"""T-53 — suite «вредоносный вход»: CLI-часть.

Консолидированное, явно поименованное покрытие сценариев из
`inspection/06-tests.md` §3 ("нет тестов на... path traversal, code.py:45")
и roadmap T-53 Done when: SARIF с недоверенным `uri` (относительный `../`
traversal и абсолютный путь) не должен позволить enrich прочитать файл вне
`repo_root`. Помеченная фикстура лежит в `tests/data/malicious/` (не
`valid/`) — она синтаксически валидный SARIF, но с намеренно враждебным
содержимым (в отличие от `tests/data/invalid/`, где SARIF сломан случайно/
структурно).

Отвержение самого пути (`code=None`, warning, exit 0) уже покрыто
`tests/cli/test_code.py` (юнит-уровень `extract_snippet`/`resolve_under_root`,
T-01) и `tests/cli/test_enrich.py::test_enrich_traversal_uris_get_null_code_and_warn`
(та же фикстура, до переноса сюда — end-to-end уровень `enrich()`). Этот файл
существует, чтобы сценарий был дискаверабелен как единый вредоносный suite
(`pytest -k malicious`) и добавляет проверку, которой не было: что реальное
содержимое файла, на который указывает абсолютный traversal-uri, нигде не
всплывает в выходном swbmeta — не просто "code is None", а "секрет не утёк".
"""
from __future__ import annotations

import json
from pathlib import Path

from swb_cli.commands.enrich import enrich

DATA = Path(__file__).parent.parent / "data"
MALICIOUS = DATA / "malicious"

_SENTINEL_PATH = Path("/etc/passwd")


class Args:
    """Минимальный объект аргументов для вызова enrich() напрямую."""
    def __init__(self, sarif, out=None, repo_root=None, context_policy="lines",
                 context_lines=5, no_git=True, fail_on_missing_source=False,
                 log_level="error"):
        self.sarif = str(sarif)
        self.out = str(out) if out else None
        self.repo_root = str(repo_root) if repo_root else None
        self.context_policy = context_policy
        self.context_lines = context_lines
        self.no_git = no_git
        self.fail_on_missing_source = fail_on_missing_source
        self.log_level = log_level


def test_traversal_uris_rejected_legit_finding_still_enriched(tmp_path):
    """Фикстура содержит три находки: relative-traversal uri, absolute uri
    вне repo_root и одну легитимную (src/db.py, реально существует под DATA).
    enrich не падает (exit 0), обе враждебные находки получают code=None,
    легитимная — обычный сниппет.
    """
    out = tmp_path / "out.swbmeta.json"
    code = enrich(Args(MALICIOUS / "path_traversal.sarif", out=out,
                        repo_root=DATA, context_policy="line"))
    assert code == 0

    data = json.loads(out.read_text())
    by_uri = {f["locator"]["uri"]: f for f in data["findings"]}

    assert by_uri["../../../../../../../../etc/passwd"]["code"] is None
    assert by_uri["/etc/passwd"]["code"] is None

    legit = by_uri["src/db.py"]["code"]
    assert legit is not None
    assert "CWE-89" in legit["snippet"]


def test_absolute_traversal_does_not_leak_target_file_content(tmp_path):
    """Сильнее, чем "code is None": содержимое /etc/passwd (реальный файл вне
    repo_root, на который указывает абсолютный uri фикстуры) не должно
    появиться нигде в сгенерированном swbmeta — ни в снипете, ни где-либо ещё.
    """
    if not _SENTINEL_PATH.exists():
        return  # платформа без /etc/passwd (не Linux/macOS) — сценарий неприменим
    try:
        secret_content = _SENTINEL_PATH.read_text(errors="replace")
    except OSError:
        return  # нет прав на чтение — тем более не может утечь

    out = tmp_path / "out.swbmeta.json"
    code = enrich(Args(MALICIOUS / "path_traversal.sarif", out=out,
                        repo_root=DATA, context_policy="line"))
    assert code == 0

    out_text = out.read_text()
    # самая длинная строка файла — достаточно специфичный маркер (не "##" или
    # пустая строка), чтобы не давать случайных совпадений со служебным JSON
    lines = [ln for ln in secret_content.splitlines() if len(ln.strip()) > 20]
    if lines:
        marker = max(lines, key=len)
        assert marker not in out_text
