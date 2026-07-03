import hashlib
import json
import logging
import pytest
from pathlib import Path

from swb_cli.commands.enrich import _get_git_info, enrich

DATA = Path(__file__).parent.parent / "data"
VALID = DATA / "valid"
INVALID = DATA / "invalid"


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


# ── exit codes ────────────────────────────────────────────────────────────────

def test_enrich_returns_0_on_valid_sarif(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    code = enrich(Args(VALID / "minimal.sarif", out=out))
    assert code == 0

def test_enrich_returns_2_on_missing_file(tmp_path):
    code = enrich(Args(tmp_path / "nonexistent.sarif"))
    assert code == 2

def test_enrich_returns_1_on_malformed_json(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    code = enrich(Args(INVALID / "malformed_json.sarif", out=out))
    assert code == 1

def test_enrich_returns_1_on_empty_file(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    code = enrich(Args(INVALID / "empty_file.sarif", out=out))
    assert code == 1


# ── output correctness ────────────────────────────────────────────────────────

def test_output_is_valid_json(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out))
    data = json.loads(out.read_text())
    assert data["schema"] == "swbmeta/v1"

def test_sha256_matches_source_file(tmp_path):
    sarif = VALID / "minimal.sarif"
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(sarif, out=out))
    data = json.loads(out.read_text())
    expected = hashlib.sha256(sarif.read_bytes()).hexdigest()
    assert data["source_sarif"]["sha256"] == expected

def test_output_finding_count(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out))
    data = json.loads(out.read_text())
    assert len(data["findings"]) == 1

def test_empty_runs_produces_zero_findings(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "empty_runs.sarif", out=out))
    data = json.loads(out.read_text())
    assert data["findings"] == []

def test_no_locations_finding_is_skipped(tmp_path):
    # результаты без locations не попадают в findings
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "no_locations.sarif", out=out))
    data = json.loads(out.read_text())
    assert data["findings"] == []

def test_original_sarif_not_modified(tmp_path):
    sarif = VALID / "minimal.sarif"
    original_bytes = sarif.read_bytes()
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(sarif, out=out))
    assert sarif.read_bytes() == original_bytes

def test_default_out_path_is_next_to_sarif(tmp_path):
    sarif = tmp_path / "report.sarif"
    sarif.write_bytes((VALID / "minimal.sarif").read_bytes())
    enrich(Args(sarif, out=None))
    assert (tmp_path / "report.sarif.swbmeta.json").exists()

def test_multi_run_findings_count(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "multi_run.sarif", out=out))
    data = json.loads(out.read_text())
    assert len(data["findings"]) == 2


# ── occurrence counter ────────────────────────────────────────────────────────

def test_duplicate_findings_get_different_occurrences(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "duplicate_findings.sarif", out=out))
    data = json.loads(out.read_text())
    occurrences = [f["occurrence"] for f in data["findings"]]
    assert occurrences == [0, 1, 2]

def test_duplicate_findings_get_different_swb_ids(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "duplicate_findings.sarif", out=out))
    data = json.loads(out.read_text())
    ids = [f["swb_id"] for f in data["findings"]]
    assert len(ids) == len(set(ids))


# ── provenance ────────────────────────────────────────────────────────────────

def test_provenance_tool_name(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out))
    data = json.loads(out.read_text())
    assert data["provenance"]["tool"] == "TestTool"

def test_provenance_no_git_flag(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out, no_git=True))
    data = json.loads(out.read_text())
    assert data["provenance"]["commit"] == "0" * 40


# ── code snippets ─────────────────────────────────────────────────────────────

def test_code_is_null_without_repo_root(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out, repo_root=None))
    data = json.loads(out.read_text())
    assert data["findings"][0]["code"] is None

def test_code_is_null_with_none_policy(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out,
                repo_root=DATA, context_policy="none"))
    data = json.loads(out.read_text())
    assert data["findings"][0]["code"] is None

def test_code_snippet_extracted_with_repo_root(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out, repo_root=DATA, context_policy="line"))
    data = json.loads(out.read_text())
    code = data["findings"][0]["code"]
    assert code is not None
    assert code["lang"] == "python"
    assert "CWE-89" in code["snippet"]

def test_code_start_line_matches_finding(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out, repo_root=DATA, context_policy="line"))
    data = json.loads(out.read_text())
    code = data["findings"][0]["code"]
    assert code["start_line"] == 42

def test_code_lines_policy_expands_context(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out,
                repo_root=DATA, context_policy="lines", context_lines=5))
    data = json.loads(out.read_text())
    code = data["findings"][0]["code"]
    assert code["start_line"] < 42
    assert code["end_line"] > 42


# ── git info ──────────────────────────────────────────────────────────────────

def test_git_is_null_when_no_git_flag(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out, repo_root=DATA, no_git=True))
    data = json.loads(out.read_text())
    assert data["findings"][0]["git"] is None

def test_git_is_null_without_repo_root(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out, repo_root=None, no_git=False))
    data = json.loads(out.read_text())
    assert data["findings"][0]["git"] is None


# ── path traversal через uri (T-01) ──────────────────────────────────────────

def _record_git_calls(monkeypatch):
    """Подменяет _git; возвращает список перехваченных вызовов."""
    calls = []

    def fake_git(cwd, git_args):
        calls.append(git_args)
        return ""

    monkeypatch.setattr("swb_cli.commands.enrich._git", fake_git)
    return calls

def test_git_info_rejects_relative_traversal(tmp_path, monkeypatch, caplog):
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "secret.py").write_text("TOP_SECRET = 1\n")
    calls = _record_git_calls(monkeypatch)
    with caplog.at_level(logging.WARNING):
        assert _get_git_info(root, "../secret.py", 1, None) is None
    assert calls == []
    assert "repo root" in caplog.text

def test_git_info_rejects_absolute_uri_outside_root(tmp_path, monkeypatch, caplog):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "secret.py"
    outside.write_text("TOP_SECRET = 1\n")
    calls = _record_git_calls(monkeypatch)
    with caplog.at_level(logging.WARNING):
        assert _get_git_info(root, str(outside), 1, None) is None
    assert calls == []

def test_git_info_rejects_symlink_escaping_root(tmp_path, monkeypatch, caplog):
    root = tmp_path / "repo"
    root.mkdir()
    secret = tmp_path / "secret.py"
    secret.write_text("TOP_SECRET = 1\n")
    (root / "link.py").symlink_to(secret)
    calls = _record_git_calls(monkeypatch)
    with caplog.at_level(logging.WARNING):
        assert _get_git_info(root, "link.py", 1, None) is None
    assert calls == []

def test_enrich_traversal_uris_get_null_code_and_warn(tmp_path, caplog):
    # SARIF с двумя вредоносными uri и одним легитимным: enrich не падает,
    # вредоносные находки получают code=None, легитимная обогащается как раньше
    out = tmp_path / "out.swbmeta.json"
    with caplog.at_level(logging.WARNING):
        code = enrich(Args(VALID / "path_traversal.sarif", out=out,
                           repo_root=DATA, context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    by_uri = {f["locator"]["uri"]: f for f in data["findings"]}
    assert by_uri["../../../../../../../../etc/passwd"]["code"] is None
    assert by_uri["/etc/passwd"]["code"] is None
    good = by_uri["src/db.py"]["code"]
    assert good is not None
    assert "CWE-89" in good["snippet"]
    assert "repo root" in caplog.text


# ── лимит размера исходников (T-02) ──────────────────────────────────────────

def test_enrich_oversized_source_gets_null_code_and_warns(tmp_path, monkeypatch, caplog):
    # исходник крупнее лимита: enrich не падает, code=None, warning в stderr-лог
    monkeypatch.setenv("SWB_MAX_SOURCE_MB", "1")
    src = tmp_path / "src"
    src.mkdir()
    (src / "db.py").write_bytes(b"# huge\n" * 300_000)  # ~2 МБ > лимита в 1 МБ
    out = tmp_path / "out.swbmeta.json"
    with caplog.at_level(logging.WARNING):
        code = enrich(Args(VALID / "minimal.sarif", out=out,
                           repo_root=tmp_path, context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    assert data["findings"][0]["code"] is None
    assert "SWB_MAX_SOURCE_MB" in caplog.text
