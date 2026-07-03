import logging

import pytest
from pathlib import Path

from swb_cli.code import detect_lang, extract_snippet

SRC = Path(__file__).parent.parent / "data" / "src"


# ── detect_lang ───────────────────────────────────────────────────────────────

def test_detect_lang_python():
    assert detect_lang("src/db.py") == "python"

def test_detect_lang_c():
    assert detect_lang("src/utils.c") == "c"

def test_detect_lang_cpp():
    assert detect_lang("src/main.cpp") == "cpp"

def test_detect_lang_unknown():
    assert detect_lang("src/file.sarif") is None

def test_detect_lang_case_insensitive():
    assert detect_lang("src/Main.PY") == "python"


# ── extract_snippet — policy: none ───────────────────────────────────────────

def test_none_policy_returns_none():
    result = extract_snippet(SRC.parent, "src/db.py", 42, None, "none", 5)
    assert result is None


# ── extract_snippet — policy: line ───────────────────────────────────────────

def test_line_policy_returns_single_line():
    result = extract_snippet(SRC.parent, "src/db.py", 42, None, "line", 5)
    assert result is not None
    assert result.start_line == 42
    assert result.end_line == 42
    assert "\n" not in result.snippet

def test_line_policy_contains_finding_code():
    result = extract_snippet(SRC.parent, "src/db.py", 42, None, "line", 5)
    assert "CWE-89" in result.snippet


# ── extract_snippet — policy: lines ──────────────────────────────────────────

def test_lines_policy_expands_context():
    result = extract_snippet(SRC.parent, "src/db.py", 42, None, "lines", 5)
    assert result is not None
    assert result.start_line == 37   # 42 - 5
    assert result.end_line == 47     # 42 + 5

def test_lines_policy_snippet_contains_finding_line():
    result = extract_snippet(SRC.parent, "src/db.py", 42, None, "lines", 5)
    lines = result.snippet.splitlines()
    # finding line is at offset (42 - result.start_line) inside the snippet
    offset = 42 - result.start_line
    assert "CWE-89" in lines[offset]

def test_lines_policy_clamps_to_file_start():
    # exec.py: finding at line 7, context 5 → can't go below line 1
    result = extract_snippet(SRC.parent, "src/exec.py", 7, None, "lines", 5)
    assert result.start_line == 2   # 7 - 5 = 2 (line 1 has no blank before it)
    assert result.start_line >= 1

def test_lines_policy_clamps_to_file_end():
    # views.py has ~14 lines, finding at 10, +5 would be 15 — clamp to actual end
    result = extract_snippet(SRC.parent, "src/views.py", 10, None, "lines", 5)
    total = len((SRC / "views.py").read_text().splitlines())
    assert result.end_line <= total

def test_lines_correct_line_count():
    result = extract_snippet(SRC.parent, "src/utils.c", 20, None, "lines", 5)
    expected_lines = result.end_line - result.start_line + 1
    assert len(result.snippet.splitlines()) == expected_lines


# ── extract_snippet — lang detection ─────────────────────────────────────────

def test_snippet_has_correct_lang_python():
    result = extract_snippet(SRC.parent, "src/db.py", 42, None, "line", 5)
    assert result.lang == "python"

def test_snippet_has_correct_lang_c():
    result = extract_snippet(SRC.parent, "src/utils.c", 20, None, "line", 5)
    assert result.lang == "c"


# ── extract_snippet — missing file ───────────────────────────────────────────

def test_missing_file_returns_none():
    result = extract_snippet(SRC.parent, "src/nonexistent.py", 10, None, "lines", 5)
    assert result is None


# ── extract_snippet — path traversal (T-01) ──────────────────────────────────

def test_relative_traversal_returns_none(caplog):
    # tests/cli/test_code.py существует, но лежит вне repo_root=tests/data
    with caplog.at_level(logging.WARNING):
        result = extract_snippet(SRC.parent, "../cli/test_code.py", 1, None, "line", 0)
    assert result is None
    assert "repo root" in caplog.text

def test_absolute_uri_outside_root_returns_none(tmp_path, caplog):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "secret.py"
    outside.write_text("TOP_SECRET = 1\n")
    with caplog.at_level(logging.WARNING):
        result = extract_snippet(root, str(outside), 1, None, "line", 0)
    assert result is None
    assert "repo root" in caplog.text

def test_symlink_escaping_root_returns_none(tmp_path, caplog):
    root = tmp_path / "repo"
    root.mkdir()
    secret = tmp_path / "secret.py"
    secret.write_text("TOP_SECRET = 1\n")
    (root / "link.py").symlink_to(secret)
    with caplog.at_level(logging.WARNING):
        result = extract_snippet(root, "link.py", 1, None, "line", 0)
    assert result is None
    assert "repo root" in caplog.text

def test_symlink_inside_root_still_allowed(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "real.py").write_text("x = 1  # marker\n")
    (root / "alias.py").symlink_to(root / "real.py")
    result = extract_snippet(root, "alias.py", 1, None, "line", 0)
    assert result is not None
    assert "marker" in result.snippet

def test_dotdot_staying_inside_root_still_allowed():
    # ".." в uri сам по себе не криминал — важно, куда резолвится путь
    result = extract_snippet(SRC.parent, "src/../src/db.py", 42, None, "line", 0)
    assert result is not None
    assert "CWE-89" in result.snippet


# ── extract_snippet — size cap (T-02) ────────────────────────────────────────

def test_oversized_file_skipped_without_reading(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("SWB_MAX_SOURCE_MB", "1")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "big.py").write_bytes(b"x" * (2 * 1024 * 1024))  # 2 МБ > лимита в 1 МБ

    def _must_not_read(self, *args, **kwargs):
        raise AssertionError("oversized file must not be read")

    monkeypatch.setattr(Path, "read_text", _must_not_read)
    with caplog.at_level(logging.WARNING):
        result = extract_snippet(root, "big.py", 1, None, "line", 0)
    assert result is None
    assert "SWB_MAX_SOURCE_MB" in caplog.text

def test_file_exactly_at_limit_still_read(tmp_path, monkeypatch):
    # лимит не строгий вниз: файл размером ровно в лимит ещё читается
    monkeypatch.setenv("SWB_MAX_SOURCE_MB", "1")
    root = tmp_path / "repo"
    root.mkdir()
    line = b"x" * 63 + b"\n"
    (root / "edge.py").write_bytes(line * (1024 * 1024 // 64))  # ровно 1 МБ
    result = extract_snippet(root, "edge.py", 1, None, "line", 0)
    assert result is not None

def test_file_under_limit_still_read(tmp_path, monkeypatch):
    monkeypatch.setenv("SWB_MAX_SOURCE_MB", "1")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "small.py").write_text("x = 1  # marker\n")
    result = extract_snippet(root, "small.py", 1, None, "line", 0)
    assert result is not None
    assert "marker" in result.snippet


# ── each fixture file — finding line contains expected marker ─────────────────

@pytest.mark.parametrize("uri,line,marker", [
    ("src/exec.py",  7,  "CWE-78"),
    ("src/views.py", 10, "CWE-79"),
    ("src/utils.c",  20, "CWE-476"),
    ("src/db.py",    42, "CWE-89"),
    ("src/files.py", 55, "CWE-22"),
])
def test_finding_line_contains_marker(uri, line, marker):
    result = extract_snippet(SRC.parent, uri, line, None, "line", 0)
    assert result is not None
    assert marker in result.snippet
