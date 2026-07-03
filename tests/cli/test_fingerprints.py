"""T-12: SARIF-отпечатки и нормализация uri (ADR 0001 §1/§3/§4/§5)."""
import hashlib
import json
from pathlib import Path

from swb_cli.commands.enrich import enrich
from swb_cli.fingerprints import content_hash, normalize_uri, normalize_window

DATA = Path(__file__).parent.parent / "data"
VALID = DATA / "valid"
SRC = DATA / "src"


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


def _enrich(sarif_path, tmp_path, **kwargs):
    out = tmp_path / "out.swbmeta.json"
    assert enrich(Args(sarif_path, out=out, **kwargs)) == 0
    return json.loads(out.read_text())


def _write_sarif(tmp_path, run_extra=None, result_extra=None,
                 uri="src/db.py", start_line=42, tool="TestTool"):
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "version": "1.0.0"}},
            "results": [{
                "ruleId": "CWE-89",
                "level": "error",
                "message": {"text": "finding"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": start_line},
                    },
                }],
                **(result_extra or {}),
            }],
            **(run_extra or {}),
        }],
    }
    path = tmp_path / "report.sarif"
    path.write_text(json.dumps(sarif))
    return path


# ── norm_uri (ADR §3) ─────────────────────────────────────────────────────────

def test_norm_uri_resolves_uri_base_id():
    bases = {"SRC": {"uri": "src/"}}
    assert normalize_uri("db.py", "SRC", bases, None) == "src/db.py"

def test_norm_uri_resolves_recursive_base():
    bases = {
        "SRCROOT": {"uri": "file:///work/repo/"},
        "SRC": {"uri": "src", "uriBaseId": "SRCROOT"},
    }
    # file:// снят, база раскручена рекурсивно, ведущий "/" убран (§3 шаг 5)
    assert normalize_uri("db.py", "SRC", bases, None) == "work/repo/src/db.py"

def test_norm_uri_missing_base_is_tolerated():
    assert normalize_uri("db.py", "NOPE", {}, None) == "db.py"

def test_norm_uri_cyclic_base_terminates():
    bases = {"A": {"uri": "x/", "uriBaseId": "A"}}
    assert normalize_uri("db.py", "A", bases, None) == "x/db.py"

def test_norm_uri_file_scheme_percent_encoding_backslashes():
    assert (
        normalize_uri("file:///c%20dir\\sub\\x.py", None, {}, None)
        == "c dir/sub/x.py"
    )

def test_norm_uri_collapses_dot_and_dotdot_segments():
    assert normalize_uri("src/./a/../db.py", None, {}, None) == "src/db.py"

def test_norm_uri_keeps_leading_dotdot_of_relative_path():
    # схлопывание не выходит за корень строки — ведущие ".." остаются
    assert normalize_uri("../../etc/passwd", None, {}, None) == "../../etc/passwd"

def test_norm_uri_absolute_inside_repo_root_becomes_relative(tmp_path):
    root = tmp_path.resolve()
    (root / "src").mkdir()
    uri = (root / "src" / "db.py").as_posix()
    assert normalize_uri(uri, None, {}, root) == "src/db.py"

def test_norm_uri_absolute_outside_repo_root_not_relativized(tmp_path):
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    # путь вне repo_root не релятивизируется; ведущий "/" снят по §3 шаг 5
    assert normalize_uri("/opt/other/x.c", None, {}, root) == "opt/other/x.c"

def test_norm_uri_written_next_to_original_uri(tmp_path):
    sarif = _write_sarif(tmp_path, uri="src/./a/../db.py")
    data = _enrich(sarif, tmp_path)
    loc = data["findings"][0]["locator"]
    assert loc["uri"] == "src/./a/../db.py"       # исходный uri — как есть
    assert loc["norm_uri"] == "src/db.py"

def test_norm_uri_via_uri_base_id_reaches_source(tmp_path):
    # uri относительный к базе: без раскрутки uriBaseId исходник не найти
    sarif = _write_sarif(
        tmp_path,
        uri="db.py",
        run_extra={"originalUriBaseIds": {"SRC": {"uri": "src/"}}},
    )
    sarif_obj = json.loads(sarif.read_text())
    loc = sarif_obj["runs"][0]["results"][0]["locations"][0]
    loc["physicalLocation"]["artifactLocation"]["uriBaseId"] = "SRC"
    sarif.write_text(json.dumps(sarif_obj))

    data = _enrich(sarif, tmp_path, repo_root=DATA)
    finding = data["findings"][0]
    assert finding["locator"]["norm_uri"] == "src/db.py"
    assert finding["fingerprints"]["level"] == "content"
    assert finding["fingerprints"]["content"] is not None


# ── уровень tool (ADR §1 уровень 1) ──────────────────────────────────────────

def test_partial_fingerprints_extracted_to_tool_level(tmp_path):
    data = _enrich(VALID / "with_partial_fingerprints.sarif", tmp_path)
    fp = data["findings"][0]["fingerprints"]
    assert fp["algo"] == "swb-fp/2"
    assert fp["level"] == "tool"
    assert fp["tool_kind"] == "partialFingerprints"
    assert fp["tool"] == {
        "primaryLocationLineHash": "39fa2ee980eb94b0:1",
        "primaryLocationStartColumnFingerprint": "4",
    }
    assert fp["rule"] == "py/sql-injection"

def test_fingerprints_key_wins_over_partial(tmp_path):
    sarif = _write_sarif(tmp_path, result_extra={
        "fingerprints": {"stableHash/v1": "abc"},
        "partialFingerprints": {"lineHash": "def"},
    })
    fp = _enrich(sarif, tmp_path)["findings"][0]["fingerprints"]
    assert fp["level"] == "tool"
    assert fp["tool_kind"] == "fingerprints"
    assert fp["tool"] == {"stableHash/v1": "abc"}

def test_tool_level_still_computes_content_for_diagnostics(tmp_path):
    # уровни 2 вычисляются и сохраняются даже при уровне 1 (ADR §1)
    data = _enrich(VALID / "with_partial_fingerprints.sarif", tmp_path,
                   repo_root=DATA)
    fp = data["findings"][0]["fingerprints"]
    assert fp["level"] == "tool"
    assert fp["content"] is not None
    assert fp["context"] is not None


# ── уровень content (ADR §1 уровень 2, §4) ───────────────────────────────────

def test_content_level_when_source_readable(tmp_path):
    data = _enrich(VALID / "minimal.sarif", tmp_path, repo_root=DATA)
    fp = data["findings"][0]["fingerprints"]
    assert fp["algo"] == "swb-fp/2"
    assert fp["level"] == "content"
    assert fp["tool"] is None and fp["tool_kind"] is None
    assert len(fp["content"]) == 64 and len(fp["context"]) == 64
    assert fp["content"] != fp["context"]
    assert fp["scope"] is None and fp["flow"] is None

def test_content_hash_matches_adr_material(tmp_path):
    # материал уровня 2 (ADR §1): algo NUL "content" NUL tool NUL rule NUL norm_uri NUL norm_window
    data = _enrich(VALID / "minimal.sarif", tmp_path, repo_root=DATA)
    fp = data["findings"][0]["fingerprints"]
    line42 = (SRC / "db.py").read_text().splitlines()[41]
    window = " ".join(line42.split())
    material = "\x00".join(["swb-fp/2", "content", "testtool", "CWE-89",
                            "src/db.py", window])
    assert fp["content"] == hashlib.sha256(material.encode()).hexdigest()


# ── уровень legacy (ADR §1 уровень 3) ────────────────────────────────────────

def test_legacy_without_repo_root(tmp_path):
    data = _enrich(VALID / "minimal.sarif", tmp_path, repo_root=None)
    fp = data["findings"][0]["fingerprints"]
    assert fp["level"] == "legacy"
    assert fp["tool"] is None
    assert fp["content"] is None and fp["context"] is None

def test_legacy_when_source_missing(tmp_path):
    sarif = _write_sarif(tmp_path, uri="src/nonexistent.py")
    fp = _enrich(sarif, tmp_path, repo_root=DATA)["findings"][0]["fingerprints"]
    assert fp["level"] == "legacy"
    assert fp["content"] is None

def test_legacy_when_uri_escapes_repo_root(tmp_path):
    data = _enrich(VALID / "path_traversal.sarif", tmp_path, repo_root=DATA)
    by_uri = {f["locator"]["uri"]: f["fingerprints"] for f in data["findings"]}
    assert by_uri["../../../../../../../../etc/passwd"]["level"] == "legacy"
    assert by_uri["../../../../../../../../etc/passwd"]["content"] is None
    assert by_uri["src/db.py"]["level"] == "content"


# ── нормализация окна (ADR §4) ───────────────────────────────────────────────

def test_normalize_window_collapses_whitespace():
    lines = ["\tx\t =   1  ", "", "  y = 2"]
    assert normalize_window(lines, 1, 3) == "x = 1\n\ny = 2"

def test_normalize_window_caps_at_10_lines():
    lines = [f"l{i}" for i in range(1, 31)]
    assert normalize_window(lines, 1, 30) == "\n".join(f"l{i}" for i in range(1, 11))

def test_normalize_window_beyond_eof_is_empty():
    # пустое после нормализации окно — валидный материал (§4)
    assert normalize_window(["x = 1"], 99, None) == ""

def test_normalize_window_context_pad():
    lines = ["a", "b", "c", "d", "e"]
    assert normalize_window(lines, 3, None, pad=2) == "a\nb\nc\nd\ne"

def _content_of(tmp_path, name, source_text, start_line):
    repo = tmp_path / name
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text(source_text)
    sarif = _write_sarif(repo, uri="src/a.py", start_line=start_line)
    data = _enrich(sarif, repo, repo_root=repo)
    return data["findings"][0]["fingerprints"]["content"]

def test_content_hash_stable_under_whitespace_changes(tmp_path):
    h1 = _content_of(tmp_path, "r1", "def f():\n    q =  build( x )\n", 2)
    h2 = _content_of(tmp_path, "r2", "def f():\n\tq = build( x )\n", 2)
    assert h1 == h2

def test_content_hash_stable_when_lines_inserted_above(tmp_path):
    # главное свойство уровня 2: без номера строки в материале
    h1 = _content_of(tmp_path, "r1", "a = 1\nq = build(x)\n", 2)
    h2 = _content_of(tmp_path, "r2", "# new\n# new\n# new\na = 1\nq = build(x)\n", 5)
    assert h1 == h2

def test_content_hash_changes_when_window_changes(tmp_path):
    h1 = _content_of(tmp_path, "r1", "q = build(x)\n", 1)
    h2 = _content_of(tmp_path, "r2", "q = build(y)\n", 1)
    assert h1 != h2

def test_content_hash_helper_matches_direct_material():
    material = "\x00".join(["swb-fp/2", "content", "t", "r", "u", "w"])
    assert content_hash("t", "r", "u", "w") == hashlib.sha256(material.encode()).hexdigest()


# ── схема v2 (ADR §5) ────────────────────────────────────────────────────────

def test_swbmeta_schema_is_v2(tmp_path):
    data = _enrich(VALID / "minimal.sarif", tmp_path)
    assert data["schema"] == "swbmeta/v2"
