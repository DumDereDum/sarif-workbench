"""T-13: swb_id v2 — стабильный отпечаток (ADR 0001 §1/§2)."""
import json
import re
from pathlib import Path

from swb_cli.commands.enrich import enrich

DATA = Path(__file__).parent.parent / "data"
VALID = DATA / "valid"

SWB_ID_RE = re.compile(r"^sw2:[tcl]:[0-9a-f]{24}:\d+$")


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


def _enrich(sarif_path, out_dir, **kwargs):
    out = Path(out_dir) / (Path(sarif_path).name + ".swbmeta.json")
    assert enrich(Args(sarif_path, out=out, **kwargs)) == 0
    return json.loads(out.read_text())


def _result(uri="src/a.py", start_line=1, rule="CWE-89", message="finding",
            **extra):
    return {
        "ruleId": rule,
        "level": "error",
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": start_line},
            },
        }],
        **extra,
    }


def _write_sarif(path, results, tool="TestTool"):
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "version": "1.0.0"}},
            "results": results,
        }],
    }
    Path(path).write_text(json.dumps(sarif))
    return Path(path)


def _make_repo(tmp_path, name, source_text, filename="src/a.py"):
    repo = tmp_path / name
    file = repo / filename
    file.parent.mkdir(parents=True)
    file.write_text(source_text)
    return repo


# ── стабильность к сдвигу строк (уровень content) ─────────────────────────────

def test_content_swb_id_stable_when_lines_inserted_above(tmp_path):
    src = "a = 1\nq = build(x)\n"
    r1 = _make_repo(tmp_path, "r1", src)
    s1 = _write_sarif(r1 / "report.sarif", [_result(start_line=2)])
    id1 = _enrich(s1, r1, repo_root=r1)["findings"][0]["swb_id"]

    # вставка 3 строк выше находки + соответствующий сдвиг startLine
    r2 = _make_repo(tmp_path, "r2", "# new\n# new\n# new\n" + src)
    s2 = _write_sarif(r2 / "report.sarif", [_result(start_line=5)])
    f2 = _enrich(s2, r2, repo_root=r2)["findings"][0]

    assert f2["fingerprints"]["level"] == "content"
    assert f2["swb_id"] == id1


# ── стабильность к перестановке результатов (§2) ─────────────────────────────

def test_swb_ids_invariant_under_result_permutation(tmp_path):
    src = "q = build(x)\ny = 2\nq = build(x)\n"
    results = [
        _result(start_line=1),          # дубль 1 (тот же контент, что строка 3)
        _result(start_line=2, rule="CWE-79"),
        _result(start_line=3),          # дубль 2
    ]
    r1 = _make_repo(tmp_path, "r1", src)
    s1 = _write_sarif(r1 / "report.sarif", results)
    d1 = _enrich(s1, r1, repo_root=r1)["findings"]

    r2 = _make_repo(tmp_path, "r2", src)
    s2 = _write_sarif(r2 / "report.sarif", list(reversed(results)))
    d2 = _enrich(s2, r2, repo_root=r2)["findings"]

    by_line_1 = {f["locator"]["region"]["start_line"]: f["swb_id"] for f in d1}
    by_line_2 = {f["locator"]["region"]["start_line"]: f["swb_id"] for f in d2}
    assert by_line_1 == by_line_2                       # каждая находка — тот же id
    assert sorted(f["swb_id"] for f in d1) == sorted(f["swb_id"] for f in d2)


# ── перенос файла (ADR: уровни 2–3 меняются, уровень 1 — решает инструмент) ──

def test_content_swb_id_changes_on_file_move(tmp_path):
    src = "q = build(x)\n"
    r1 = _make_repo(tmp_path, "r1", src, filename="src/a.py")
    s1 = _write_sarif(r1 / "report.sarif", [_result(uri="src/a.py")])
    f1 = _enrich(s1, r1, repo_root=r1)["findings"][0]

    r2 = _make_repo(tmp_path, "r2", src, filename="src/b.py")
    s2 = _write_sarif(r2 / "report.sarif", [_result(uri="src/b.py")])
    f2 = _enrich(s2, r2, repo_root=r2)["findings"][0]

    assert f1["fingerprints"]["level"] == "content"
    assert f2["fingerprints"]["level"] == "content"
    assert f1["swb_id"] != f2["swb_id"]                 # norm_uri входит в материал


def test_legacy_swb_id_changes_on_file_move(tmp_path):
    s1 = _write_sarif(tmp_path / "a.sarif", [_result(uri="src/a.py")])
    s2 = _write_sarif(tmp_path / "b.sarif", [_result(uri="src/b.py")])
    f1 = _enrich(s1, tmp_path)["findings"][0]
    f2 = _enrich(s2, tmp_path)["findings"][0]

    assert f1["fingerprints"]["level"] == "legacy"
    assert f2["fingerprints"]["level"] == "legacy"
    assert f1["swb_id"] != f2["swb_id"]


def test_tool_swb_id_survives_file_move_with_same_fingerprint(tmp_path):
    fp = {"partialFingerprints": {"stableHash/v1": "abc123"}}
    s1 = _write_sarif(tmp_path / "a.sarif", [_result(uri="src/a.py", **fp)])
    s2 = _write_sarif(tmp_path / "b.sarif", [_result(uri="src/b.py", **fp)])
    f1 = _enrich(s1, tmp_path)["findings"][0]
    f2 = _enrich(s2, tmp_path)["findings"][0]

    assert f1["fingerprints"]["level"] == "tool"
    assert f1["swb_id"] == f2["swb_id"]                 # uri не входит в материал


# ── дубли и occurrence (§2) ──────────────────────────────────────────────────

def test_duplicate_occurrence_assigned_by_sort_key_not_file_order(tmp_path):
    # 60 строк; строки 10 и 50 идентичны -> один контент-хеш, группа из двух.
    # В SARIF дубль со строкой 50 идёт РАНЬШЕ строки 10 — occurrence=0 всё
    # равно должен достаться строке 10 (сортировка §2, не порядок файла).
    lines = ["# pad"] * 60
    lines[9] = "q = build(x)"
    lines[49] = "q = build(x)"
    repo = _make_repo(tmp_path, "r1", "\n".join(lines) + "\n")
    sarif = _write_sarif(repo / "report.sarif",
                         [_result(start_line=50), _result(start_line=10)])
    findings = _enrich(sarif, repo, repo_root=repo)["findings"]

    by_line = {f["locator"]["region"]["start_line"]: f for f in findings}
    assert by_line[10]["fingerprints"]["level"] == "content"
    assert by_line[10]["fingerprints"]["content"] == by_line[50]["fingerprints"]["content"]
    assert by_line[10]["occurrence"] == 0
    assert by_line[50]["occurrence"] == 1
    assert by_line[10]["swb_id"] != by_line[50]["swb_id"]


def test_byte_identical_duplicates_keep_file_order(tmp_path):
    data = _enrich(VALID / "duplicate_findings.sarif", tmp_path)
    occurrences = [f["occurrence"] for f in data["findings"]]
    ids = [f["swb_id"] for f in data["findings"]]
    assert occurrences == [0, 1, 2]
    assert len(set(ids)) == 3


# ── формат id (§1) ───────────────────────────────────────────────────────────

def test_swb_id_format_and_level_tag_consistency(tmp_path):
    cases = [
        (VALID / "with_partial_fingerprints.sarif", None, "tool", "t"),
        (VALID / "minimal.sarif", DATA, "content", "c"),
        (VALID / "minimal.sarif", None, "legacy", "l"),
    ]
    for i, (sarif, repo_root, level, tag) in enumerate(cases):
        out_dir = tmp_path / f"case{i}"
        out_dir.mkdir()
        f = _enrich(sarif, out_dir, repo_root=repo_root)["findings"][0]
        assert SWB_ID_RE.match(f["swb_id"]), f["swb_id"]
        assert f["fingerprints"]["level"] == level
        assert f["swb_id"].split(":")[1] == tag


def test_occurrence_field_matches_id_suffix(tmp_path):
    data = _enrich(VALID / "duplicate_findings.sarif", tmp_path)
    for f in data["findings"]:
        assert f["swb_id"].endswith(f":{f['occurrence']}")


# ── уровень 1: канонизация fp_dict (§1) ──────────────────────────────────────

def test_tool_fp_dict_key_order_does_not_change_id(tmp_path):
    r_ab = _result(partialFingerprints={"aKey": "1", "bKey": "2"})
    r_ba = _result(partialFingerprints={"bKey": "2", "aKey": "1"})
    # порядок ключей различен именно в байтах JSON
    s1 = _write_sarif(tmp_path / "ab.sarif", [r_ab])
    s2 = _write_sarif(tmp_path / "ba.sarif", [r_ba])
    assert '"aKey": "1", "bKey": "2"' in s1.read_text()
    assert '"bKey": "2", "aKey": "1"' in s2.read_text()

    f1 = _enrich(s1, tmp_path)["findings"][0]
    f2 = _enrich(s2, tmp_path)["findings"][0]
    assert f1["fingerprints"]["level"] == "tool"
    assert f1["swb_id"] == f2["swb_id"]
