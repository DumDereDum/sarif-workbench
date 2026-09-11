import json
import logging

from swb_cli.sarif.parser import parse_sarif_data

from swb_cli.code import extract_snippet
from swb_cli.commands.enrich import enrich

from .test_enrich import Args

# Отчёт может нести исходник в себе: SARIF отводит под это
# `artifacts[].contents.text`, и Svace им пользуется — пути в его находках
# указывают на каталог сборки чужой машины (`/.build/main.cpp`), которого на
# диске здесь нет. Раньше сниппет в этом случае терялся, хотя код лежал в
# отчёте.

SOURCE = "\n".join(f"line {i}" for i in range(1, 21)) + "\n"


def _doc(uri="/.build/main.cpp", contents=SOURCE, index=0, artifacts=None):
    location = {"physicalLocation": {
        "artifactLocation": {"uri": uri},
        "region": {"startLine": 10},
    }}
    if index is not None:
        location["physicalLocation"]["artifactLocation"]["index"] = index
    if artifacts is None:
        artifacts = [{"location": {"uri": uri}}]
        if contents is not None:
            artifacts[0]["contents"] = {"text": contents}
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Svace", "rules": []}},
            "artifacts": artifacts,
            "results": [{
                "ruleId": "DEREF_OF_NULL",
                "message": {"text": "null dereference"},
                "locations": [location],
            }],
        }],
    }


def _enrich(tmp_path, doc, **kw):
    sarif = tmp_path / "report.sarif"
    sarif.write_text(json.dumps(doc), encoding="utf-8")
    out = tmp_path / "out.swbmeta.json"
    assert enrich(Args(sarif, out=out, **kw)) == 0
    return json.loads(out.read_text(encoding="utf-8"))


# ── разбор ───────────────────────────────────────────────────────────────────

def test_artifact_contents_are_parsed():
    run = parse_sarif_data(_doc())[0]
    assert run.artifacts[0].uri == "/.build/main.cpp"
    assert run.artifacts[0].contents == SOURCE

def test_location_keeps_the_artifact_index():
    run = parse_sarif_data(_doc())[0]
    assert run.results[0].locations[0].artifact_index == 0

def test_location_without_index_has_none():
    run = parse_sarif_data(_doc(index=None))[0]
    assert run.results[0].locations[0].artifact_index is None

def test_artifact_without_contents_is_still_listed():
    run = parse_sarif_data(_doc(contents=None))[0]
    assert run.artifacts[0].contents is None

def test_run_without_artifacts_gets_an_empty_list():
    doc = _doc()
    del doc["runs"][0]["artifacts"]
    assert parse_sarif_data(doc)[0].artifacts == []

def test_malformed_artifacts_do_not_break_parsing():
    # кривая запись становится артефактом без содержимого, а не роняет разбор
    run = parse_sarif_data(_doc(artifacts=["nonsense", {}, {"contents": 42}]))[0]
    assert [a.uri for a in run.artifacts] == ["", "", ""]
    assert all(a.contents is None for a in run.artifacts)


# ── extract_snippet с готовыми строками ──────────────────────────────────────

def test_snippet_from_given_lines_without_a_source_root():
    snippet = extract_snippet(None, "main.cpp", 10, None, "lines", 2, lines=SOURCE.splitlines())
    assert snippet is not None
    assert snippet.start_line == 8
    assert snippet.end_line == 12
    assert snippet.lang == "cpp"
    assert snippet.snippet.splitlines()[2] == "line 10"

def test_without_lines_and_without_a_source_root_there_is_no_snippet():
    assert extract_snippet(None, "main.cpp", 10, None, "lines", 2) is None


# ── enrich ───────────────────────────────────────────────────────────────────

def test_snippet_comes_from_the_report_when_the_file_is_absent(tmp_path):
    meta = _enrich(tmp_path, _doc())
    code = meta["findings"][0]["code"]
    assert code["start_line"] == 5
    assert code["end_line"] == 15
    assert "line 10" in code["snippet"]

def test_embedded_contents_work_without_a_source_root(tmp_path):
    # исходников рядом нет вообще — ровно тот случай, ради которого
    # спецификация разрешает вкладывать текст в отчёт
    meta = _enrich(tmp_path, _doc(), repo_root=None)
    assert meta["findings"][0]["code"] is not None

def test_the_artifact_is_found_by_uri_when_there_is_no_index(tmp_path):
    meta = _enrich(tmp_path, _doc(index=None))
    assert "line 10" in meta["findings"][0]["code"]["snippet"]

def test_disk_wins_over_the_embedded_copy(tmp_path):
    # на диске — дерево, которое пользователь смотрит; в отчёте — снимок того,
    # что собирал анализатор
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.cpp").write_text("\n".join(f"disk {i}" for i in range(1, 21)) + "\n")
    meta = _enrich(tmp_path, _doc(uri="main.cpp"), repo_root=src, source_root=src)
    assert "disk 10" in meta["findings"][0]["code"]["snippet"]

def test_artifact_without_contents_leaves_no_snippet(tmp_path):
    meta = _enrich(tmp_path, _doc(contents=None))
    assert meta["findings"][0]["code"] is None

def test_index_out_of_range_falls_back_to_the_uri(tmp_path):
    # индекс за пределами списка — отчёт кривой, но uri по-прежнему называет файл
    meta = _enrich(tmp_path, _doc(index=7))
    assert "line 10" in meta["findings"][0]["code"]["snippet"]

def test_oversized_embedded_contents_are_skipped(tmp_path, monkeypatch, caplog):
    # лимит SWB_MAX_SOURCE_MB действует и на вложенный текст: отчёт — такой же
    # недоверенный вход, как и файл на диске
    monkeypatch.setenv("SWB_MAX_SOURCE_MB", "1")
    with caplog.at_level(logging.WARNING):
        meta = _enrich(tmp_path, _doc(contents="x" * (2 * 1024 * 1024)))
    assert meta["findings"][0]["code"] is None
    assert "SWB_MAX_SOURCE_MB" in caplog.text


# ── отпечатки ────────────────────────────────────────────────────────────────

def test_embedded_contents_feed_the_content_fingerprint(tmp_path):
    # ADR 0001 §1: уровень content считается, когда исходник читается. Он
    # читается — просто не с диска.
    meta = _enrich(tmp_path, _doc())
    assert meta["findings"][0]["fingerprints"]["content"] is not None


# ── пустое содержимое — это отсутствие исходника ─────────────────────────────

def test_empty_embedded_contents_leave_no_snippet(tmp_path):
    # Svace пишет `contents: {"text": ""}` каждому артефакту, когда выгрузка
    # шла без содержимого. Пустая строка — это отсутствие исходника, а не файл
    # из нуля строк: иначе получился бы пустой сниппет и отпечаток содержимого
    # по пустому окну, одинаковый у всех находок файла.
    meta = _enrich(tmp_path, _doc(contents=""))
    assert meta["findings"][0]["code"] is None

def test_empty_embedded_contents_leave_no_content_fingerprint(tmp_path):
    meta = _enrich(tmp_path, _doc(contents=""))
    assert meta["findings"][0]["fingerprints"]["content"] is None

def test_whitespace_only_embedded_contents_leave_no_snippet(tmp_path):
    meta = _enrich(tmp_path, _doc(contents="\n\n   \n"))
    assert meta["findings"][0]["code"] is None
