"""T-52: E2E-матрица «вердикт сквозь сканы» на реальных golden-фикстурах.

Все остальные carry-over/diff тесты (`test_carry_over.py`, `test_baseline_diff.py`)
используют `upload_run`/`make_meta` из `conftest.py`, которые берут `swb_id`
**синтетически из спецификации теста** (`spec.get("swb_id") or hash(...)`), а не
вычисляют его реальным алгоритмом `cli/swb_cli/fingerprints.py`. Это оставляет
дыру: регрессия в самом алгоритме identity (T-13, `swb-fp/2`) не ловится ни одним
серверным тестом — только "сервер верит любому переданному swb_id".

Этот файл закрывает дыру: golden-пары сканов (реальный SARIF + реальные
исходники на диске, `tests/data/golden/`, см. `tests/data/golden/README.md`)
прогоняются через настоящий `swb_cli.commands.enrich.enrich()` → upload →
carry-over/diff. Материал взят из ADR 0001 (`roadmap/adr/0001-identity-and-verdict.md`):

- §4 (сдвиг строк): content-hash без номера строки → swb_id стабилен;
- §1 (переименование, приложение A / T-13): смена uri меняет norm_uri →
  swb_id меняется на уровне content → вердикт НЕ переносится;
- §2 (перестановка результатов): occurrence считается после сортировки, не
  зависит от порядка results[] → swb_id стабилен;
- §6/§7 (добавленная/исчезнувшая находка): общие находки carry-over,
  исчезнувшая остаётся как есть в старом ране и уходит в closed, новая — new.
"""
import shutil
import uuid
from pathlib import Path

DATA = Path(__file__).parent.parent / "data"
GOLDEN = DATA / "golden"


class _EnrichArgs:
    """Минимальный объект аргументов для вызова enrich() напрямую (как в tests/cli)."""

    def __init__(self, sarif, out, repo_root):
        self.sarif = str(sarif)
        self.out = str(out)
        self.repo_root = str(repo_root)
        self.context_policy = "lines"
        self.context_lines = 5
        self.no_git = True
        self.fail_on_missing_source = False
        self.log_level = "error"


def _unique_repo() -> str:
    return f"swb-golden-{uuid.uuid4().hex[:8]}"


def _enrich(tmp_path: Path, scenario: str, variant: str, repo_name: str) -> tuple[Path, Path]:
    """Копирует golden/<scenario>/<variant> в repo_root=<tmp>/<repo_name> и
    вызывает настоящий swb_cli enrich(). Возвращает (sarif_path, meta_out_path).

    `repo_root.name` становится `provenance.repo` (см. `_build_provenance` в
    `cli/swb_cli/commands/enrich.py`) — держим его одинаковым для v1 и v2
    одного теста, чтобы обе загрузки попали в один и тот же проект на сервере.
    """
    from swb_cli.commands.enrich import enrich

    src = GOLDEN / scenario / variant
    assert src.is_dir(), f"missing golden fixture: {src}"
    container = tmp_path / f"{scenario}-{variant}-{uuid.uuid4().hex[:6]}"
    repo_root = container / repo_name
    shutil.copytree(src / "repo", repo_root)
    sarif_path = container / "report.sarif"
    shutil.copy(src / "report.sarif", sarif_path)
    out_path = container / "report.sarif.swbmeta.json"
    code = enrich(_EnrichArgs(sarif_path, out_path, repo_root))
    assert code == 0, f"enrich() failed for {scenario}/{variant}"
    return sarif_path, out_path


def _upload(client, sarif_path: Path, meta_path: Path) -> dict:
    resp = client.post(
        "/api/v1/runs",
        files={
            "sarif": ("report.sarif", sarif_path.read_bytes(), "application/json"),
            "meta": ("report.swbmeta.json", meta_path.read_bytes(), "application/json"),
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _upload_pair(client, tmp_path, scenario: str) -> tuple[dict, dict]:
    """Enrich+upload v1 и v2 одного golden-сценария в один и тот же проект."""
    repo_name = _unique_repo()
    sarif_a, meta_a = _enrich(tmp_path, scenario, "v1", repo_name)
    sarif_b, meta_b = _enrich(tmp_path, scenario, "v2", repo_name)
    run_a = _upload(client, sarif_a, meta_a)
    run_b = _upload(client, sarif_b, meta_b)
    return run_a, run_b


def _findings(client, run_id: str) -> list[dict]:
    return client.get(f"/api/v1/runs/{run_id}/findings").json()["items"]


def _find_by_uri(items: list[dict], uri: str) -> dict:
    matches = [it for it in items if it["uri"] == uri]
    assert len(matches) == 1, f"expected exactly one finding at {uri!r}, got {matches}"
    return matches[0]


def _patch_verdict(client, finding_id: str, verdict: str, rationale: str | None = None) -> dict:
    resp = client.patch(
        f"/api/v1/findings/{finding_id}/verdict",
        json={"verdict": verdict, "rationale": rationale, "version": 1},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _diff(client, target_run_id: str, baseline_run_id: str) -> dict:
    resp = client.get(
        f"/api/v1/runs/{target_run_id}/diff",
        params={"baseline": baseline_run_id},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# ── line_shift: вставка строк выше находки не меняет identity (ADR §4) ────────


def test_line_shift_carry_over(client, tmp_path):
    run_a, run_b = _upload_pair(client, tmp_path, "line_shift")

    items_a = _findings(client, run_a["run_id"])
    assert len(items_a) == 1
    finding_a = items_a[0]
    assert finding_a["fingerprint_level"] == "content"

    _patch_verdict(client, finding_a["id"], "true_positive", rationale="confirmed sqli")

    items_b = _findings(client, run_b["run_id"])
    assert len(items_b) == 1
    finding_b = items_b[0]

    # главное свойство сценария: swb_id стабилен несмотря на сдвиг start_line
    assert finding_b["swb_id"] == finding_a["swb_id"]
    assert finding_b["start_line"] != finding_a["start_line"]  # 11 -> 18, сдвиг реален

    # вердикт перенёсся автоматически (carried)
    assert finding_b["verdict"] == "true_positive"
    assert finding_b["verdict_source"] == "human"


def test_line_shift_diff_is_unchanged(client, tmp_path):
    run_a, run_b = _upload_pair(client, tmp_path, "line_shift")

    body = _diff(client, target_run_id=run_b["run_id"], baseline_run_id=run_a["run_id"])
    assert body["new"] == []
    assert body["closed"] == []
    assert len(body["unchanged"]) == 1
    assert body["counts"] == {"new": 0, "closed": 0, "unchanged": 1}
    assert body["unchanged"][0]["swb_id"] == _findings(client, run_a["run_id"])[0]["swb_id"]


# ── rename: смена uri меняет identity, вердикт НЕ переносится (ADR §1) ────────


def test_rename_breaks_identity_verdict_not_carried(client, tmp_path):
    run_a, run_b = _upload_pair(client, tmp_path, "rename")

    items_a = _findings(client, run_a["run_id"])
    finding_a = _find_by_uri(items_a, "src/a.py")
    assert finding_a["fingerprint_level"] == "content"

    _patch_verdict(client, finding_a["id"], "true_positive", rationale="confirmed traversal")

    items_b = _findings(client, run_b["run_id"])
    finding_b = _find_by_uri(items_b, "src/b.py")

    # переименование -> norm_uri меняется -> content-hash меняется -> swb_id другой
    assert finding_b["swb_id"] != finding_a["swb_id"]
    # значит вердикт НЕ переносится: новая находка снова unmarked
    assert finding_b["verdict"] == "unmarked"
    assert finding_b["verdict_source"] is None

    # исходная находка в run A не тронута переименованием
    finding_a_again = _find_by_uri(_findings(client, run_a["run_id"]), "src/a.py")
    assert finding_a_again["verdict"] == "true_positive"


def test_rename_diff_old_uri_closed_new_uri_new(client, tmp_path):
    run_a, run_b = _upload_pair(client, tmp_path, "rename")

    body = _diff(client, target_run_id=run_b["run_id"], baseline_run_id=run_a["run_id"])
    assert body["unchanged"] == []
    assert body["counts"] == {"new": 1, "closed": 1, "unchanged": 0}
    assert body["closed"][0]["uri"] == "src/a.py"
    assert body["new"][0]["uri"] == "src/b.py"
    # closed и new — заведомо разные identity (проверяем, что diff не спутал их)
    assert body["closed"][0]["swb_id"] != body["new"][0]["swb_id"]


# ── reorder: перестановка results[] не влияет на occurrence (ADR §2) ──────────


def test_reorder_all_three_carry_over_individually(client, tmp_path):
    run_a, run_b = _upload_pair(client, tmp_path, "reorder")

    items_a = _findings(client, run_a["run_id"])
    assert len(items_a) == 3
    marked = _find_by_uri(items_a, "src/two.py")
    _patch_verdict(client, marked["id"], "false_positive", rationale="not exploitable here")

    items_b = _findings(client, run_b["run_id"])
    assert len(items_b) == 3

    swb_ids_a = {it["uri"]: it["swb_id"] for it in items_a}
    swb_ids_b = {it["uri"]: it["swb_id"] for it in items_b}
    # набор swb_id идентичен вне зависимости от порядка results[] в v2 SARIF
    assert swb_ids_a == swb_ids_b

    by_uri_b = {it["uri"]: it for it in items_b}
    assert by_uri_b["src/two.py"]["verdict"] == "false_positive"
    assert by_uri_b["src/one.py"]["verdict"] == "unmarked"
    assert by_uri_b["src/three.py"]["verdict"] == "unmarked"


def test_reorder_diff_everything_unchanged(client, tmp_path):
    run_a, run_b = _upload_pair(client, tmp_path, "reorder")

    body = _diff(client, target_run_id=run_b["run_id"], baseline_run_id=run_a["run_id"])
    assert body["new"] == []
    assert body["closed"] == []
    assert len(body["unchanged"]) == 3
    assert body["counts"] == {"new": 0, "closed": 0, "unchanged": 3}


# ── added_removed: одна находка исчезает, другая появляется ───────────────────


def test_added_removed_shared_carries_removed_stays_new_is_unmarked(client, tmp_path):
    run_a, run_b = _upload_pair(client, tmp_path, "added_removed")

    items_a = _findings(client, run_a["run_id"])
    assert {it["uri"] for it in items_a} == {"src/one.py", "src/two.py"}
    shared_a = _find_by_uri(items_a, "src/one.py")
    removed_a = _find_by_uri(items_a, "src/two.py")

    _patch_verdict(client, shared_a["id"], "true_positive", rationale="shared, confirmed")
    _patch_verdict(client, removed_a["id"], "false_positive", rationale="removed later, but was FP")

    items_b = _findings(client, run_b["run_id"])
    assert {it["uri"] for it in items_b} == {"src/one.py", "src/three.py"}
    shared_b = _find_by_uri(items_b, "src/one.py")
    new_b = _find_by_uri(items_b, "src/three.py")

    # общая находка переносит вердикт
    assert shared_b["swb_id"] == shared_a["swb_id"]
    assert shared_b["verdict"] == "true_positive"
    assert shared_b["verdict_source"] == "human"

    # новая находка — unmarked, её identity не встречалась раньше
    assert new_b["verdict"] == "unmarked"
    assert new_b["verdict_source"] is None

    # исчезнувшая находка остаётся как есть в run A (не удаляется, не сбрасывается)
    removed_a_again = _find_by_uri(_findings(client, run_a["run_id"]), "src/two.py")
    assert removed_a_again["verdict"] == "false_positive"
    # и физически отсутствует в run B
    assert all(it["uri"] != "src/two.py" for it in items_b)


def test_added_removed_diff_categorizes_all_three(client, tmp_path):
    run_a, run_b = _upload_pair(client, tmp_path, "added_removed")

    body = _diff(client, target_run_id=run_b["run_id"], baseline_run_id=run_a["run_id"])
    assert body["counts"] == {"new": 1, "closed": 1, "unchanged": 1}
    assert body["unchanged"][0]["uri"] == "src/one.py"
    assert body["closed"][0]["uri"] == "src/two.py"
    assert body["new"][0]["uri"] == "src/three.py"
