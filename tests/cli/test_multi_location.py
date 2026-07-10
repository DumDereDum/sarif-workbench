"""T-39: multi-location finding model (ADR 0001 §8).

- extra locations (`result.locations[1:]`), relatedLocations and codeFlows
  are captured structurally in swbmeta (not dropped, not collapsed into
  strings);
- identity (swb_id/fingerprints) is built from `locations[0]` alone — the
  extra payload never feeds it, per ADR 0001 §8 (this task does not touch
  the identity algorithm).
"""
import json
from pathlib import Path

from swb_cli.commands.enrich import enrich

DATA = Path(__file__).parent.parent / "data"
VALID = DATA / "valid"


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


# ── structural capture (Done when #1/#2) ────────────────────────────────────


def test_primary_locator_is_still_locations_0(tmp_path):
    data = _enrich(VALID / "multi_location.sarif", tmp_path)
    locator = data["findings"][0]["locator"]
    assert locator["uri"] == "src/sink.py"
    assert locator["region"]["start_line"] == 42
    assert locator["region"]["start_column"] == 5


def test_extra_locations_captured_from_locations_1_plus(tmp_path):
    data = _enrich(VALID / "multi_location.sarif", tmp_path)
    extra = data["findings"][0]["extra_locations"]
    assert extra == [
        {"uri": "src/source.py", "region": {"start_line": 10, "end_line": None, "start_column": None}},
    ]


def test_related_locations_captured_with_message(tmp_path):
    data = _enrich(VALID / "multi_location.sarif", tmp_path)
    related = data["findings"][0]["related_locations"]
    assert related == [
        {
            "uri": "src/helper.py",
            "region": {"start_line": 5, "end_line": None, "start_column": None},
            "message": "Sanitizer bypass here",
        },
    ]


def test_code_flows_structure_preserved_not_collapsed_to_strings(tmp_path):
    data = _enrich(VALID / "multi_location.sarif", tmp_path)
    code_flows = data["findings"][0]["code_flows"]
    assert code_flows == [
        {
            "thread_flows": [
                {
                    "steps": [
                        {"uri": "src/source.py", "line": 10, "message": "user input enters"},
                        {"uri": "src/transform.py", "line": 20, "message": "passed through transform()"},
                        {"uri": "src/sink.py", "line": 42, "message": "reaches SQL sink"},
                    ],
                },
            ],
        },
    ]


# ── backward compatibility: single-location findings unaffected ────────────


def test_single_location_finding_gets_empty_multi_location_fields(tmp_path):
    data = _enrich(VALID / "minimal.sarif", tmp_path)
    f = data["findings"][0]
    assert f["extra_locations"] == []
    assert f["related_locations"] == []
    assert f["code_flows"] == []


# ── identity unaffected by multi-location payload (Done when #3, ADR §8) ───


def _write_sarif(path: Path, result: dict) -> Path:
    path.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "TestTool", "version": "1.0.0"}},
            "results": [result],
        }],
    }))
    return path


_PRIMARY = {
    "physicalLocation": {
        "artifactLocation": {"uri": "src/x.py"},
        "region": {"startLine": 10},
    },
}


def test_multi_location_finding_identity_uses_primary_location_only(tmp_path):
    # A: single location, nothing else.
    result_a = {
        "ruleId": "CWE-89", "level": "error", "message": {"text": "finding"},
        "locations": [_PRIMARY],
    }
    # B: same primary location[0], PLUS an extra location, relatedLocations
    # and a multi-step codeFlow — all noise that must not affect identity.
    result_b = {
        "ruleId": "CWE-89", "level": "error", "message": {"text": "finding"},
        "locations": [
            _PRIMARY,
            {"physicalLocation": {"artifactLocation": {"uri": "src/other.py"},
                                   "region": {"startLine": 99}}},
        ],
        "relatedLocations": [
            {"physicalLocation": {"artifactLocation": {"uri": "src/helper.py"},
                                   "region": {"startLine": 3}},
             "message": {"text": "unrelated noise"}},
        ],
        "codeFlows": [{"threadFlows": [{"locations": [
            {"location": {"physicalLocation": {
                "artifactLocation": {"uri": "src/a.py"}, "region": {"startLine": 1}}}},
            {"location": {"physicalLocation": {
                "artifactLocation": {"uri": "src/b.py"}, "region": {"startLine": 2}}}},
        ]}]}],
    }

    sarif_a = _write_sarif(tmp_path / "a.sarif", result_a)
    sarif_b = _write_sarif(tmp_path / "b.sarif", result_b)

    # no repo_root -> legacy level: material is tool+rule+norm_uri+start_line
    # only (ADR 0001 §1 level 3) — the cleanest demonstration that the extra
    # payload on B doesn't leak into identity.
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    out_a.mkdir()
    out_b.mkdir()
    f_a = _enrich(sarif_a, out_a)["findings"][0]
    f_b = _enrich(sarif_b, out_b)["findings"][0]

    assert f_a["fingerprints"]["level"] == "legacy"
    assert f_b["fingerprints"]["level"] == "legacy"
    assert f_a["swb_id"] == f_b["swb_id"]
    assert f_a["fingerprints"] == f_b["fingerprints"]
    # fingerprints.flow stays reserved/unset — T-39 does not populate it
    # (ADR 0001 §8: diagnostic-only, would need swb-fp/3 to become material).
    assert f_b["fingerprints"]["flow"] is None

    # ...while the payload itself DOES differ and IS captured on B.
    assert f_a["extra_locations"] == []
    assert len(f_b["extra_locations"]) == 1
    assert f_a["related_locations"] == []
    assert len(f_b["related_locations"]) == 1
    assert f_a["code_flows"] == []
    assert len(f_b["code_flows"]) == 1
