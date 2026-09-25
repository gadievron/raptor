"""Tests for core/run/verdicts.py — finding-id resolution and
manual_override edits on run-dir findings artifacts."""

import json
from pathlib import Path

from core.run.verdicts import (
    finding_coords,
    finding_rule_id,
    iter_findings,
    resolve_finding,
    set_manual_override,
)


def _write_findings(run_dir: Path, findings, rel="findings.json",
                    wrapped=False):
    path = run_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"findings": findings} if wrapped else findings
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _finding(fid, **extra):
    base = {"id": fid, "file": "src/a.c", "function": "parse",
            "line": 12, "rule_id": "cpp/overflow"}
    base.update(extra)
    return base


class TestIterFindings:
    def test_both_container_shapes(self, tmp_path):
        _write_findings(tmp_path, [_finding("f-1")])
        run2 = tmp_path / "r2"
        run2.mkdir()
        _write_findings(run2, [_finding("f-2")], wrapped=True)
        assert [r.finding_id for r in iter_findings(tmp_path)] == ["f-1"]
        assert [r.finding_id for r in iter_findings(run2)] == ["f-2"]

    def test_sca_and_openant_artifacts_walked(self, tmp_path):
        _write_findings(tmp_path, [_finding("sca-1")],
                        rel="sca/findings.json")
        _write_findings(tmp_path, [_finding("oa-1")],
                        rel="openant_findings.json")
        ids = {r.finding_id for r in iter_findings(tmp_path)}
        assert ids == {"sca-1", "oa-1"}

    def test_malformed_artifact_skipped(self, tmp_path):
        (tmp_path / "findings.json").write_text("{not json",
                                                encoding="utf-8")
        assert list(iter_findings(tmp_path)) == []

    def test_finding_id_key_variant(self, tmp_path):
        _write_findings(tmp_path, [{"finding_id": "alt-1"}])
        assert [r.finding_id for r in iter_findings(tmp_path)] == ["alt-1"]

    def test_orchestrated_results_resolve_read_only(self, tmp_path):
        (tmp_path / "orchestrated_report.json").write_text(json.dumps({
            "mode": "orchestrated",
            "results": [{"finding_id": "orc-1", "status": "analysed",
                         "file_path": "a.c", "function": "parse",
                         "line": 3, "rule_id": "cpp/overflow"}],
        }), encoding="utf-8")
        (ref,) = iter_findings(tmp_path)
        assert ref.finding_id == "orc-1"
        assert ref.editable is False
        # A verdict edit never rewrites an analysis report.
        before = (tmp_path / "orchestrated_report.json").read_text(
            encoding="utf-8")
        assert set_manual_override([ref], True, "r") == ([], [])
        assert (tmp_path / "orchestrated_report.json").read_text(
            encoding="utf-8") == before

    def test_validation_findings_are_editable(self, tmp_path):
        path = _write_findings(tmp_path, [_finding("v-1")],
                               rel="validation/findings.json")
        matches, _ = resolve_finding([tmp_path], "v-1")
        assert matches and matches[0].editable
        assert set_manual_override(matches, True, "r") == ([path], [])


class TestResolveFinding:
    def test_exact_match_across_runs(self, tmp_path):
        r1, r2 = tmp_path / "r1", tmp_path / "r2"
        r1.mkdir(), r2.mkdir()
        _write_findings(r1, [_finding("dup-1")])
        _write_findings(r2, [_finding("dup-1"), _finding("other")])
        matches, suggestions = resolve_finding([r1, r2], "dup-1")
        assert len(matches) == 2
        assert suggestions == []

    def test_unique_prefix_resolves(self, tmp_path):
        _write_findings(tmp_path, [_finding("abcdef123456"),
                                   _finding("zzz")])
        matches, _ = resolve_finding([tmp_path], "abcdef")
        assert [m.finding_id for m in matches] == ["abcdef123456"]

    def test_ambiguous_prefix_suggests(self, tmp_path):
        _write_findings(tmp_path, [_finding("abc-one"),
                                   _finding("abc-two")])
        matches, suggestions = resolve_finding([tmp_path], "abc")
        assert matches == []
        assert set(suggestions) == {"abc-one", "abc-two"}

    def test_miss_gives_did_you_mean(self, tmp_path):
        _write_findings(tmp_path, [_finding("semgrep-sql-42")])
        matches, suggestions = resolve_finding([tmp_path],
                                               "semgrep-sql-43")
        assert matches == []
        assert "semgrep-sql-42" in suggestions

    def test_total_miss_no_suggestions(self, tmp_path):
        _write_findings(tmp_path, [_finding("aaa")])
        matches, suggestions = resolve_finding([tmp_path],
                                               "completely-unrelated")
        assert matches == []
        assert suggestions == []


class TestFindingCoords:
    def test_pipeline_binding_order(self):
        rel, fn, line = finding_coords({
            "file_path": "a.c", "file": "b.c",
            "metadata": {"name": "meta_fn"},
            "startLine": 7,
        })
        assert (rel, fn, line) == ("a.c", "meta_fn", 7)

    def test_missing_pieces_default(self):
        assert finding_coords({}) == ("", "", 0)
        assert finding_coords({"line": "N/A"})[2] == 0

    def test_rule_id_variants(self):
        assert finding_rule_id({"rule_id": "r1"}) == "r1"
        assert finding_rule_id({"check_id": "c1"}) == "c1"
        assert finding_rule_id({}) == ""


class TestSetManualOverride:
    def test_set_writes_flag_and_reason(self, tmp_path):
        path = _write_findings(
            tmp_path, [_finding("f-1"), _finding("f-2")], wrapped=True)
        matches, _ = resolve_finding([tmp_path], "f-1")
        changed, failed = set_manual_override(matches, True, "operator says real")
        assert changed == [path]
        assert failed == []
        data = json.loads(path.read_text(encoding="utf-8"))
        by_id = {f["id"]: f for f in data["findings"]}
        assert by_id["f-1"]["manual_override"] is True
        assert by_id["f-1"]["manual_override_reason"] == "operator says real"
        assert "manual_override" not in by_id["f-2"]

    def test_clear_removes_both_keys(self, tmp_path):
        path = _write_findings(tmp_path, [
            _finding("f-1", manual_override=True,
                     manual_override_reason="old"),
        ])
        matches, _ = resolve_finding([tmp_path], "f-1")
        changed, failed = set_manual_override(matches, False)
        assert changed == [path]
        assert failed == []
        (rec,) = json.loads(path.read_text(encoding="utf-8"))
        assert "manual_override" not in rec
        assert "manual_override_reason" not in rec

    def test_idempotent_set_rewrites_nothing(self, tmp_path):
        path = _write_findings(tmp_path, [
            _finding("f-1", manual_override=True,
                     manual_override_reason="r"),
        ])
        before = path.stat().st_mtime_ns
        matches, _ = resolve_finding([tmp_path], "f-1")
        assert set_manual_override(matches, True, "r") == ([], [])
        assert path.stat().st_mtime_ns == before

    def test_container_shape_preserved(self, tmp_path):
        path = _write_findings(tmp_path, [_finding("f-1")], wrapped=True)
        matches, _ = resolve_finding([tmp_path], "f-1")
        set_manual_override(matches, True)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data, dict) and "findings" in data

    def test_vanished_artifact_reports_as_failed(self, tmp_path):
        path = _write_findings(tmp_path, [_finding("f-1")])
        matches, _ = resolve_finding([tmp_path], "f-1")
        path.unlink()
        path.write_text("{not json", encoding="utf-8")
        changed, failed = set_manual_override(matches, True, "r")
        assert changed == []
        assert failed == [path]
