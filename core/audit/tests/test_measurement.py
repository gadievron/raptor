"""Tests for core.audit.measurement."""

from __future__ import annotations

import json

from core.audit.measurement import (
    EvaluationResult,
    GroundTruthEntry,
    evaluate_run,
    format_evaluation,
    load_ground_truth,
    write_evaluation,
)


class TestGroundTruthEntry:
    def test_key(self):
        e = GroundTruthEntry(
            id="GT-1", file="foo.c", function="bar",
            line=10, vuln_type="overflow", description="desc",
        )
        assert e.key() == "foo.c:bar"

    def test_defaults(self):
        e = GroundTruthEntry(
            id="GT-1", file="f.c", function="g",
            line=1, vuln_type="t", description="d",
        )
        assert e.depth == "L1"
        assert e.failure_mode == ""


class TestLoadGroundTruth:
    def test_loads_from_target_dir(self, tmp_path):
        gt = {
            "vulnerabilities": [
                {
                    "id": "GT-1",
                    "file": "a.c",
                    "function": "fn",
                    "line": 5,
                    "vuln_type": "overflow",
                    "description": "stack smash",
                }
            ]
        }
        (tmp_path / "ground-truth.json").write_text(json.dumps(gt))
        entries = load_ground_truth(tmp_path)
        assert len(entries) == 1
        assert entries[0].id == "GT-1"
        assert entries[0].file == "a.c"

    def test_loads_from_parent_dir(self, tmp_path):
        subdir = tmp_path / "target"
        subdir.mkdir()
        gt = {
            "vulnerabilities": [
                {
                    "id": "GT-2",
                    "file": "b.c",
                    "function": "parse",
                    "line": 10,
                    "vuln_type": "sqli",
                    "description": "injection",
                    "depth": "L2",
                }
            ]
        }
        (tmp_path / "ground-truth.json").write_text(json.dumps(gt))
        entries = load_ground_truth(subdir)
        assert len(entries) == 1
        assert entries[0].depth == "L2"

    def test_missing_returns_empty(self, tmp_path):
        entries = load_ground_truth(tmp_path)
        assert entries == []

    def test_bare_list_format(self, tmp_path):
        gt = [
            {
                "file": "c.c",
                "function": "open",
                "line": 1,
                "vuln_type": "traversal",
                "description": "path escape",
            }
        ]
        (tmp_path / "ground-truth.json").write_text(json.dumps(gt))
        entries = load_ground_truth(tmp_path)
        assert len(entries) == 1
        assert entries[0].id == "GT-1"

    def test_optional_fields_default(self, tmp_path):
        gt = {
            "vulnerabilities": [
                {"file": "x.c", "function": "y", "line": 1}
            ]
        }
        (tmp_path / "ground-truth.json").write_text(json.dumps(gt))
        entries = load_ground_truth(tmp_path)
        assert entries[0].vuln_type == ""
        assert entries[0].description == ""
        assert entries[0].depth == "L1"


class TestEvaluationResult:
    def test_empty_result(self):
        r = EvaluationResult()
        assert r.detection_rate == 0.0
        assert r.fp_rate == 0.0
        assert r.precision == 0.0
        assert r.recall == 0.0
        assert r.f1 == 0.0

    def test_perfect_detection(self):
        entries = [
            GroundTruthEntry(
                id="GT-1", file="a.c", function="f",
                line=1, vuln_type="t", description="d",
            ),
        ]
        r = EvaluationResult(
            true_positives=entries,
            false_negatives=[],
            false_positives=[],
            total_findings=1,
            total_ground_truth=1,
        )
        assert r.detection_rate == 1.0
        assert r.precision == 1.0
        assert r.recall == 1.0
        assert r.f1 == 1.0

    def test_mixed_result(self):
        tp = GroundTruthEntry(
            id="GT-1", file="a.c", function="f",
            line=1, vuln_type="t", description="d",
        )
        fn = GroundTruthEntry(
            id="GT-2", file="b.c", function="g",
            line=2, vuln_type="t", description="d",
        )
        r = EvaluationResult(
            true_positives=[tp],
            false_negatives=[fn],
            false_positives=[{"file": "c.c", "function": "h"}],
            total_findings=2,
            total_ground_truth=2,
        )
        assert r.detection_rate == 0.5
        assert r.precision == 0.5
        assert r.recall == 0.5

    def test_to_dict(self):
        r = EvaluationResult(total_findings=0, total_ground_truth=0)
        d = r.to_dict()
        assert "detection_rate" in d
        assert "precision" in d
        assert "f1" in d
        assert d["total_findings"] == 0


class TestEvaluateRun:
    def _write_findings(self, out_dir, findings, graded=True):
        out_dir.mkdir(parents=True, exist_ok=True)
        if graded:
            path = out_dir / "findings-graded.json"
            path.write_text(json.dumps({"findings": findings}))
        else:
            path = out_dir / "findings.json"
            path.write_text(json.dumps(findings))

    def test_all_found(self, tmp_path):
        gt = [
            GroundTruthEntry(
                id="GT-1", file="a.c", function="f",
                line=1, vuln_type="t", description="d",
            ),
        ]
        self._write_findings(tmp_path, [
            {"file": "a.c", "function": "f", "status": "finding"},
        ])
        result = evaluate_run(tmp_path, gt)
        assert len(result.true_positives) == 1
        assert len(result.false_negatives) == 0
        assert len(result.false_positives) == 0

    def test_all_missed(self, tmp_path):
        gt = [
            GroundTruthEntry(
                id="GT-1", file="a.c", function="f",
                line=1, vuln_type="t", description="d",
            ),
        ]
        self._write_findings(tmp_path, [])
        result = evaluate_run(tmp_path, gt)
        assert len(result.true_positives) == 0
        assert len(result.false_negatives) == 1

    def test_false_positive(self, tmp_path):
        self._write_findings(tmp_path, [
            {"file": "x.c", "function": "z", "status": "finding"},
        ])
        result = evaluate_run(tmp_path, [])
        assert len(result.false_positives) == 1

    def test_suspicious_counts_as_tp(self, tmp_path):
        gt = [
            GroundTruthEntry(
                id="GT-1", file="a.c", function="f",
                line=1, vuln_type="t", description="d",
            ),
        ]
        self._write_findings(tmp_path, [
            {"file": "a.c", "function": "f", "status": "suspicious"},
        ])
        result = evaluate_run(tmp_path, gt)
        assert len(result.true_positives) == 1

    def test_clean_status_ignored(self, tmp_path):
        gt = [
            GroundTruthEntry(
                id="GT-1", file="a.c", function="f",
                line=1, vuln_type="t", description="d",
            ),
        ]
        self._write_findings(tmp_path, [
            {"file": "a.c", "function": "f", "status": "clean"},
        ])
        result = evaluate_run(tmp_path, gt)
        assert len(result.true_positives) == 0
        assert len(result.false_negatives) == 1

    def test_standard_findings_format(self, tmp_path):
        gt = [
            GroundTruthEntry(
                id="GT-1", file="a.c", function="f",
                line=1, vuln_type="t", description="d",
            ),
        ]
        self._write_findings(tmp_path, [
            {"file": "a.c", "function": "f", "status": "finding"},
        ], graded=False)
        result = evaluate_run(tmp_path, gt)
        assert len(result.true_positives) == 1

    def test_no_findings_file(self, tmp_path):
        tmp_path.mkdir(parents=True, exist_ok=True)
        result = evaluate_run(tmp_path, [])
        assert result.total_findings == 0


class TestFormatEvaluation:
    def test_renders_found(self):
        tp = GroundTruthEntry(
            id="GT-1", file="a.c", function="f",
            line=1, vuln_type="overflow", description="d",
        )
        r = EvaluationResult(
            true_positives=[tp],
            total_findings=1,
            total_ground_truth=1,
        )
        text = format_evaluation(r)
        assert "GT-1" in text
        assert "100%" in text

    def test_renders_missed(self):
        fn = GroundTruthEntry(
            id="GT-2", file="b.c", function="g",
            line=2, vuln_type="sqli", description="d",
            depth="L2", failure_mode="cross-function flow",
        )
        r = EvaluationResult(
            false_negatives=[fn],
            total_findings=0,
            total_ground_truth=1,
        )
        text = format_evaluation(r)
        assert "Missed" in text
        assert "GT-2" in text
        assert "cross-function flow" in text

    def test_renders_fp(self):
        r = EvaluationResult(
            false_positives=[
                {"file": "x.c", "function": "z", "hypothesis": "maybe overflow"},
            ],
            total_findings=1,
            total_ground_truth=0,
        )
        text = format_evaluation(r)
        assert "False positives" in text


class TestWriteEvaluation:
    def test_writes_json(self, tmp_path):
        r = EvaluationResult(
            total_findings=3,
            total_ground_truth=2,
        )
        path = write_evaluation(r, tmp_path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["total_findings"] == 3
        assert data["total_ground_truth"] == 2

    def test_roundtrip_metrics(self, tmp_path):
        tp = GroundTruthEntry(
            id="GT-1", file="a.c", function="f",
            line=1, vuln_type="t", description="d",
        )
        r = EvaluationResult(
            true_positives=[tp],
            total_findings=1,
            total_ground_truth=1,
        )
        path = write_evaluation(r, tmp_path)
        data = json.loads(path.read_text())
        assert data["detection_rate"] == 1.0
        assert data["precision"] == 1.0
        assert data["f1"] == 1.0


class TestDuplicateGroundTruthKeys:
    def test_duplicate_key_keeps_first(self, tmp_path):
        gt = [
            GroundTruthEntry(
                id="GT-1", file="a.c", function="f",
                line=10, vuln_type="overflow", description="first",
            ),
            GroundTruthEntry(
                id="GT-2", file="a.c", function="f",
                line=20, vuln_type="uaf", description="second",
            ),
        ]
        out = tmp_path / "run"
        out.mkdir()
        (out / "findings.json").write_text(json.dumps([]))
        result = evaluate_run(out, gt)
        assert result.total_ground_truth == 2
        assert len(result.false_negatives) == 1
        assert result.false_negatives[0].id == "GT-1"
