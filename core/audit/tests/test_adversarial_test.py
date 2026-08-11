"""Tests for core.audit.adversarial_test."""

from __future__ import annotations

import json

from core.audit.adversarial_test import (
    AdversarialMatrix,
    MatrixCell,
    PlantedBug,
    build_matrix,
    format_matrix_report,
    load_planted_bugs,
    match_findings_to_bugs,
    write_matrix,
)


class TestPlantedBug:
    def test_to_dict(self):
        bug = PlantedBug(
            bug_id="ADV-001", depth="L2", failure_mode="api_trust",
            file="auth.c", function="sanitize_html", line=42,
            vuln_type="xss", description="SVG onload bypass",
        )
        d = bug.to_dict()
        assert d["bug_id"] == "ADV-001"
        assert d["depth"] == "L2"
        assert d["failure_mode"] == "api_trust"

    def test_cell_key(self):
        bug = PlantedBug(
            bug_id="ADV-001", depth="L3", failure_mode="composition",
            file="a.c", function="f",
        )
        assert bug.cell_key == "L3:composition"


class TestMatrixCell:
    def test_active_cell(self):
        cell = MatrixCell(depth="L2", failure_mode="api_trust")
        assert cell.is_active is True

    def test_inactive_cell(self):
        cell = MatrixCell(depth="L0", failure_mode="api_trust")
        assert cell.is_active is False

    def test_detection_rate_no_bugs(self):
        cell = MatrixCell(depth="L2", failure_mode="api_trust")
        assert cell.detection_rate is None

    def test_detection_rate_all_detected(self):
        cell = MatrixCell(depth="L2", failure_mode="api_trust")
        bug = PlantedBug(
            bug_id="B1", depth="L2", failure_mode="api_trust",
            file="a.c", function="f",
        )
        cell.planted_bugs.append(bug)
        from core.audit.adversarial_test import DetectionResult
        cell.detection_results["default"] = [
            DetectionResult(bug_id="B1", detected=True, configuration="default"),
        ]
        assert cell.detection_rate == 1.0

    def test_detection_rate_none_detected(self):
        cell = MatrixCell(depth="L2", failure_mode="api_trust")
        bug = PlantedBug(
            bug_id="B1", depth="L2", failure_mode="api_trust",
            file="a.c", function="f",
        )
        cell.planted_bugs.append(bug)
        from core.audit.adversarial_test import DetectionResult
        cell.detection_results["default"] = [
            DetectionResult(bug_id="B1", detected=False, configuration="default"),
        ]
        assert cell.detection_rate == 0.0


class TestAdversarialMatrix:
    def _make_bugs(self):
        return [
            PlantedBug(
                bug_id="B1", depth="L2", failure_mode="api_trust",
                file="auth.c", function="check_input", line=10,
            ),
            PlantedBug(
                bug_id="B2", depth="L3", failure_mode="composition",
                file="parse.c", function="validate", line=50,
            ),
        ]

    def test_build_matrix(self):
        bugs = self._make_bugs()
        matrix = build_matrix(bugs)
        assert len(matrix.cells) == 2

    def test_record_detection(self):
        bugs = self._make_bugs()
        matrix = build_matrix(bugs)
        matrix.record_detection("B1", True, "full", evidence_tier="HIGH")
        matrix.record_detection("B2", False, "full")
        assert "full" in matrix.configurations

        cell = matrix.get_cell("L2", "api_trust")
        assert cell.detection_rate == 1.0

        cell2 = matrix.get_cell("L3", "composition")
        assert cell2.detection_rate == 0.0

    def test_blind_spots(self):
        bugs = self._make_bugs()
        matrix = build_matrix(bugs)
        matrix.record_detection("B1", True, "full")
        matrix.record_detection("B2", False, "full")
        spots = matrix.blind_spots()
        assert len(spots) == 1
        assert spots[0].depth == "L3"

    def test_coverage_summary(self):
        bugs = self._make_bugs()
        matrix = build_matrix(bugs)
        matrix.record_detection("B1", True, "full")
        matrix.record_detection("B2", False, "full")
        summary = matrix.coverage_summary()
        assert summary["populated_cells"] == 2
        assert summary["cells_with_detections"] == 1
        assert summary["blind_spot_count"] == 1

    def test_to_dict(self):
        bugs = self._make_bugs()
        matrix = build_matrix(bugs)
        d = matrix.to_dict()
        assert "cells" in d
        assert "summary" in d
        assert "configurations" in d


class TestMatchFindings:
    def test_match_by_file_and_function(self):
        bugs = [PlantedBug(
            bug_id="B1", depth="L2", failure_mode="api_trust",
            file="auth.c", function="check_pw",
        )]
        findings = [{"file": "auth.c", "function": "check_pw"}]
        results = match_findings_to_bugs(findings, bugs)
        assert len(results) == 1
        assert results[0].detected is True

    def test_match_by_line_proximity(self):
        bugs = [PlantedBug(
            bug_id="B1", depth="L2", failure_mode="api_trust",
            file="auth.c", function="check_pw", line=100,
        )]
        findings = [{"file": "auth.c", "function": "other", "line": 105}]
        results = match_findings_to_bugs(findings, bugs)
        assert results[0].detected is True

    def test_no_match(self):
        bugs = [PlantedBug(
            bug_id="B1", depth="L2", failure_mode="api_trust",
            file="auth.c", function="check_pw",
        )]
        findings = [{"file": "other.c", "function": "foo"}]
        results = match_findings_to_bugs(findings, bugs)
        assert results[0].detected is False

    def test_suffix_path_match(self):
        bugs = [PlantedBug(
            bug_id="B1", depth="L1", failure_mode="absence",
            file="src/auth.c", function="check",
        )]
        findings = [{"file": "target/src/auth.c", "function": "check"}]
        results = match_findings_to_bugs(findings, bugs)
        assert results[0].detected is True


class TestLoadPlantedBugs:
    def test_load_list(self, tmp_path):
        data = [
            {"bug_id": "B1", "depth": "L2", "failure_mode": "api_trust",
             "file": "a.c", "function": "f"},
        ]
        path = tmp_path / "bugs.json"
        path.write_text(json.dumps(data))
        bugs = load_planted_bugs(path)
        assert len(bugs) == 1
        assert bugs[0].bug_id == "B1"

    def test_load_object_with_bugs_key(self, tmp_path):
        data = {"bugs": [
            {"bug_id": "B1", "depth": "L1", "failure_mode": "absence",
             "file": "b.c", "function": "g"},
        ]}
        path = tmp_path / "bugs.json"
        path.write_text(json.dumps(data))
        bugs = load_planted_bugs(path)
        assert len(bugs) == 1

    def test_load_nonexistent(self, tmp_path):
        bugs = load_planted_bugs(tmp_path / "nope.json")
        assert bugs == []

    def test_load_invalid_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not json")
        bugs = load_planted_bugs(path)
        assert bugs == []


class TestFormatReport:
    def test_empty_matrix(self):
        matrix = AdversarialMatrix()
        report = format_matrix_report(matrix)
        assert "Adversarial Self-Test Matrix" in report
        assert "Blind spots: 0" in report

    def test_with_blind_spots(self):
        bugs = [PlantedBug(
            bug_id="B1", depth="L3", failure_mode="composition",
            file="a.c", function="f",
        )]
        matrix = build_matrix(bugs)
        matrix.record_detection("B1", False, "full")
        report = format_matrix_report(matrix)
        assert "BLIND" in report
        assert "Blind Spots" in report


class TestWriteMatrix:
    def test_write_and_read(self, tmp_path):
        bugs = [PlantedBug(
            bug_id="B1", depth="L2", failure_mode="api_trust",
            file="a.c", function="f",
        )]
        matrix = build_matrix(bugs)
        path = write_matrix(matrix, tmp_path)
        assert path.is_file()
        data = json.loads(path.read_text())
        assert "cells" in data
        assert "summary" in data
