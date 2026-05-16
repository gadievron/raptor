"""Tests for core.project.correlate — action-oriented cross-run correlation."""

import json
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from core.project.correlate import (
    INCONCLUSIVE_VERDICTS,
    LLM_COMMAND_TYPES,
    NEGATIVE_VERDICTS,
    POSITIVE_VERDICTS,
    SCAN_COMMAND_TYPES,
    correlate_project,
    get_finding_status,
    normalize_verdict,
    _build_action_list,
    _build_tool_gaps,
    _find_disagreements,
    _find_new_and_resolved,
    _find_persistent,
)


# --- normalize_verdict ---

class TestNormalizeVerdict(TestCase):
    def test_positive_verdicts(self):
        for v in POSITIVE_VERDICTS:
            self.assertEqual(normalize_verdict(v), "positive", v)

    def test_negative_verdicts(self):
        for v in NEGATIVE_VERDICTS:
            self.assertEqual(normalize_verdict(v), "negative", v)

    def test_inconclusive_verdicts(self):
        for v in INCONCLUSIVE_VERDICTS:
            self.assertEqual(normalize_verdict(v), "inconclusive", v)

    def test_unknown(self):
        self.assertEqual(normalize_verdict("something_random"), "unknown")
        self.assertEqual(normalize_verdict(""), "unknown")

    def test_whitespace_and_case(self):
        self.assertEqual(normalize_verdict("  Exploitable  "), "positive")
        self.assertEqual(normalize_verdict("RULED_OUT"), "negative")


# --- get_finding_status ---

class TestGetFindingStatus(TestCase):
    def test_exploitable_boolean(self):
        self.assertEqual(get_finding_status({"is_exploitable": True}), "exploitable")

    def test_true_positive_false(self):
        self.assertEqual(get_finding_status({"is_true_positive": False}), "false_positive")

    def test_true_positive_true(self):
        self.assertEqual(get_finding_status({"is_true_positive": True}), "confirmed")

    def test_final_status_fallback(self):
        self.assertEqual(get_finding_status({"final_status": "ruled_out"}), "ruled_out")

    def test_status_fallback(self):
        self.assertEqual(get_finding_status({"status": "not_disproven"}), "not_disproven")

    def test_empty(self):
        self.assertEqual(get_finding_status({}), "")


# --- _find_disagreements ---

def _make_finding(file="a.c", function="fn", line=1, vuln_type="bof", **kw):
    return {"file": file, "function": function, "line": line, "vuln_type": vuln_type, **kw}


class TestFindDisagreements(TestCase):
    def test_no_disagreement_all_positive(self):
        findings = {
            "run-A": [_make_finding(final_status="exploitable")],
            "run-B": [_make_finding(final_status="confirmed")],
        }
        result = _find_disagreements(findings, {})
        self.assertEqual(result, [])

    def test_positive_vs_negative(self):
        findings = {
            "run-A": [_make_finding(final_status="exploitable")],
            "run-B": [_make_finding(final_status="ruled_out")],
        }
        result = _find_disagreements(findings, {})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["disagreement_type"], "positive_vs_negative")

    def test_positive_vs_inconclusive(self):
        findings = {
            "run-A": [_make_finding(final_status="confirmed")],
            "run-B": [_make_finding(final_status="not_disproven")],
        }
        result = _find_disagreements(findings, {})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["disagreement_type"], "positive_vs_inconclusive")

    def test_negative_vs_inconclusive_no_disagreement(self):
        findings = {
            "run-A": [_make_finding(final_status="ruled_out")],
            "run-B": [_make_finding(final_status="not_disproven")],
        }
        self.assertEqual(_find_disagreements(findings, {}), [])

    def test_sorted_by_type_then_score(self):
        findings = {
            "run-A": [
                _make_finding(file="x.c", final_status="exploitable", exploitability_score=9),
                _make_finding(file="y.c", final_status="confirmed", exploitability_score=5),
            ],
            "run-B": [
                _make_finding(file="x.c", final_status="ruled_out"),
                _make_finding(file="y.c", final_status="not_disproven"),
            ],
        }
        result = _find_disagreements(findings, {})
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["disagreement_type"], "positive_vs_negative")
        self.assertEqual(result[1]["disagreement_type"], "positive_vs_inconclusive")

    def test_model_from_run_models(self):
        findings = {
            "run-A": [_make_finding(final_status="exploitable")],
            "run-B": [_make_finding(final_status="ruled_out")],
        }
        result = _find_disagreements(findings, {"run-A": "gpt-4o", "run-B": "claude-3-opus"})
        verdicts = result[0]["verdicts"]
        models = {v["model"] for v in verdicts}
        self.assertIn("gpt-4o", models)
        self.assertIn("claude-3-opus", models)

    def test_model_from_analysed_by_field(self):
        findings = {
            "run-A": [_make_finding(final_status="exploitable", analysed_by="gpt-4o")],
            "run-B": [_make_finding(final_status="ruled_out", analysed_by="claude")],
        }
        result = _find_disagreements(findings, {"run-A": "fallback", "run-B": "fallback"})
        models = {v["model"] for v in result[0]["verdicts"]}
        self.assertIn("gpt-4o", models)
        self.assertIn("claude", models)


# --- _find_new_and_resolved ---

class TestNewAndResolved(TestCase):
    def _make_run_dirs(self, names):
        d = tempfile.mkdtemp()
        dirs = []
        for n in names:
            p = Path(d) / n
            p.mkdir()
            meta = {"command": "validate"}
            (p / "run-metadata.json").write_text(json.dumps(meta))
            dirs.append(p)
        return dirs

    def test_new_finding_detected(self):
        dirs = self._make_run_dirs(["validate-001", "validate-002"])
        findings = {
            "validate-001": [],
            "validate-002": [_make_finding(final_status="exploitable")],
        }
        types = {"validate-001": "validate", "validate-002": "validate"}
        result = _find_new_and_resolved(findings, dirs, types)
        self.assertEqual(len(result["new_findings"]), 1)
        self.assertEqual(result["new_findings"][0]["first_seen_run"], "validate-002")

    def test_resolved_finding_detected(self):
        dirs = self._make_run_dirs(["validate-001", "validate-002"])
        findings = {
            "validate-001": [_make_finding(final_status="exploitable")],
            "validate-002": [],
        }
        types = {"validate-001": "validate", "validate-002": "validate"}
        result = _find_new_and_resolved(findings, dirs, types)
        self.assertEqual(len(result["potentially_resolved"]), 1)

    def test_cross_type_not_resolved(self):
        dirs = self._make_run_dirs(["scan-001", "validate-001"])
        findings = {
            "scan-001": [_make_finding(final_status="exploitable")],
            "validate-001": [],
        }
        types = {"scan-001": "scan", "validate-001": "validate"}
        result = _find_new_and_resolved(findings, dirs, types)
        self.assertEqual(len(result["potentially_resolved"]), 0)

    def test_single_run_no_new_or_resolved(self):
        dirs = self._make_run_dirs(["validate-001"])
        findings = {
            "validate-001": [_make_finding(final_status="exploitable")],
        }
        types = {"validate-001": "validate"}
        result = _find_new_and_resolved(findings, dirs, types)
        self.assertEqual(len(result["new_findings"]), 0)
        self.assertEqual(len(result["potentially_resolved"]), 0)

    def test_finding_in_all_runs_not_new(self):
        dirs = self._make_run_dirs(["validate-001", "validate-002", "validate-003"])
        f = _make_finding(final_status="exploitable")
        findings = {
            "validate-001": [f],
            "validate-002": [f],
            "validate-003": [f],
        }
        types = {"validate-001": "validate", "validate-002": "validate",
                 "validate-003": "validate"}
        result = _find_new_and_resolved(findings, dirs, types)
        self.assertEqual(len(result["new_findings"]), 0)
        self.assertEqual(len(result["potentially_resolved"]), 0)


# --- _build_tool_gaps ---

class TestBuildToolGaps(TestCase):
    def _make_run_dirs(self, names):
        d = tempfile.mkdtemp()
        dirs = []
        for n in names:
            p = Path(d) / n
            p.mkdir()
            dirs.append(p)
        return dirs

    def test_validated_not_scanned(self):
        dirs = self._make_run_dirs(["validate-001"])
        findings = {
            "validate-001": [_make_finding(file="x.c", final_status="confirmed")],
        }
        types = {"validate-001": "validate"}
        result = _build_tool_gaps(dirs, findings, types)
        self.assertEqual(len(result["validated_not_scanned"]), 1)

    def test_scanned_not_validated(self):
        dirs = self._make_run_dirs(["scan-001"])
        findings = {
            "scan-001": [_make_finding(file="x.c", final_status="confirmed")],
        }
        types = {"scan-001": "scan"}
        result = _build_tool_gaps(dirs, findings, types)
        self.assertEqual(len(result["scanned_not_validated"]), 1)

    def test_both_covered_no_gap(self):
        dirs = self._make_run_dirs(["scan-001", "validate-001"])
        findings = {
            "scan-001": [_make_finding(file="x.c")],
            "validate-001": [_make_finding(file="x.c")],
        }
        types = {"scan-001": "scan", "validate-001": "validate"}
        result = _build_tool_gaps(dirs, findings, types)
        self.assertEqual(result["scanned_not_validated"], [])
        self.assertEqual(result["validated_not_scanned"], [])

    def test_missing_scan_commands(self):
        dirs = self._make_run_dirs(["validate-001"])
        types = {"validate-001": "validate"}
        result = _build_tool_gaps(dirs, {}, types)
        self.assertIn("scan", result["missing_command_types"])

    def test_missing_validate_commands(self):
        dirs = self._make_run_dirs(["scan-001"])
        types = {"scan-001": "scan"}
        result = _build_tool_gaps(dirs, {}, types)
        self.assertIn("validate", result["missing_command_types"])

    def test_suggested_next_runs(self):
        dirs = self._make_run_dirs(["validate-001"])
        findings = {
            "validate-001": [_make_finding(file="a.c"), _make_finding(file="b.c")],
        }
        types = {"validate-001": "validate"}
        result = _build_tool_gaps(dirs, findings, types)
        suggested = result["suggested_next_runs"]
        self.assertTrue(any("raptor scan" in s for s in suggested))


# --- _build_action_list ---

class TestBuildActionList(TestCase):
    def test_priority_ordering(self):
        disagreements = [{
            "file": "a.c", "line": 1, "vuln_type": "bof",
            "verdicts": [
                {"verdict": "positive", "run": "r1", "status": "exploitable", "model": "", "score": 9},
                {"verdict": "negative", "run": "r2", "status": "ruled_out", "model": "", "score": None},
            ],
            "disagreement_type": "positive_vs_negative",
            "max_score": 9,
        }]
        new_resolved = {
            "new_findings": [{
                "file": "b.c", "line": 5, "vuln_type": "xss",
                "status": "exploitable", "verdict": "positive",
                "first_seen_run": "r2", "command_type": "validate",
            }],
            "potentially_resolved": [],
        }
        tool_gaps = {
            "scanned_not_validated": [{"file": "c.c", "finding_count": 2}],
            "missing_command_types": [],
            "suggested_next_runs": [],
        }
        persistent = []

        actions = _build_action_list(disagreements, new_resolved, tool_gaps, persistent)
        self.assertEqual(actions[0]["category"], "disagreement")
        self.assertEqual(actions[0]["priority"], 1)
        self.assertEqual(actions[1]["category"], "new_finding")
        self.assertEqual(actions[1]["priority"], 2)
        self.assertEqual(actions[2]["category"], "tool_gap")
        self.assertEqual(actions[2]["priority"], 3)

    def test_empty_input(self):
        actions = _build_action_list(
            [], {"new_findings": [], "potentially_resolved": []},
            {"scanned_not_validated": [], "missing_command_types": []}, [],
        )
        self.assertEqual(actions, [])


# --- _find_persistent ---

class TestFindPersistent(TestCase):
    def test_single_run_not_persistent(self):
        findings = {
            "run-A": [_make_finding(final_status="exploitable")],
        }
        self.assertEqual(_find_persistent(findings, {}), [])

    def test_two_runs_persistent(self):
        findings = {
            "run-A": [_make_finding(final_status="exploitable")],
            "run-B": [_make_finding(final_status="confirmed")],
        }
        result = _find_persistent(findings, {})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["runs_seen"], 2)

    def test_different_findings_not_persistent(self):
        findings = {
            "run-A": [_make_finding(file="a.c")],
            "run-B": [_make_finding(file="b.c")],
        }
        result = _find_persistent(findings, {})
        self.assertEqual(result, [])

    def test_models_tracked(self):
        findings = {
            "run-A": [_make_finding(final_status="exploitable", analysed_by="gpt-4o")],
            "run-B": [_make_finding(final_status="confirmed", analysed_by="claude")],
        }
        result = _find_persistent(findings, {})
        self.assertEqual(len(result), 1)
        self.assertIn("gpt-4o", result[0]["models"])
        self.assertIn("claude", result[0]["models"])

    def test_models_from_run_models(self):
        findings = {
            "run-A": [_make_finding(final_status="exploitable")],
            "run-B": [_make_finding(final_status="confirmed")],
        }
        result = _find_persistent(findings, {"run-A": "model-a", "run-B": "model-b"})
        self.assertEqual(len(result), 1)
        self.assertIn("model-a", result[0]["models"])

    def test_sorted_by_frequency(self):
        findings = {
            "run-A": [_make_finding(file="a.c"), _make_finding(file="b.c")],
            "run-B": [_make_finding(file="a.c"), _make_finding(file="b.c")],
            "run-C": [_make_finding(file="a.c")],
        }
        result = _find_persistent(findings, {})
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["runs_seen"], 3)
        self.assertEqual(result[1]["runs_seen"], 2)

    def test_status_from_latest_finding(self):
        findings = {
            "run-A": [_make_finding(final_status="not_disproven")],
            "run-B": [_make_finding(final_status="exploitable")],
        }
        result = _find_persistent(findings, {})
        self.assertEqual(len(result), 1)


# --- correlate_project integration ---

class TestCorrelateProject(TestCase):
    def _make_project(self, run_specs):
        """Create a mock project with given run specs.

        run_specs: list of (run_name, command, findings_list)
        """
        base = Path(tempfile.mkdtemp())
        runs_dir = base / "runs"
        runs_dir.mkdir()

        run_dirs = []
        for name, command, findings in run_specs:
            d = runs_dir / name
            d.mkdir()
            meta = {"command": command, "status": "complete"}
            (d / "run-metadata.json").write_text(json.dumps(meta))
            if findings:
                report = {"mode": "prep_only", "results": findings}
                (d / "findings.json").write_text(json.dumps(report))
            run_dirs.append(d)

        project = mock.MagicMock()
        project.name = "test-project"
        project.get_run_dirs.return_value = run_dirs
        return project

    def test_empty_project(self):
        project = mock.MagicMock()
        project.get_run_dirs.return_value = []
        result = correlate_project(project)
        self.assertEqual(result["summary"]["runs"], 0)

    def test_basic_integration(self):
        f = _make_finding(final_status="exploitable")
        project = self._make_project([
            ("validate-001", "validate", [f]),
            ("validate-002", "validate", [f]),
        ])
        result = correlate_project(project)
        self.assertEqual(result["summary"]["runs"], 2)
        self.assertGreater(len(result["persistent_findings"]), 0)

    def test_disagreement_surfaces_in_actions(self):
        project = self._make_project([
            ("validate-001", "validate", [_make_finding(final_status="exploitable")]),
            ("validate-002", "validate", [_make_finding(final_status="ruled_out")]),
        ])
        result = correlate_project(project)
        self.assertGreater(result["summary"]["disagreements"], 0)
        categories = [a["category"] for a in result["actions"]]
        self.assertIn("disagreement", categories)

    def test_tool_gap_surfaces_in_actions(self):
        project = self._make_project([
            ("validate-001", "validate",
             [_make_finding(file="only_llm.c", final_status="confirmed")]),
        ])
        result = correlate_project(project)
        suggested = result["tool_gaps"]["suggested_next_runs"]
        self.assertTrue(any("scan" in s for s in suggested))
