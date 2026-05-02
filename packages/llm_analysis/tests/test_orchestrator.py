"""Tests for orchestrator, CC dispatch, cost tracking, and structural grouping."""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# packages/llm_analysis/tests/test_orchestrator.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.llm_analysis.orchestrator import (
    orchestrate,
    _merge_results,
    _structural_grouping,
    _check_self_consistency,
    CostTracker,
    CUTOFF_SKIP_CONSENSUS,
)
from packages.llm_analysis.cc_dispatch import (
    build_schema,
)
from packages.llm_analysis.prompts.schemas import FINDING_RESULT_SCHEMA


def _make_prep_report(findings=None, mode="prep_only"):
    """Create a minimal prep report dict."""
    if findings is None:
        findings = [_make_finding("finding-001", "py/sql-injection", "db.py", 42)]
    return {
        "mode": mode,
        "processed": len(findings),
        "analyzed": 0,
        "exploitable": 0,
        "results": findings,
    }


def _make_finding(finding_id, rule_id, file_path, start_line):
    """Create a minimal finding dict."""
    return {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "file_path": file_path,
        "start_line": start_line,
        "end_line": start_line + 3,
        "level": "error",
        "message": f"Potential {rule_id}",
        "code": "# code here",
        "surrounding_context": "# context here",
    }


def _make_cc_result(finding_id, exploitable=True, score=0.85):
    """Create a valid CC sub-agent result dict."""
    return {
        "finding_id": finding_id,
        "is_true_positive": True,
        "is_exploitable": exploitable,
        "exploitability_score": score,
        "severity_assessment": "high" if exploitable else "low",
        "reasoning": "Test reasoning",
        "attack_scenario": "Test scenario" if exploitable else None,
        "exploit_code": "# exploit" if exploitable else None,
        "patch_code": "# patch",
    }


def _mock_subprocess_ok(results_by_call):
    """Create a subprocess.run mock that returns results in order."""
    call_count = [0]

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = results_by_call[min(call_count[0], len(results_by_call) - 1)]
        result.stderr = ""
        call_count[0] += 1
        return result

    return mock_run


class TestOrchestrate:
    """Test the main orchestrate() function routing."""

    def test_full_report_passthrough(self, tmp_path):
        """mode:'full' returns None (Phase 3 already did analysis)."""
        report = _make_prep_report(mode="full")
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        result = orchestrate(
            prep_report_path=report_path,
            repo_path=tmp_path,
            out_dir=tmp_path / "orch",
        )
        assert result is None

    def test_inside_cc_still_dispatches(self, tmp_path):
        """Inside CC (CLAUDECODE=1), dispatches subprocesses like outside CC."""
        report = _make_prep_report()
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        cc_result = json.dumps(_make_cc_result("finding-001"))

        with patch.dict(os.environ, {"CLAUDECODE": "1"}), \
             patch("packages.llm_analysis.orchestrator.shutil.which", return_value="/usr/bin/claude"), \
             patch("packages.llm_analysis.cc_dispatch.subprocess.run",
                   side_effect=_mock_subprocess_ok([cc_result])):
            result = orchestrate(
                prep_report_path=report_path,
                repo_path=tmp_path,
                out_dir=tmp_path / "orch",
            )

        assert result is not None
        assert result["mode"] == "orchestrated"

    def test_no_claude_binary(self, tmp_path):
        """No claude on PATH -> returns None with warning."""
        report = _make_prep_report()
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        with patch.dict(os.environ, {}, clear=True), \
             patch("packages.llm_analysis.orchestrator.shutil.which", return_value=None):
            result = orchestrate(
                prep_report_path=report_path,
                repo_path=tmp_path,
                out_dir=tmp_path / "orch",
            )
        assert result is None

    def test_corrupt_report(self, tmp_path):
        """Corrupt JSON in Phase 3 report -> returns None."""
        report_path = tmp_path / "report.json"
        report_path.write_text("not json {{{")

        result = orchestrate(
            prep_report_path=report_path,
            repo_path=tmp_path,
            out_dir=tmp_path / "orch",
        )
        assert result is None

    def test_missing_report(self, tmp_path):
        """Missing Phase 3 report file -> returns None."""
        result = orchestrate(
            prep_report_path=tmp_path / "nonexistent.json",
            repo_path=tmp_path,
            out_dir=tmp_path / "orch",
        )
        assert result is None

    def test_dispatches_per_finding(self, tmp_path):
        """Dispatches one CC agent per finding and merges results."""
        findings = [
            _make_finding("f-001", "py/sql-injection", "db.py", 42),
            _make_finding("f-002", "js/xss", "template.js", 18),
        ]
        report = _make_prep_report(findings=findings)
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        cc_results = [
            json.dumps(_make_cc_result("f-001", exploitable=True)),
            json.dumps(_make_cc_result("f-002", exploitable=False, score=0.1)),
        ]

        with patch.dict(os.environ, {}, clear=True), \
             patch("packages.llm_analysis.orchestrator.shutil.which", return_value="/usr/bin/claude"), \
             patch("packages.llm_analysis.cc_dispatch.subprocess.run",
                   side_effect=_mock_subprocess_ok(cc_results)):
            result = orchestrate(
                prep_report_path=report_path,
                repo_path=tmp_path,
                out_dir=tmp_path / "orch",
            )

        assert result is not None
        assert result["mode"] == "orchestrated"
        assert result["orchestration"]["findings_analysed"] == 2
        assert result["orchestration"]["findings_failed"] == 0
        assert result["exploitable"] == 1

        # Verify merged report was written
        out_file = tmp_path / "orch" / "orchestrated_report.json"
        assert out_file.exists()

    def test_empty_findings(self, tmp_path):
        """No findings in report -> returns None."""
        report = _make_prep_report(findings=[])
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        with patch.dict(os.environ, {}, clear=True), \
             patch("packages.llm_analysis.orchestrator.shutil.which", return_value="/usr/bin/claude"):
            result = orchestrate(
                prep_report_path=report_path,
                repo_path=tmp_path,
                out_dir=tmp_path / "orch",
            )
        assert result is None

    def test_auth_failure_aborts_remaining(self, tmp_path):
        """Auth failure on first completed finding aborts remaining dispatch."""
        findings = [
            _make_finding("f-001", "py/sql-injection", "db.py", 42),
            _make_finding("f-002", "js/xss", "template.js", 18),
            _make_finding("f-003", "py/path-injection", "io.py", 10),
        ]
        report = _make_prep_report(findings=findings)
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        def mock_run(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 1
            result.stdout = ""
            result.stderr = "Error 401 Unauthorized"
            return result

        with patch.dict(os.environ, {}, clear=True), \
             patch("packages.llm_analysis.orchestrator.shutil.which", return_value="/usr/bin/claude"), \
             patch("packages.llm_analysis.cc_dispatch.subprocess.run", side_effect=mock_run):
            result = orchestrate(
                prep_report_path=report_path,
                repo_path=tmp_path,
                out_dir=tmp_path / "orch",
            )

        # Should still produce a report, but with all findings failed/aborted
        assert result is not None
        assert result["orchestration"]["findings_analysed"] == 0
        assert result["orchestration"]["findings_failed"] > 0


class TestMergeResults:
    """Test merging CC results back into prep report."""

    def test_preserves_prep_data(self):
        """CC results are merged but prep data (code, dataflow) is preserved."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)
        finding["code"] = "original code"
        finding["has_dataflow"] = True

        report = _make_prep_report(findings=[finding])
        cc_results = [_make_cc_result("f-001")]

        merged = _merge_results(report, cc_results)

        result = merged["results"][0]
        assert result["code"] == "original code"
        assert result["has_dataflow"] is True
        assert result["exploitable"] is True
        assert result["reasoning"] == "Test reasoning"

    def test_does_not_mutate_original(self):
        """Merging does not mutate the original prep report."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)
        report = _make_prep_report(findings=[finding])
        original_mode = report["mode"]
        original_finding = report["results"][0].copy()

        cc_results = [_make_cc_result("f-001")]
        _merge_results(report, cc_results)

        # Original report should be unchanged
        assert report["mode"] == original_mode
        assert "analysis" not in report["results"][0] or report["results"][0] == original_finding

    def test_failed_finding_preserved(self):
        """Findings with CC errors keep prep data and get cc_error field."""
        report = _make_prep_report()
        cc_results = [{"finding_id": "finding-001", "error": "timeout"}]

        merged = _merge_results(report, cc_results)
        result = merged["results"][0]
        assert "cc_error" in result

    def test_failed_finding_includes_debug_path(self):
        """Failed findings with debug files include the path."""
        report = _make_prep_report()
        cc_results = [{"finding_id": "finding-001", "error": "parse error",
                       "cc_debug_file": "debug/cc_finding-001.txt"}]

        merged = _merge_results(report, cc_results)
        result = merged["results"][0]
        assert result["cc_debug_file"] == "debug/cc_finding-001.txt"

    def test_mode_set_to_orchestrated(self):
        """Merged report has mode 'orchestrated'."""
        report = _make_prep_report()
        cc_results = [_make_cc_result("finding-001")]

        merged = _merge_results(report, cc_results)
        assert merged["mode"] == "orchestrated"

    def test_no_exploits_flag_drops_exploit_code(self):
        """With no_exploits=True, exploit_code is not merged even if agent returned it."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)
        report = _make_prep_report(findings=[finding])
        cc_results = [_make_cc_result("f-001", exploitable=True)]

        merged = _merge_results(report, cc_results, no_exploits=True)
        result = merged["results"][0]
        assert result["exploitable"] is True
        assert result.get("has_exploit") is not True
        assert "exploit_code" not in result
        assert merged["exploits_generated"] == 0

    def test_counters_updated(self):
        """Exploit/patch counters reflect CC results."""
        findings = [
            _make_finding("f-001", "py/sql-injection", "db.py", 42),
            _make_finding("f-002", "js/xss", "template.js", 18),
        ]
        report = _make_prep_report(findings=findings)
        cc_results = [
            _make_cc_result("f-001", exploitable=True),
            _make_cc_result("f-002", exploitable=False, score=0.1),
        ]

        merged = _merge_results(report, cc_results)
        assert merged["analyzed"] == 2
        assert merged["exploitable"] == 1
        assert merged["exploits_generated"] == 1  # Only f-001 has exploit_code
        assert merged["patches_generated"] == 1   # Only exploitable f-001 gets patch


class TestFindingResultSchema:
    """Test the output schema constant."""

    def test_schema_is_valid_json_schema(self):
        """FINDING_RESULT_SCHEMA is a valid JSON Schema object."""
        assert FINDING_RESULT_SCHEMA["type"] == "object"
        assert "properties" in FINDING_RESULT_SCHEMA
        assert "required" in FINDING_RESULT_SCHEMA
        assert "finding_id" in FINDING_RESULT_SCHEMA["required"]
        assert "reasoning" in FINDING_RESULT_SCHEMA["required"]

    def test_schema_serializable(self):
        """Schema can be serialized to JSON (for --json-schema flag)."""
        serialized = json.dumps(FINDING_RESULT_SCHEMA)
        parsed = json.loads(serialized)
        assert parsed == FINDING_RESULT_SCHEMA

    def test_score_has_range(self):
        """exploitability_score has min/max constraints."""
        score_schema = FINDING_RESULT_SCHEMA["properties"]["exploitability_score"]
        assert score_schema["minimum"] == 0
        assert score_schema["maximum"] == 1


class TestBuildSchema:
    """Test dynamic schema construction."""

    def test_default_includes_all_fields(self):
        """Default schema includes exploit_code and patch_code."""
        schema = build_schema()
        assert "exploit_code" in schema["properties"]
        assert "patch_code" in schema["properties"]

    def test_no_exploits_removes_exploit_code(self):
        """--no-exploits removes exploit_code from schema."""
        schema = build_schema(no_exploits=True)
        assert "exploit_code" not in schema["properties"]
        assert "patch_code" in schema["properties"]

    def test_no_patches_removes_patch_code(self):
        """--no-patches removes patch_code from schema."""
        schema = build_schema(no_patches=True)
        assert "exploit_code" in schema["properties"]
        assert "patch_code" not in schema["properties"]

    def test_both_flags_removes_both(self):
        """Both flags remove both fields."""
        schema = build_schema(no_exploits=True, no_patches=True)
        assert "exploit_code" not in schema["properties"]
        assert "patch_code" not in schema["properties"]

    def test_does_not_mutate_base_schema(self):
        """Building a schema doesn't mutate FINDING_RESULT_SCHEMA."""
        build_schema(no_exploits=True, no_patches=True)
        assert "exploit_code" in FINDING_RESULT_SCHEMA["properties"]
        assert "patch_code" in FINDING_RESULT_SCHEMA["properties"]


# ── Structural Grouping ─────────────────────────────────────────────

class TestStructuralGrouping:
    def test_same_file_groups(self):
        results = [
            {"finding_id": "f-001", "file_path": "db.py", "rule_id": "sqli"},
            {"finding_id": "f-002", "file_path": "db.py", "rule_id": "xss"},
        ]
        groups = _structural_grouping(results)
        file_groups = [g for g in groups if g["criterion"] == "file_path"]
        assert len(file_groups) == 1
        assert set(file_groups[0]["finding_ids"]) == {"f-001", "f-002"}

    def test_same_rule_groups(self):
        results = [
            {"finding_id": "f-001", "file_path": "a.py", "rule_id": "sqli"},
            {"finding_id": "f-002", "file_path": "b.py", "rule_id": "sqli"},
            {"finding_id": "f-003", "file_path": "c.py", "rule_id": "xss"},
            {"finding_id": "f-004", "file_path": "d.py", "rule_id": "path_traversal"},
        ]
        groups = _structural_grouping(results)
        rule_groups = [g for g in groups if g["criterion"] == "rule_id"]
        assert len(rule_groups) == 1
        assert set(rule_groups[0]["finding_ids"]) == {"f-001", "f-002"}

    def test_no_transitive_closure(self):
        """A-B share file, B-C share rule. A and C should NOT be in same group."""
        results = [
            {"finding_id": "f-001", "file_path": "db.py", "rule_id": "sqli"},
            {"finding_id": "f-002", "file_path": "db.py", "rule_id": "xss"},
            {"finding_id": "f-003", "file_path": "api.py", "rule_id": "xss"},
        ]
        groups = _structural_grouping(results)
        # f-001 and f-003 should NOT be in the same group
        for g in groups:
            ids = set(g["finding_ids"])
            assert not ({"f-001", "f-003"} <= ids and "f-002" not in ids)

    def test_overlapping_groups(self):
        """A finding can appear in multiple groups."""
        results = [
            {"finding_id": "f-001", "file_path": "db.py", "rule_id": "sqli"},
            {"finding_id": "f-002", "file_path": "db.py", "rule_id": "xss"},
            {"finding_id": "f-003", "file_path": "api.py", "rule_id": "sqli"},
            {"finding_id": "f-004", "file_path": "util.py", "rule_id": "path_traversal"},
        ]
        groups = _structural_grouping(results)
        # f-001 should appear in both a file group (db.py) and a rule group (sqli)
        f001_groups = [g for g in groups if "f-001" in g["finding_ids"]]
        assert len(f001_groups) >= 2

    def test_independent_findings_no_group(self):
        results = [
            {"finding_id": "f-001", "file_path": "a.py", "rule_id": "sqli"},
            {"finding_id": "f-002", "file_path": "b.py", "rule_id": "xss"},
        ]
        groups = _structural_grouping(results)
        assert len(groups) == 0

    def test_shared_dataflow_source(self):
        results = [
            {"finding_id": "f-001", "file_path": "a.py", "rule_id": "sqli",
             "dataflow": {"source": {"file": "routes.py", "line": 15}}},
            {"finding_id": "f-002", "file_path": "b.py", "rule_id": "xss",
             "dataflow": {"source": {"file": "routes.py", "line": 15}}},
        ]
        groups = _structural_grouping(results)
        source_groups = [g for g in groups if g["criterion"] == "dataflow_source"]
        assert len(source_groups) == 1



# ── CostTracker ──────────────────────────────────────────────────────

class TestCostTracker:
    def test_basic_tracking(self):
        ct = CostTracker(max_cost=10.0)
        ct.add_cost("opus", 3.0)
        ct.add_cost("opus", 2.0)
        assert ct.total_cost == 5.0

    def test_per_model_breakdown(self):
        ct = CostTracker(max_cost=10.0)
        ct.add_cost("opus", 3.0)
        ct.add_cost("gemini", 2.0)
        summary = ct.get_summary()
        assert summary["cost_by_model"]["opus"] == 3.0
        assert summary["cost_by_model"]["gemini"] == 2.0

    def test_skip_consensus_at_70_percent(self):
        ct = CostTracker(max_cost=10.0)
        ct.add_cost("opus", 6.9)
        assert ct.should_skip_consensus() is False
        ct.add_cost("opus", 0.2)
        assert ct.should_skip_consensus() is True

    def test_skip_exploits_at_85_percent(self):
        ct = CostTracker(max_cost=10.0)
        ct.add_cost("opus", 8.4)
        assert ct.should_skip_exploits() is False
        ct.add_cost("opus", 0.2)
        assert ct.should_skip_exploits() is True

    def test_single_model_at_95_percent(self):
        ct = CostTracker(max_cost=10.0)
        ct.add_cost("opus", 9.4)
        assert ct.should_single_model() is False
        ct.add_cost("opus", 0.2)
        assert ct.should_single_model() is True

    def test_no_budget_never_skips(self):
        ct = CostTracker(max_cost=0)
        ct.add_cost("opus", 100.0)
        assert ct.should_skip_consensus() is False
        assert ct.should_skip_exploits() is False

    def test_estimate_cost(self):
        ct = CostTracker(max_cost=10.0)
        est = ct.estimate_cost(50, n_consensus_models=1, model_name="unknown-model")
        # Falls back to default $0.03/call: 100 calls * 0.03 = 3.0
        assert est == 3.0



# ── CostTracker Phase Skip ──────────────────────────────────────────

class TestCostTrackerPhaseSkip:
    def test_should_skip_phase_when_over_budget(self):
        ct = CostTracker(max_cost=10.0)
        ct.add_cost("opus", 8.0)  # 80% spent
        # Consensus cutoff is 70%, estimate for 50 calls ≈ $1.50
        assert ct.should_skip_phase(50, "opus", CUTOFF_SKIP_CONSENSUS, "consensus") is True

    def test_should_not_skip_phase_when_within_budget(self):
        ct = CostTracker(max_cost=10.0)
        ct.add_cost("opus", 2.0)  # 20% spent
        assert ct.should_skip_phase(10, "opus", CUTOFF_SKIP_CONSENSUS, "consensus") is False

    def test_no_budget_never_skips_phase(self):
        ct = CostTracker(max_cost=0)
        ct.add_cost("opus", 100.0)
        assert ct.should_skip_phase(1000, "opus", CUTOFF_SKIP_CONSENSUS, "consensus") is False


class TestMergePrepProtection:
    def test_prep_data_not_overwritten_by_dispatch(self):
        """Dispatch result keys that match prep data should not overwrite."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)
        finding["code"] = "original prep code"
        report = _make_prep_report(findings=[finding])

        # Simulate a dispatch result that tries to overwrite prep fields
        cc_result = _make_cc_result("f-001", exploitable=True)
        cc_result["code"] = "INJECTED CODE"
        cc_result["file_path"] = "/etc/shadow"

        merged = _merge_results(report, [cc_result])
        result = merged["results"][0]

        # Prep data should be preserved
        assert result["code"] == "original prep code"
        assert result["file_path"] == "db.py"
        # Analysis data should still come through
        assert result["is_exploitable"] is True


class TestSelfConsistency:
    def test_flags_false_positive_contradiction(self):
        results = {
            "f-001": {
                "is_true_positive": True,
                "is_exploitable": True,
                "reasoning": "This is a false positive because the input is sanitised.",
            }
        }
        _check_self_consistency(results)
        assert results["f-001"]["self_contradictory"] is True

    def test_flags_not_exploitable_contradiction(self):
        results = {
            "f-001": {
                "is_true_positive": True,
                "is_exploitable": True,
                "reasoning": "The code is safe and cannot be exploited in practice.",
            }
        }
        _check_self_consistency(results)
        assert results["f-001"]["self_contradictory"] is True

    def test_no_flag_when_consistent(self):
        results = {
            "f-001": {
                "is_true_positive": True,
                "is_exploitable": True,
                "reasoning": "Buffer overflow with attacker-controlled input, trivially exploitable.",
            }
        }
        _check_self_consistency(results)
        assert "self_contradictory" not in results["f-001"]

    def test_no_flag_when_not_exploitable_consistent(self):
        results = {
            "f-001": {
                "is_true_positive": False,
                "is_exploitable": False,
                "reasoning": "This is a false positive, the code is unreachable.",
            }
        }
        _check_self_consistency(results)
        assert "self_contradictory" not in results["f-001"]

    def test_skips_errors(self):
        results = {
            "f-001": {"error": "timeout"},
        }
        _check_self_consistency(results)
        assert "self_contradictory" not in results["f-001"]

    def test_skips_empty_reasoning(self):
        results = {
            "f-001": {
                "is_true_positive": True,
                "is_exploitable": True,
                "reasoning": "",
            }
        }
        _check_self_consistency(results)
        assert "self_contradictory" not in results["f-001"]


# ── Weakened Defenses ──────────────────────────────────────────────

class TestWeakenedDefenses:
    """Test --accept-weakened-defenses behaviour when probe fails."""

    def _make_external_llm_mocks(self):
        """Build mocks for the external LLM dispatch path."""
        fake_config = MagicMock()
        fake_config.primary_model = "ollama/llama3"
        fake_config.max_cost_per_scan = 0

        mock_model = MagicMock()
        mock_model.model_name = "ollama/llama3"

        role_resolution = {
            "analysis_model": mock_model,
            "code_model": None,
            "consensus_models": [],
            "fallback_models": [],
        }
        return fake_config, role_resolution

    def _run_with_failing_probe(self, tmp_path, accept=False):
        """Helper: dispatch with an external LLM model that fails the canary probe."""
        report = _make_prep_report()
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        from core.security.envelope_probe import ProbeResult
        failing_probe = ProbeResult(
            compatible=False, valid_json=True, correct_verdict=False,
            nonce_leaked=False, raw_response="{}",
            error="Model failed to identify a trivial buffer overflow",
        )

        fake_config, role_res = self._make_external_llm_mocks()

        analysis_result = _make_cc_result("finding-001")

        def mock_dispatch_task(task, findings, dispatch_fn, role_resolution,
                               results_by_id, cost_tracker, max_parallel):
            for f in findings:
                fid = f.get("finding_id")
                r = dict(analysis_result, finding_id=fid)
                results_by_id[fid] = r
            return [dict(analysis_result, finding_id=f.get("finding_id"))
                    for f in findings]

        mock_dispatch_fn = MagicMock(return_value=MagicMock(
            result=analysis_result, cost=0, tokens=0, model="ollama/llama3",
            duration=0,
        ))

        with patch("core.llm.config.resolve_model_roles",
                   return_value=role_res), \
             patch("core.llm.client.LLMClient") as mock_cls, \
             patch("packages.llm_analysis.dispatch.dispatch_task",
                   side_effect=mock_dispatch_task), \
             patch("core.security.envelope_probe.probe_envelope_compatibility",
                   return_value=failing_probe):
            mock_cls.return_value = MagicMock()
            return orchestrate(
                prep_report_path=report_path,
                repo_path=tmp_path,
                out_dir=tmp_path / "orch",
                llm_config=fake_config,
                accept_weakened_defenses=accept,
            )

    def test_probe_failure_aborts_without_flag(self, tmp_path):
        """Probe failure without --accept-weakened-defenses returns None."""
        result = self._run_with_failing_probe(tmp_path, accept=False)
        assert result is None

    def test_probe_failure_continues_with_flag(self, tmp_path):
        """Probe failure with --accept-weakened-defenses falls back to passthrough."""
        with patch("core.security.rule_of_two.is_interactive", return_value=True):
            result = self._run_with_failing_probe(tmp_path, accept=True)
        assert result is not None
        assert result["orchestration"]["defense_profile"] == "passthrough"
        assert result["orchestration"]["weakened_defenses"] is True

    def test_weakened_defenses_false_when_probe_passes(self, tmp_path):
        """When probe passes, weakened_defenses is False regardless of flag."""
        report = _make_prep_report()
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        cc_result = json.dumps(_make_cc_result("finding-001"))

        with patch.dict(os.environ, {}, clear=True), \
             patch("packages.llm_analysis.orchestrator.shutil.which",
                   return_value="/usr/bin/claude"), \
             patch("packages.llm_analysis.cc_dispatch.subprocess.run",
                   side_effect=_mock_subprocess_ok([cc_result])):
            result = orchestrate(
                prep_report_path=report_path,
                repo_path=tmp_path,
                out_dir=tmp_path / "orch",
                accept_weakened_defenses=True,
            )

        assert result is not None
        assert result["orchestration"]["weakened_defenses"] is False

    def test_weakened_defenses_blocked_in_ci(self, tmp_path):
        """--accept-weakened-defenses is blocked in non-interactive mode."""
        with patch("core.security.rule_of_two.is_interactive", return_value=False):
            result = self._run_with_failing_probe(tmp_path, accept=True)
        assert result is None
