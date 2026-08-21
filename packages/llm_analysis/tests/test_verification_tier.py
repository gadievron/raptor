"""Evidence tiering on /analyze verdicts — derivation, ordering, wiring."""

from __future__ import annotations

from pathlib import Path

from packages.llm_analysis.agent import VulnerabilityContext
from packages.llm_analysis.verification_tier import (
    derive_verification_tier,
    sort_results_by_tier,
    tier_counts,
)


def _finding(**overrides):
    base = {
        "finding_id": "f-1",
        "analysis": {"is_true_positive": True, "is_exploitable": True},
    }
    base.update(overrides)
    return base


class TestDeriveVerificationTier:
    def test_execution_oracle_confirms(self):
        f = _finding(execute_outcome="exit_signal")
        assert derive_verification_tier(f) == "confirmed"

    def test_sanitizer_report_confirms(self):
        f = _finding(execute_outcome="sanitizer_report")
        assert derive_verification_tier(f) == "confirmed"

    def test_off_target_execution_does_not_confirm(self):
        f = _finding(
            execute_outcome="exit_signal",
            intent_match={"verdict": "off_target"},
        )
        assert derive_verification_tier(f) == "llm_only"

    def test_no_obvious_effect_does_not_confirm(self):
        f = _finding(execute_outcome="no_obvious_effect")
        assert derive_verification_tier(f) == "llm_only"

    def test_smt_witness_is_tool_backed(self):
        f = _finding(
            analysis={"smt_witness": {"model": {"len": 32}}},
        )
        assert derive_verification_tier(f) == "tool_backed"

    def test_smt_witness_top_level_shape(self):
        # cc-dispatch merge copies result keys onto the finding itself.
        f = _finding(smt_witness={"model": {"len": 32}})
        assert derive_verification_tier(f) == "tool_backed"

    def test_empty_smt_model_does_not_count(self):
        f = _finding(analysis={"smt_witness": {"model": {}}})
        assert derive_verification_tier(f) == "llm_only"

    def test_iris_validation_confirmed_is_tool_backed(self):
        f = _finding(
            analysis={
                "dataflow_validation": {
                    "verdict": "confirmed",
                    "method": "codeql-iris",
                },
            },
        )
        assert derive_verification_tier(f) == "tool_backed"

    def test_structural_refuted_is_tool_backed(self):
        # The tier grades the evidence, not the verdict's sign.
        f = _finding(
            analysis={
                "dataflow_validation": {
                    "verdict": "refuted",
                    "method": "structural-treesitter",
                },
            },
        )
        assert derive_verification_tier(f) == "tool_backed"

    def test_iris_preflight_record_is_tool_backed(self):
        f = _finding(
            analysis={
                "dataflow_validation": {
                    "verdict": "refuted",
                    "tier": "iris_tier1",
                },
            },
        )
        assert derive_verification_tier(f) == "tool_backed"

    def test_llm_deep_validation_dict_does_not_count(self):
        # agent.validate_dataflow's LLM-produced dict carries neither
        # ``method`` nor ``tier`` — an LLM opinion is not a receipt.
        f = _finding(
            analysis={
                "dataflow_validation": {
                    "is_exploitable": True,
                    "false_positive": False,
                },
            },
        )
        assert derive_verification_tier(f) == "llm_only"

    def test_compiled_exploit_alone_does_not_count(self):
        f = _finding(exploit_compiled=True)
        assert derive_verification_tier(f) == "llm_only"

    def test_bare_llm_verdict_is_llm_only(self):
        assert derive_verification_tier(_finding()) == "llm_only"

    def test_partial_dict_degrades_gracefully(self):
        assert derive_verification_tier({}) == "llm_only"
        assert derive_verification_tier({"analysis": None}) == "llm_only"


class TestOrderingAndCounts:
    def test_sort_confirmed_first_stable(self):
        results = [
            {"finding_id": "a", "verification_tier": "llm_only"},
            {"finding_id": "b", "verification_tier": "confirmed"},
            {"finding_id": "c", "verification_tier": "tool_backed"},
            {"finding_id": "d", "verification_tier": "llm_only"},
            {"finding_id": "e"},  # untiered (prep-only) goes last
        ]
        ordered = [r["finding_id"] for r in sort_results_by_tier(results)]
        assert ordered == ["b", "c", "a", "d", "e"]

    def test_tier_counts(self):
        results = [
            {"verification_tier": "tool_backed"},
            {"verification_tier": "tool_backed"},
            {"verification_tier": "llm_only"},
            {},
        ]
        assert tier_counts(results) == {"tool_backed": 2, "llm_only": 1}

    def test_nothing_is_dropped_by_sorting(self):
        results = [{"verification_tier": t} for t in (
            "llm_only", "confirmed", "tool_backed",
        )] + [{}]
        assert len(sort_results_by_tier(results)) == len(results)


class TestToDictStamping:
    def _vuln(self, tmp_path):
        finding = {
            "finding_id": "f-1",
            "rule_id": "r",
            "file": "a.py",
            "startLine": 1,
            "endLine": 2,
        }
        return VulnerabilityContext(finding, Path(tmp_path))

    def test_stamped_when_analysis_present(self, tmp_path):
        vuln = self._vuln(tmp_path)
        vuln.analysis = {
            "is_true_positive": True,
            "smt_witness": {"model": {"n": 1}},
        }
        d = vuln.to_dict()
        assert d["verification_tier"] == "tool_backed"

    def test_not_stamped_in_prep_only(self, tmp_path):
        vuln = self._vuln(tmp_path)
        assert vuln.analysis is None
        assert "verification_tier" not in vuln.to_dict()

    def test_execution_outcome_reaches_tier(self, tmp_path):
        vuln = self._vuln(tmp_path)
        vuln.analysis = {"is_true_positive": True}
        vuln.exploit_code = "x"
        vuln.execute_outcome = "sanitizer_report"
        d = vuln.to_dict()
        assert d["verification_tier"] == "confirmed"


class TestMergedReportWiring:
    def test_merge_results_stamps_and_counts(self):
        from packages.llm_analysis.orchestrator import _merge_results

        prep = {
            "results": [
                {"finding_id": "f-1"},
                {"finding_id": "f-2"},
                {"finding_id": "f-3"},
            ],
        }
        cc = [
            {
                "finding_id": "f-1",
                "is_true_positive": True,
                "is_exploitable": True,
                "smt_witness": {"model": {"n": 4}},
            },
            {
                "finding_id": "f-2",
                "is_true_positive": True,
                "is_exploitable": False,
            },
        ]
        merged = _merge_results(prep, cc, no_exploits=True, no_patches=True)
        by_id = {r["finding_id"]: r for r in merged["results"]}
        assert by_id["f-1"]["verification_tier"] == "tool_backed"
        assert by_id["f-2"]["verification_tier"] == "llm_only"
        assert "verification_tier" not in by_id["f-3"]  # never dispatched
        assert merged["verification_tiers"] == {
            "tool_backed": 1, "llm_only": 1,
        }
        # tool_backed sorts ahead of llm_only; undispatched trails.
        order = [r["finding_id"] for r in merged["results"]]
        assert order == ["f-1", "f-2", "f-3"]
