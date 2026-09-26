"""Tier-aware Tier-1 exemption for cross-file taint candidates.

The IRIS Tier 1 gates refute on (language, CWE) whatever the
producer: a broad LocalFlowSource query finding no path is treated as
proof the flow does not exist. For cross-file taint findings whose
path rode sub-static hops (dispatch tables, assumed propagation,
binding guesses), CodeQL's source-language dataflow cannot represent
the edge — its silence is not refutation evidence. Such findings get
``no_check`` from the gate, counted, before any DB work; fully-static
taint paths and every other producer keep the exact pre-existing
gate behavior.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

# packages/llm_analysis/tests/... -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.dataflow_validation import (  # noqa: E402
    _TAINT_PRODUCER,
    _taint_sub_static_exemption,
    tier1_check_finding,
)


def _taint_finding(*, path_tier: str = "heuristic_dynamic",
                   shape: str = "scan", step_props: bool = False) -> dict:
    finding: dict = {
        "finding_id": "taint-crossfile-abc",
        "rule_id": "raptor.taint.crossfile.command-injection.python",
        "cwe_id": "CWE-78",
        "file": "app/exec_layer.py",
        "file_path": "app/exec_layer.py",
        "language": "python",
        "tool": _TAINT_PRODUCER,
    }
    if shape == "scan":
        finding["metadata"] = {"path_tier": path_tier}
    elif shape == "validation":
        finding["source_type"] = "taint"
        finding["taint_crossfile"] = {"path_tier": path_tier}
    if step_props:
        finding["dataflow_path"] = {
            "source": {"file": "app/views.py", "line": 7,
                       "properties": {"tier": "resolved_static"}},
            "steps": [{"file": "app/helpers.py", "line": 5,
                       "properties": {"tier": path_tier}}],
            "sink": {"file": "app/exec_layer.py", "line": 4,
                     "properties": {"tier": "resolved_static"}},
        }
    return finding


class TestExemptionHelper:
    def test_sub_static_scan_shape_exempt(self):
        assert _taint_sub_static_exemption(_taint_finding()) is True

    def test_sub_static_validation_shape_exempt(self):
        assert _taint_sub_static_exemption(
            _taint_finding(shape="validation")) is True

    def test_step_properties_alone_exempt(self):
        finding = _taint_finding(shape="none", step_props=True)
        assert "metadata" not in finding
        assert _taint_sub_static_exemption(finding) is True

    def test_approximation_tag_exempts(self):
        finding = _taint_finding(shape="none")
        finding["dataflow_path"] = {
            "source": {"properties": {"tier": "resolved_static",
                                      "tags": ["assumed_propagation"]}},
            "steps": [],
            "sink": {"properties": {"tier": "resolved_static"}},
        }
        assert _taint_sub_static_exemption(finding) is True

    def test_fully_static_taint_not_exempt(self):
        assert _taint_sub_static_exemption(
            _taint_finding(path_tier="resolved_static",
                           step_props=True)) is False

    def test_no_tier_evidence_not_exempt(self):
        # Positive evidence required: a taint finding recording no
        # tiers at all (shape drift) stays checkable.
        assert _taint_sub_static_exemption(
            _taint_finding(shape="none")) is False

    def test_non_taint_producer_never_exempt(self):
        finding = _taint_finding()
        finding["tool"] = "codeql"
        assert _taint_sub_static_exemption(finding) is False

    def test_junk_shapes_contained(self):
        assert _taint_sub_static_exemption({
            "tool": _TAINT_PRODUCER,
            "metadata": "junk",
            "taint_crossfile": 7,
            "dataflow_path": {"source": "junk", "steps": "junk",
                              "sink": {"properties": "junk"}},
        }) is False


class TestGateChokepoint:
    """tier1_check_finding is the one chokepoint both consumers
    (the analysis agent's pre-flight and /validate's Stage-B gate)
    route through."""

    def test_sub_static_taint_gets_no_check_without_db_work(
            self, tmp_path):
        # The exemption must fire before ANY discovery/DB access —
        # trip-wire the query discovery.
        with patch(
            "packages.llm_analysis.dataflow_validation."
            "discover_prebuilt_query",
            side_effect=AssertionError("gate reached discovery"),
        ):
            verdict = tier1_check_finding(
                _taint_finding(), {"python": tmp_path},
            )
        assert verdict == "no_check"

    def test_static_taint_path_proceeds_to_normal_gate(self, tmp_path):
        # Two-direction: a fully resolved_static taint path stays
        # refutable — the check reaches query discovery.
        calls = []
        with patch(
            "packages.llm_analysis.dataflow_validation."
            "discover_prebuilt_query",
            side_effect=lambda *a: calls.append(a) or None,
        ):
            verdict = tier1_check_finding(
                _taint_finding(path_tier="resolved_static"),
                {"python": tmp_path},
            )
        assert calls, "static taint path must reach the normal gate"
        assert verdict == "no_check"  # no prebuilt query in this stub

    def test_non_taint_finding_unchanged(self, tmp_path):
        # Differential: an identical-shaped finding from another
        # producer takes the pre-existing path.
        finding = _taint_finding()
        finding["tool"] = "semgrep"
        del finding["metadata"]
        finding["dataflow_path"] = {
            "source": {"properties": {"tier": "heuristic_dynamic"}},
            "steps": [], "sink": {},
        }
        calls = []
        with patch(
            "packages.llm_analysis.dataflow_validation."
            "discover_prebuilt_query",
            side_effect=lambda *a: calls.append(a) or None,
        ):
            verdict = tier1_check_finding(finding, {"python": tmp_path})
        assert calls, "non-taint findings must reach the normal gate"
        assert verdict == "no_check"


class TestValidateStageBGate:
    """The /validate Stage-B gate consumes the chokepoint verdict: an
    exempted taint finding stays not_disproven (counted as no_check),
    never flipped to disproven."""

    def _make_runner(self, tmp_path):
        from packages.exploitability_validation.orchestrator import (
            PipelineConfig,
            PipelineState,
            ValidationOrchestrator,
        )
        workdir = tmp_path / "validate"
        workdir.mkdir()
        target = tmp_path / "src"
        target.mkdir()
        cfg = PipelineConfig(target_path=str(target),
                             workdir=str(workdir))
        state = PipelineState(config=cfg)
        runner = ValidationOrchestrator.__new__(ValidationOrchestrator)
        runner.config = cfg
        runner.state = state
        return runner

    def test_exempted_taint_finding_survives_gate(self, tmp_path):
        runner = self._make_runner(tmp_path)
        finding = _taint_finding(shape="validation")
        finding.update({"id": "T1", "status": "not_disproven"})
        runner.state.findings = {"findings": [finding]}
        runner.state.save_json("findings.json", runner.state.findings)
        calls = []
        with patch(
            "packages.llm_analysis.dataflow_validation."
            "discover_codeql_databases",
            return_value={"python": tmp_path / "fake-db"},
        ), patch(
            "packages.llm_analysis.dataflow_validation."
            "discover_prebuilt_query",
            side_effect=lambda *a: calls.append(a) or None,
        ):
            runner._iris_tier1_gate()
        # A raised trip-wire would be swallowed by the gate's
        # per-finding containment, so observe the discovery calls
        # instead: the exemption returns before any query work.
        assert not calls
        assert finding["status"] == "not_disproven"
        assert not (tmp_path / "validate" / "disproven.json").exists()


class TestVocabularyPin:
    def test_producer_constant_matches_emission(self):
        from core.taint.emission import PRODUCER
        assert _TAINT_PRODUCER == PRODUCER
