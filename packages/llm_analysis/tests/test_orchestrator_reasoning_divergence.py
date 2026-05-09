"""Integration tests for the reasoning-divergence wiring inside
``packages.llm_analysis.orchestrator``.

Two layers of test:

1. **Helper unit tests** — exercise
   ``orchestrator._attach_reasoning_divergence`` against the same
   data shapes the orchestrator builds at the multi-model
   correlation hook site (``_multi_results`` dict-of-lists,
   ``correlation.confidence_signals`` map). Catches breakage in:
   panel-size gates, signal-type gates, field shape, in-place
   mutation contract.

2. **Wiring sentinel** — asserts ``_attach_reasoning_divergence`` is
   actually invoked from ``orchestrate()`` and that the report
   serialiser still surfaces the field. Without this, a refactor
   that drops the helper call leaves all helper unit tests passing
   while shipping a silently-broken orchestrator.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

# packages/llm_analysis/tests/... → repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.llm_analysis import orchestrator
from packages.llm_analysis.orchestrator import _attach_reasoning_divergence


# Reusing the same fixtures as the math + producer tests so any
# divergence on this surface fails with cross-referenceable diffs.
_AGREED_PANEL = {
    "model-a": (
        "User input flows from request.GET['q'] into cgi_query() "
        "without sanitisation. The sink at cgi.c:142 concatenates "
        "the query string directly into the SQL statement. Classic "
        "SQL injection with attacker-controlled input."
    ),
    "model-b": (
        "Tainted data from request.GET reaches cgi_query in cgi.c "
        "line 142. String concatenation builds the SQL with no "
        "parameterisation, so the attacker controls the query."
    ),
    "model-c": (
        "Source: request.GET['q']. Sink: cgi_query at cgi.c:142. "
        "The function builds SQL by string concatenation, exposing "
        "an injection vector to any untrusted query parameter."
    ),
}

_DIVERGENT_PANEL = {
    "model-a": (
        "SQL injection at cgi_query in cgi.c:142. Request.GET['q'] "
        "reaches the sink unsanitised, attacker controls the SQL."
    ),
    "model-b": (
        "Path traversal in upload_file at upload.c:88. The filename "
        "from multipart form data is joined with the storage path "
        "without normalisation, so '../../etc/passwd' escapes."
    ),
    "model-c": (
        "Insecure deserialisation in api_handler at api.py:31. The "
        "pickle.loads call on the request body trusts arbitrary "
        "attacker-supplied serialised objects."
    ),
}


def _multi_records(reasonings: dict) -> list:
    return [{"analysed_by": m, "reasoning": r}
            for m, r in reasonings.items()]


def _make_orchestrator_inputs(*, signals: dict, panels: dict):
    """Build (results_by_id, multi_results) the way orchestrate()
    builds them at the multi-model correlation hook site.

    ``panels`` keys are finding_ids; values are
    ``{model: reasoning}`` dicts. Each finding gets a synthetic
    rule_id so cells land on distinct decision_classes when the
    producer fires.
    """
    results_by_id = {}
    multi_results = {}
    for fid, panel in panels.items():
        results_by_id[fid] = {
            "finding_id": fid,
            "rule_id": f"py/{fid}-rule",
            "is_exploitable": True,
            "analysed_by": next(iter(panel)),
        }
        multi_results[fid] = _multi_records(panel)
    return results_by_id, multi_results


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


class TestAttachReasoningDivergence:
    def test_attaches_field_for_agreed_panel(self):
        results_by_id, multi_results = _make_orchestrator_inputs(
            signals={"f1": "high"},
            panels={"f1": _AGREED_PANEL},
        )
        _attach_reasoning_divergence(
            results_by_id=results_by_id,
            multi_results=multi_results,
            confidence_signals={"f1": "high"},
        )
        assert "reasoning_divergence" in results_by_id["f1"]
        div = results_by_id["f1"]["reasoning_divergence"]
        assert set(div) == {
            "mean_pairwise_distance",
            "max_pairwise_distance",
            "outlier_model",
            "n_models",
        }
        assert div["n_models"] == 3
        assert 0.0 <= div["mean_pairwise_distance"] <= 1.0

    def test_divergent_higher_than_agreed(self):
        results_by_id, multi_results = _make_orchestrator_inputs(
            signals={"agreed": "high", "div": "high"},
            panels={"agreed": _AGREED_PANEL, "div": _DIVERGENT_PANEL},
        )
        _attach_reasoning_divergence(
            results_by_id=results_by_id,
            multi_results=multi_results,
            confidence_signals={"agreed": "high", "div": "high"},
        )
        agreed_d = results_by_id["agreed"]["reasoning_divergence"]
        div_d = results_by_id["div"]["reasoning_divergence"]
        # Same gap pinned in test_semantic_entropy.py: divergent
        # panel sits visibly farther apart than aligned. Documents
        # that the orchestrator helper preserves the math contract.
        assert (div_d["mean_pairwise_distance"]
                > agreed_d["mean_pairwise_distance"] + 0.10)

    def test_disputed_findings_skipped(self):
        results_by_id, multi_results = _make_orchestrator_inputs(
            signals={"f1": "disputed"},
            panels={"f1": _DIVERGENT_PANEL},
        )
        _attach_reasoning_divergence(
            results_by_id=results_by_id,
            multi_results=multi_results,
            confidence_signals={"f1": "disputed"},
        )
        assert "reasoning_divergence" not in results_by_id["f1"]

    def test_high_negative_findings_attached(self):
        # ``high-negative`` (everyone agreed NOT exploitable) is
        # equally an agreed-verdict case and gets the field.
        results_by_id, multi_results = _make_orchestrator_inputs(
            signals={"f1": "high-negative"},
            panels={"f1": _AGREED_PANEL},
        )
        _attach_reasoning_divergence(
            results_by_id=results_by_id,
            multi_results=multi_results,
            confidence_signals={"f1": "high-negative"},
        )
        assert "reasoning_divergence" in results_by_id["f1"]

    def test_two_model_panel_returns_none(self):
        # Math layer requires N>=3. Helper must not attach a field
        # when the metric is unmeasurable.
        two = {k: v for k, v in list(_AGREED_PANEL.items())[:2]}
        results_by_id, multi_results = _make_orchestrator_inputs(
            signals={"f1": "high"},
            panels={"f1": two},
        )
        _attach_reasoning_divergence(
            results_by_id=results_by_id,
            multi_results=multi_results,
            confidence_signals={"f1": "high"},
        )
        assert "reasoning_divergence" not in results_by_id["f1"]

    def test_no_op_on_empty_multi_results(self):
        results_by_id = {"f1": {"rule_id": "r"}}
        _attach_reasoning_divergence(
            results_by_id=results_by_id,
            multi_results={},
            confidence_signals={"f1": "high"},
        )
        assert "reasoning_divergence" not in results_by_id["f1"]

    def test_no_op_on_none_multi_results(self):
        results_by_id = {"f1": {"rule_id": "r"}}
        _attach_reasoning_divergence(
            results_by_id=results_by_id,
            multi_results=None,
            confidence_signals={"f1": "high"},
        )
        assert "reasoning_divergence" not in results_by_id["f1"]

    def test_does_not_create_keys_for_missing_findings(self):
        # If confidence_signals references a finding that isn't in
        # results_by_id (corrupt input), the helper must skip it
        # rather than auto-create a stub record.
        results_by_id = {}
        multi_results = {"orphan": _multi_records(_DIVERGENT_PANEL)}
        _attach_reasoning_divergence(
            results_by_id=results_by_id,
            multi_results=multi_results,
            confidence_signals={"orphan": "high"},
        )
        assert results_by_id == {}


# ---------------------------------------------------------------------------
# Wiring sentinel — orchestrate() actually calls the helper
# ---------------------------------------------------------------------------


class TestWiringSentinel:
    """Source-level wiring assertions. Catches refactors that drop
    the helper call from orchestrate() — without these, the helper
    unit tests above all pass while the orchestrator silently
    skips divergence attachment."""

    def test_orchestrate_calls_helper(self):
        # Inspect orchestrate()'s source for a literal call to the
        # helper. Cheap, source-level check; no LLM mocking needed.
        src = inspect.getsource(orchestrator.orchestrate)
        assert "_attach_reasoning_divergence(" in src, (
            "orchestrate() no longer references "
            "_attach_reasoning_divergence — wiring lost"
        )

    def test_orchestrate_records_divergence_events(self):
        src = inspect.getsource(orchestrator.orchestrate)
        assert "record_reasoning_divergence" in src, (
            "orchestrate() no longer references "
            "record_reasoning_divergence — scorecard producer lost"
        )

    def test_aggregation_payload_surfaces_field(self):
        # The serialiser at line ~1267 lifts the field onto
        # ``findings[].reasoning_divergence`` in the orchestrated
        # report — without this, the metric is computed but never
        # reaches the operator's report.
        src = inspect.getsource(orchestrator._build_aggregation_payload)
        assert '"reasoning_divergence"' in src, (
            "_build_aggregation_payload no longer surfaces "
            "reasoning_divergence — operator report lost the field"
        )


# ---------------------------------------------------------------------------
# Behavioural integration — _build_aggregation_payload actually flows
# the field through with realistic input shapes
# ---------------------------------------------------------------------------


class TestAggregationPayloadFlow:
    """Behavioural test for the aggregation serialiser.

    Complements the source-level sentinel above: that one catches
    "someone deleted the field literal"; this one catches "field
    literal is there but doesn't actually flow because of a
    surrounding bug" (e.g. the dict shape changed, key got typo'd
    on read, etc.). Together they cover both ways the wiring can
    silently break.
    """

    def test_field_flows_when_present_on_result(self):
        results_by_id = {
            "f1": {
                "finding_id": "f1",
                "rule_id": "py/sqli",
                "file_path": "app.py",
                "start_line": 42,
                "is_exploitable": True,
                "analysed_by": "model-a",
                "reasoning": "...",
                "reasoning_divergence": {
                    "mean_pairwise_distance": 0.91,
                    "max_pairwise_distance": 0.95,
                    "outlier_model": "model-c",
                    "n_models": 3,
                },
            },
        }
        payload = orchestrator._build_aggregation_payload(
            results_by_id, correlation=None,
        )
        findings = payload["findings"]
        assert len(findings) == 1
        # Field is preserved as the same dict, not coerced or
        # truncated, so downstream consumers (LLM aggregator + any
        # operator dashboard) see the full metric.
        assert findings[0]["reasoning_divergence"] == {
            "mean_pairwise_distance": 0.91,
            "max_pairwise_distance": 0.95,
            "outlier_model": "model-c",
            "n_models": 3,
        }

    def test_field_is_none_when_absent_on_result(self):
        # Findings without the field (single-model analysis, panel
        # too small, reasoning too short) get ``None`` — not
        # missing-key, not silently dropped. Operators reading the
        # JSON can distinguish "no signal" from "field absent due
        # to schema bug".
        results_by_id = {
            "f1": {
                "finding_id": "f1",
                "rule_id": "py/sqli",
                "is_exploitable": True,
                "analysed_by": "model-a",
                "reasoning": "...",
            },
        }
        payload = orchestrator._build_aggregation_payload(
            results_by_id, correlation=None,
        )
        findings = payload["findings"]
        assert len(findings) == 1
        assert findings[0]["reasoning_divergence"] is None
        # Sister field stays consistent in the same case.
        assert findings[0]["multi_model_confidence"] is None

    def test_aggregator_prompt_threshold_matches_producer(self):
        # The aggregator's system prompt embeds the threshold value
        # (0.80 in v1). Pin that the prompt text actually reflects
        # the producer's current default — catches drift if either
        # is updated without the other.
        from packages.llm_analysis.tasks import AggregationTask
        from core.llm.scorecard.reasoning_divergence import (
            DEFAULT_DIVERGENCE_THRESHOLD,
        )
        threshold_str = f"{DEFAULT_DIVERGENCE_THRESHOLD:.2f}"
        assert threshold_str in AggregationTask._SYSTEM_TEXT, (
            f"prompt threshold drifted from "
            f"DEFAULT_DIVERGENCE_THRESHOLD={threshold_str} — "
            "either re-import the constant in tasks.py or update "
            "the formatting"
        )
