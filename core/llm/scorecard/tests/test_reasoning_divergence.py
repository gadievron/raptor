"""Tests for ``core.llm.scorecard.reasoning_divergence``.

Pins the producer's contract:
  * Agreed findings (``high`` / ``high-negative``) with dispersion
    above threshold → outlier ``incorrect``, others ``correct``.
  * Agreed findings with dispersion below threshold → no events.
  * Disputed findings → no events (consensus producer's domain).
  * Findings with too-short / missing reasoning → no events.
  * Decision class shape: ``agentic:<rule_id>``.
  * No-op on ``scorecard=None``, empty correlation, missing
    ``per_finding_results``.
  * Other event-type counters untouched (this producer feeds its own
    slot).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.llm.scorecard.reasoning_divergence import (
    DEFAULT_DIVERGENCE_THRESHOLD,
    record_reasoning_divergence,
)
from core.llm.scorecard.scorecard import EventType, ModelScorecard


# Reasonings reused from the math tests so failures cross-reference
# the same fixtures. Keep these in lock-step with
# ``core/llm/tests/test_semantic_entropy.py``.

_AGREED_SQL = {
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
        "reaches the sink unsanitised, attacker controls the SQL "
        "via the query parameter and can read arbitrary tables."
    ),
    "model-b": (
        "Path traversal in upload_file at upload.c:88. The filename "
        "from multipart form data is joined with the storage path "
        "without normalisation, so '../../etc/passwd' escapes the "
        "upload directory."
    ),
    "model-c": (
        "Insecure deserialisation in api_handler at api.py:31. The "
        "pickle.loads call on the request body trusts arbitrary "
        "attacker-supplied serialised objects, leading to remote "
        "code execution."
    ),
}


@pytest.fixture
def scorecard(tmp_path: Path) -> ModelScorecard:
    return ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)


def _records(reasonings: dict[str, str]) -> list[dict]:
    return [
        {"analysed_by": m, "reasoning": r}
        for m, r in reasonings.items()
    ]


def _correlation(*, signals: dict[str, str]) -> dict:
    # Producer ignores the agreement matrix shape — only confidence
    # signals are read — but a realistic dict keeps tests readable.
    return {
        "agreement_matrix": {
            fid: {m: {"is_exploitable": True} for m in _AGREED_SQL}
            for fid in signals
        },
        "confidence_signals": signals,
    }


def _stat(sc: ModelScorecard, dc: str, model: str, ev: str):
    s = sc.get_stat(dc, model)
    if s is None:
        return (0, 0)
    return s.events[ev].correct, s.events[ev].incorrect


# ---------------------------------------------------------------------------
# No-op paths
# ---------------------------------------------------------------------------


class TestNoOp:
    def test_none_scorecard(self):
        n = record_reasoning_divergence(
            None,
            correlation=_correlation(signals={"f1": "high"}),
            results_by_id={"f1": {"rule_id": "r"}},
            per_finding_results={"f1": _records(_DIVERGENT_PANEL)},
        )
        assert n == 0

    def test_empty_correlation(self, scorecard):
        n = record_reasoning_divergence(
            scorecard, correlation={}, results_by_id={},
            per_finding_results={},
        )
        assert n == 0

    def test_no_per_finding_results(self, scorecard):
        # Without per-model reasoning text we cannot measure
        # divergence — must return 0 (not crash, not record).
        n = record_reasoning_divergence(
            scorecard,
            correlation=_correlation(signals={"f1": "high"}),
            results_by_id={"f1": {"rule_id": "r"}},
            per_finding_results=None,
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Confidence-signal gating
# ---------------------------------------------------------------------------


class TestSignalGating:
    def test_disputed_findings_skipped(self, scorecard):
        # Disputed findings are the consensus producer's domain.
        n = record_reasoning_divergence(
            scorecard,
            correlation=_correlation(signals={"f1": "disputed"}),
            results_by_id={"f1": {"rule_id": "r"}},
            per_finding_results={"f1": _records(_DIVERGENT_PANEL)},
        )
        assert n == 0

    def test_agreed_with_high_dispersion_fires(self, scorecard):
        n = record_reasoning_divergence(
            scorecard,
            correlation=_correlation(signals={"f1": "high"}),
            results_by_id={"f1": {"rule_id": "py/sqli"}},
            per_finding_results={"f1": _records(_DIVERGENT_PANEL)},
        )
        # 3 models on the panel → 3 events.
        assert n == 3

    def test_agreed_negative_with_high_dispersion_fires(self, scorecard):
        # ``high-negative`` (everyone agreed NOT exploitable) is
        # equally an agreed-verdict case and should be measured.
        n = record_reasoning_divergence(
            scorecard,
            correlation=_correlation(signals={"f1": "high-negative"}),
            results_by_id={"f1": {"rule_id": "py/sqli"}},
            per_finding_results={"f1": _records(_DIVERGENT_PANEL)},
        )
        assert n == 3

    def test_agreed_with_tight_panel_skipped(self, scorecard):
        # Aligned panel sits ~0.67 — below the 0.80 default.
        n = record_reasoning_divergence(
            scorecard,
            correlation=_correlation(signals={"f1": "high"}),
            results_by_id={"f1": {"rule_id": "py/sqli"}},
            per_finding_results={"f1": _records(_AGREED_SQL)},
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Outcome attribution: outlier → incorrect, others → correct
# ---------------------------------------------------------------------------


class TestOutcomeAttribution:
    def test_outlier_incorrect_others_correct(self, scorecard):
        record_reasoning_divergence(
            scorecard,
            correlation=_correlation(signals={"f1": "high"}),
            results_by_id={"f1": {"rule_id": "py/sqli"}},
            per_finding_results={"f1": _records(_DIVERGENT_PANEL)},
        )
        dc = "agentic:py/sqli"
        # Mostly-aligned: pull the outlier from the metric directly to
        # avoid hard-coding which model wins — the math test pins
        # determinism, here we just check the shape.
        outlier_count_incorrect = 0
        non_outlier_count_correct = 0
        for m in _DIVERGENT_PANEL:
            correct, incorrect = _stat(
                scorecard, dc, m, EventType.REASONING_DIVERGENCE)
            if incorrect == 1 and correct == 0:
                outlier_count_incorrect += 1
            elif incorrect == 0 and correct == 1:
                non_outlier_count_correct += 1
        assert outlier_count_incorrect == 1
        assert non_outlier_count_correct == 2

    def test_other_event_types_untouched(self, scorecard):
        record_reasoning_divergence(
            scorecard,
            correlation=_correlation(signals={"f1": "high"}),
            results_by_id={"f1": {"rule_id": "py/sqli"}},
            per_finding_results={"f1": _records(_DIVERGENT_PANEL)},
        )
        dc = "agentic:py/sqli"
        for m in _DIVERGENT_PANEL:
            for ev in (EventType.CHEAP_SHORT_CIRCUIT,
                       EventType.MULTI_MODEL_CONSENSUS,
                       EventType.JUDGE_REVIEW,
                       EventType.TOOL_EVIDENCE,
                       EventType.OPERATOR_FEEDBACK):
                assert _stat(scorecard, dc, m, ev) == (0, 0)


# ---------------------------------------------------------------------------
# Reasoning-text floors: unmeasurable panels skipped
# ---------------------------------------------------------------------------


class TestReasoningTextFloors:
    def test_short_reasoning_skipped(self, scorecard):
        n = record_reasoning_divergence(
            scorecard,
            correlation=_correlation(signals={"f1": "high"}),
            results_by_id={"f1": {"rule_id": "r"}},
            per_finding_results={"f1": [
                {"analysed_by": "m1", "reasoning": "ok"},
                {"analysed_by": "m2", "reasoning": "fine"},
                {"analysed_by": "m3", "reasoning": "yep"},
            ]},
        )
        assert n == 0

    def test_missing_reasoning_skipped(self, scorecard):
        n = record_reasoning_divergence(
            scorecard,
            correlation=_correlation(signals={"f1": "high"}),
            results_by_id={"f1": {"rule_id": "r"}},
            per_finding_results={"f1": [
                {"analysed_by": "m1"},
                {"analysed_by": "m2"},
                {"analysed_by": "m3"},
            ]},
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Threshold tunability
# ---------------------------------------------------------------------------


class TestThresholdTunability:
    def test_lower_threshold_fires_on_aligned_panel(self, scorecard):
        # With threshold 0.5 the aligned panel (~0.67) trips.
        n = record_reasoning_divergence(
            scorecard,
            correlation=_correlation(signals={"f1": "high"}),
            results_by_id={"f1": {"rule_id": "r"}},
            per_finding_results={"f1": _records(_AGREED_SQL)},
            divergence_threshold=0.5,
        )
        assert n == 3

    def test_higher_threshold_suppresses_divergent_panel(self, scorecard):
        # With threshold 0.99 even the divergent panel (~0.91) skips.
        n = record_reasoning_divergence(
            scorecard,
            correlation=_correlation(signals={"f1": "high"}),
            results_by_id={"f1": {"rule_id": "r"}},
            per_finding_results={"f1": _records(_DIVERGENT_PANEL)},
            divergence_threshold=0.99,
        )
        assert n == 0

    def test_default_threshold_constant(self):
        # Pin the default so changes are conscious.
        assert DEFAULT_DIVERGENCE_THRESHOLD == 0.80
