"""Tests for IRIS scorecard bridge."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.iris.scorecard_bridge import (
    DECISION_CLASS,
    SpecOutcome,
    cwe_quality_summary,
    record_refinement_outcomes,
)
from core.iris.specs import TaintSpec
from core.iris.store import _spec_key


def _make_specs():
    return [
        TaintSpec(function="exec_query", file="db.py", role="sink",
                  taint_classes=["sql"]),
        TaintSpec(function="sanitise_html", file="util.py", role="sanitiser",
                  taint_classes=["xss"]),
        TaintSpec(function="read_input", file="io.py", role="source",
                  taint_classes=["command"]),
    ]


def _key(spec):
    return _spec_key(spec)


class TestRecordRefinementOutcomes:
    def test_records_confirmed_as_correct(self):
        sc = MagicMock()
        specs = _make_specs()
        outcomes = record_refinement_outcomes(
            sc, specs,
            confirmed_keys=[_key(_make_specs()[0])],
            refuted_keys=[],
            model="test-model",
        )
        assert len(outcomes) == 1
        assert outcomes[0].confirmed is True
        sc.record_event.assert_called_once_with(
            DECISION_CLASS, "test-model", "tool_evidence", "correct",
            model_version=None, sample=None,
        )

    def test_records_refuted_as_incorrect(self):
        sc = MagicMock()
        specs = _make_specs()
        outcomes = record_refinement_outcomes(
            sc, specs,
            confirmed_keys=[],
            refuted_keys=[_key(_make_specs()[1])],
            model="test-model",
        )
        assert len(outcomes) == 1
        assert outcomes[0].confirmed is False
        sc.record_event.assert_called_once()
        args = sc.record_event.call_args
        assert args[0][3] == "incorrect"
        assert args[1]["sample"]["function"] == "sanitise_html"

    def test_mixed_outcomes(self):
        sc = MagicMock()
        specs = _make_specs()
        outcomes = record_refinement_outcomes(
            sc, specs,
            confirmed_keys=[_key(_make_specs()[0]), _key(_make_specs()[2])],
            refuted_keys=[_key(_make_specs()[1])],
            model="m1",
        )
        assert len(outcomes) == 3
        assert sc.record_event.call_count == 3

    def test_no_scorecard_returns_empty(self):
        specs = _make_specs()
        outcomes = record_refinement_outcomes(
            None, specs,
            confirmed_keys=[_key(_make_specs()[0])],
            refuted_keys=[],
            model="m1",
        )
        assert outcomes == []

    def test_untested_specs_skipped(self):
        sc = MagicMock()
        specs = _make_specs()
        outcomes = record_refinement_outcomes(
            sc, specs,
            confirmed_keys=[],
            refuted_keys=[],
            model="m1",
        )
        assert outcomes == []
        sc.record_event.assert_not_called()

    def test_scorecard_error_swallowed(self):
        sc = MagicMock()
        sc.record_event.side_effect = RuntimeError("disk full")
        specs = _make_specs()
        outcomes = record_refinement_outcomes(
            sc, specs,
            confirmed_keys=[_key(_make_specs()[0])],
            refuted_keys=[],
            model="m1",
        )
        assert len(outcomes) == 1

    def test_model_version_forwarded(self):
        sc = MagicMock()
        specs = _make_specs()
        record_refinement_outcomes(
            sc, specs,
            confirmed_keys=[_key(_make_specs()[0])],
            refuted_keys=[],
            model="m1",
            model_version="v2.1",
        )
        assert sc.record_event.call_args[1]["model_version"] == "v2.1"

    def test_round_num_in_sample(self):
        sc = MagicMock()
        specs = _make_specs()
        record_refinement_outcomes(
            sc, specs,
            confirmed_keys=[],
            refuted_keys=[_key(_make_specs()[0])],
            model="m1",
            round_num=2,
        )
        sample = sc.record_event.call_args[1]["sample"]
        assert sample["round"] == "2"


class TestCweQualitySummary:
    def test_maps_taint_classes_to_cwes(self):
        outcomes = [
            SpecOutcome(function="f", file="a.py", role="sink",
                        model="m", round=0, confirmed=True,
                        taint_classes=["sql"]),
            SpecOutcome(function="g", file="b.py", role="sink",
                        model="m", round=0, confirmed=False,
                        taint_classes=["sql"]),
            SpecOutcome(function="h", file="c.py", role="sink",
                        model="m", round=0, confirmed=True,
                        taint_classes=["xss"]),
        ]
        summary = cwe_quality_summary(outcomes)
        assert "CWE-89" in summary
        assert summary["CWE-89"]["n_specs"] == 2
        assert summary["CWE-89"]["tp_rate"] == 0.5
        assert summary["CWE-89"]["coverage"] == "gap"
        assert "CWE-79" in summary
        assert summary["CWE-79"]["tp_rate"] == 1.0
        assert summary["CWE-79"]["coverage"] == "good"

    def test_unknown_taint_class(self):
        outcomes = [
            SpecOutcome(function="f", file="a.py", role="sink",
                        model="m", round=0, confirmed=True,
                        taint_classes=["custom_thing"]),
        ]
        summary = cwe_quality_summary(outcomes)
        assert "unknown" in summary
        assert summary["unknown"]["n_specs"] == 1

    def test_empty_outcomes(self):
        assert cwe_quality_summary([]) == {}

    def test_multi_class_spec(self):
        outcomes = [
            SpecOutcome(function="f", file="a.py", role="sink",
                        model="m", round=0, confirmed=True,
                        taint_classes=["sql", "command"]),
        ]
        summary = cwe_quality_summary(outcomes)
        assert "CWE-89" in summary
        assert "CWE-78" in summary


class TestSpecOutcomeDataclass:
    def test_fields(self):
        o = SpecOutcome(
            function="f", file="a.py", role="sink",
            model="m", round=0, confirmed=True,
            taint_classes=["sql"], finding_count=3,
        )
        assert o.function == "f"
        assert o.confirmed is True
        assert o.finding_count == 3

    def test_defaults(self):
        o = SpecOutcome(
            function="f", file="a.py", role="sink",
            model="m", round=0, confirmed=None,
        )
        assert o.taint_classes == []
        assert o.finding_count == 0
