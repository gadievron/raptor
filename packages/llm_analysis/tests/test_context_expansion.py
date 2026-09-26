"""Context-expansion policy: trigger predicate, join rule, record
shape, derived limits, and the +1-hop block builders.

The trigger cases below are the classifier's REAL verdict shapes —
the ``ANALYSIS_SCHEMA`` dict the LLM path stores (``is_true_positive``
/ ``is_exploitable`` bools nulled-on-abstention by response
validation, ``confidence`` from the high/medium/low enum) and the
synthesised records the mechanical chokepoints stamp. Both directions
are pinned everywhere: what triggers, and what must never trigger;
what replaces, and what must never replace.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.llm.context_window import FINDING_CONTEXT_LINES  # noqa: E402
from packages.llm_analysis.context_expansion import (  # noqa: E402
    EXPANDED_FINDING_CONTEXT_LINES,
    EXPANSION_WINDOW_MULTIPLIER,
    MAX_EXPANSIONS_PER_RUN,
    build_expansion_record,
    expansion_context_blocks,
    expansion_trigger,
    join_verdicts,
    verdict_summary,
)


def _analysis(
    tp: Any = True,
    ex: Any = False,
    confidence: Any = "high",
    **extra: Any,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "is_true_positive": tp,
        "is_exploitable": ex,
        "exploitability_score": 0.4,
        "reasoning": "because",
        "confidence": confidence,
    }
    out.update(extra)
    return out


class TestDerivedLimits:
    def test_expanded_window_is_derived_not_a_literal(self):
        assert EXPANDED_FINDING_CONTEXT_LINES == (
            EXPANSION_WINDOW_MULTIPLIER * FINDING_CONTEXT_LINES
        )

    def test_shipped_defaults_pinned(self):
        # Changing either is a behaviour/spend change, not a refactor.
        assert EXPANSION_WINDOW_MULTIPLIER == 2
        assert MAX_EXPANSIONS_PER_RUN == 10


class TestTriggerNeverFires:
    """The never-expand direction — confident calls stay single-pass."""

    @pytest.mark.parametrize("confidence", ["high", "medium"])
    @pytest.mark.parametrize("tp,ex", [
        (True, True),    # confident exploitable TP
        (True, False),   # confident non-exploitable TP
        (False, False),  # confident FP
    ])
    def test_confident_verdicts(self, tp, ex, confidence):
        assert expansion_trigger(_analysis(tp, ex, confidence)) is None

    def test_missing_confidence_with_verdict(self):
        a = _analysis(True, True)
        del a["confidence"]
        assert expansion_trigger(a) is None

    @pytest.mark.parametrize(
        "confidence", ["uncertain", "unknown", "LOWISH", "", 0.2, None],
    )
    def test_off_enum_confidence_is_not_an_explicit_signal(self, confidence):
        assert expansion_trigger(_analysis(True, True, confidence)) is None

    def test_partial_verdict_with_stated_confidence(self):
        # One genuine field + medium confidence: not a full abstention,
        # not explicit low — no trigger.
        a = _analysis(True, None, "medium")
        assert expansion_trigger(a) is None

    @pytest.mark.parametrize("marker", [
        "fixture_demotion",
        "reachability_suppression",
        "sage_fp_suppression",
        "guard_dominance_refutation",
        "fail_open_refutation",
    ])
    def test_mechanical_records_never_trigger(self, marker):
        # Synthesised chokepoint records — even a hostile shape that
        # ALSO claims low confidence stays refused.
        a = _analysis(False, False, "low", **{marker: True})
        assert expansion_trigger(a) is None

    @pytest.mark.parametrize("analysis", [None, [], "text", 7])
    def test_non_dict_shapes(self, analysis):
        assert expansion_trigger(analysis) is None


class TestTriggerFires:
    def test_low_confidence_verdict(self):
        assert (
            expansion_trigger(_analysis(True, True, "low"))
            == "low_confidence"
        )

    def test_low_confidence_is_normalised(self):
        assert (
            expansion_trigger(_analysis(True, False, "  LOW "))
            == "low_confidence"
        )

    def test_full_abstention_missing_keys(self):
        assert (
            expansion_trigger({"reasoning": "??", "confidence": "high"})
            == "verdict_abstained"
        )

    def test_full_abstention_explicit_nulls(self):
        a = _analysis(None, None, "medium")
        assert expansion_trigger(a) == "verdict_abstained"

    def test_full_abstention_junk_shapes(self):
        # Non-bool verdict fields read as abstentions (read_verdict
        # tri-state contract).
        a = _analysis("yes", 1, "medium")
        assert expansion_trigger(a) == "verdict_abstained"

    def test_abstention_reported_over_low_confidence(self):
        a = _analysis(None, None, "low")
        assert expansion_trigger(a) == "verdict_abstained"


class TestJoinReplaces:
    def test_more_confident_second_replaces_low_first(self):
        first = _analysis(True, True, "low")
        second = _analysis(False, False, "high")
        chosen, replaced = join_verdicts(first, second)
        assert replaced is True
        assert chosen is second

    def test_medium_second_outranks_low_first(self):
        chosen, replaced = join_verdicts(
            _analysis(True, False, "low"), _analysis(True, True, "medium"),
        )
        assert replaced is True

    def test_any_full_verdict_replaces_abstained_first(self):
        first = {"reasoning": "??", "confidence": "high"}
        second = _analysis(True, True, "low")
        chosen, replaced = join_verdicts(first, second)
        assert replaced is True
        assert chosen is second

    def test_unstated_confidence_full_verdict_replaces_abstention(self):
        first = _analysis(None, None, "medium")
        second = _analysis(False, False, None)
        _, replaced = join_verdicts(first, second)
        assert replaced is True


class TestJoinNeverReplaces:
    def test_equally_low_second_keeps_first(self):
        first = _analysis(True, True, "low")
        chosen, replaced = join_verdicts(first, _analysis(False, False, "low"))
        assert replaced is False
        assert chosen is first

    def test_unranked_second_never_outranks_stated_low(self):
        first = _analysis(True, True, "low")
        second = _analysis(False, False, None)
        _, replaced = join_verdicts(first, second)
        assert replaced is False

    def test_second_abstention_never_replaces(self):
        first = _analysis(True, True, "low")
        second = _analysis(None, None, "high")
        chosen, replaced = join_verdicts(first, second)
        assert replaced is False
        assert chosen is first

    def test_partial_second_verdict_never_replaces(self):
        first = _analysis(True, True, "low")
        second = _analysis(True, None, "high")
        _, replaced = join_verdicts(first, second)
        assert replaced is False

    @pytest.mark.parametrize("confidence", ["high", "medium"])
    def test_confident_first_is_never_demoted(self, confidence):
        # Defensive re-check: a first verdict that would not have
        # triggered is never replaced, whatever a caller passes.
        first = _analysis(True, True, confidence)
        second = _analysis(False, False, "high")
        chosen, replaced = join_verdicts(first, second)
        assert replaced is False
        assert chosen is first


class TestRecordShape:
    def test_record_carries_both_verdicts_and_join_outcome(self):
        first = _analysis(None, None, "low")
        second = _analysis(True, True, "high", ruling="validated")
        record = build_expansion_record(
            reason="verdict_abstained",
            first=first,
            second=second,
            replaced=True,
            window_lines=EXPANDED_FINDING_CONTEXT_LINES,
            caller_context_attached=True,
            callee_context_attached=False,
        )
        assert record["triggered"] is True
        assert record["reason"] == "verdict_abstained"
        assert record["replaced"] is True
        assert record["window_lines"] == EXPANDED_FINDING_CONTEXT_LINES
        assert record["caller_context_attached"] is True
        assert record["callee_context_attached"] is False
        assert record["first_verdict"]["is_exploitable"] is None
        assert record["first_verdict"]["confidence"] == "low"
        assert record["second_verdict"]["is_exploitable"] is True
        assert record["second_verdict"]["confidence"] == "high"
        assert record["second_verdict"]["ruling"] == "validated"

    def test_summary_null_safe_on_junk(self):
        s = verdict_summary({"exploitability_score": "NaNish",
                             "ruling": 3, "confidence": "LOUD"})
        assert s == {
            "is_true_positive": None,
            "is_exploitable": None,
            "confidence": None,
            "exploitability_score": None,
            "ruling": None,
        }
        assert verdict_summary(None)["is_exploitable"] is None


class TestExpansionBlocks:
    def _repo(self, tmp_path: Path) -> Path:
        (tmp_path / "callee.c").write_text(
            "int helper_0(int n) { return n < 8 ? n : 8; }\n"
        )
        (tmp_path / "svc.c").write_text(
            "void other(void){}\n"
            "void entry(void) { target_fn(buf); }\n"
        )
        return tmp_path

    def _context_map(self) -> dict[str, Any]:
        return {
            "call_edges": [
                {
                    "caller": "entry",
                    "caller_file": "svc.c",
                    "callee": "target_fn",
                    "callee_file": "svc.c",
                },
                {
                    "caller": "target_fn",
                    "caller_file": "svc.c",
                    "callee": "helper_0",
                    "callee_file": "callee.c",
                },
            ],
        }

    def test_caller_and_callee_blocks_built(self, tmp_path: Path):
        repo = self._repo(tmp_path)
        blocks = expansion_context_blocks(
            None, "svc.c", "target_fn", repo,
            context_map=self._context_map(),
        )
        kinds = [b.kind for b in blocks]
        assert "caller-call-sites" in kinds
        assert "callee-sources" in kinds
        callee = next(b for b in blocks if b.kind == "callee-sources")
        assert "helper_0" in callee.content
        assert "n < 8" in callee.content

    def test_no_function_name_degrades_to_empty(self, tmp_path: Path):
        assert expansion_context_blocks(
            None, "svc.c", "", tmp_path, context_map=self._context_map(),
        ) == ()

    def test_nothing_resolvable_degrades_to_empty(self, tmp_path: Path):
        assert expansion_context_blocks(
            None, "svc.c", "target_fn", tmp_path,
        ) == ()

    def test_callee_snippet_lines_width_capped(self, tmp_path: Path):
        (tmp_path / "callee.c").write_text(
            "int helper_0(void) { return 0; } /* "
            + "A" * 800 + " */\n"
        )
        blocks = expansion_context_blocks(
            None, "svc.c", "target_fn", tmp_path,
            context_map=self._context_map(),
        )
        callee = next(b for b in blocks if b.kind == "callee-sources")
        assert max(len(line) for line in callee.content.splitlines()) <= 220
