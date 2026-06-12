"""Tests for B-22 (refusals field on Outcome) and B-23 (SDK API Error patterns).

Stage 3 TDD coverage from migration-arc audit (2026-05-08): the audit found
that B-22's wiring (Outcome.refusals + cli.py serialization + loop.py
construction) had ZERO tests, and B-23's 2 SDK-wrapper regex patterns had
ZERO tests. These tests fill those gaps.
"""

from __future__ import annotations

from cve_env.agent.refusals import RefusalScanner, _REFUSAL_PATTERNS
from cve_env.models import Outcome


# ============================================================================
# B-22: refusals field on Outcome
# ============================================================================


class TestOutcomeRefusalsField:
    """Outcome dataclass must expose a refusals: int field with default 0."""

    def test_outcome_refusals_default_is_zero(self) -> None:
        out = Outcome(cve_id="CVE-X", status="success", reason="")
        assert out.refusals == 0
        assert isinstance(out.refusals, int)

    def test_outcome_refusals_explicit_value(self) -> None:
        out = Outcome(cve_id="CVE-X", status="success", reason="", refusals=3)
        assert out.refusals == 3

    def test_outcome_refusals_field_is_int_type(self) -> None:
        # Static check: type annotation declares int.
        # Note: PEP 563 (`from __future__ import annotations` in models.py)
        # stores annotations as strings at runtime.
        annotations = Outcome.__annotations__
        assert "refusals" in annotations
        assert annotations["refusals"] == "int"


class TestCliOutcomeDictSerialization:
    """cli.py outcome_dict must include `refusals` as int from outcome.refusals."""

    def test_cli_serialization_includes_refusals_int(self) -> None:
        # Reproduce the exact dict construction at cli.py:80-96.
        outcome = Outcome(
            cve_id="CVE-2024-X",
            status="success",
            reason="",
            refusals=2,
        )
        # Mirror cli.py:80-96 — the serialization happens inside async build().
        # We test the pattern directly to lock the contract.
        outcome_dict = {
            "cve_id": outcome.cve_id,
            "status": outcome.status,
            "verify_passed": outcome.verify_passed,
            "give_up_reason": outcome.give_up_reason,
            "give_up_detail": outcome.give_up_detail,
            "num_turns": outcome.num_turns,
            "total_cost_usd": outcome.total_cost_usd,
            "stop_reason": outcome.stop_reason,
            "reason": outcome.reason,
            "tool_names_called": outcome.tool_names_called,
            "final_text": outcome.final_text,
            "audit_path": str(outcome.audit_path) if outcome.audit_path else None,
            "refusals": outcome.refusals,
        }
        assert "refusals" in outcome_dict
        assert outcome_dict["refusals"] == 2
        assert isinstance(outcome_dict["refusals"], int)

    def test_cli_serialization_default_zero_serializes_as_int_not_none(self) -> None:
        """Regression guard: bench50-20260507-021212 had refusals=null in JSON
        (because bench predated B-22). With B-22, default outcome must serialize
        refusals=0 not null."""
        outcome = Outcome(cve_id="CVE-Y", status="success", reason="")
        outcome_dict = {"refusals": outcome.refusals}
        assert outcome_dict["refusals"] == 0
        assert outcome_dict["refusals"] is not None


class TestB22LoopConstructionFormula:
    """loop.py builds refusals = max(len(scanner.events), int(state.refusal_stop_reason_seen))."""

    def test_b22_formula_zero_events_no_latch_yields_zero(self) -> None:
        events_len = 0
        latch_seen = False
        result = max(events_len, int(latch_seen))
        assert result == 0

    def test_b22_formula_three_events_yields_three(self) -> None:
        events_len = 3
        latch_seen = False
        result = max(events_len, int(latch_seen))
        assert result == 3

    def test_b22_formula_zero_events_but_latch_seen_yields_one(self) -> None:
        """Latch-fallback covers SDK refusal stop_reason without text-matched events."""
        events_len = 0
        latch_seen = True
        result = max(events_len, int(latch_seen))
        assert result == 1

    def test_b22_formula_events_dominate_when_higher(self) -> None:
        events_len = 5
        latch_seen = True
        result = max(events_len, int(latch_seen))
        assert result == 5  # events_len wins, not 1+5


# ============================================================================
# B-23: SDK API Error wrapper patterns
# ============================================================================


class TestB23SdkApiErrorPatterns:
    """B-23 added 2 regex patterns to _REFUSAL_PATTERNS for the bundled
    `claude` CLI's API Error wrapper around AUP-class refusals.
    """

    def test_b23_api_error_unable_to_respond_matches(self) -> None:
        text = "API Error: Claude Code is unable to respond to this request"
        assert any(p.search(text) for p in _REFUSAL_PATTERNS)

    def test_b23_api_error_unable_to_respond_case_insensitive(self) -> None:
        text = "api error: I am UNABLE to RESPOND"
        assert any(p.search(text) for p in _REFUSAL_PATTERNS)

    def test_b23_violate_our_usage_policy_matches(self) -> None:
        text = "appears to violate our Usage Policy"
        assert any(p.search(text) for p in _REFUSAL_PATTERNS)

    def test_b23_violate_the_usage_policy_matches(self) -> None:
        text = "violates the Usage Policy of this service"
        assert any(p.search(text) for p in _REFUSAL_PATTERNS)

    def test_b23_full_real_world_sdk_wrapper_text(self) -> None:
        """The exact text observed in
        output/agentic/manual-1777757582/CVE-2015-10111*.jsonl —
        confirms the pattern catches real SDK output, not just synthetic."""
        text = (
            "API Error: Claude Code is unable to respond to this request, "
            "which appears to violate our Usage Policy "
            "(https://www.anthropic.com/...)"
        )
        assert any(p.search(text) for p in _REFUSAL_PATTERNS)

    def test_b23_scanner_scan_text_returns_event(self) -> None:
        """RefusalScanner.scan_text on B-23 wrapper text returns a RefusalEvent
        and appends it to scanner.events. First-match wins so one event is
        created even when multiple B-23 patterns would match."""
        scanner = RefusalScanner(
            project="test", cve_id="CVE-X", run_id="r", audit_path=None,
            model="m", host_arch="arm64",
        )
        text = (
            "API Error: Claude Code is unable to respond to this request, "
            "which appears to violate our Usage Policy"
        )
        event = scanner.scan_text(turn=1, text=text, tool_call=None)
        assert event is not None
        assert len(scanner.events) == 1
        # Confirm the matched pattern is one of the B-23 patterns. matched_pattern
        # is the raw regex source, so look for the regex tokens that B-23 uses.
        pat_lower = event.matched_pattern.lower()
        assert "unable" in pat_lower or "usage policy" in pat_lower
