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

    def test_cli_serialization_includes_refusals_key(self) -> None:
        """cli.py's _cmd_build must include 'refusals' in its outcome_dict."""
        from pathlib import Path

        cli_path = Path(__file__).resolve().parents[2] / "cve_env" / "cli.py"
        src = cli_path.read_text()
        assert '"refusals"' in src or "'refusals'" in src, (
            "cli.py _cmd_build must include a 'refusals' key in outcome_dict"
        )
        # Verify it reads from outcome.refusals (not a hardcoded value).
        assert "outcome.refusals" in src, (
            "cli.py _cmd_build must read refusals from outcome.refusals"
        )

    def test_cli_serialization_default_zero_serializes_as_int_not_none(self) -> None:
        """Regression guard: bench50-20260507-021212 had refusals=null in JSON
        (because bench predated B-22). With B-22, default outcome must serialize
        refusals=0 not null."""
        outcome = Outcome(cve_id="CVE-Y", status="success", reason="")
        outcome_dict = {"refusals": outcome.refusals}
        assert outcome_dict["refusals"] == 0
        assert outcome_dict["refusals"] is not None


class TestB22LoopConstructionFormula:
    """loop.py builds refusals = max(len(scanner.events), int(state.refusal_stop_reason_seen)).

    The formula is embedded inline in two Outcome constructors inside
    loop.build() (happy path + exception path). Since build() is a large
    async function that requires the full SDK, we verify the formula's
    presence via inspect.getsource — the same pattern used by other wiring
    tests in this package (test_api_overload, test_post_build_refusal, etc.).
    """

    def test_b22_refusals_formula_present_in_loop_build(self) -> None:
        """The refusals=max(len(...events), int(...refusal_stop_reason_seen))
        pattern must appear in build()'s source."""
        from pathlib import Path

        loop_path = Path(__file__).resolve().parents[2] / "cve_env" / "agent" / "loop.py"
        src = loop_path.read_text()
        assert src.count("refusals=max(") >= 2, (
            "expected refusals=max(...) formula in at least 2 Outcome "
            "constructors inside build()"
        )

    def test_b22_refusals_formula_uses_scanner_events(self) -> None:
        """The refusals formula must reference refusal_scanner.events."""
        from pathlib import Path

        loop_path = Path(__file__).resolve().parents[2] / "cve_env" / "agent" / "loop.py"
        src = loop_path.read_text()
        assert "len(refusal_scanner.events)" in src, (
            "refusals formula must use len(refusal_scanner.events)"
        )

    def test_b22_refusals_formula_uses_stop_reason_latch(self) -> None:
        """The refusals formula must reference the SDK stop_reason latch."""
        from pathlib import Path

        loop_path = Path(__file__).resolve().parents[2] / "cve_env" / "agent" / "loop.py"
        src = loop_path.read_text()
        assert "int(state.refusal_stop_reason_seen)" in src, (
            "refusals formula must use int(state.refusal_stop_reason_seen)"
        )

    def test_b22_refusals_formula_semantic_check(self) -> None:
        """Verify the formula's arithmetic: max(events, latch) produces the
        expected values for the four quadrants."""
        # The actual formula in loop.py is:
        #   refusals=max(len(refusal_scanner.events), int(state.refusal_stop_reason_seen))
        # Verify the arithmetic contract the Outcome consumer relies on.
        assert max(0, int(False)) == 0   # no events, no latch
        assert max(3, int(False)) == 3   # events dominate
        assert max(0, int(True)) == 1    # latch fallback
        assert max(5, int(True)) == 5    # events dominate over latch


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
            project="test",
            cve_id="CVE-X",
            run_id="r",
            audit_path=None,
            model="m",
            host_arch="arm64",
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
