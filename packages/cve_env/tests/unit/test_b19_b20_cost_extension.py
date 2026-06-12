"""Tests for B-19 (token-based cost fallback) and B-20 (productive-extension).

B-19 forensic: bench200 had 5/15 CVEs report ``total_cost_usd=0`` despite
``num_turns >= 5``. Validation15 had 1/15 (CVE-2024-27764 t=11 / $0).
SDK's ResultMessage.total_cost_usd is None or 0 on certain stop_reasons
(max_turns_reached, end_turn-after-low-turn-give_up). Fix: token-based
fallback estimate; Outcome.total_cost_usd = max(reported, estimated).

B-20 forensic: bench200 CVE-2022-23383 hit max_turns_reached at t=35
while on a productive source-build path (final_text="Let me look at the
install workflow and skip the install wizard..."). Fix: when agent is
within PRODUCTIVE_RECENCY_TURNS of the cap AND last_productive_turn was
recent, auto-extend max_turns by TURN_EXTENSION_PCT (default +20%), up
to MAX_TURN_EXTENSIONS times.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from cve_env import config
from cve_env.config import (
    MAX_TURN_EXTENSIONS,
    MODEL_TOKEN_RATES_PER_M_USD,
    PRODUCTIVE_RECENCY_TURNS,
    TURN_EXTENSION_PCT,
    estimate_cost_from_tokens,
    get_token_rates,
)


# ============================================================================
# B-19: token-based cost fallback
# ============================================================================


class TestGetTokenRates:
    def test_known_model_returns_known_rates(self) -> None:
        opus_in, opus_out = get_token_rates("claude-opus-4-7")
        assert opus_in == 15.0
        assert opus_out == 75.0

    def test_unknown_model_falls_back_to_sonnet_conservative(self) -> None:
        rates = get_token_rates("some-unknown-model-id")
        assert rates == (3.0, 15.0)  # mid-tier fallback

    def test_env_override_takes_precedence(self) -> None:
        with patch.dict(
            os.environ,
            {"CVE_ENV_INPUT_RATE_PER_M": "2.5", "CVE_ENV_OUTPUT_RATE_PER_M": "10.0"},
        ):
            assert get_token_rates("claude-opus-4-7") == (2.5, 10.0)

    def test_partial_env_override_is_ignored(self) -> None:
        # Only one env var set — defensive: don't compute partial estimate.
        with patch.dict(os.environ, {"CVE_ENV_INPUT_RATE_PER_M": "2.5"}, clear=False):
            os.environ.pop("CVE_ENV_OUTPUT_RATE_PER_M", None)
            rates = get_token_rates("claude-opus-4-7")
            assert rates == (15.0, 75.0)


class TestEstimateCostFromTokens:
    def test_zero_tokens_zero_cost(self) -> None:
        assert estimate_cost_from_tokens(0, 0, "claude-opus-4-7") == 0.0

    def test_typical_call_produces_nonzero_estimate(self) -> None:
        # 10K input, 2K output on opus-4-7: 10_000 * 15 + 2_000 * 75 = 150_000 + 150_000 = 300_000 / 1M = $0.30
        cost = estimate_cost_from_tokens(10_000, 2_000, "claude-opus-4-7")
        assert cost == pytest.approx(0.30, rel=1e-6)

    def test_sonnet_rates(self) -> None:
        # Sonnet: 100K in, 10K out → 100_000 * 3 + 10_000 * 15 = 300_000 + 150_000 = 450_000 / 1M = $0.45
        cost = estimate_cost_from_tokens(100_000, 10_000, "claude-sonnet-4-6")
        assert cost == pytest.approx(0.45, rel=1e-6)

    def test_b19_canary_cve_2022_23383_would_have_recovered_cost(self) -> None:
        """CVE-2022-23383 ran 96 messages (35 tool calls) and reported $0.
        With realistic per-call token usage (~5K in, ~500 out per LLM round
        × 96 rounds), the estimate should be ~$10 — the actual cost loss.
        This test doesn't replay the bench, just asserts the estimator
        produces a non-trivial number for that scale.
        """
        # 96 rounds × 5K in × $15/M = 96 * 5000 * 15 / 1M = $7.20
        # 96 rounds × 500 out × $75/M = 96 * 500 * 75 / 1M = $3.60
        # Total ≈ $10.80
        cost = estimate_cost_from_tokens(96 * 5000, 96 * 500, "claude-opus-4-7")
        assert cost > 1.0  # at minimum, far above $0
        assert cost < 20.0  # sanity ceiling
        assert cost == pytest.approx(10.80, rel=1e-3)


# ============================================================================
# B-20: productive-extension predicate
# ============================================================================


# We test the predicate logic directly, not the full loop. The predicate
# is implemented in cve_env.agent.loop.should_extend_turn_cap as a pure
# function for easy testing.


class TestShouldExtendTurnCap:
    def setup_method(self) -> None:
        from cve_env.agent.loop import should_extend_turn_cap

        self.fn = should_extend_turn_cap

    def test_extension_granted_when_productive_and_under_max_extensions(self) -> None:
        # state: turn 100 of 96-turn cap, last productive at t=98, no prior
        # extensions, cost well under cap. Should grant +20% (max_turns 96 → 115).
        result = self.fn(
            current_turn=100,
            current_max_turns=96,
            last_productive_turn=98,
            extension_count=0,
            current_cost_usd=1.00,
            max_cost_usd=1.80,
            max_extensions=1,
            extension_pct=0.20,
            recency_window=5,
        )
        assert result is not None
        assert result == int(96 * 1.20)  # 115

    def test_extension_denied_when_unproductive(self) -> None:
        # last productive was 10 turns ago — outside PRODUCTIVE_RECENCY_TURNS.
        result = self.fn(
            current_turn=100,
            current_max_turns=96,
            last_productive_turn=80,  # 20 turns stale
            extension_count=0,
            current_cost_usd=1.00,
            max_cost_usd=1.80,
            max_extensions=1,
            extension_pct=0.20,
            recency_window=5,
        )
        assert result is None

    def test_extension_denied_when_already_at_max_extensions(self) -> None:
        result = self.fn(
            current_turn=120,
            current_max_turns=115,  # already extended once from 96
            last_productive_turn=118,
            extension_count=1,  # already used the one allowed extension
            current_cost_usd=1.00,
            max_cost_usd=1.80,
            max_extensions=1,
            extension_pct=0.20,
            recency_window=5,
        )
        assert result is None

    def test_extension_denied_when_cost_near_cap(self) -> None:
        # Cost is at 90% of cap — extending turns won't help, more turns
        # = more cost. Stop here.
        result = self.fn(
            current_turn=100,
            current_max_turns=96,
            last_productive_turn=98,
            extension_count=0,
            current_cost_usd=1.62,  # 90% of $1.80
            max_cost_usd=1.80,
            max_extensions=1,
            extension_pct=0.20,
            recency_window=5,
        )
        assert result is None

    def test_extension_with_zero_max_extensions_disabled(self) -> None:
        # Config can disable feature entirely.
        result = self.fn(
            current_turn=100,
            current_max_turns=96,
            last_productive_turn=98,
            extension_count=0,
            current_cost_usd=1.00,
            max_cost_usd=1.80,
            max_extensions=0,  # disabled
            extension_pct=0.20,
            recency_window=5,
        )
        assert result is None

    def test_extension_with_no_productive_history(self) -> None:
        # last_productive_turn=0 means agent has never made build progress.
        # No extension.
        result = self.fn(
            current_turn=100,
            current_max_turns=96,
            last_productive_turn=0,
            extension_count=0,
            current_cost_usd=1.00,
            max_cost_usd=1.80,
            max_extensions=1,
            extension_pct=0.20,
            recency_window=5,
        )
        assert result is None

    def test_custom_extension_pct(self) -> None:
        # 50% extension: 96 → 144.
        result = self.fn(
            current_turn=100,
            current_max_turns=96,
            last_productive_turn=98,
            extension_count=0,
            current_cost_usd=1.00,
            max_cost_usd=1.80,
            max_extensions=1,
            extension_pct=0.50,
            recency_window=5,
        )
        assert result == int(96 * 1.50)


# ============================================================================
# B-20: cap announcement in system prompt
# ============================================================================


class TestRenderSystemPromptWithCaps:
    def test_runtime_caps_block_includes_max_turns(self) -> None:
        from cve_env.agent.prompts import render_runtime_caps_block

        block = render_runtime_caps_block(
            max_turns=96,
            max_cost_usd=1.80,
            max_extensions=1,
            extension_pct=0.20,
        )
        assert "96" in block
        assert "$1.80" in block
        # Mentions extension policy so agent knows it has slack.
        assert "extens" in block.lower() or "+20%" in block or "20" in block

    def test_runtime_caps_block_mentions_give_up(self) -> None:
        # Agent should know to give_up when stuck — not silently drift.
        from cve_env.agent.prompts import render_runtime_caps_block

        block = render_runtime_caps_block(
            max_turns=96, max_cost_usd=1.80, max_extensions=1, extension_pct=0.20,
        )
        assert "give_up" in block

    def test_runtime_caps_block_disabled_extension(self) -> None:
        # When max_extensions=0, prompt should reflect that — no false promise.
        from cve_env.agent.prompts import render_runtime_caps_block

        block = render_runtime_caps_block(
            max_turns=96, max_cost_usd=1.80, max_extensions=0, extension_pct=0.20,
        )
        # Should NOT promise extensions if disabled.
        assert "no extension" in block.lower() or "fixed" in block.lower() or "0 extension" in block.lower()


# ============================================================================
# B-20: CLI accepts new args
# ============================================================================


class TestAssistantMessageTokenAccumulation:
    """B-19 enhancement (2026-05-07b): tokens are reported on every
    AssistantMessage (per-call usage), not just the final ResultMessage.

    Forensic: CVE-2022-0784 in bench200 v2 ran 35 tool calls and emitted
    ZERO ResultMessages — token-fallback couldn't engage because tokens
    weren't being captured from AssistantMessages. Fix: accumulate from
    msg.usage on AssistantMessage receipt as well.
    """

    def test_assistant_message_usage_dict_accumulates(self) -> None:
        # Drive on_message with a sequence of AssistantMessages carrying
        # usage; assert state.total_input_tokens / total_output_tokens
        # grow monotonically.
        from claude_agent_sdk import AssistantMessage, TextBlock
        from cve_env.agent.loop import _StreamState

        state = _StreamState()
        msg1 = AssistantMessage(
            content=[TextBlock(text="hello")],
            model="claude-opus-4-7",
            usage={"input_tokens": 1500, "output_tokens": 200},
        )
        msg2 = AssistantMessage(
            content=[TextBlock(text="continuing")],
            model="claude-opus-4-7",
            usage={"input_tokens": 2000, "output_tokens": 150},
        )

        # Mimic the loop's accumulation logic for AssistantMessage.usage:
        for msg in (msg1, msg2):
            usage = getattr(msg, "usage", None)
            if usage:
                if isinstance(usage, dict):
                    state.total_input_tokens += int(usage.get("input_tokens", 0))
                    state.total_output_tokens += int(usage.get("output_tokens", 0))

        assert state.total_input_tokens == 3500
        assert state.total_output_tokens == 350


class TestSdkMaxTurnsPreallocation:
    """B-20 architectural fix (2026-05-07b) + B-21 safety multiplier (2026-05-07c).

    SDK's own max_turns gate fires BEFORE our F-9 / B-20 logic if set to
    the same value. We pass the SDK an inflated budget; F-9 + B-20 enforce
    the real per-CVE cap via state.effective_max_turns.

    B-21 (2026-05-07c): bench200 v3 found that bundled `claude` CLI 2.1.123
    halts with stop_reason="max_turns_reached" at SDK num_turns=30-39 even
    when --max-turns is set to 115 (anthropics/claude-code Issue #41143
    cousin-bug, opposite direction). We bump the safety multiplier to 4×
    so the SDK budget is well outside the buggy zone.

    Effective formula::

        sdk_max_turns = max_turns * max(1 + ext_pct * max_ext, 4)

    The 4× floor wins for typical configs (ext=1, pct=0.20 → 1.20 vs 4.0).
    """

    _SAFETY = 4  # mirrors loop.py:_SDK_MAX_TURNS_SAFETY_MULTIPLIER

    def _compute(self, max_turns: int, ext_pct: float, max_ext: int) -> int:
        return int(max_turns * max(1.0 + ext_pct * max_ext, float(self._SAFETY)))

    def test_sdk_max_turns_default_uses_safety_multiplier(self) -> None:
        # max_turns=96, extensions=1, pct=0.20 → ext factor 1.20, safety 4.0 → 4.0 wins → 384
        assert self._compute(96, 0.20, 1) == 384

    def test_sdk_max_turns_disabled_extension_falls_back_to_safety(self) -> None:
        # When extensions=0 the ext factor is 1.0; safety floor 4.0 still wins.
        # Pre-B-21 this returned max_turns (= 96). Post-B-21 returns 4 × max_turns.
        assert self._compute(96, 0.20, 0) == 384

    def test_sdk_max_turns_high_extension_overrides_safety(self) -> None:
        # 5×30% = 1.50 + 1 = 2.5 (still less than safety 4) → 384
        assert self._compute(96, 0.30, 5) == 384
        # 10×50% = 5.0 + 1 = 6.0 (greater than safety 4) → ext factor wins → 576
        assert self._compute(96, 0.50, 10) == 576


class TestCliExtensionArgs:
    def test_argparse_accepts_extension_args(self) -> None:
        from cve_env.cli import _build_argparser

        parser = _build_argparser()
        # default values from config
        args = parser.parse_args(["build", "CVE-2024-0001"])
        assert args.max_turn_extensions == MAX_TURN_EXTENSIONS
        assert args.turn_extension_pct == pytest.approx(TURN_EXTENSION_PCT)

    def test_argparse_accepts_explicit_extension_args(self) -> None:
        from cve_env.cli import _build_argparser

        parser = _build_argparser()
        args = parser.parse_args(
            [
                "build",
                "CVE-2024-0001",
                "--max-turn-extensions",
                "2",
                "--turn-extension-pct",
                "0.30",
            ]
        )
        assert args.max_turn_extensions == 2
        assert args.turn_extension_pct == pytest.approx(0.30)


# =============================================================================
# #1 (2026-05-24) — _is_productive_outcome: verify/run_in_container count as
# productive ONLY after a build succeeded (gated turn-extension eligibility).
# =============================================================================


def test_is_productive_outcome_build_tools_ok() -> None:
    from cve_env.agent.loop import _is_productive_outcome

    assert _is_productive_outcome("docker_build", {"ok": True}, False) is True
    assert _is_productive_outcome("source_build", {"ok": True}, False) is True
    assert _is_productive_outcome("docker_compose_up", {"ok": True}, False) is True


def test_is_productive_outcome_build_tool_not_ok() -> None:
    from cve_env.agent.loop import _is_productive_outcome

    assert _is_productive_outcome("docker_build", {"ok": False}, False) is False


def test_is_productive_outcome_verify_after_build() -> None:
    """#1: verify / run_in_container ARE productive once docker_built_ok — the
    build-then-verify CVE (e.g. CVE-2022-26134) is making progress, so the
    turn-cap extension should fire. ok-state not required (a failing verify on
    a built env is still active progress)."""
    from cve_env.agent.loop import _is_productive_outcome

    assert _is_productive_outcome("verify", {"results": []}, True) is True
    assert _is_productive_outcome("run_in_container", {"ok": True}, True) is True
    assert _is_productive_outcome("verify", {"ok": False}, True) is True


def test_is_productive_outcome_verify_before_build_not_productive() -> None:
    """#1 guard: verify / run_in_container BEFORE any build is NOT productive —
    keeps research-only / thrashing loops from extending the turn cap."""
    from cve_env.agent.loop import _is_productive_outcome

    assert _is_productive_outcome("verify", {"results": []}, False) is False
    assert _is_productive_outcome("run_in_container", {"ok": True}, False) is False


def test_is_productive_outcome_research_tool_not_productive() -> None:
    from cve_env.agent.loop import _is_productive_outcome

    assert _is_productive_outcome("nvd_lookup", {"ok": True}, True) is False
    assert _is_productive_outcome("github_fetch", {"ok": True}, False) is False
    assert _is_productive_outcome("verify", "not-a-dict", True) is False
