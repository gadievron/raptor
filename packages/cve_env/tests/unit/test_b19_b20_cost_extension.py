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

import pytest


from cve_env.config import (
    MAX_TURN_EXTENSIONS,
    TURN_EXTENSION_PCT,
)

# ============================================================================
# B-19: token-based cost fallback
# ============================================================================



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
            max_turns=96,
            max_cost_usd=1.80,
            max_extensions=1,
            extension_pct=0.20,
        )
        assert "give_up" in block

    def test_runtime_caps_block_disabled_extension(self) -> None:
        # When max_extensions=0, prompt should reflect that — no false promise.
        from cve_env.agent.prompts import render_runtime_caps_block

        block = render_runtime_caps_block(
            max_turns=96,
            max_cost_usd=1.80,
            max_extensions=0,
            extension_pct=0.20,
        )
        # Should NOT promise extensions if disabled.
        assert (
            "no extension" in block.lower()
            or "fixed" in block.lower()
            or "0 extension" in block.lower()
        )

# ============================================================================
# B-20: CLI accepts new args
# ============================================================================



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
