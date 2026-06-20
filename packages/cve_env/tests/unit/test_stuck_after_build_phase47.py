"""Phase 47.C (2026-05-17) — Phase 7.3 trigger extension for docker_build path.

Current Phase 7.3 classifier (src/cve_env/agent/loop.py:819-835) emits
`stuck_after_launch` triage marker on turn_cap when:
  state.launched_ok AND not state.verify_attempted

`launched_ok` is set when docker_run/compose_up.ok=True (loop.py:1174).
CVEs that succeed `docker_build` but NEVER call docker_run get plain
`turn_cap` with no triage marker — a gap.

Empirical evidence: CVE-2024-12828 in Phase 43 partial
(`output/bench/bench50-20260517-005503/CVE-2024-12828.json`):
  tool_names_called includes docker_build (5×) but NOT docker_run
  status=turn_cap, reason=max_turns_reached (no stuck marker)

Phase 47.C extends the trigger to:
  (state.launched_ok OR state.docker_built_ok) AND not state.verify_attempted

With a distinct reason marker `stuck_after_launch_after_build` when the
trigger fires on docker_built_ok only (not launched_ok). Per past-bench-
lessons §M-class: TRIAGE-ENRICHMENT not behavior-change — same terminal
status, richer reason for analysis.

Per past-bench-lessons §1 — TDD with RED test first.
"""

from __future__ import annotations


from cve_env.agent.loop import _map_status, _StreamState


def _make_state(**kw) -> _StreamState:
    """Construct fresh _StreamState with kw overrides."""
    s = _StreamState()
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def test_docker_built_ok_no_run_no_verify_emits_post_build_marker() -> None:
    """Phase 47.C primary RED: turn_cap with docker_build but no docker_run
    + no verify → reason should include `stuck_after_launch_after_build`.

    Matches CVE-2024-12828 (Phase 43 partial) shape: agent called
    docker_build 5× successfully, never called docker_run, hit max_turns.
    """
    state = _make_state(
        docker_built_ok=True,
        launched_ok=False,
        verify_attempted=False,
    )
    status, reason = _map_status("max_turns_reached", state)
    assert status == "turn_cap", f"expected turn_cap, got {status!r}"
    assert "stuck_after_launch_after_build" in reason, (
        f"expected 'stuck_after_launch_after_build' in reason; got: {reason!r}"
    )


def test_launched_ok_takes_precedence_over_docker_built_ok() -> None:
    """When BOTH flags are set (agent reached docker_run after docker_build),
    the existing `stuck_after_launch` marker wins — don't show the
    `_after_build` suffix for the more-specific launched-but-no-verify
    case. Backwards-compat with CVE-2024-11664 (Phase 38 reference)
    which already gets `stuck_after_launch`.
    """
    state = _make_state(
        docker_built_ok=True,
        launched_ok=True,
        verify_attempted=False,
    )
    status, reason = _map_status("max_turns_reached", state)
    assert status == "turn_cap"
    # The non-suffixed marker fires (existing behavior); not the new one.
    assert "stuck_after_launch:" in reason or "stuck_after_launch " in reason, reason
    # Specifically: the docker_build-only suffix must NOT appear
    assert "stuck_after_launch_after_build" not in reason, reason


def test_docker_built_ok_but_verify_attempted_no_marker() -> None:
    """If verify was attempted (regardless of pass), the docker-built-only
    marker should NOT fire. Verify-attempted means agent reached the
    verification stage — not stuck pre-launch."""
    state = _make_state(
        docker_built_ok=True,
        launched_ok=False,
        verify_attempted=True,  # verify was tried
    )
    status, reason = _map_status("max_turns_reached", state)
    assert status == "turn_cap"
    assert "stuck_after_launch_after_build" not in reason


def test_neither_flag_set_returns_plain_turn_cap() -> None:
    """Regression-lock: agents that never reached build OR run get plain
    turn_cap (research-only loop case — CVE-2024-1925 / CVE-2024-13545
    in Phase 43). NOT xfail — this behavior must be preserved both
    pre- and post-Phase-47.C."""
    state = _make_state(
        launched_ok=False,
        verify_attempted=False,
    )
    # docker_built_ok defaults to False after Phase 47.C ship
    status, reason = _map_status("max_turns_reached", state)
    assert status == "turn_cap"
    assert "stuck_after_launch" not in reason
