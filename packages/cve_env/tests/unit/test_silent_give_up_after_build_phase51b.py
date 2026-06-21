"""Phase 51B RED tests: paired prompt + runtime classifier extension for
post-docker_build silent-give-up.

Context: Phase 49 Phase 44 re-run had 6 silent-give-up cases (CVE-2024-25415,
43402, 4435, 45302, 45390, 45692). Phase 47.C added `stuck_after_launch_
after_build` triage marker on TURN_CAP branch when `docker_built_ok=True
AND not verify_attempted`. Phase 51B extends this distinction to the
END_TURN branch + adds the paired prompt rule for the actual observed
build-failure pattern.

Phase 51B has two layers (per past-bench-lessons §1 #1 paired-fix):

  1. RUNTIME: new marker `quit_without_verify_after_build` (DEFENSIVE,
     parallel to Phase 47.C). Fires when `docker_built_ok=True AND
     not launched_ok` at end_turn. The 6 Phase 49 CVEs had
     docker_build.ok=False so this marker doesn't fire for them — but
     symmetric to Phase 47.C per past-bench-lessons §P (don't delete
     unexercised defenses).

  2. PROMPT: new commitment rule for the docker_build.ok=FALSE case
     (the actual observed 6-CVE pattern). After docker_build fails,
     agent MUST either (a) retry dockerfile_gen with different content,
     OR (b) call give_up() with explicit reason. Do NOT emit end_turn.

Per past-bench-lessons §13 #1 TDD: RED commit first; GREEN flip atomic
in 51.B.2 (runtime) + 51.B.3 (prompt).
"""

from __future__ import annotations
import pytest
pytest.importorskip("claude_agent_sdk")

import pytest

from cve_env.agent.loop import _map_status, _StreamState

def _make_state(**kw) -> _StreamState:
    """Construct fresh _StreamState with kw overrides for end_turn branch."""
    s = _StreamState()
    for k, v in kw.items():
        setattr(s, k, v)
    return s

def _seed_tool_uses(state: _StreamState, names: list[str]) -> None:
    """Seed state.tool_uses_seen with the given tool names (in order)."""
    for n in names:
        state.tool_uses_seen.append({"name": n, "input": {}})

def test_docker_built_ok_no_launch_end_turn_emits_new_marker() -> None:
    """Phase 51B primary RED: docker_build succeeded but agent emitted
    end_turn without docker_run + verify → new marker fires.

    This is the DEFENSIVE case (parallel to Phase 47.C turn_cap marker).
    Phase 49's 6 silent-give-up CVEs had docker_built_ok=False — this
    marker is symmetric insurance for the success-then-quit case.
    """
    state = _make_state(
        docker_built_ok=True,
        launched_ok=False,
        verify_attempted=False,
        verify_passed=False,
    )
    _seed_tool_uses(state, ["docker_build", "dockerfile_gen"])
    status, reason = _map_status("end_turn", state)
    # Status maps to unresolvable (give_up_reason synthesized)
    assert status == "unresolvable", f"expected unresolvable, got {status!r}"
    assert state.give_up_reason == "quit_without_verify_after_build", (
        f"expected give_up_reason='quit_without_verify_after_build'; "
        f"got: {state.give_up_reason!r}"
    )

def test_build_failed_end_turn_keeps_existing_marker() -> None:
    """Phase 51B regression-guard: the 6 Phase 49 CVE pattern.

    docker_build was called but docker_built_ok=False (build failed).
    Existing `quit_without_verify_or_giveup` marker still fires.
    Must remain unchanged after 51B ships.

    Forensic: CVE-2024-43402, CVE-2024-45692 etc. — agent called
    docker_build but ok=False, then emitted end_turn.
    """
    state = _make_state(
        docker_built_ok=False,  # build attempted but failed
        launched_ok=False,
        verify_attempted=False,
        verify_passed=False,
    )
    _seed_tool_uses(state, ["docker_build", "dockerfile_gen", "Bash"])
    status, reason = _map_status("end_turn", state)
    assert status == "unresolvable"
    assert state.give_up_reason == "quit_without_verify_or_giveup", (
        f"existing marker should fire when docker_built_ok=False; "
        f"got: {state.give_up_reason!r}"
    )
    # Phase 51B new marker should NOT fire here
    assert state.give_up_reason != "quit_without_verify_after_build"

def test_launched_no_verify_branch_takes_precedence_over_new_marker() -> None:
    """Phase 51B regression-guard: Phase 57 `launched_no_verify` precedence.

    When launched_ok=True, the agent reached docker_run; the Phase 57
    branch (loop.py:866-880) fires FIRST and returns `launched_no_verify`
    status. The Phase 51B new marker should NOT activate (more specific
    signal already won).
    """
    state = _make_state(
        docker_built_ok=True,
        launched_ok=True,  # agent reached docker_run
        verify_attempted=False,
        verify_passed=False,
    )
    _seed_tool_uses(state, ["docker_build", "docker_run"])
    status, reason = _map_status("end_turn", state)
    assert status == "launched_no_verify", (
        f"Phase 57 branch should fire first when launched_ok=True; got: {status!r}"
    )
    # New marker must not have set give_up_reason
    assert state.give_up_reason != "quit_without_verify_after_build", (
        f"new marker should not fire when Phase 57 already classified; "
        f"got: {state.give_up_reason!r}"
    )

def test_phase_51b_build_failure_commitment_rule_present_in_prompt() -> None:
    """Phase 51B prompt-presence RED: assert prompts.py contains the new
    build-FAILURE commitment rule.

    Targets the 6 Phase 49 silent-give-up CVE pattern where agent called
    docker_build, build returned ok=False, agent emitted end_turn (no
    retry, no give_up). The Phase 41 rule covers build-success → docker_run;
    Phase 51B adds the build-failure → retry OR give_up rule.

    Sentinel-phrase check: the new rule must contain a Phase-51B-specific
    sentinel that doesn't already appear in the prompt pre-impl. Existing
    markers like 'ok=false' / 'retry' / 'dockerfile_gen' / 'give_up' / 'build
    failure' all appear elsewhere in unrelated contexts and don't prove the
    new rule landed.
    """
    from cve_env.agent import prompts as prompts_mod

    text = prompts_mod.SYSTEM_PROMPT.lower()
    # Phase 51B sentinel phrases — any one of these proves the new rule
    # landed. None should match pre-impl.
    sentinels = (
        "phase 51b",
        "post-`docker_build` failure",
        "docker_build returns ok=false",
        "post-docker_build-failure",
    )
    matched = [s for s in sentinels if s in text]
    assert matched, (
        "Phase 51B prompt rule sentinel not found. Expected one of: "
        f"{sentinels}. Add the new commitment rule with one of these "
        "sentinel phrases to mark Phase 51B's landing."
    )

def test_phase_47c_marker_unchanged_in_turn_cap_branch() -> None:
    """Phase 51B regression-guard: Phase 47.C turn_cap marker stays.

    The end_turn branch extension must NOT affect the turn_cap branch
    (lines 854-860) which is the Phase 47.C path. CVE-2024-12828
    shape: docker_built_ok=True, launched_ok=False, verify_attempted=False,
    stop_reason=max_turns_reached → still emits
    `stuck_after_launch_after_build` in reason.
    """
    state = _make_state(
        docker_built_ok=True,
        launched_ok=False,
        verify_attempted=False,
    )
    status, reason = _map_status("max_turns_reached", state)
    assert status == "turn_cap"
    assert "stuck_after_launch_after_build" in reason, (
        f"Phase 47.C marker regressed; got: {reason!r}"
    )
