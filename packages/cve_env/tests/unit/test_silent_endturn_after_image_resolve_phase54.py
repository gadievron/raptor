"""Phase 54-deep.2 RED tests for the generalized silent-give-up
classifier — the "silent end_turn after image_resolve.ok=True before
launch" pattern (Cand 2-G from Phase 53-inv).

Forensic evidence (Phase 53-impl.3a corrigendum, commit e357bb6):
CVE-2014-6271 (Shellshock) in bench50-20260518-005810:
  T13: image_resolve(vulhub/bash:4.3.0-with-httpd) → ok=True, decision=rosetta_ok
  T15-T18: 2 × github_fetch
  T19-T20: Bash (prep dir cleanup)
  T21: final_no_verify (NO docker_run, NO docker_compose_up, NO verify)

None of the existing classifier branches catch this:
- Phase 7.3 stuck_after_launch requires launched_ok=True (NOT met)
- Phase 51B quit_without_verify_after_build requires docker_built_ok (NOT met)
- Phase 47.C docker_built_ok marker requires docker_built_ok (NOT met)
- research_or_diag fallback CATCHES it but as "research-only" — wrong
  classification because the agent HAD a usable image.

Cand 2-G adds a `image_resolve_ok` state field + new classifier branch
emitting distinct give_up_reason `quit_after_image_resolve` (matching
Phase 32 rename convention).

Paired with prompts.py open-clause rule (Phase 54-deep.2.3) per
past-bench-lessons §1 #1.

TDD discipline per Phase 35 / 51B / 53-impl.1.1 / 54-deep.1.1:
xfail(strict=True) at RED, atomic removal at GREEN.
"""

from __future__ import annotations
import pytest
pytest.importorskip("claude_agent_sdk")

from cve_env.agent.loop import _map_status, _StreamState

def _make_state(**kw) -> _StreamState:
    """Construct fresh _StreamState with kw overrides for end_turn branch.

    Mirrors the Phase 51B test_silent_give_up_after_build_phase51b helper.
    """
    s = _StreamState()
    for k, v in kw.items():
        setattr(s, k, v)
    return s

def _seed_tool_uses(state: _StreamState, names: list[str]) -> None:
    """Seed state.tool_uses_seen with the given tool names (in order)."""
    for n in names:
        state.tool_uses_seen.append({"name": n, "input": {}})

def test_stream_state_has_image_resolve_ok_field() -> None:
    """The _StreamState dataclass must have an image_resolve_ok: bool field."""
    import inspect

    from cve_env.agent import loop as loop_module

    src = inspect.getsource(loop_module)
    # Field declaration appears as `image_resolve_ok: bool = False`
    assert "image_resolve_ok: bool" in src, (
        "_StreamState missing image_resolve_ok field declaration"
    )

def test_loop_sets_image_resolve_ok_on_tool_result_ok() -> None:
    """loop.py must set state.image_resolve_ok = True when image_resolve
    tool returns payload.ok=True. Source-inspection test: the set site
    must reference image_resolve + ok within a single conditional block."""
    import inspect

    from cve_env.agent import loop as loop_module

    src = inspect.getsource(loop_module)
    idx = src.find("state.image_resolve_ok = True")
    assert idx != -1, "set site for state.image_resolve_ok not present"
    # Within 400 chars upstream of the set, expect both 'image_resolve' check
    # and payload.get("ok") guard.
    window = src[max(0, idx - 400) : idx]
    assert 'tool_name == "image_resolve"' in window, (
        "set site missing tool_name == 'image_resolve' guard within 400 chars"
    )
    assert 'payload.get("ok") is True' in window, (
        "set site missing payload.get('ok') is True guard within 400 chars"
    )

def test_classifier_emits_quit_after_image_resolve() -> None:
    """The silent-end-turn classifier must emit give_up_reason
    'quit_after_image_resolve' when state.image_resolve_ok=True AND
    NOT docker_built_ok AND NOT launched_ok AND NOT verify_attempted
    AND source_build was not in tool_names_called.

    Source-inspection test: look for the new give_up_reason string in
    a conditional that checks image_resolve_ok.
    """
    import inspect

    from cve_env.agent import loop as loop_module

    src = inspect.getsource(loop_module)
    assert '"quit_after_image_resolve"' in src, (
        "give_up_reason 'quit_after_image_resolve' not present in loop.py"
    )
    idx = src.find('"quit_after_image_resolve"')
    window_up = src[max(0, idx - 800) : idx]
    assert "image_resolve_ok" in window_up, (
        "quit_after_image_resolve emission missing image_resolve_ok guard within 800 chars"
    )

def test_prompts_contains_post_image_resolve_rule() -> None:
    """prompts.py SYSTEM_PROMPT must contain an open-clause commitment rule:
    after image_resolve.ok=True with a usable image_ref, next call MUST
    be docker_run / docker_compose_up / source_build / give_up_explicit
    (not silent end_turn, not more research).

    Per past-bench-lessons §N: open-clause language, not a static enum
    table (the four-way OR matches Phase 24E #29 / Phase 41 chain rule
    shape).
    """
    from cve_env.agent.prompts import SYSTEM_PROMPT

    sp_lower = SYSTEM_PROMPT.lower()
    # Marker phrases
    assert (
        "image_resolve" in sp_lower
        and "ok=true" in sp_lower
        and ("next" in sp_lower or "must" in sp_lower)
    ), "post-image_resolve commitment rule missing canonical markers"
    # The action set: at least docker_run AND source_build mentioned in
    # rule proximity. Use the phrase "image_resolve" anchored:
    idx = sp_lower.find("after image_resolve")
    assert idx != -1, "rule phrase 'After image_resolve' missing"
    # Within 400 chars downstream, the four-way OR should be visible
    window = sp_lower[idx : idx + 600]
    assert (
        "docker_run" in window
        and "source_build" in window
        and ("give_up" in window or "give up" in window)
    ), (
        f"post-image_resolve rule missing docker_run/source_build/give_up "
        f"action set within 600 chars; window={window[:200]!r}"
    )

# ============================================================================
# Behavioral _map_status truth-table tests (Phase 54-deep.S.A.2 F-02 fix)
#
# Pass A surfaced that the source-inspection tests above don't lock the
# runtime behavior. These tests exercise _map_status with seeded state and
# assert the canonical mapping.
# ============================================================================

def test_quit_after_image_resolve_branch_fires_on_shellshock_pattern() -> None:
    """Phase 54-deep.2 primary behavioral test: the Shellshock pattern.

    Pre-conditions reproducing CVE-2014-6271 in bench50-20260518-005810:
    - image_resolve.ok=True observed (state.image_resolve_ok=True)
    - docker_build never succeeded (state.docker_built_ok=False)
    - launched_ok=False (no docker_run / compose_up reached)
    - source_build never called (not in tool_uses)
    - verify never attempted
    - agent emitted end_turn

    Expected: status=='unresolvable' AND state.give_up_reason==
    'quit_after_image_resolve'.
    """
    state = _make_state(
        image_resolve_ok=True,
        docker_built_ok=False,
        launched_ok=False,
        verify_attempted=False,
        verify_passed=False,
    )
    _seed_tool_uses(
        state,
        ["ToolSearch", "nvd_lookup", "github_fetch", "image_resolve", "Bash"],
    )
    status, reason = _map_status("end_turn", state)
    assert status == "unresolvable", f"expected unresolvable, got {status!r}"
    assert state.give_up_reason == "quit_after_image_resolve", (
        f"expected give_up_reason='quit_after_image_resolve'; "
        f"got: {state.give_up_reason!r}"
    )

def test_quit_after_image_resolve_yields_to_phase_51b_when_docker_built_ok() -> None:
    """Phase 51B branch takes precedence — docker_built_ok is the more
    specific signal. Order in _map_status is intentional."""
    state = _make_state(
        image_resolve_ok=True,
        docker_built_ok=True,
        launched_ok=False,
        verify_attempted=False,
        verify_passed=False,
    )
    _seed_tool_uses(state, ["image_resolve", "dockerfile_gen", "docker_build"])
    status, reason = _map_status("end_turn", state)
    assert status == "unresolvable"
    assert state.give_up_reason == "quit_without_verify_after_build", (
        f"Phase 51B precedence broken; got give_up_reason={state.give_up_reason!r}"
    )

def test_quit_after_image_resolve_yields_when_build_attempted() -> None:
    """W (2026-05-23): false-positive fix. When the agent resolved an image then
    ATTEMPTED a build (dockerfile_gen / docker_build) that didn't succeed before
    quitting, it did NOT 'quit after image_resolve' — the build-path branch must
    label it quit_without_verify_or_giveup. Forensic: CVE-2024-45692 ran
    dockerfile_gen + docker_build then end_turn yet was mislabeled
    quit_after_image_resolve (Phase 54-deep.2 NEEDS-FOLLOW-UP wiring bug)."""
    state = _make_state(
        image_resolve_ok=True,
        docker_built_ok=False,
        launched_ok=False,
        verify_attempted=False,
        verify_passed=False,
    )
    _seed_tool_uses(state, ["image_resolve", "dockerfile_gen", "docker_build"])
    status, reason = _map_status("end_turn", state)
    assert status == "unresolvable"
    assert state.give_up_reason == "quit_without_verify_or_giveup", (
        "build was attempted (dockerfile_gen/docker_build); must NOT be labeled "
        f"quit_after_image_resolve; got {state.give_up_reason!r}"
    )

def test_quit_after_image_resolve_yields_when_source_build_attempted() -> None:
    """source_build attempt = build-path pivot; Phase 54-deep.2 marker
    does NOT fire — generic quit_without_verify_or_giveup catches it."""
    state = _make_state(
        image_resolve_ok=True,
        docker_built_ok=False,
        launched_ok=False,
        verify_attempted=False,
        verify_passed=False,
    )
    _seed_tool_uses(state, ["image_resolve", "source_build", "Bash"])
    status, reason = _map_status("end_turn", state)
    assert status == "unresolvable"
    assert state.give_up_reason == "quit_without_verify_or_giveup", (
        f"source_build path should yield generic marker; got: {state.give_up_reason!r}"
    )

def test_image_resolve_ok_false_does_not_emit_marker() -> None:
    """Regression-guard: if image_resolve.ok=False (or never called), the
    Phase 54-deep.2 marker MUST NOT fire."""
    state = _make_state(
        image_resolve_ok=False,
        docker_built_ok=False,
        launched_ok=False,
        verify_attempted=False,
        verify_passed=False,
    )
    _seed_tool_uses(state, ["ToolSearch", "nvd_lookup", "Bash"])
    status, reason = _map_status("end_turn", state)
    assert state.give_up_reason != "quit_after_image_resolve", (
        f"marker fired with image_resolve_ok=False; got: {state.give_up_reason!r}"
    )
