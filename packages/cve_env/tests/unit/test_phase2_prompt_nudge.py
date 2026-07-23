"""Phase 2 (2026-05-23): drift-lock for the strengthened OUTPUT-trigger
de-escalation guidance.

The agentic de-escalation nudge already existed — P0-7 (reactive
reframe-and-continue) + a proactive 'avoid attack-pattern tool inputs'
rule. Rather than add a redundant layer, the proactive rule was extended
to also cover the agent's own reasoning/narration text — the gap that
tripped CVE-2024-21626 (refused on exploit-framed reasoning, yet still
built). These tests lock that coverage so a future prompt edit can't
silently drop it.
"""

from __future__ import annotations

from cve_env.agent.prompts import SYSTEM_PROMPT


def test_output_trigger_rule_covers_reasoning_not_just_tool_inputs() -> None:
    sp = SYSTEM_PROMPT
    # The proactive rule must name both surfaces the AUP classifier scores:
    # composed tool inputs AND the agent's own reasoning/narration.
    assert "tool inputs AND" in sp, "rule must name tool-inputs + reasoning surfaces"
    assert "reasoning" in sp
    assert "BUILD-FUNCTIONAL register" in sp, (
        "the reasoning-register guidance (CVE-2024-21626 gap) must be present"
    )


def test_p0_7_reactive_refusal_recovery_still_present() -> None:
    """We strengthened the existing nudge, we did NOT replace it — the
    reactive P0-7 rule must remain (no redundant new layer added)."""
    assert "P0-7 refusal recovery rule" in SYSTEM_PROMPT


def test_verify_promptly_rule_present() -> None:
    """#2 cap-binding (2026-06-01): the winning profile verifies the MOMENT a
    build/launch succeeds — before any detour — so a built env does not run out
    the turn/cost cap before verify.passed (the biggest non-build bucket, walls
    = 28% of buildable in bench50-20260601). Backed structurally by the existing
    should_extend_turn_cap post-build extension; this prompt rule is the agentic
    nudge. Drift-lock so a future prompt edit can't silently drop it."""
    sp = SYSTEM_PROMPT
    assert "Verify promptly" in sp, "verify-promptly cap-binding rule missing"
    assert "VERY NEXT action is `verify`" in sp


def test_fix4_library_no_service_verify_guidance_present() -> None:
    """Fix #4 (2026-05-24): library-only CVEs (no listening service) must be
    verified with exec_check ONLY — no http_check / scaffold server (which can
    crash and sink the run, e.g. CVE-2022-21231 deep-get-set), and a failing
    scaffold check should be dropped + re-verified rather than ending partial."""
    sp = SYSTEM_PROMPT
    assert "exec_check ONLY" in sp, "library-verify rule (exec_check only) missing"
    assert "http.createServer" in sp, "must warn against scaffolding a listener"
    assert "DROP that check and re-verify" in sp, "drop-and-re-verify guidance missing"


def test_fix8_continuation_verify_imperative_present() -> None:
    """#3b (2026-06-02): the fix8 continuation re-prompt (CONTINUATION_USER_PROMPT)
    must IMPERATIVELY steer a launched env to verify, not exploratory Bash — tier-1
    forensic (CVE-2022-25396) showed the agent doing Bash/Read instead of verify
    after the gate fired. LOW-CONFIDENCE (prompt-follow-through); drift-locked so a
    future edit can't silently drop it; efficacy measured on the next bench."""
    from cve_env.agent.prompts import CONTINUATION_USER_PROMPT as p

    assert "ALREADY running" in p
    assert "ONLY next action is `verify`" in p
    assert "do NOT call Bash/Read to inspect" in p
