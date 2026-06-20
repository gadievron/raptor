"""Proprietary-verify continuation gate (2026-06-05, agentic, default-OFF).

Design: a give_up(`proprietary`) reasoned from the target's name/metadata WITHOUT
probing can FALSE-POSITIVE on an open-source product from a vendor that also ships
closed software (the Spring4Shell/vmware, Oracle→MySQL class). (The static
proprietary-vendor blacklist that used to feed such give-ups was removed
2026-06-08; this gate is now the sole runtime backstop for an unprobed give-up.)

This gate is the runtime "verify-the-negative": when the agent gives up
`proprietary` WITHOUT having probed `image_resolve` (a name-only give-up),
re-prompt ONCE to run a single image_resolve before the give-up is final. If an
image resolves, the proprietary give-up is rejected and the build continues; if
not, it stands.

Efficiency preserved: the gate SKIPS proprietary CVEs that ALREADY probed
image_resolve (the 12/51 probed class) — no point re-probing a confirmed negative.

Past-lessons compliance: this is a RUNTIME continuation (mirrors
`_should_continue_for_resolve`), NOT a prompt-only nudge (prompt rules have ~0%
follow-through — see the force-resolve docstring). Default-OFF behind
CVE_ENV_ENABLE_PROPRIETARY_VERIFY_CONTINUATION so control == current production.
"""

from __future__ import annotations

from typing import Any

import pytest


def _run_stub(stop_reason: str = "end_turn", session_id: str = "sess-1") -> Any:
    import types

    return types.SimpleNamespace(stop_reason=stop_reason, session_id=session_id)


def _state(reason: str, tool_names: list[str]) -> Any:
    from cve_env.agent.loop import _StreamState

    st = _StreamState()
    st.give_up_reason = reason
    st.tool_uses_seen = [{"name": n} for n in tool_names]
    return st


@pytest.fixture
def _on(monkeypatch: Any) -> None:
    monkeypatch.setenv("CVE_ENV_ENABLE_PROPRIETARY_VERIFY_CONTINUATION", "1")


def test_gate_on_by_default(monkeypatch: Any) -> None:
    """Default-ON (2026-06-09): post-blacklist-removal the gate is the SOLE runtime
    proprietary backstop, so an unprobed give_up(proprietary) fires the
    verify-the-negative probe by default. Explicit '0'/'false'/'off' disables it."""
    from cve_env.agent.loop import _should_continue_for_proprietary_verify

    # unset → ON by default → fires
    monkeypatch.delenv("CVE_ENV_ENABLE_PROPRIETARY_VERIFY_CONTINUATION", raising=False)
    st = _state("proprietary", ["nvd_lookup", "give_up"])
    assert _should_continue_for_proprietary_verify(_run_stub(), st, 0, 0.1, 2.5) is True
    # explicit "0" → disabled → does NOT fire
    monkeypatch.setenv("CVE_ENV_ENABLE_PROPRIETARY_VERIFY_CONTINUATION", "0")
    st2 = _state("proprietary", ["nvd_lookup", "give_up"])
    assert (
        _should_continue_for_proprietary_verify(_run_stub(), st2, 0, 0.1, 2.5) is False
    )


def test_gate_fires_on_blacklist_trusted_proprietary(_on: None) -> None:
    """The 39/51 no-probe class: give_up(proprietary) with NO image_resolve →
    fire ONE verify probe."""
    from cve_env.agent.loop import _should_continue_for_proprietary_verify

    st = _state("proprietary", ["nvd_lookup", "github_fetch", "give_up"])
    assert _should_continue_for_proprietary_verify(_run_stub(), st, 0, 0.1, 2.5) is True


def test_gate_skips_already_probed_proprietary(_on: None) -> None:
    """The 12/51 probed class: image_resolve already ran (confirmed negative) →
    honor the give_up, do NOT re-probe (efficiency)."""
    from cve_env.agent.loop import _should_continue_for_proprietary_verify

    st = _state("proprietary", ["nvd_lookup", "image_resolve", "give_up"])
    assert (
        _should_continue_for_proprietary_verify(_run_stub(), st, 0, 0.1, 2.5) is False
    )


def test_gate_skips_non_proprietary(_on: None) -> None:
    """Only proprietary give-ups are in scope; no_image/arch/etc. are handled by
    their own gates."""
    from cve_env.agent.loop import _should_continue_for_proprietary_verify

    for reason in ("no_image", "arch_incompatible", "skipped_image_lookup", "budget"):
        st = _state(reason, ["nvd_lookup", "give_up"])
        assert (
            _should_continue_for_proprietary_verify(_run_stub(), st, 0, 0.1, 2.5)
            is False
        ), reason


def test_gate_is_one_shot(_on: None) -> None:
    """Once attempted, never again this CVE."""
    from cve_env.agent.loop import _should_continue_for_proprietary_verify

    st = _state("proprietary", ["nvd_lookup", "give_up"])
    st.proprietary_verify_attempted = True
    assert (
        _should_continue_for_proprietary_verify(_run_stub(), st, 0, 0.1, 2.5) is False
    )


def test_gate_requires_resumable_session(_on: None) -> None:
    """No session id (last_session_id empty AND run.session_id empty) → cannot
    resume → do not fire."""
    from cve_env.agent.loop import _should_continue_for_proprietary_verify

    st = _state("proprietary", ["nvd_lookup", "give_up"])
    assert (
        _should_continue_for_proprietary_verify(
            _run_stub(session_id=""), st, 0, 0.1, 2.5
        )
        is False
    )


def test_gate_respects_max(_on: None) -> None:
    """count >= max disables (default max = 1)."""
    from cve_env.agent.loop import _should_continue_for_proprietary_verify

    st = _state("proprietary", ["nvd_lookup", "give_up"])
    assert (
        _should_continue_for_proprietary_verify(_run_stub(), st, 1, 0.1, 2.5) is False
    )


def test_gate_respects_budget_fraction(_on: None) -> None:
    """Accumulated cost over the force-resolve budget fraction (0.50) of the cap
    leaves no headroom → do not fire."""
    from cve_env.agent.loop import _should_continue_for_proprietary_verify

    st = _state("proprietary", ["nvd_lookup", "give_up"])
    # cost_acc 2.0 of cap 2.5 = 80% >> 50% → blocked
    assert (
        _should_continue_for_proprietary_verify(_run_stub(), st, 0, 2.0, 2.5) is False
    )


# --- known-case experiment: the 2026-06-04 proprietary classes -------------
# 39/51 gave up with ZERO image_resolve (blacklist-trusted) → gate SHOULD fire.
# 12/51 probed image_resolve first (confirmed negative)     → gate should SKIP.
@pytest.mark.parametrize(
    "tools,expect_fire",
    [
        (["nvd_lookup", "give_up"], True),  # Cisco/SAP/Oracle no-probe
        (
            ["nvd_lookup", "github_fetch", "give_up"],
            True,
        ),  # found PoC repo, no image probe
        (
            ["nvd_lookup", "image_resolve", "give_up"],
            False,
        ),  # Zimbra-class: probed, negative
        (
            ["nvd_lookup", "image_resolve", "github_fetch", "give_up"],
            False,
        ),  # probed + searched
    ],
)
def test_known_proprietary_classes(
    _on: None, tools: list[str], expect_fire: bool
) -> None:
    from cve_env.agent.loop import _should_continue_for_proprietary_verify

    st = _state("proprietary", tools)
    assert (
        _should_continue_for_proprietary_verify(_run_stub(), st, 0, 0.1, 2.5)
        is expect_fire
    )


# --- observability-companion guards: the emit surface (loop.py) must be wired to
# the AuditStatus Literal, else the status is a type-unregistered string (the exact
# latent omission force_resolve_continuation hit — see audit.py docstring). ---
def test_proprietary_verify_status_registered_in_audit_status() -> None:
    from typing import get_args
    from cve_env.agent.audit import AuditStatus

    assert "proprietary_verify_continuation" in get_args(AuditStatus)


def test_audit_status_registers_all_continuation_statuses() -> None:
    """Parity guard: every *_continuation status the loop can emit MUST be in the
    AuditStatus Literal. Prevents the force_resolve-class omission for ANY future
    continuation gate."""
    from typing import get_args
    from cve_env.agent.audit import AuditStatus

    registered = set(get_args(AuditStatus))
    for status in (
        "fix8_continuation",
        "force_resolve_continuation",
        "benign_verify_continuation",
        "proprietary_verify_continuation",
    ):
        assert status in registered, (
            f"{status} emitted but not registered in AuditStatus"
        )
