"""Phase 54-deep.3 RED tests for Cand 3-W api_overload runtime wiring.

`_classify_api_overload` (loop.py:178) currently exists but is only
called post-hoc from cli.py:595 for path-categorization. The runtime
hot path (loop.py exception handler) does NOT invoke it; SDK exceptions
matching "API Error: Repeated 529 Overloaded errors" fall through to
generic terminal_status_on_err="error" with give_up_reason="".

Phase 54-deep.3 wires the classifier into the exception handler so:
- When SDK raises with str(exc) matching the 529 Overload pattern,
  loop.py sets state.give_up_reason="api_overload" so downstream
  consumers (Outcome.give_up_reason, cli.py path-categorize, bench
  narrative) see a clean classification instead of empty.

Paired with NO prompt change (api_overload is an external Anthropic
outage class, NOT agent-behavior-under-uncertainty per past-bench-
lessons §1 #1). Runtime-only fix; nothing the agent can do differently.

TDD discipline per Phase 35 / 51B / 53-impl.1.1 / 54-deep.1.1 / 54-deep.2.1:
xfail(strict=True) at RED, atomic removal at GREEN.
"""

from __future__ import annotations

import pytest

pytest.importorskip("claude_agent_sdk")

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import patch


def test_loop_exception_handler_wires_classify_api_overload() -> None:
    """Source-inspection: loop.py exception handler must reference
    _classify_api_overload in proximity to setting state.give_up_reason
    to api_overload. The function is currently defined at loop.py:178
    but only used in cli.py post-hoc."""
    import inspect

    from cve_env.agent import loop as loop_module

    src = inspect.getsource(loop_module)
    # The runtime wiring must contain the assignment to state.give_up_reason
    # — the literal "api_overload" alone appears in the helper docstring
    # so we must look for the runtime assignment specifically.
    assert 'state.give_up_reason = "api_overload"' in src, (
        "loop.py does not assign state.give_up_reason to api_overload (runtime wiring missing)"
    )
    idx = src.find('state.give_up_reason = "api_overload"')
    # Within 600 chars upstream, expect _classify_api_overload(str(exc)) call
    window_up = src[max(0, idx - 600) : idx]
    assert "_classify_api_overload" in window_up, (
        "api_overload assignment missing _classify_api_overload call within 600 chars upstream"
    )
    # Within 600 chars upstream, expect str(exc) since the classifier takes
    # the exception message
    assert "str(exc)" in window_up, (
        "api_overload assignment not driven by str(exc) within 600 chars upstream"
    )


def _cve() -> Any:
    from cve_env.models import CveRecord

    return CveRecord(
        cve_id="CVE-TEST-APIOVERLOAD",
        product="testproduct",
        version="1.0.0",
        description="Test fixture for Phase 54-deep.3 api_overload wiring",
    )


def _host() -> Any:
    from cve_env.models import HostInfo

    return HostInfo(arch="arm64", os="darwin", rosetta_available=True)


def test_outcome_give_up_reason_set_to_api_overload_on_529_exception(
    tmp_path: Path,
) -> None:
    """Behavioral end-to-end: drive build() with a fake run_agent that
    raises a RuntimeError with the canonical 'API Error: Repeated 529
    Overloaded errors' message. Assert outcome.give_up_reason is
    'api_overload' (not empty)."""
    from cve_env.agent.loop import build

    async def fake_run_agent_with_overload(
        *,
        system_prompt: str,
        user_prompt: str,
        tools: Any,
        model: str = "",
        max_turns: int = 12,
        max_cost_usd: float = 0.5,
        on_message: Any = None,
        mcp_server_name: str = "cve_env",
        resume: str | None = None,
        verify_passed_check: Any = None,
    ) -> Any:
        # Canonical 529 Overload message (Phase 31 014156 28-CVE pattern).
        raise RuntimeError(
            "API Error: Repeated 529 Overloaded errors. The API is at capacity. "
            "Please try again later."
        )

    with patch("cve_env.agent.loop.run_agent", fake_run_agent_with_overload):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="phase54-deep-3-apioverload",
                audit_root=tmp_path,
            )
        )

    # The give_up_reason should be set to api_overload by the runtime
    # classifier wiring.
    assert outcome.give_up_reason == "api_overload", (
        f"expected give_up_reason='api_overload'; got: {outcome.give_up_reason!r}"
    )


def test_non_529_exception_does_not_set_api_overload(
    tmp_path: Path,
) -> None:
    """Regression-guard (GREEN at RED time): a generic RuntimeError
    without the 529 Overload signature must NOT set
    give_up_reason='api_overload'. Passes pre-fix (give_up_reason
    starts empty for generic errors); must stay GREEN post-fix
    (classifier must be specific to the 529 pattern)."""
    from cve_env.agent.loop import build

    async def fake_run_agent_generic_error(
        *,
        system_prompt: str,
        user_prompt: str,
        tools: Any,
        model: str = "",
        max_turns: int = 12,
        max_cost_usd: float = 0.5,
        on_message: Any = None,
        mcp_server_name: str = "cve_env",
        resume: str | None = None,
        verify_passed_check: Any = None,
    ) -> Any:
        # Generic non-Overload error.
        raise RuntimeError("Some transient network glitch.")

    with patch("cve_env.agent.loop.run_agent", fake_run_agent_generic_error):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="phase54-deep-3-generic",
                audit_root=tmp_path,
            )
        )

    # Generic errors should NOT trigger api_overload classification.
    assert outcome.give_up_reason != "api_overload", (
        f"api_overload incorrectly set on non-529 error; "
        f"got give_up_reason={outcome.give_up_reason!r}"
    )
