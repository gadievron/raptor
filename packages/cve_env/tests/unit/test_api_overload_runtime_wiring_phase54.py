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


from pathlib import Path
from typing import Any
from unittest.mock import patch


def test_loop_exception_handler_wires_classify_api_overload() -> None:
    """Source-inspection: the live engine's (core_loop) exception
    handler must reference _classify_api_overload in proximity to
    setting state.give_up_reason to api_overload."""
    import inspect

    from cve_env.agent import core_loop as loop_module

    src = inspect.getsource(loop_module)
    # The runtime wiring must contain the assignment to state.give_up_reason
    # — the literal "api_overload" alone appears in the helper docstring
    # so we must look for the runtime assignment specifically.
    assert 'state.give_up_reason = "api_overload"' in src, (
        "core_loop.py does not assign state.give_up_reason to api_overload (runtime wiring missing)"
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


def _build_with_raising_provider(tmp_path: Path, message: str) -> Any:
    """Drive the live engine (build_core) with a provider whose turn()
    raises ``message`` — exercises the exception-path classifier."""
    from cve_env.agent.core_loop import build_core

    class _RaisingProvider:
        def supports_tool_use(self) -> bool:
            return True

        def supports_prompt_caching(self) -> bool:
            return True

        def supports_parallel_tools(self) -> bool:
            return True

        def supports_streaming(self) -> bool:
            return False

        def context_window(self) -> int:
            return 200_000

        def price_per_million(self) -> tuple[float, float]:
            return (3.0, 15.0)

        def estimate_tokens(self, text: str) -> int:
            return 1

        def compute_cost(self, response: Any) -> float:
            return 0.0

        def turn(self, *a: Any, **k: Any) -> Any:
            raise RuntimeError(message)

    with patch("cve_env.agent.core_loop._resolve_provider",
               return_value=_RaisingProvider()):
        return build_core(_cve(), _host(),
                          run_id="phase54-deep-3-apioverload",
                          audit_root=tmp_path)


def test_outcome_give_up_reason_set_to_api_overload_on_529_exception(
    tmp_path: Path,
) -> None:
    """Behavioral end-to-end: a provider exception carrying the canonical
    'API Error: Repeated 529 Overloaded errors' message classifies
    give_up_reason='api_overload' and status rate_limited (re-runnable,
    not a CVE-merit failure)."""
    outcome = _build_with_raising_provider(
        tmp_path,
        "API Error: Repeated 529 Overloaded errors. The API is at "
        "capacity. Please try again later.",
    )
    assert outcome.give_up_reason == "api_overload", (
        f"expected give_up_reason='api_overload'; got: {outcome.give_up_reason!r}"
    )
    assert outcome.status == "rate_limited"


def test_non_529_exception_does_not_set_api_overload(
    tmp_path: Path,
) -> None:
    """Regression-guard: a generic provider error without the 529
    signature must NOT classify api_overload."""
    outcome = _build_with_raising_provider(
        tmp_path, "Some transient network glitch.")
    assert outcome.give_up_reason != "api_overload"
    assert outcome.status != "rate_limited"
