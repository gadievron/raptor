"""A single over-long model turn must not terminate the whole build.

The core engine drives ``ToolUseLoop`` with a per-turn output cap;
a turn cut off by that cap used to terminate the run with
``stop_reason=max_tokens`` (terminal error) even when the agent was
mid-plan with budget left. The engine now opts in to the loop's
bounded max_tokens recovery: the loop injects a be-concise user nudge
and the build continues.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from core.llm.tool_use.types import (
    StopReason,
    TextBlock,
    TurnResponse,
)


def _cve() -> Any:
    from cve_env.models import CveRecord

    return CveRecord(
        cve_id="CVE-TEST-MAXTOKENS",
        product="testproduct",
        version="1.0.0",
        description="Fixture for max_tokens turn recovery",
    )


def _host() -> Any:
    from cve_env.models import HostInfo

    return HostInfo(arch="arm64", os="linux", rosetta_available=False)


class _ScriptedProvider:
    """Replays scripted ``TurnResponse``\\ s and records each turn's
    messages."""

    def __init__(self, responses: list[TurnResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[list[Any]] = []

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
        return 0.001

    def turn(self, messages: Any, tools: Any, **_kw: Any) -> TurnResponse:
        self.calls.append(list(messages))
        return self._responses.pop(0)


def test_over_long_turn_recovers_instead_of_terminal_error(
    tmp_path: Path,
) -> None:
    from cve_env.agent.core_loop import build_core

    provider = _ScriptedProvider([
        TurnResponse(
            content=[TextBlock(text="planning... (cut off)")],
            stop_reason=StopReason.MAX_TOKENS,
            input_tokens=100, output_tokens=4096,
        ),
        TurnResponse(
            content=[TextBlock(text="done, concisely")],
            stop_reason=StopReason.COMPLETE,
            input_tokens=100, output_tokens=50,
        ),
    ])
    with patch("cve_env.agent.core_loop._resolve_provider",
               return_value=provider):
        outcome = build_core(_cve(), _host(),
                             run_id="max-tokens-nudge",
                             audit_root=tmp_path)

    # Pre-fix: the run died on the first turn with the terminal
    # stop_reason "max_tokens". Post-fix: the loop nudged and the
    # second turn completed the run.
    assert outcome.stop_reason == "end_turn", (
        f"expected the build to survive the truncated turn; got "
        f"stop_reason={outcome.stop_reason!r} reason={outcome.reason!r}"
    )
    assert len(provider.calls) == 2
    nudge = provider.calls[1][-1]
    assert nudge.role == "user"
    assert "cut off" in nudge.content[0].text
