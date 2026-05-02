"""Schema-validated tests for ``AnthropicToolUseProvider``.

The ``test_anthropic.py`` companion file uses hand-built stubs that
mirror the SDK's wire shape. This file uses the **real** SDK types
(``anthropic.types.Message``, ``Usage``, ``TextBlock``,
``ToolUseBlock``) to construct response objects — catching the bug
class hand-built stubs miss: field-name typos, schema drift, and
type-shape mismatches.

These tests don't hit the network: the ``Anthropic`` client object is
still stubbed, but the response objects it returns are validated by
the SDK's own Pydantic models. If a future ``anthropic`` SDK rev
renames ``cache_read_input_tokens`` or removes ``pause_turn`` from
the stop_reason Literal, these tests fail loud at construction —
exactly when the live API would have started rejecting our requests.
"""

from __future__ import annotations

from typing import Any

import pytest

# Skip this whole file in environments without the anthropic SDK
# installed (CI matrix runs that don't pip install it). The provider
# itself soft-imports and raises a clean RuntimeError on construction;
# these tests can't run without the real types.
anthropic_types = pytest.importorskip("anthropic.types")

# Real SDK types — construction here validates fields against the
# SDK's Pydantic schemas. If anything below fails to import or
# construct, our wire-format assumptions in anthropic.py are stale.
Message = anthropic_types.Message
SDKTextBlock = anthropic_types.TextBlock
SDKToolUseBlock = anthropic_types.ToolUseBlock
Usage = anthropic_types.Usage

from core.llm.tool_use import (
    Message as OurMessage,
    StopReason,
    TextBlock,
    ToolCall,
)
from core.llm.tool_use.anthropic import AnthropicToolUseProvider


# ---------------------------------------------------------------------------
# Helpers — build a real anthropic.types.Message envelope
# ---------------------------------------------------------------------------


def _make_real_message(
    content: list[Any],
    stop_reason: str = "end_turn",
    *,
    input_tokens: int = 100,
    output_tokens: int = 50,
    cache_read_input_tokens: int | None = None,
    cache_creation_input_tokens: int | None = None,
) -> Message:
    """Build a real ``anthropic.types.Message`` from real block types.
    Pydantic validation runs at construction — any field name or type
    drift breaks the test immediately."""
    return Message(
        id="msg_test_01",
        model="claude-opus-4-6",
        role="assistant",
        type="message",
        content=content,
        stop_reason=stop_reason,                           # type: ignore[arg-type]
        stop_sequence=None,
        usage=Usage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_input_tokens=cache_read_input_tokens,
            cache_creation_input_tokens=cache_creation_input_tokens,
        ),
        container=None,
    )


class _ClientWithRealResponse:
    """Stub Anthropic client whose ``messages.create`` returns the
    real ``Message`` we hand it — the rest of the SDK isn't exercised."""

    def __init__(self, response: Message) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

        class _Messages:
            def create(_self, **kwargs: Any) -> Message:
                self.calls.append(kwargs)
                return self._response

        self.messages = _Messages()
        self.beta = type("_Beta", (), {"messages": self.messages})()


def _provider_with_real_response(response: Message) -> AnthropicToolUseProvider:
    p = AnthropicToolUseProvider("claude-opus-4-6")
    p._client = _ClientWithRealResponse(response)         # type: ignore[attr-defined]
    return p


def _user_msg(text: str) -> OurMessage:
    return OurMessage(role="user", content=[TextBlock(text=text)])


# ---------------------------------------------------------------------------
# Stop-reason values — schema confirms exact set
# ---------------------------------------------------------------------------


def test_real_sdk_stop_reasons_match_our_mapping() -> None:
    """The ``Message.stop_reason`` Literal in the real SDK is the
    authoritative source of valid values. Our ``_STOP_REASON_MAP``
    must cover every value the SDK can emit, otherwise unmapped
    stops fall through to ``ERROR`` and the loop terminates wrongly.

    This test extracts the SDK's literal set via Pydantic's field
    metadata and asserts each value has a corresponding mapping.
    """
    import typing
    from core.llm.tool_use.anthropic import _STOP_REASON_MAP

    # Pydantic stores the field's annotation; Optional[Literal[...]]
    # → Union[Literal[...], None]. Walk to find the Literal.
    stop_reason_anno = Message.model_fields["stop_reason"].annotation
    sdk_literals: set[str] = set()
    for arg in typing.get_args(stop_reason_anno):
        if arg is type(None):
            continue
        sdk_literals.update(typing.get_args(arg))

    unmapped = sdk_literals - set(_STOP_REASON_MAP.keys())
    assert not unmapped, (
        f"SDK stop_reason values not handled by _STOP_REASON_MAP: "
        f"{unmapped}. Update anthropic.py to map these to a "
        f"StopReason."
    )


# ---------------------------------------------------------------------------
# Block normalisation — real SDK blocks survive turn() unchanged
# ---------------------------------------------------------------------------


def test_real_text_block_normalises_correctly() -> None:
    response = _make_real_message(
        content=[SDKTextBlock(type="text", text="hello world", citations=None)],
        stop_reason="end_turn",
    )
    p = _provider_with_real_response(response)
    out = p.turn(messages=[_user_msg("p")], tools=[])

    assert out.stop_reason is StopReason.COMPLETE
    assert len(out.content) == 1
    assert isinstance(out.content[0], TextBlock)
    assert out.content[0].text == "hello world"


def test_real_tool_use_block_normalises_correctly() -> None:
    response = _make_real_message(
        content=[SDKToolUseBlock(
            type="tool_use",
            id="toolu_xyz",
            name="echo",
            input={"q": "y", "n": 7},
        )],
        stop_reason="tool_use",
    )
    p = _provider_with_real_response(response)
    out = p.turn(messages=[_user_msg("p")], tools=[])

    assert out.stop_reason is StopReason.NEEDS_TOOL_CALL
    assert len(out.content) == 1
    call = out.content[0]
    assert isinstance(call, ToolCall)
    assert call.id == "toolu_xyz"
    assert call.name == "echo"
    assert call.input == {"q": "y", "n": 7}


def test_real_mixed_text_plus_tool_use_normalises_both() -> None:
    """Anthropic emits text + tool_use in a single response. Both
    must survive the conversion (the loop's tool-dispatch logic
    iterates ``isinstance(block, ToolCall)`` to find the calls)."""
    response = _make_real_message(
        content=[
            SDKTextBlock(type="text", text="checking...", citations=None),
            SDKToolUseBlock(type="tool_use", id="toolu_abc",
                            name="search", input={"q": "x"}),
        ],
        stop_reason="tool_use",
    )
    p = _provider_with_real_response(response)
    out = p.turn(messages=[_user_msg("p")], tools=[])

    assert len(out.content) == 2
    assert isinstance(out.content[0], TextBlock)
    assert out.content[0].text == "checking..."
    assert isinstance(out.content[1], ToolCall)
    assert out.content[1].name == "search"


# ---------------------------------------------------------------------------
# Stop-reason mapping — every real Literal value
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("native, expected", [
    ("end_turn", StopReason.COMPLETE),
    ("stop_sequence", StopReason.COMPLETE),
    ("tool_use", StopReason.NEEDS_TOOL_CALL),
    ("pause_turn", StopReason.PAUSE_TURN),
    ("max_tokens", StopReason.MAX_TOKENS),
    ("refusal", StopReason.REFUSED),
])
def test_each_real_stop_reason_normalises(
    native: str, expected: StopReason,
) -> None:
    """Each value in the SDK's ``stop_reason`` Literal maps to the
    expected ``StopReason``. Constructed via the real ``Message`` so
    SDK-side validation rejects invalid Literal values at test-build
    time — no way to silently test against a typo."""
    response = _make_real_message(
        content=[SDKTextBlock(type="text", text="x", citations=None)],
        stop_reason=native,
    )
    p = _provider_with_real_response(response)
    out = p.turn(messages=[_user_msg("p")], tools=[])
    assert out.stop_reason is expected


# ---------------------------------------------------------------------------
# Usage / cache fields — real SDK Usage shape
# ---------------------------------------------------------------------------


def test_real_usage_input_output_tokens_pass_through() -> None:
    """``Usage.input_tokens`` and ``Usage.output_tokens`` are required
    int fields per the SDK schema — we surface them on TurnResponse."""
    response = _make_real_message(
        content=[SDKTextBlock(type="text", text="x", citations=None)],
        stop_reason="end_turn",
        input_tokens=1234,
        output_tokens=567,
    )
    p = _provider_with_real_response(response)
    out = p.turn(messages=[_user_msg("p")], tools=[])
    assert out.input_tokens == 1234
    assert out.output_tokens == 567


def test_real_usage_cache_fields_pass_through() -> None:
    """``cache_read_input_tokens`` and ``cache_creation_input_tokens``
    are Optional[int] in the SDK — we surface them as 0 when None,
    real values when set."""
    response = _make_real_message(
        content=[SDKTextBlock(type="text", text="x", citations=None)],
        stop_reason="end_turn",
        cache_read_input_tokens=2000,
        cache_creation_input_tokens=300,
    )
    p = _provider_with_real_response(response)
    out = p.turn(messages=[_user_msg("p")], tools=[])
    assert out.cache_read_tokens == 2000
    assert out.cache_write_tokens == 300


def test_real_usage_with_none_cache_fields_normalises_to_zero() -> None:
    """When the API omits cache fields (``None`` per SDK), our wire
    converter must not propagate None into ``int``-typed
    ``cache_read_tokens`` / ``cache_write_tokens`` fields. v1 of the
    code did ``getattr(usage, ..., 0)`` — but ``getattr`` returns the
    actual ``None`` since the attribute exists, not the default. This
    test would catch that bug."""
    response = _make_real_message(
        content=[SDKTextBlock(type="text", text="x", citations=None)],
        stop_reason="end_turn",
        cache_read_input_tokens=None,
        cache_creation_input_tokens=None,
    )
    p = _provider_with_real_response(response)
    out = p.turn(messages=[_user_msg("p")], tools=[])
    assert out.cache_read_tokens == 0
    assert out.cache_write_tokens == 0


# ---------------------------------------------------------------------------
# Cost computation against real Usage values
# ---------------------------------------------------------------------------


def test_real_usage_drives_cost_computation_correctly() -> None:
    """Real Usage with cache fields → cost matches Anthropic's
    documented multipliers (cache write 1.25x, cache read 0.1x)."""
    response = _make_real_message(
        content=[SDKTextBlock(type="text", text="x", citations=None)],
        stop_reason="end_turn",
        input_tokens=1000,
        output_tokens=500,
        cache_read_input_tokens=10_000,
        cache_creation_input_tokens=2_000,
    )
    p = _provider_with_real_response(response)
    out = p.turn(messages=[_user_msg("p")], tools=[])

    # opus-4-6: in $5/M, out $25/M
    expected = (
        1000 * 5
        + 500 * 25
        + 10_000 * 5 * 0.1                                  # cache read
        + 2_000 * 5 * 1.25                                  # cache write
    ) / 1_000_000
    assert abs(p.compute_cost(out) - expected) < 1e-9
