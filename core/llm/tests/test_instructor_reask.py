"""Tool-use / tool-result pairing repair on instructor reask retries.

Reproduces the live failure shape: a structured-output completion
carrying PARALLEL ``tool_use`` blocks fails pydantic validation,
instructor's Anthropic tools-mode reask handler appends the assistant
turn with ALL the tool_use blocks but a ``tool_result`` for only ONE
of them, and the retry request is a guaranteed protocol error::

    400 invalid_request_error: messages.N: `tool_use` ids were found
    without `tool_result` blocks immediately after: ...

The repair layer (core.llm.instructor_reask) must pair every
``tool_use`` id on every reask-assembled conversation, and must be a
silent no-op when instructor is absent.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.llm.instructor_reask import (
    _WRAP_MARKER,
    ensure_anthropic_reask_pairing,
    repair_tool_result_pairing,
)


def _tool_use(block_id: str) -> dict:
    return {
        "type": "tool_use",
        "id": block_id,
        "name": "Answer",
        "input": {"value": block_id},
    }


def _unpaired_ids(messages: list) -> list[str]:
    """The 400's complaint, recomputed locally: tool_use ids in an
    assistant message with no tool_result in the next message."""
    missing: list[str] = []
    for i, msg in enumerate(messages):
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        ids = [
            b.get("id") for b in content
            if isinstance(b, dict) and b.get("type") == "tool_use"
        ]
        if not ids:
            continue
        nxt = messages[i + 1] if i + 1 < len(messages) else None
        answered = set()
        if nxt is not None and nxt.get("role") == "user" and isinstance(
            nxt.get("content"), list,
        ):
            answered = {
                b.get("tool_use_id") for b in nxt["content"]
                if isinstance(b, dict) and b.get("type") == "tool_result"
            }
        missing.extend(t for t in ids if t not in answered)
    return missing


class TestRepairToolResultPairing:
    def test_parallel_tool_use_with_single_result_gets_paired(self):
        """The observed 400 shape: 4 tool_use blocks, 1 tool_result."""
        messages = [
            {"role": "user", "content": "review this function"},
            {
                "role": "assistant",
                "content": [
                    _tool_use("toolu_A"),
                    _tool_use("toolu_B"),
                    _tool_use("toolu_C"),
                    _tool_use("toolu_D"),
                ],
            },
            {
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": "toolu_D",
                    "content": "Validation Error found",
                    "is_error": True,
                }],
            },
        ]
        assert _unpaired_ids(messages) == ["toolu_A", "toolu_B", "toolu_C"]

        inserted = repair_tool_result_pairing(messages)

        assert inserted == 3
        assert _unpaired_ids(messages) == []
        # Original result block survives; synthetic ones are errors.
        results = messages[2]["content"]
        assert all(b["type"] == "tool_result" for b in results)
        assert {b["tool_use_id"] for b in results} == {
            "toolu_A", "toolu_B", "toolu_C", "toolu_D",
        }
        assert all(b["is_error"] for b in results)

    def test_trailing_assistant_tool_use_gets_result_message(self):
        """A conversation ending on an assistant tool_use turn (the
        abort/partial shape) gains a user tool_result message."""
        messages = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [_tool_use("toolu_X")]},
        ]
        inserted = repair_tool_result_pairing(messages)
        assert inserted == 1
        assert len(messages) == 3
        assert messages[2]["role"] == "user"
        assert _unpaired_ids(messages) == []

    def test_string_user_content_is_promoted_to_blocks(self):
        """A plain-text reask user message after a tool_use turn is
        rebuilt as blocks with the results FIRST."""
        messages = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [_tool_use("toolu_X")]},
            {"role": "user", "content": "Validation Error: fix it"},
        ]
        inserted = repair_tool_result_pairing(messages)
        assert inserted == 1
        content = messages[2]["content"]
        assert content[0]["type"] == "tool_result"
        assert content[0]["tool_use_id"] == "toolu_X"
        assert content[1] == {
            "type": "text", "text": "Validation Error: fix it",
        }
        assert _unpaired_ids(messages) == []

    def test_valid_conversation_untouched(self):
        messages = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [_tool_use("toolu_X")]},
            {
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": "toolu_X",
                    "content": "ok",
                }],
            },
            {"role": "assistant", "content": [{
                "type": "text", "text": "done",
            }]},
        ]
        before = [dict(m) for m in messages]
        assert repair_tool_result_pairing(messages) == 0
        assert messages == before

    def test_text_only_and_empty_messages_are_noops(self):
        messages = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": [{
                "type": "text", "text": "hi",
            }]},
        ]
        assert repair_tool_result_pairing(messages) == 0
        assert repair_tool_result_pairing([]) == 0

    def test_consecutive_assistant_tool_use_messages(self):
        """Assistant follows assistant: each gets its own results."""
        messages = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [_tool_use("toolu_1")]},
            {"role": "assistant", "content": [_tool_use("toolu_2")]},
        ]
        inserted = repair_tool_result_pairing(messages)
        assert inserted == 2
        assert _unpaired_ids(messages) == []


class TestInstructorRegistryWrap:
    """End-to-end against the real installed handler (skipped when
    instructor's v2 registry is absent)."""

    @pytest.fixture()
    def registry(self):
        pytest.importorskip("instructor")
        try:
            from instructor.mode import Mode
            from instructor.v2.core.registry import (
                Provider,
                mode_registry,
            )
        except ImportError:
            pytest.skip("instructor v2 registry layout not present")
        handlers = mode_registry.get_handlers(Provider.ANTHROPIC, Mode.TOOLS)
        original = handlers.reask_handler
        # Unwrap so each test exercises a fresh install regardless of
        # what earlier tests (or provider constructions) did.
        while getattr(original, _WRAP_MARKER, False):
            original = original.__wrapped__
        handlers.reask_handler = original
        yield handlers
        handlers.reask_handler = original

    @staticmethod
    def _completion(ids):
        """A stand-in for the SDK Message: content blocks with
        ``.type`` / ``.id`` / ``.model_dump()``."""
        blocks = []
        for block_id in ids:
            dumped = _tool_use(block_id)
            blocks.append(SimpleNamespace(
                type="tool_use",
                id=block_id,
                model_dump=lambda d=dumped, **kw: dict(d),
            ))
        return SimpleNamespace(content=blocks)

    def test_unwrapped_handler_reproduces_the_400_shape(self, registry):
        """Regression oracle: the stock reask handler leaves N-1
        parallel tool_use ids unpaired. If this starts passing 0,
        upstream fixed it and the wrap can be retired."""
        kwargs = registry.reask_handler(
            kwargs={"messages": [{"role": "user", "content": "go"}]},
            response=self._completion(["toolu_A", "toolu_B", "toolu_C"]),
            exception=ValueError("List should have at most 1 item"),
        )
        assert _unpaired_ids(kwargs["messages"]) == ["toolu_A", "toolu_B"]

    def test_wrapped_handler_pairs_every_tool_use(self, registry):
        assert ensure_anthropic_reask_pairing() is True
        kwargs = registry.reask_handler(
            kwargs={"messages": [{"role": "user", "content": "go"}]},
            response=self._completion(["toolu_A", "toolu_B", "toolu_C"]),
            exception=ValueError("List should have at most 1 item"),
        )
        assert _unpaired_ids(kwargs["messages"]) == []

    def test_install_is_idempotent(self, registry):
        assert ensure_anthropic_reask_pairing() is True
        first = registry.reask_handler
        assert ensure_anthropic_reask_pairing() is True
        assert registry.reask_handler is first

    def test_none_response_path_still_works(self, registry):
        """The timeout/abort path hands the handler no completion —
        the wrap must pass it through untouched."""
        assert ensure_anthropic_reask_pairing() is True
        kwargs = registry.reask_handler(
            kwargs={"messages": [{"role": "user", "content": "go"}]},
            response=None,
            exception=ValueError("timed out"),
        )
        assert _unpaired_ids(kwargs["messages"]) == []
        assert kwargs["messages"][-1]["role"] == "user"
