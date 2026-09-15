"""x-source known-values seeding for RESUMED conversations.

The pre-dispatch gate's contract is "discovered values must come from
the prompt or prior tool outputs". In-run, only user text and
successful tool results enter ``known_values`` — the model's own prose
never does. Seeding from history must apply the SAME rule: pre-fix,
``run_with_history`` seeded from every message's TextBlocks with no
role filter, so a value the model merely asserted in a prior run's
prose became "discovered" after persist/resume, laundering
injected/hallucinated assistant text past ``ToolCallBlocked``.
"""

from __future__ import annotations

from core.llm.tool_use import (
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolCallReturned,
    ToolDef,
    ToolResult,
    TurnResponse,
)
from core.llm.tool_use.loop import ToolUseLoop
from core.llm.tool_use.types import ToolCallBlocked

SHA = "deadbeef00112233"


class _FakeProvider:
    def __init__(self, responses: list[TurnResponse]) -> None:
        self._responses = list(responses)

    def supports_tool_use(self) -> bool: return True
    def supports_prompt_caching(self) -> bool: return True
    def supports_parallel_tools(self) -> bool: return True
    def context_window(self) -> int: return 200_000
    def price_per_million(self) -> tuple[float, float]: return (3.0, 15.0)
    def estimate_tokens(self, text: str) -> int: return max(len(text) // 4, 1)

    def compute_cost(self, response: TurnResponse) -> float:
        return 0.0

    def turn(self, messages, tools, *, system, max_tokens, cache_control,
             **provider_specific) -> TurnResponse:
        if not self._responses:
            raise RuntimeError("fake provider exhausted")
        return self._responses.pop(0)


def _use_sha_tool() -> ToolDef:
    return ToolDef(
        name="use_sha",
        description="uses a discovered sha",
        input_schema={
            "type": "object",
            "properties": {
                "sha": {"type": "string", "x-source": "discovered"},
            },
        },
        handler=lambda inp: f"got {inp.get('sha')}",
    )


def _run_resumed(history: list[Message]):
    events: list = []
    fp = _FakeProvider([
        TurnResponse(
            content=[ToolCall(id="c1", name="use_sha",
                              input={"sha": SHA})],
            stop_reason=StopReason.NEEDS_TOOL_CALL,
            input_tokens=1, output_tokens=1,
        ),
        TurnResponse(
            content=[TextBlock(text="done")],
            stop_reason=StopReason.COMPLETE,
            input_tokens=1, output_tokens=1,
        ),
    ])
    loop = ToolUseLoop(fp, [_use_sha_tool()], events=events.append)
    loop.run_with_history(history, "continue the analysis")
    blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
    returned = [e for e in events if isinstance(e, ToolCallReturned)]
    return blocked, returned


class TestResumedSeeding:
    def test_assistant_prose_does_not_seed(self):
        """A value that only ever appeared in assistant text must stay
        undiscovered on resume — same verdict the in-run gate gives."""
        history = [
            Message(role="user", content=[TextBlock(text="analyse this")]),
            Message(role="assistant", content=[
                TextBlock(text=f"I believe the target sha is {SHA}"),
            ]),
        ]
        blocked, returned = _run_resumed(history)
        assert len(blocked) == 1
        assert blocked[0].call.name == "use_sha"
        # The blocked call surfaces only as an is_error placeholder —
        # the handler never ran.
        assert all(r.result.is_error for r in returned)

    def test_user_text_seeds(self):
        history = [
            Message(role="user", content=[
                TextBlock(text=f"the sha to inspect is {SHA}"),
            ]),
            Message(role="assistant", content=[TextBlock(text="ok")]),
        ]
        blocked, returned = _run_resumed(history)
        assert blocked == []
        assert any(SHA in r.result.content for r in returned)

    def test_successful_tool_result_seeds(self):
        history = [
            Message(role="user", content=[TextBlock(text="analyse this")]),
            Message(role="assistant", content=[
                ToolCall(id="c0", name="discover", input={}),
            ]),
            Message(role="user", content=[
                ToolResult(tool_use_id="c0", content=f'{{"sha": "{SHA}"}}'),
            ]),
        ]
        blocked, returned = _run_resumed(history)
        assert blocked == []
        assert any(SHA in r.result.content for r in returned)

    def test_error_tool_result_does_not_seed(self):
        """Error results don't seed in-run; resumed histories match."""
        history = [
            Message(role="user", content=[TextBlock(text="analyse this")]),
            Message(role="assistant", content=[
                ToolCall(id="c0", name="discover", input={}),
            ]),
            Message(role="user", content=[
                ToolResult(tool_use_id="c0",
                           content=f'{{"sha": "{SHA}"}}', is_error=True),
            ]),
        ]
        blocked, returned = _run_resumed(history)
        assert len(blocked) == 1
        assert all(r.result.is_error for r in returned)

    def test_in_run_assistant_prose_still_does_not_seed(self):
        """In-run behaviour is unchanged: the model announcing a value
        in prose does not discover it."""
        events: list = []
        fp = _FakeProvider([
            TurnResponse(
                content=[TextBlock(text=f"the sha must be {SHA}"),
                         ToolCall(id="c1", name="use_sha",
                                  input={"sha": SHA})],
                stop_reason=StopReason.NEEDS_TOOL_CALL,
                input_tokens=1, output_tokens=1,
            ),
            TurnResponse(
                content=[TextBlock(text="done")],
                stop_reason=StopReason.COMPLETE,
                input_tokens=1, output_tokens=1,
            ),
        ])
        loop = ToolUseLoop(fp, [_use_sha_tool()], events=events.append)
        loop.run("go")
        blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
        assert len(blocked) == 1


# ---------------------------------------------------------------------------
# Envelope-wrapped persisted histories — the shape the loop itself
# persists (``ToolLoopResult.messages`` carries wrap_tool_result output,
# not raw JSON). Seeding must unwrap before extraction so resume applies
# the same JSON-leaf rule as in-run discovery.
# ---------------------------------------------------------------------------

from core.security.prompt_envelope import wrap_tool_result  # noqa: E402

MULTIWORD = "multi word value"


def _use_note_tool() -> ToolDef:
    return ToolDef(
        name="use_note",
        description="uses a discovered note",
        input_schema={
            "type": "object",
            "properties": {
                "note": {"type": "string", "x-source": "discovered"},
            },
        },
        handler=lambda inp: f"got {inp.get('note')}",
    )


def _run_resumed_with(history: list[Message], call_input: dict):
    events: list = []
    fp = _FakeProvider([
        TurnResponse(
            content=[ToolCall(id="c1", name="use_note", input=call_input)],
            stop_reason=StopReason.NEEDS_TOOL_CALL,
            input_tokens=1, output_tokens=1,
        ),
        TurnResponse(
            content=[TextBlock(text="done")],
            stop_reason=StopReason.COMPLETE,
            input_tokens=1, output_tokens=1,
        ),
    ])
    loop = ToolUseLoop(fp, [_use_note_tool()], events=events.append)
    loop.run_with_history(history, "continue the analysis")
    blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
    returned = [e for e in events if isinstance(e, ToolCallReturned)]
    return blocked, returned


def _wrapped_history(result_json: str, *,
                     with_raw: bool = True) -> list[Message]:
    """The shape the loop itself persists: wrapped content plus the
    raw provenance on ``raw_content`` (omit it to model a history
    that violated the persistence contract)."""
    return [
        Message(role="user", content=[TextBlock(text="analyse this")]),
        Message(role="assistant", content=[
            ToolCall(id="c0", name="discover", input={}),
        ]),
        Message(role="user", content=[
            ToolResult(tool_use_id="c0",
                       content=wrap_tool_result(result_json, "discover"),
                       raw_content=result_json if with_raw else None),
        ]),
    ]


class TestWrappedHistorySeeding:
    def test_multiword_leaf_survives_persist_resume(self):
        """False-block direction: a whitespace-containing JSON leaf the
        run legitimately discovered must stay discovered after
        persist/resume. Pre-fix the wrapped string failed json.loads,
        the tokenisation fallback split the leaf apart, and the resumed
        dispatch was spuriously blocked."""
        history = _wrapped_history(f'{{"note": "{MULTIWORD}"}}')
        blocked, returned = _run_resumed_with(history,
                                              {"note": MULTIWORD})
        assert blocked == []
        assert any(MULTIWORD in r.result.content for r in returned)

    def test_json_key_does_not_launder_through_resume(self):
        """Laundering direction: in-run discovery seeds JSON leaf
        strings only — key names never seed. Pre-fix the tokenisation
        fallback over the wrapped string seeded key names from
        attacker-controllable tool output, so a value the in-run gate
        refused dispatched after a persist/resume cycle."""
        history = _wrapped_history('{"secretkey987": "smallvalue"}')
        blocked, returned = _run_resumed_with(history,
                                              {"note": "secretkey987"})
        assert len(blocked) == 1
        assert blocked[0].call.name == "use_note"
        assert all(r.result.is_error for r in returned)

    def test_leaf_value_still_seeds_when_wrapped(self):
        """The leaf VALUE of the same wrapped result stays discovered —
        unwrapping restores the in-run JSON-leaf rule symmetrically."""
        history = _wrapped_history('{"secretkey987": "smallvalue"}')
        blocked, _ = _run_resumed_with(history, {"note": "smallvalue"})
        assert blocked == []

    def test_round_trip_result_messages_reseed_like_in_run(self):
        """Feed ``ToolLoopResult.messages`` straight back into
        ``run_with_history`` — the docstring's persist/resume contract
        ("SAME trust rule as in-run discovery") on the loop's own
        persisted shape."""
        discover = ToolDef(
            name="discover",
            description="returns a note",
            input_schema={"type": "object", "properties": {}},
            handler=lambda inp: f'{{"note": "{MULTIWORD}"}}',
        )
        fp1 = _FakeProvider([
            TurnResponse(
                content=[ToolCall(id="c0", name="discover", input={})],
                stop_reason=StopReason.NEEDS_TOOL_CALL,
                input_tokens=1, output_tokens=1,
            ),
            TurnResponse(
                content=[TextBlock(text="found it")],
                stop_reason=StopReason.COMPLETE,
                input_tokens=1, output_tokens=1,
            ),
        ])
        loop1 = ToolUseLoop(fp1, [discover, _use_note_tool()])
        first = loop1.run("go")

        blocked, returned = _run_resumed_with(list(first.messages),
                                              {"note": MULTIWORD})
        assert blocked == []
        assert any(MULTIWORD in r.result.content for r in returned)


class TestSeedingProvenance:
    """Resume seeding trusts ``raw_content`` provenance, never a
    textual unwrap heuristic: a loop-wrapped result and attacker
    output that ARRIVED envelope-shaped are byte-indistinguishable, so
    envelope-shaped content without raw provenance seeds nothing
    (fail closed — the safe, false-block direction, and only for
    histories that violated the persistence contract)."""

    def test_attacker_envelope_shaped_raw_history_seeds_nothing(self):
        """Reviewer shape: a hand-built raw history whose ToolResult
        content IS a pristine envelope wrapping JSON. Unwrapping it
        would seed the whitespace-containing inner leaf — a value the
        in-run tokenisation rule refused for this raw shape."""
        from core.security.prompt_envelope import wrap_untrusted

        attacker_content = wrap_untrusted(
            f'{{"note": "{MULTIWORD}"}}', kind="tool-result",
            origin="discover",
        )
        history = [
            Message(role="user", content=[TextBlock(text="analyse this")]),
            Message(role="assistant", content=[
                ToolCall(id="c0", name="discover", input={}),
            ]),
            Message(role="user", content=[
                ToolResult(tool_use_id="c0", content=attacker_content),
            ]),
        ]
        blocked, returned = _run_resumed_with(history,
                                              {"note": MULTIWORD})
        assert len(blocked) == 1
        assert all(r.result.is_error for r in returned)

    def test_wrapped_without_raw_provenance_seeds_nothing(self):
        """A loop-shaped wrapped block that lost its raw_content (a
        consumer that serialised only role/content) fails closed —
        even the legitimate leaf value stays undiscovered rather than
        risking the unwrap-laundering direction."""
        history = _wrapped_history('{"note": "smallvalue"}',
                                   with_raw=False)
        blocked, _ = _run_resumed_with(history, {"note": "smallvalue"})
        assert len(blocked) == 1

    def test_plain_raw_history_still_seeds_in_run_rule(self):
        """Control: non-envelope raw content keeps the exact in-run
        rule (JSON-leaf extraction on the content itself)."""
        history = [
            Message(role="user", content=[TextBlock(text="analyse this")]),
            Message(role="assistant", content=[
                ToolCall(id="c0", name="discover", input={}),
            ]),
            Message(role="user", content=[
                ToolResult(tool_use_id="c0",
                           content=f'{{"note": "{MULTIWORD}"}}'),
            ]),
        ]
        blocked, _ = _run_resumed_with(history, {"note": MULTIWORD})
        assert blocked == []


# ---------------------------------------------------------------------------
# Loop-injected user text — the loop's own nudges/steering never seed
# in-run; resume must apply the same rule instead of reading them as
# user-authored (in_fire_mutator text can quote tool output the in-run
# rule refused, so seeding it launders those tokens after one resume).
# ---------------------------------------------------------------------------


class TestLoopInjectedSeeding:
    def test_tagged_loop_injected_text_does_not_seed(self):
        history = [
            Message(role="user", content=[TextBlock(text="analyse this")]),
            Message(role="assistant", content=[TextBlock(text="ok")]),
            Message(role="user", content=[
                TextBlock(text=f"steering: consider sha {SHA}",
                          loop_injected=True),
            ]),
        ]
        blocked, returned = _run_resumed(history)
        assert len(blocked) == 1
        assert all(r.result.is_error for r in returned)

    def test_untagged_text_with_same_role_still_seeds(self):
        # Genuine user text is untouched by the injected-block rule.
        history = [
            Message(role="user", content=[
                TextBlock(text=f"please inspect sha {SHA}"),
            ]),
            Message(role="assistant", content=[TextBlock(text="ok")]),
        ]
        blocked, _ = _run_resumed(history)
        assert blocked == []

    def test_untagged_static_nudge_text_does_not_seed(self):
        """Histories rebuilt without the tag (a consumer serialising
        only role/text) still refuse the loop's STATIC nudge strings
        by exact text."""
        nudge = f"no tool call — try the sha {SHA} with use_sha"
        events: list = []
        submit = ToolDef(
            name="submit",
            description="finalise",
            input_schema={"type": "object"},
            handler=lambda inp: "submitted",
        )
        fp = _FakeProvider([
            TurnResponse(
                content=[ToolCall(id="c1", name="use_sha",
                                  input={"sha": SHA})],
                stop_reason=StopReason.NEEDS_TOOL_CALL,
                input_tokens=1, output_tokens=1,
            ),
            TurnResponse(
                content=[ToolCall(id="c2", name="submit", input={})],
                stop_reason=StopReason.NEEDS_TOOL_CALL,
                input_tokens=1, output_tokens=1,
            ),
        ])
        loop = ToolUseLoop(
            fp, [_use_sha_tool(), submit], events=events.append,
            terminal_tool="submit",
            nudge_on_no_tool_call=nudge,
        )
        history = [
            Message(role="user", content=[TextBlock(text="analyse this")]),
            Message(role="assistant", content=[TextBlock(text="prose")]),
            Message(role="user", content=[TextBlock(text=nudge)]),
        ]
        loop.run_with_history(history, "continue")
        blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
        assert len(blocked) == 1

    def test_round_trip_nudge_never_seeds(self):
        """The loop's own persisted shape: a nudge injected in run 1
        (tagged at append time) must not seed run 2's known_values."""
        nudge = f"keep going — sha {SHA} might matter"
        fp1 = _FakeProvider([
            TurnResponse(
                content=[TextBlock(text="thinking...")],
                stop_reason=StopReason.COMPLETE,
                input_tokens=1, output_tokens=1,
            ),
            TurnResponse(
                content=[TextBlock(text="still thinking")],
                stop_reason=StopReason.COMPLETE,
                input_tokens=1, output_tokens=1,
            ),
        ])
        loop1 = ToolUseLoop(
            fp1, [_use_sha_tool()], max_iterations=2,
            nudge_on_no_tool_call=nudge,
        )
        first = loop1.run("go")
        injected = [
            b for m in first.messages if m.role == "user"
            for b in m.content
            if isinstance(b, TextBlock) and b.text == nudge
        ]
        assert injected and all(b.loop_injected for b in injected)

        events: list = []
        fp2 = _FakeProvider([
            TurnResponse(
                content=[ToolCall(id="c1", name="use_sha",
                                  input={"sha": SHA})],
                stop_reason=StopReason.NEEDS_TOOL_CALL,
                input_tokens=1, output_tokens=1,
            ),
            TurnResponse(
                content=[TextBlock(text="done")],
                stop_reason=StopReason.COMPLETE,
                input_tokens=1, output_tokens=1,
            ),
        ])
        loop2 = ToolUseLoop(fp2, [_use_sha_tool()], events=events.append)
        loop2.run_with_history(list(first.messages), "continue")
        blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
        assert len(blocked) == 1
