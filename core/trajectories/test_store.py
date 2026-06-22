"""Tests for trajectory storage."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from core.llm.tool_use.types import (  # noqa: E402
    Message,
    TextBlock,
    ToolCall,
    ToolResult,
)
from core.trajectories import (  # noqa: E402
    TRAJECTORY_FILENAME,
    TrajectoryRecord,
    serialize_messages,
    trajectory_path,
    write_trajectory,
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _msg_assistant_text(text: str) -> Message:
    return Message(role="assistant", content=[TextBlock(text=text)])


def _msg_assistant_tool_call(tool_name: str, **input_) -> Message:
    return Message(
        role="assistant",
        content=[ToolCall(
            id=f"call-{tool_name}", name=tool_name, input=input_,
        )],
    )


def _msg_user_tool_result(tool_use_id: str, content: str,
                          is_error: bool = False) -> Message:
    return Message(
        role="user",
        content=[ToolResult(
            tool_use_id=tool_use_id, content=content, is_error=is_error,
        )],
    )


def _record(run_id: str = "run-0001", **overrides) -> TrajectoryRecord:
    base = dict(
        run_id=run_id,
        finding_id="FND-77",
        model_name="claude-haiku-4-5",
        cwe="CWE-787",
        terminated_by="terminal_tool",
        iterations=3,
        tool_calls_made=4,
        cost_usd=0.12,
        steps=[],
        timestamp="2026-06-03T14:05:32+00:00",
    )
    base.update(overrides)
    return TrajectoryRecord(**base)


# --------------------------------------------------------------------------
# serialize_messages
# --------------------------------------------------------------------------


def test_serialize_empty_returns_empty():
    assert serialize_messages([]) == []


def test_serialize_text_only_assistant_turn():
    msgs = [_msg_assistant_text("I will call find_symbol next.")]
    [step] = serialize_messages(msgs)
    assert step.role == "assistant"
    assert step.text_blocks == ["I will call find_symbol next."]
    assert step.tool_calls == []
    assert step.tool_results == []
    assert step.iteration == 0


def test_serialize_assistant_tool_call():
    msgs = [_msg_assistant_tool_call("find_symbol", symbol="parse_header")]
    [step] = serialize_messages(msgs)
    assert step.tool_calls == [{
        "id": "call-find_symbol",
        "name": "find_symbol",
        "input": {"symbol": "parse_header"},
    }]


def test_serialize_user_tool_result():
    msgs = [_msg_user_tool_result("call-1", "found at 0x1234")]
    [step] = serialize_messages(msgs)
    assert step.role == "user"
    assert step.tool_results == [{
        "tool_use_id": "call-1",
        "content": "found at 0x1234",
        "is_error": False,
    }]


def test_serialize_iteration_counter_advances_on_assistant():
    """User turns share the iteration index of the preceding assistant
    turn — the counter advances on each assistant turn."""
    msgs = [
        _msg_assistant_text("step 0"),               # iteration 0
        _msg_user_tool_result("c0", "r0"),            # still 1 (next slot)
        _msg_assistant_text("step 1"),               # iteration 1
        _msg_user_tool_result("c1", "r1"),
        _msg_assistant_text("step 2"),               # iteration 2
    ]
    steps = serialize_messages(msgs)
    assert [s.iteration for s in steps] == [0, 1, 1, 2, 2]


def test_serialize_truncates_long_text():
    big = "x" * (200 * 1024)                     # 200 KB > 64 KB cap
    msgs = [_msg_assistant_text(big)]
    [step] = serialize_messages(msgs)
    assert len(step.text_blocks[0]) < len(big)
    assert "truncated" in step.text_blocks[0]


def test_serialize_truncates_long_tool_result():
    big = "y" * (200 * 1024)
    msgs = [_msg_user_tool_result("c0", big)]
    [step] = serialize_messages(msgs)
    assert "truncated" in step.tool_results[0]["content"]


def test_serialize_preserves_mixed_assistant_content():
    """Assistant turn with text + tool call in the same message."""
    msg = Message(role="assistant", content=[
        TextBlock(text="Calling find_symbol."),
        ToolCall(id="c0", name="find_symbol", input={"name": "x"}),
    ])
    [step] = serialize_messages([msg])
    assert step.text_blocks == ["Calling find_symbol."]
    assert len(step.tool_calls) == 1


def test_serialize_preserves_is_error_flag():
    msgs = [_msg_user_tool_result("c0", "tool crashed", is_error=True)]
    [step] = serialize_messages(msgs)
    assert step.tool_results[0]["is_error"] is True


# --------------------------------------------------------------------------
# write_trajectory / trajectory_path
# --------------------------------------------------------------------------


def test_trajectory_path_under_base(tmp_path):
    p = trajectory_path(tmp_path, "run-x")
    assert p == tmp_path / "trajectories" / "run-x" / TRAJECTORY_FILENAME


def test_write_creates_run_dir_and_file(tmp_path):
    rec = _record()
    written = write_trajectory(rec, base=tmp_path)
    assert written.exists()
    assert written.parent.name == "run-0001"
    assert written.parent.parent.name == "trajectories"


def test_write_round_trips_through_json(tmp_path):
    msg = _msg_assistant_tool_call("find_symbol", symbol="parse_header")
    rec = _record(steps=serialize_messages([msg]))
    written = write_trajectory(rec, base=tmp_path)
    data = json.loads(written.read_text())
    assert data["run_id"] == "run-0001"
    assert data["finding_id"] == "FND-77"
    assert len(data["steps"]) == 1
    assert data["steps"][0]["tool_calls"][0]["name"] == "find_symbol"


def test_write_collision_retries_with_random_suffix(tmp_path):
    """If the trajectory path already exists (or is planted as a
    symlink), the write should still land — at a name-suffixed path."""
    rec = _record(run_id="dup")
    first = write_trajectory(rec, base=tmp_path)
    # Second write at same run_id collides and retries.
    second = write_trajectory(rec, base=tmp_path)
    assert second.exists()
    assert second != first
    assert second.parent == first.parent  # same run dir


def test_write_refuses_to_follow_symlink(tmp_path):
    """A symlink planted at the trajectory path must not get its
    target overwritten."""
    rec = _record(run_id="link-x")
    out = trajectory_path(tmp_path, rec.run_id)
    out.parent.mkdir(parents=True)

    victim = tmp_path / "victim.txt"
    victim.write_text("UNTOUCHED")
    os.symlink(victim, out)

    written = write_trajectory(rec, base=tmp_path)
    # Did NOT overwrite the symlink target.
    assert victim.read_text() == "UNTOUCHED"
    # Landed at a different filename.
    assert written != out


# --------------------------------------------------------------------------
# TrajectoryRecord validation
# --------------------------------------------------------------------------


def test_record_rejects_invalid_run_id():
    bad = [
        "",
        "../../etc",        # path traversal
        "a/b",              # slash
        "a" * 200,          # too long
        "spaces in name",
        "name\x00null",
    ]
    for run_id in bad:
        with pytest.raises(ValueError, match="run_id"):
            _record(run_id=run_id)


def test_record_accepts_typical_run_ids():
    for run_id in [
        "run-0001",
        "exploit_2026-06-03",
        "FND-77.v1",
        "abc",
        "A" * 128,                # max length
    ]:
        rec = _record(run_id=run_id)
        assert rec.run_id == run_id


def test_record_finding_id_optional():
    """finding_id defaults to empty so non-finding-driven consumers
    (e.g. open-ended ToolUseLoop runs from /understand or /cve-diff)
    can persist trajectories without inventing identifiers."""
    rec = _record(finding_id="")
    assert rec.finding_id == ""


def test_record_cwe_optional():
    """cwe defaults to empty for the same reason — non-security-finding
    consumers shouldn't need to fabricate a CWE."""
    rec = _record(cwe="")
    assert rec.cwe == ""


# --------------------------------------------------------------------------
# E2E: full trace + write + read
# --------------------------------------------------------------------------


def test_e2e_engine_run_trajectory(tmp_path):
    """Simulate a 3-turn engine run end-to-end: messages → serialize →
    write → read back."""
    msgs = [
        # Initial user prompt
        Message(role="user", content=[
            TextBlock(text="Exploit the buffer overflow in parse_header."),
        ]),
        # Assistant calls find_symbol
        Message(role="assistant", content=[
            TextBlock(text="Looking up parse_header."),
            ToolCall(id="c1", name="find_symbol",
                     input={"name": "parse_header"}),
        ]),
        # Tool result
        Message(role="user", content=[
            ToolResult(tool_use_id="c1",
                       content="parse_header @ src/parser.c:42"),
        ]),
        # Assistant submits exploit
        Message(role="assistant", content=[
            TextBlock(text="Submitting exploit."),
            ToolCall(id="c2", name="submit_exploit",
                     input={"exploit_code": "int main(){abort();}"}),
        ]),
    ]
    rec = TrajectoryRecord(
        run_id="e2e-run",
        finding_id="FND-E2E",
        model_name="claude-haiku-4-5",
        cwe="CWE-787",
        terminated_by="terminal_tool",
        iterations=2,
        tool_calls_made=2,
        cost_usd=0.05,
        steps=serialize_messages(msgs),
        timestamp="2026-06-03T15:00:00+00:00",
    )
    written = write_trajectory(rec, base=tmp_path)
    data = json.loads(written.read_text())

    assert data["finding_id"] == "FND-E2E"
    assert data["model_name"] == "claude-haiku-4-5"
    assert len(data["steps"]) == 4

    # Step 0: initial user prompt
    assert data["steps"][0]["role"] == "user"
    assert "buffer overflow" in data["steps"][0]["text_blocks"][0]

    # Step 1: assistant's find_symbol call
    assert data["steps"][1]["role"] == "assistant"
    assert data["steps"][1]["tool_calls"][0]["name"] == "find_symbol"

    # Step 2: tool result
    assert data["steps"][2]["tool_results"][0]["tool_use_id"] == "c1"

    # Step 3: terminal submission
    assert data["steps"][3]["tool_calls"][0]["name"] == "submit_exploit"
