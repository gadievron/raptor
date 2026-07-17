"""Tests for ``core.trajectories.auto`` — env-var opt-in helper."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.llm.tool_use.types import (
    CostBudgetExceeded,
    Message,
    TextBlock,
    ToolCall,
    ToolResult,
)
from core.trajectories.auto import (
    TRAJECTORY_DIR_ENV,
    persist_from_loop_result,
    persist_partial_from_exception,
)


def _fake_result(messages=None, terminated_by="complete"):
    """Build a minimal ToolLoopResult stand-in. We don't depend on
    the real dataclass because the helper only reads a small subset
    of attributes — using a MagicMock keeps the test cheap and
    insensitive to upstream schema changes."""
    r = MagicMock()
    r.messages = messages or [
        Message(role="user", content=[TextBlock(text="hi")]),
        Message(role="assistant", content=[
            TextBlock(text="ok"),
            ToolCall(id="c1", name="echo", input={}),
        ]),
        Message(role="user", content=[
            ToolResult(tool_use_id="c1", content="result", is_error=False),
        ]),
    ]
    r.terminated_by = terminated_by
    r.iterations = 2
    r.tool_calls_made = 1
    r.total_cost_usd = 0.01
    return r


def test_unset_env_var_is_noop(monkeypatch):
    """No ``RAPTOR_TRAJECTORY_DIR`` → helper returns None, writes
    nothing. This is the default path on hosts that haven't opted in."""
    monkeypatch.delenv(TRAJECTORY_DIR_ENV, raising=False)
    result = _fake_result()
    out = persist_from_loop_result(
        result, run_id="run1", model_name="claude",
    )
    assert out is None


def test_set_env_var_persists(monkeypatch, tmp_path):
    """With the env var set, the helper writes a trajectory.json under
    ``<dir>/trajectories/<run_id>/`` and returns the path."""
    monkeypatch.setenv(TRAJECTORY_DIR_ENV, str(tmp_path))
    result = _fake_result()
    out = persist_from_loop_result(
        result, run_id="run-a", model_name="claude-haiku-4-5",
    )
    assert out is not None
    assert out.exists()
    payload = json.loads(out.read_text())
    assert payload["run_id"] == "run-a"
    assert payload["model_name"] == "claude-haiku-4-5"
    assert payload["terminated_by"] == "complete"
    assert payload["iterations"] == 2
    assert payload["tool_calls_made"] == 1
    assert payload["cost_usd"] == pytest.approx(0.01)
    # finding_id / cwe default to empty for non-finding-driven runs
    assert payload["finding_id"] == ""
    assert payload["cwe"] == ""
    # Three messages → three steps
    assert len(payload["steps"]) == 3


def test_optional_fields_propagate(monkeypatch, tmp_path):
    """finding_id and cwe land in the record when passed."""
    monkeypatch.setenv(TRAJECTORY_DIR_ENV, str(tmp_path))
    out = persist_from_loop_result(
        _fake_result(), run_id="rid", model_name="m",
        finding_id="F-001", cwe="CWE-787",
    )
    assert out is not None
    payload = json.loads(out.read_text())
    assert payload["finding_id"] == "F-001"
    assert payload["cwe"] == "CWE-787"


def test_persist_failure_swallowed(monkeypatch, caplog):
    """A trajectory write failure must not propagate — the caller's
    tool-use loop result is the load-bearing artefact, the trajectory
    is best-effort observability. Failures land in the log so the
    operator can see them."""
    # Point the env var at a path that can't be created (file, not dir).
    bad_target = Path("/dev/null")  # exists, not a directory
    monkeypatch.setenv(TRAJECTORY_DIR_ENV, str(bad_target))
    out = persist_from_loop_result(
        _fake_result(), run_id="rid", model_name="m",
    )
    assert out is None
    # The failure should have been logged at WARNING.
    assert any(
        "trajectory persist failed" in r.message
        for r in caplog.records
    ), f"expected warning about persist failure, got: {caplog.records}"


def test_traversal_run_id_sanitized_not_rejected(monkeypatch, tmp_path):
    """A traversal-looking run_id gets sanitised (``/`` → ``-``,
    ``..`` collapsed to ``.``) and lands successfully — operators
    don't lose a trajectory because the producer passed a run_id with
    forbidden characters. The on-disk path stays inside the base dir
    (verified by write_trajectory's realpath check)."""
    monkeypatch.setenv(TRAJECTORY_DIR_ENV, str(tmp_path))
    out = persist_from_loop_result(
        _fake_result(), run_id="../escape", model_name="m",
    )
    assert out is not None
    assert out.exists()
    # The on-disk path must stay under tmp_path — the realpath check
    # in store.write_trajectory blocks any escape.
    assert str(out).startswith(str(tmp_path))
    # ``../`` is sanitised: '/' → '-' then '..' → '.' so 'escape' is
    # preserved and the dirname does NOT contain traversal syntax.
    assert ".." not in str(out)


def test_real_world_bedrock_model_name_persists(monkeypatch, tmp_path):
    """Bedrock model IDs end in ``:0`` which the validator rejects.
    Sanitisation must turn this into a valid run_id so operators get
    a trajectory file rather than a silently-swallowed warning."""
    monkeypatch.setenv(TRAJECTORY_DIR_ENV, str(tmp_path))
    out = persist_from_loop_result(
        _fake_result(),
        run_id="hunt-claude-3-haiku-20240307-v1:0",
        model_name="claude-3-haiku-20240307-v1:0",
    )
    assert out is not None
    assert out.exists()
    payload = json.loads(out.read_text())
    # Model name in the body is preserved verbatim.
    assert payload["model_name"] == "claude-3-haiku-20240307-v1:0"
    # run_id in the body is the sanitised form.
    assert ":" not in payload["run_id"]


# ---------------------------------------------------------------------------
# persist_partial_from_exception — exception-path trajectory.
# ---------------------------------------------------------------------------


def test_partial_from_cost_budget_exception_carries_messages(
    monkeypatch, tmp_path,
):
    """CostBudgetExceeded carries ``messages`` + ``tool_calls_made``
    (PR #828 contract). The partial-trajectory helper reads them and
    writes whatever survived to the point of termination."""
    monkeypatch.setenv(TRAJECTORY_DIR_ENV, str(tmp_path))
    partial_messages = [
        Message(role="user", content=[TextBlock(text="hunt")]),
        Message(role="assistant", content=[
            TextBlock(text="grep first"),
            ToolCall(id="c1", name="grep", input={"pattern": "x"}),
        ]),
        Message(role="user", content=[
            ToolResult(tool_use_id="c1", content="result", is_error=False),
        ]),
    ]
    exc = CostBudgetExceeded(
        "budget", messages=partial_messages, tool_calls_made=1,
    )
    out = persist_partial_from_exception(
        exc, run_id="hunt-x", model_name="claude",
        terminated_by="max_cost_usd",
    )
    assert out is not None
    payload = json.loads(out.read_text())
    assert payload["run_id"] == "hunt-x"
    assert payload["terminated_by"] == "max_cost_usd"
    assert payload["tool_calls_made"] == 1
    # Three messages → three steps.
    assert len(payload["steps"]) == 3


def test_partial_from_bare_exception_writes_skeleton(
    monkeypatch, tmp_path,
):
    """A generic Exception has no ``messages`` / ``tool_calls_made``.
    The helper still writes a skeleton trajectory so the operator can
    see the run happened and what killed it."""
    monkeypatch.setenv(TRAJECTORY_DIR_ENV, str(tmp_path))
    out = persist_partial_from_exception(
        RuntimeError("something broke"),
        run_id="hunt-x", model_name="claude",
        terminated_by="exception:RuntimeError",
    )
    assert out is not None
    payload = json.loads(out.read_text())
    assert payload["run_id"] == "hunt-x"
    assert payload["terminated_by"] == "exception:RuntimeError"
    assert payload["tool_calls_made"] == 0
    assert payload["steps"] == []


def test_partial_unset_env_var_is_noop(monkeypatch):
    """Same opt-in contract as the success path: no env var → no-op."""
    monkeypatch.delenv(TRAJECTORY_DIR_ENV, raising=False)
    out = persist_partial_from_exception(
        RuntimeError("x"),
        run_id="hunt-x", model_name="claude",
        terminated_by="exception:RuntimeError",
    )
    assert out is None


def test_partial_persist_failure_swallowed(monkeypatch, caplog):
    """Write failure must not propagate — caller's own error handling
    is the load-bearing thing, the trajectory is best-effort."""
    monkeypatch.setenv(TRAJECTORY_DIR_ENV, "/dev/null")
    out = persist_partial_from_exception(
        RuntimeError("x"),
        run_id="hunt-x", model_name="claude",
        terminated_by="exception:RuntimeError",
    )
    assert out is None
    assert any(
        "partial-trajectory persist failed" in r.message
        for r in caplog.records
    )
