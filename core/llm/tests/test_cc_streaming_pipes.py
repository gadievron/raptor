"""Pipe-handling in ``run_cc_streaming`` — no real ``claude`` calls,
children are tiny ``python -c`` scripts.

Two failure modes the read loop must survive:

1. A chatty child that writes more than the 64KB pipe buffer to
   stderr blocks in write(2) if the parent never drains stderr — the
   call then dies as a timeout instead of surfacing the real output.
2. A child that exits at startup (bad flag, missing backend) closes
   stdin before consuming the prompt; the unguarded prompt write
   raised BrokenPipeError instead of reaching the nice
   ``claude -p exited N`` error path.
"""

from __future__ import annotations

import json
import os
import sys

from core.llm.cc_adapter import run_cc_streaming

# Well over the 64KB pipe buffer.
_STDERR_SPEW = 256 * 1024


def _env() -> dict[str, str]:
    return dict(os.environ)


def test_chatty_stderr_child_does_not_deadlock():
    """Child floods stderr past the pipe buffer BEFORE writing its
    stdout result. Without a stderr drain the child blocks in
    write(2) forever and the parent times out."""
    result_line = json.dumps({
        "type": "result",
        "session_id": "sess-spew",
        "is_error": False,
    })
    script = (
        "import sys\n"
        f"sys.stderr.write('x' * {_STDERR_SPEW})\n"
        "sys.stderr.flush()\n"
        f"sys.stdout.write({result_line!r} + '\\n')\n"
    )
    sr = run_cc_streaming(
        [sys.executable, "-c", script],
        prompt="",
        env=_env(),
        timeout_s=30,
    )
    assert sr.error is None
    assert sr.session_id == "sess-spew"


def test_chatty_stderr_is_reported_on_failure():
    """When the chatty child fails, its (drained) stderr must reach
    the error message."""
    script = (
        "import sys\n"
        f"sys.stderr.write('E' * {_STDERR_SPEW})\n"
        "sys.stderr.flush()\n"
        "sys.exit(2)\n"
    )
    sr = run_cc_streaming(
        [sys.executable, "-c", script],
        prompt="",
        env=_env(),
        timeout_s=30,
    )
    assert sr.error is not None
    assert "exited 2" in sr.error
    assert "E" in sr.error


def test_child_exiting_before_reading_prompt_reports_exit_code():
    """Child exits immediately without touching stdin while the
    parent writes a prompt larger than the pipe buffer — the write
    hits EPIPE. That must surface as the ``exited N`` error result,
    not a BrokenPipeError crash."""
    sr = run_cc_streaming(
        [sys.executable, "-c", "import sys; sys.exit(7)"],
        prompt="y" * (1024 * 1024),
        env=_env(),
        timeout_s=30,
    )
    assert sr.error is not None
    assert "exited 7" in sr.error


def test_failed_call_carries_parsed_spend_telemetry():
    """A budget abort exits nonzero AFTER emitting a result event with
    the real spend. The error StreamJsonResult must carry that
    cost/usage so the provider can book it — dropping it made
    budget-aborted spend invisible to max-cost enforcement."""
    result_line = json.dumps({
        "type": "result",
        "subtype": "error_max_budget_usd",
        "session_id": "sess-abort",
        "is_error": True,
        "result": "",
        "total_cost_usd": 4.8,
        "usage": {"input_tokens": 1000, "output_tokens": 2000},
    })
    script = (
        "import sys\n"
        f"sys.stdout.write({result_line!r} + '\\n')\n"
        "sys.exit(1)\n"
    )
    sr = run_cc_streaming(
        [sys.executable, "-c", script],
        prompt="",
        env=_env(),
        timeout_s=30,
    )
    assert sr.error is not None
    assert "exited 1" in sr.error
    assert "error_max_budget_usd" in sr.error
    assert sr.cost_usd == 4.8
    assert sr.input_tokens == 1000
    assert sr.output_tokens == 2000
    assert sr.session_id == "sess-abort"


def test_large_prompt_to_busy_child_does_not_deadlock():
    """Mutual pipe-block: child floods stderr past the pipe buffer
    BEFORE reading stdin, while the parent feeds a prompt larger than
    the pipe buffer. Pre-fix the parent wrote the whole prompt in one
    blocking call before the drain loop started — both processes
    blocked in write(2) forever, outside timeout coverage. The stdin
    feed now happens inside the select loop, interleaved with the
    stderr drain."""
    result_line = json.dumps({
        "type": "result",
        "session_id": "sess-bigprompt",
        "is_error": False,
    })
    script = (
        "import sys\n"
        f"sys.stderr.write('x' * {_STDERR_SPEW})\n"
        "sys.stderr.flush()\n"
        "n = len(sys.stdin.read())\n"
        f"sys.stdout.write({result_line!r} + '\\n')\n"
    )
    sr = run_cc_streaming(
        [sys.executable, "-c", script],
        prompt="y" * (1024 * 1024),
        env=_env(),
        timeout_s=30,
    )
    assert sr.error is None
    assert sr.session_id == "sess-bigprompt"


def test_timeout_covers_stdin_write():
    """A child that never reads stdin leaves the parent's prompt feed
    stalled at the pipe buffer — the deadline must still fire as
    TimeoutExpired instead of hanging in a blocking write."""
    import subprocess
    import time

    import pytest

    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_cc_streaming(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            prompt="y" * (1024 * 1024),
            env=_env(),
            timeout_s=2,
        )
    # Well under the child's sleep — the deadline, not the child,
    # ended the call.
    assert time.monotonic() - start < 30
