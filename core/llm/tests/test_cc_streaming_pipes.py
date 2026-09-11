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

import pytest

from core.llm.cc_adapter import run_cc_streaming

# Children here are test-local fakes (module docstring) — the spawn
# machinery itself is under test, so the transport kill switch the
# root conftest sets is cleared for this module.
pytestmark = pytest.mark.usefixtures("cc_spawn_machinery_enabled")

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


def test_grandchild_holding_stdout_does_not_block_drain():
    """Child spawns a background grandchild that inherits the stdout
    pipe, then exits. The post-exit stdout drain must not read to EOF
    — the grandchild keeps the write end open for its whole lifetime,
    so an unguarded drain wedges until the grandchild dies."""
    import time

    result_line = json.dumps({
        "type": "result",
        "session_id": "sess-grandchild",
        "is_error": False,
    })
    script = (
        "import subprocess, sys\n"
        # Grandchild inherits stdout/stderr and outlives the child by
        # far longer than the assertion window below.
        "subprocess.Popen([sys.executable, '-c', "
        "'import time; time.sleep(20)'])\n"
        f"sys.stdout.write({result_line!r} + '\\n')\n"
        "sys.stdout.flush()\n"
    )
    start = time.monotonic()
    sr = run_cc_streaming(
        [sys.executable, "-c", script],
        prompt="",
        env=_env(),
        timeout_s=30,
    )
    elapsed = time.monotonic() - start
    assert sr.error is None
    assert sr.session_id == "sess-grandchild"
    # Far under the grandchild's 20s lifetime — the drain returned
    # instead of waiting for pipe EOF.
    assert elapsed < 10


def test_partial_line_does_not_block_past_deadline():
    """Child writes a partial line (no trailing newline) then goes
    silent. A buffered readline would block inside the read even after
    select() reported readiness; the deadline must still fire."""
    import subprocess
    import time

    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_cc_streaming(
            [sys.executable, "-c",
             "import sys, time\n"
             "sys.stdout.write('{\"type\": \"result\", ')\n"
             "sys.stdout.flush()\n"
             "time.sleep(60)\n"],
            prompt="",
            env=_env(),
            timeout_s=2,
        )
    # Well under the child's sleep — the deadline, not the child,
    # ended the call.
    assert time.monotonic() - start < 30


def test_partial_line_completed_later_assembles_correctly():
    """A line delivered in two flushes (partial, pause, remainder)
    must be reassembled into one JSON line, not consumed as two
    fragments."""
    result_line = json.dumps({
        "type": "result",
        "session_id": "sess-split",
        "is_error": False,
    })
    head, tail = result_line[:12], result_line[12:]
    script = (
        "import sys, time\n"
        f"sys.stdout.write({head!r})\n"
        "sys.stdout.flush()\n"
        "time.sleep(0.5)\n"
        f"sys.stdout.write({tail!r} + '\\n')\n"
    )
    sr = run_cc_streaming(
        [sys.executable, "-c", script],
        prompt="",
        env=_env(),
        timeout_s=30,
    )
    assert sr.error is None
    assert sr.session_id == "sess-split"


def test_final_line_without_trailing_newline_is_parsed():
    """A child whose last line has no trailing newline (exit before
    the final flush completes the line) must still have that line
    reach the parser."""
    result_line = json.dumps({
        "type": "result",
        "session_id": "sess-no-newline",
        "is_error": False,
    })
    script = (
        "import sys\n"
        f"sys.stdout.write({result_line!r})\n"  # NO trailing newline
    )
    sr = run_cc_streaming(
        [sys.executable, "-c", script],
        prompt="",
        env=_env(),
        timeout_s=30,
    )
    assert sr.error is None
    assert sr.session_id == "sess-no-newline"


def test_invalid_utf8_on_stdout_does_not_raise():
    """Invalid UTF-8 bytes from the child must decode with
    replacement characters, not raise mid-stream (a strict text-mode
    decode would), and later valid lines must still parse."""
    result_line = json.dumps({
        "type": "result",
        "session_id": "sess-badbytes",
        "is_error": False,
    })
    script = (
        "import sys\n"
        "sys.stdout.buffer.write(b'\\xff\\xfe garbage \\xff\\n')\n"
        f"sys.stdout.write({result_line!r} + '\\n')\n"
    )
    sr = run_cc_streaming(
        [sys.executable, "-c", script],
        prompt="",
        env=_env(),
        timeout_s=30,
    )
    assert sr.error is None
    assert sr.session_id == "sess-badbytes"


def test_abnormal_loop_exit_reaps_child(monkeypatch):
    """An exception escaping the select loop must not leak a running
    (billed) child — the child is terminated on the way out."""
    import select as select_mod
    import subprocess

    procs: list[subprocess.Popen] = []
    real_popen = subprocess.Popen

    def recording_popen(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        procs.append(proc)
        return proc

    monkeypatch.setattr(subprocess, "Popen", recording_popen)

    real_select = select_mod.select

    def raising_select(*args, **kwargs):
        raise RuntimeError("injected mid-loop failure")

    monkeypatch.setattr(select_mod, "select", raising_select)
    try:
        with pytest.raises(RuntimeError, match="injected mid-loop"):
            run_cc_streaming(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                prompt="",
                env=_env(),
                timeout_s=30,
            )
    finally:
        monkeypatch.setattr(select_mod, "select", real_select)

    assert len(procs) == 1
    # The child was killed by the cleanup path, not left running.
    assert procs[0].poll() is not None


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
