"""Request ownership starts before fallible post-spawn bookkeeping."""

from contextlib import ExitStack
import signal
import sys
import time
from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view
from core.testing.processes import reap_on_exit


@pytest.mark.parametrize("handler", ["probe", "conversation"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt], ids=["error", "interrupt"])
def test_initial_clock_failure_retires_the_started_request(handler, error):
    primary = error("owned post-spawn clock failure")
    processes = []
    armed = False

    def clock():
        nonlocal armed
        if armed:
            armed = False
            raise primary
        return time.monotonic()

    with ExitStack() as owners:
        def create(argv):
            nonlocal armed
            proc = daemon._spawn_request_target(argv)
            owners.enter_context(reap_on_exit(proc, process_group=True))
            processes.append(proc)
            armed = True
            return proc

        local_time = SimpleNamespace(**vars(time))
        local_time.monotonic = clock
        view = module_function_view(daemon, bindings={
            "time": local_time, "_spawn_request_target": create,
        })
        payload = {
            "target_argv": [sys.executable, "-I", "-S", "-B", "-c",
                            "import sys; sys.stdin.buffer.read()"],
            "sends": [{"bytes_hex": ""}],
        }
        with pytest.raises(error) as caught:
            getattr(view, "_handle_" + handler)(payload)
        assert caught.value is primary
        assert len(processes) == 1
        proc = processes[0]
        # Assert before the independent fixture safety net reaps the child.
        assert proc.returncode == -signal.SIGKILL
        assert all(stream.closed for stream in (proc.stdin, proc.stdout, proc.stderr))


@pytest.mark.parametrize("handler,field", [
    ("spawn", "timeout"),
    ("probe", "per_recv_timeout"),
    ("probe", "total_wait_seconds"),
    ("conversation", "per_recv_timeout"),
    ("conversation", "total_wait_seconds"),
])
@pytest.mark.parametrize("value", [float("nan"), "nan", float("inf"), -float("inf")],
                         ids=["number", "text", "positive-infinity", "negative-infinity"])
def test_nonfinite_request_budget_is_refused_before_launch(handler, field, value):
    launches = []

    def forbidden_launch(argv):
        launches.append(argv)
        raise AssertionError("invalid budget reached target launch")

    view = module_function_view(daemon, bindings={"_spawn_request_target": forbidden_launch})
    payload = {
        "argv": ["unused"], "target_argv": ["unused"],
        "sends": [{"bytes_hex": ""}], field: value,
    }
    response = getattr(view, "_handle_" + handler)(payload)
    assert response["ok"] is False
    assert "finite" in response["error"]
    assert launches == []


@pytest.mark.parametrize("value", [0.01, 1, "5", 30.0])
def test_finite_budget_including_ceiling_retains_its_value(value):
    assert daemon._cap("timeout", value, 30.0) == float(value)


def test_huge_integer_count_is_refused_without_float_conversion():
    with pytest.raises(ValueError, match="exceeds cap"):
        daemon._cap("count", 10 ** 400, 64, fn=int)
