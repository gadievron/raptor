"""Marker selection controls record signal intent; they signal no process."""

import io
import os
import signal
import time

import pytest

from core.sandbox import context
from core.testing.module_views import module_function_view


TOKEN = "owned-run-token"
PID = 2147483000
MARKER = f"_SBX_RUN_ID={TOKEN}".encode()


def select_marker(environment):
    sent = []
    alive = True

    def names(path):
        assert path == "/proc"
        return [str(PID)] if alive else []

    def open_environment(path, mode):
        assert path == f"/proc/{PID}/environ" and mode == "rb"
        return io.BytesIO(environment)

    def record_signal(pid, sig):
        nonlocal alive
        sent.append((pid, sig))
        alive = False

    private = module_function_view(context, bindings={
        "os": module_function_view(os, bindings={"listdir": names, "kill": record_signal}),
        "open": open_environment,
        "time": module_function_view(time, bindings={"sleep": lambda seconds: None}),
    })
    killed = private._sweep_marked_processes(TOKEN)
    return killed, sent


def test_marker_text_inside_another_value_is_not_selected():
    killed, sent = select_marker(b"DESCRIPTION=" + MARKER + b"\0")
    assert killed == [] and sent == []


@pytest.mark.parametrize("environment", [
    b"NOT" + MARKER + b"\0",
    MARKER + b"-foreign\0",
    MARKER,
    b"OTHER=x\0DESCRIPTION=" + MARKER + b"\0",
])
def test_inexact_or_unterminated_marker_never_requests_signal(environment):
    assert select_marker(environment) == ([], [])


@pytest.mark.parametrize("environment", [
    MARKER + b"\0OTHER=x\0",
    b"OTHER=x\0" + MARKER + b"\0NEXT=y\0",
    b"OTHER=x\0" + MARKER + b"\0",
])
def test_exact_marker_entry_is_still_selected(environment):
    assert select_marker(environment) == ([PID], [(PID, signal.SIGKILL)])


def test_byte_cap_cannot_turn_a_longer_value_into_an_exact_marker():
    cap = 1024 * 1024
    prefix_size = cap - len(MARKER)
    prefix = b"PADDING=" + b"x" * (prefix_size - len(b"PADDING=") - 1) + b"\0"
    environment = prefix + MARKER + b"-foreign\0"
    assert len(environment[:cap]) == cap
    assert environment[:cap].endswith(MARKER)
    assert select_marker(environment) == ([], [])
