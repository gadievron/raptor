"""Response encoding refuses oversized decimal bindings without losing the RPC."""

import json
import os
import struct
import subprocess
import sys

import pytest

from core.sandbox import _daemon as daemon
from core.sandbox.tests import test_daemon_rpc_hardening as pipe_helpers
from core.sandbox.tests.test_daemon_frame_failures import decode_response
from core.testing.module_bindings import patch_module_attribute
from core.testing.processes import run_in_process_group


@pytest.mark.parametrize("transport", ["one-shot", "persistent"])
@pytest.mark.parametrize("expression,refused,digit_limit", [
    ("1 << 3000", True, 640),
    ("-(1 << 3000)", True, 640),
    ("1 << 2000", False, 640),
    ("-(1 << 2000)", False, 640),
    ("1 << 64", False, 640),
    ("1 << 3000", False, 0),
], ids=["large-positive", "large-negative", "within-digit-budget",
        "negative-within-budget", "ordinary", "unlimited-child-decimal-budget"])
def test_integer_binding_encoding_preserves_framing_and_channel(
    transport, expression, refused, digit_limit, monkeypatch,
):
    # Own only the child interpreter's decimal limit, keeping this test
    # independent of the runner's inherited Python configuration.
    environment = {**os.environ, "PYTHONINTMAXSTRDIGITS": str(digit_limit)}
    payload = {
        "cmd": "probe", "rid": "owned-encoding-control",
        "target_argv": [sys.executable, "-I", "-S", "-B", "-c", "pass"],
        "steps": [{"compute": expression, "bind_as": "wide"}],
        "total_wait_seconds": 1,
    }
    if transport == "one-shot":
        body = json.dumps(payload).encode()
        result = run_in_process_group(
            [sys.executable, "-S", daemon.__file__, "--one-shot"],
            input=struct.pack("!I", len(body)) + body,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, timeout=5, start_new_session=True,
        )
        response = decode_response(result.stdout)
        assert result.returncode == 0
        assert b"Traceback" not in result.stderr
    else:
        native_popen = subprocess.Popen

        def spawn(*args, **kwargs):
            return native_popen(*args, **kwargs, env=environment)

        patch_module_attribute(monkeypatch, pipe_helpers, "subprocess", "Popen", spawn)
        worker = pipe_helpers._PipeDaemon()
        try:
            response = worker.rpc(payload)
            following = worker.rpc({"cmd": "ping", "rid": "following"})
            assert following["ok"] is True and following["rid"] == "following"
        finally:
            worker.close()
    assert response["rid"] == payload["rid"]
    if refused:
        assert response["ok"] is False
        assert "integer binding" in response["error"]
        assert "bindings" not in response
        assert response["steps_completed"] == 1
    else:
        assert response["ok"] is True
        expected = 1 << (2000 if "2000" in expression else 3000 if "3000" in expression else 64)
        if expression.startswith("-"):
            expected = -expected
        assert response["bindings"]["wide"] == {
            "type": "int", "value": expected, "hex": hex(expected),
        }
