"""Worker failures cannot masquerade as unmeasured nightly regex results."""
from __future__ import annotations

import builtins
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType
from unittest.mock import patch

import pytest

from core.testing.module_views import module_function_view


@pytest.fixture(scope="module")
def oracle():
    path = Path(__file__).with_name("test_redos_idiom_census.py")
    spec = importlib.util.spec_from_file_location("owned_redos_oracle_protocol", path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        spec.loader.exec_module(module)
    return module


def _consumer(oracle, run):
    # The function imports subprocess locally. Give only its private builtins
    # this module view; never replace a shared module or sys.modules entry.
    runner = ModuleType("subprocess")
    vars(runner).update(vars(subprocess))
    runner.run = run

    def import_hook(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "subprocess" and level == 0:
            return runner
        return builtins.__import__(name, globals, locals, fromlist, level)

    return module_function_view(oracle, import_hook=import_hook)


def _invoke(oracle, result):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if isinstance(result, BaseException):
            raise result
        return result

    consumer = _consumer(oracle, run)
    try:
        return consumer._oracle_lane("literal", 0, "search", "pair", 0, "x")
    finally:
        assert len(calls) == 1
        argv, options = calls[0]
        assert argv == [sys.executable, oracle.__file__, "--oracle-worker"]
        assert options["capture_output"] and options["text"]
        assert options["timeout"] == 14.0
        assert json.loads(options["input"])["pattern"] == "literal"


@pytest.mark.parametrize("returncode,stdout", [
    (7, ""), (1, "NOATTACK\n"), (-15, "500 0.01\n1000 0.02\n"),
], ids=["startup-failure", "failed-status", "failed-ladder"])
def test_failed_worker_is_not_a_measurement(oracle, returncode, stdout):
    stderr = "x" * 3000 + "\x1bowned failure"
    with pytest.raises(RuntimeError, match=f"exited {returncode}") as caught:
        _invoke(oracle, subprocess.CompletedProcess([], returncode, stdout, stderr))
    assert "owned failure" in str(caught.value)
    assert "\x1b" not in str(caught.value)
    assert len(str(caught.value)) < 2200


@pytest.mark.parametrize("output", [None, b"500 broken", "500 broken", b"DEGEN\n"],
                         ids=["empty", "partial-bytes", "partial-text", "status-bytes"])
def test_timeout_is_conservative_even_with_partial_or_bytes_output(oracle, output):
    error = subprocess.TimeoutExpired("owned-worker", 14, output=output)
    assert _invoke(oracle, error) == (99.0, "wall")


@pytest.mark.parametrize("status", ["NOATTACK", "NOPARSE", "NOLANE", "DEGEN"])
@pytest.mark.parametrize("prefix", ["", "500 0.001\n"], ids=["status-only", "after-probe"])
def test_explicit_worker_dispositions_remain_supported(oracle, status, prefix):
    result = subprocess.CompletedProcess([], 0, prefix + status + "\n", "warning")
    assert _invoke(oracle, result) == (None, status)


@pytest.mark.parametrize("stdout,expected", [
    ("500 0.01\n1000 0.02\n", (1.0, "ok")),
    ("500 0.01\n1000 0.04\n", (2.0, "ok")),
    ("500 0\n1000 0\n", (1.0, "fast")),
    ("500 1.5\n", (99.0, "wall")),
    ("500 1.000000\n", (99.0, "wall")),
], ids=["linear", "quadratic", "quantized", "first-probe-over-budget", "rounded-budget"])
def test_valid_probe_ladders_keep_their_verdicts(oracle, stdout, expected):
    exponent, status = _invoke(oracle, subprocess.CompletedProcess([], 0, stdout, ""))
    assert exponent == pytest.approx(expected[0])
    assert status == expected[1]


@pytest.mark.parametrize("stdout", [
    "", "unexpected\n", "500 broken\n", "500 nan\n1000 0.02\n",
    "500 inf\n1000 0.02\n", "500 -0.1\n1000 0.02\n", "0 0.1\n500 0.2\n",
    "500 0.1\n500 0.2\n", "1000 0.1\n500 0.2\n", "500 0.1\n",
    "500 0.1 extra\n", "NOLANE\n500 0.1\n", "DEGEN\nDEGEN\n",
], ids=["empty", "unknown-status", "bad-number", "nan", "infinity", "negative-time",
        "zero-size", "repeated-size", "decreasing-size", "incomplete", "extra-field",
        "probe-after-status", "repeated-status"])
def test_malformed_successful_output_fails_closed(oracle, stdout):
    with pytest.raises(RuntimeError, match="oracle worker"):
        _invoke(oracle, subprocess.CompletedProcess([], 0, stdout, ""))


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt], ids=["spawn", "interrupt"])
def test_spawn_errors_and_interrupts_propagate(oracle, error_type):
    error = error_type("owned failure")
    run = subprocess.run
    with pytest.raises(type(error)):
        _invoke(oracle, error)
    assert subprocess.run is run


@pytest.mark.parametrize("kind", ["pair", "scan"])
def test_real_literal_worker_reports_no_lane(oracle, kind):
    assert oracle._oracle_lane("literal", 0, "search", kind, 0, "x") == (None, "NOLANE")


def test_real_unsuccessful_child_is_reaped_and_reported(oracle, tmp_path):
    calls = []

    def run(argv, **kwargs):
        result = subprocess.run(
            [sys.executable, "-I", "-c",
             "import sys;sys.stderr.write('owned worker failure');sys.exit(7)"],
            cwd=tmp_path, capture_output=True, text=True, timeout=5,
        )
        calls.append(result.returncode)
        return result

    consumer = _consumer(oracle, run)
    with pytest.raises(RuntimeError, match="exited 7.*owned worker failure"):
        consumer._oracle_lane("literal", 0, "search", "pair", 0, "x")
    assert calls == [7]
