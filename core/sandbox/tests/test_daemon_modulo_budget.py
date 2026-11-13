"""Compute modulo is arithmetic, without sequence-format expansion."""

from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("kind", [bytes, str])
def test_formatting_refuses_before_expanding_operator(kind):
    formatted = []

    class Format(kind):
        def __mod__(self, value):
            formatted.append(True)
            raise AssertionError("compute reached formatting operator")

    pattern = b"%9s" if kind is bytes else "%9s"
    value = b"x" if kind is bytes else "x"
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 64})
    with pytest.raises(ValueError, match="formatting is not allowed"):
        private._safe_eval("pattern % value", {"pattern": Format(pattern), "value": value})
    assert formatted == []


@pytest.mark.parametrize("pattern,value", [(b"%s", b"x"), ("%s", "x"), (b"%d", 1), ("%d", 1)])
def test_small_formatting_is_also_explicitly_unsupported(pattern, value):
    with pytest.raises(ValueError, match="formatting is not allowed"):
        daemon._safe_eval("pattern % value", {"pattern": pattern, "value": value})


@pytest.mark.parametrize("left,right", [(7, 3), (-7, 3), (7, -3), (-7, -3), (5.5, 2), (True, 2)])
def test_numeric_modulo_keeps_builtin_results(left, right):
    assert daemon._safe_eval("left % right", {"left": left, "right": right}) == left % right


def test_numeric_zero_divisor_keeps_original_error():
    with pytest.raises(ZeroDivisionError):
        daemon._safe_eval("7 % 0", {})


def test_receive_format_refusal_retires_probe_owner():
    proc = SimpleNamespace()
    started, retired = [], []

    def spawn(argv):
        assert argv == ["INERT"]
        started.append(proc)
        return proc

    private = module_function_view(daemon, bindings={
        "_INT_BIT_CEILING": 64, "_spawn_request_target": spawn,
        "_retire_request_target": retired.append, "_check_request_channel": lambda: None,
        "_recv_until": lambda *args, **kwargs: b"%9s",
    })
    result = private._handle_probe({
        "target_argv": ["INERT"],
        "steps": [{"recv_until": 3, "bind_as": "raw"}, {"compute": "raw % b'x'"}],
    })
    assert result["ok"] is False
    assert result["steps_completed"] == 1
    assert "formatting is not allowed" in result["error"]
    assert started == retired == [proc]
