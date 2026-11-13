"""Integer calls admit captured source before conversion allocates a result."""

from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


def _guarded(**bindings):
    calls = []

    class IntegerMeta(type):
        def __instancecheck__(cls, value):
            return isinstance(value, int)

        def __call__(cls, *args):
            calls.append(args)
            if args and isinstance(args[0], (bytes, str)) and len(args[0]) > 2:
                raise AssertionError("over-budget source reached integer conversion")
            return int(*args)

    class Integer(metaclass=IntegerMeta):
        pass

    private = module_function_view(daemon, bindings={
        "int": Integer, "_INT_BIT_CEILING": 16, **bindings,
    })
    return private, calls


def test_raw_binding_refuses_before_integer_conversion():
    private, calls = _guarded()
    with pytest.raises(ValueError, match="byte budget"):
        private._safe_eval("int(raw, 16)", {"raw": b"FFFF"})
    assert calls == []


@pytest.mark.parametrize("expression,bindings,expected", [
    ("int()", {}, 0),
    ("int(raw, 16)", {"raw": b"FF"}, 255),
    ("int(raw, 16)", {"raw": "ＦＦ"}, None),
    ("int(raw, 2)", {"raw": b"11"}, 3),
    ("int(raw, 8)", {"raw": "17"}, 15),
    ("int(raw, 0)", {"raw": "10"}, 10),
    ("int(raw)", {"raw": "-1"}, -1),
    ("int(raw)", {"raw": "١٢"}, 12),
    ("int(raw)", {"raw": 1.9}, 1),
    ("int(raw)", {"raw": True}, 1),
])
def test_small_conversion_signatures_keep_builtin_results(expression, bindings, expected):
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 16})
    if expected is None:
        with pytest.raises(ValueError):
            private._safe_eval(expression, bindings)
    else:
        assert private._safe_eval(expression, bindings) == expected


def test_large_raw_binding_remains_usable_for_bounded_unpacking():
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 16})
    assert private._safe_eval("u16(raw)", {"raw": b"ABtail"}) == int.from_bytes(b"AB", "little")
    assert private._safe_eval("int(raw[:2],16)", {"raw": b"FFtail"}) == 255


@pytest.mark.parametrize("raw,base", [
    (b"-0X_FF", 16), ("+١٢", 10), (b"0b1_1", 0), (b"00000000", 16),
])
def test_admitted_conversion_syntax_matches_builtin(raw, base):
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 64})
    assert private._safe_eval("int(raw,base)", {"raw": raw, "base": base}) == int(raw, base)


def test_over_budget_zero_padding_refuses_even_for_small_result():
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 64})
    with pytest.raises(ValueError, match="byte budget"):
        private._safe_eval("int(raw,16)", {"raw": b"000000000"})


def test_actual_receive_fallback_refusal_retires_probe_owner():
    proc = SimpleNamespace()
    started, retired = [], []

    def spawn(argv):
        assert argv == ["INERT"]
        started.append(proc)
        return proc

    private, calls = _guarded(
        _MAX_HEX_DIGITS=2, _spawn_request_target=spawn,
        _retire_request_target=retired.append, _check_request_channel=lambda: None,
        _recv_until=lambda *args, **kwargs: b"0xAAAA",
    )
    result = private._handle_probe({
        "target_argv": ["INERT"],
        "steps": [{"recv_until": 6, "bind_as": "raw"}, {"compute": "int(raw,16)"}],
    })
    assert result["ok"] is False
    assert result["steps_completed"] == 1
    assert "byte budget" in result["error"]
    assert started == retired == [proc]
    assert calls == []
