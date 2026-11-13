"""Compute admission bounds parsing as well as arithmetic evaluation."""

import ast
from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


def _private(*, parse=ast.parse, walk=ast.walk, clock=None, **bindings):
    private_ast = module_function_view(ast, bindings={"parse": parse, "walk": walk})
    if clock is not None:
        bindings["time"] = SimpleNamespace(monotonic=lambda: clock[0])
    return module_function_view(daemon, bindings={"ast": private_ast, **bindings})


def test_oversized_expression_refuses_before_parsing():
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("oversized expression reached parser")

    private = _private(parse=forbidden)
    ceiling = getattr(daemon, "_MAX_COMPUTE_EXPR_CHARS", 1 << 20)
    expression = "0" * (ceiling + 1)
    with pytest.raises(ValueError, match="character budget") as caught:
        private._safe_eval(expression, {})
    assert calls == []
    assert len(str(caught.value)) < 128


@pytest.mark.parametrize("expression", ["1" + " " * 15, "1#" + "é" * 14])
def test_character_boundary_is_admitted(expression):
    assert len(expression) == 16
    private = _private(_MAX_COMPUTE_EXPR_CHARS=16)
    assert private._safe_eval(expression, {}) == 1


def test_parser_time_counts_toward_deadline():
    clock = [0.0]
    parsed = []

    def parse(expression, *, mode):
        assert (expression, mode) == ("1 + 2", "eval")
        parsed.append(True)
        clock[0] = daemon._COMPUTE_DEADLINE_S + 1
        return ast.parse(expression, mode=mode)

    private = _private(parse=parse, clock=clock)
    with pytest.raises(ValueError, match="deadline exceeded"):
        private._safe_eval("1 + 2", {})
    assert parsed == [True]


def test_validation_walk_counts_toward_deadline():
    clock = [0.0]
    walked = []

    def walk(tree):
        for node in ast.walk(tree):
            walked.append(type(node).__name__)
            clock[0] = daemon._COMPUTE_DEADLINE_S + 1
            yield node

    private = _private(walk=walk, clock=clock)
    with pytest.raises(ValueError, match="deadline exceeded"):
        private._safe_eval("1 + 2", {})
    assert walked == ["Expression"]


def test_ceiling_sized_hex_literal_remains_admitted():
    expression = "0x" + "f" * (daemon._INT_BIT_CEILING // 4)
    assert len(expression) < daemon._MAX_COMPUTE_EXPR_CHARS
    assert daemon._safe_eval(expression, {}).bit_length() == daemon._INT_BIT_CEILING


def test_probe_refusal_still_retires_its_created_owner():
    proc = SimpleNamespace()
    owners = []
    retired = []

    def spawn(argv):
        assert argv == ["INERT-NOT-EXECUTED"]
        owners.append(proc)
        return proc

    def forbidden(*args, **kwargs):
        raise AssertionError("oversized probe expression reached parser")

    private = _private(parse=forbidden, _spawn_request_target=spawn,
                       _retire_request_target=retired.append,
                       _check_request_channel=lambda: None)
    response = private._handle_probe({
        "target_argv": ["INERT-NOT-EXECUTED"],
        "steps": [{"compute": "0" * (daemon._MAX_COMPUTE_EXPR_CHARS + 1)}],
    })
    assert response["ok"] is False
    assert "character budget" in response["error"]
    assert len(response["error"]) < 160
    assert response["steps_completed"] == 0
    # Admission occurs after owner creation in the existing probe protocol.
    # No actual process is started; refusal still reaches final retirement.
    assert owners == retired == [proc]
