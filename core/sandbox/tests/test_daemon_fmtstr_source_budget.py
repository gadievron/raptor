"""Format write-map admission precedes evaluation and library expansion."""

from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


def _private(*, formatter=None, **bindings):
    context = SimpleNamespace(arch="i386")
    imports = []

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        assert (name, level) == ("pwn", 0)
        imports.append(name)
        assert formatter is not None, "unadmitted map reached formatter import"
        return SimpleNamespace(context=context, fmtstr_payload=formatter)

    private = module_function_view(daemon, bindings=bindings, import_hook=import_local)
    return private, context, imports


def test_oversized_write_map_refuses_before_import_or_evaluation():
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("unadmitted map reached expression evaluator")

    private, context, imports = _private(_safe_eval=forbidden)
    ceiling = getattr(daemon, "_MAX_FMTSTR_WRITES", 4096)
    spec = {"offset": 6, "writes": {str(i): "0" for i in range(ceiling + 1)}}
    with pytest.raises(ValueError, match="write count") as caught:
        private._build_fmtstr_write(spec, {})
    assert len(str(caught.value)) < 128
    assert calls == imports == []
    assert context.arch == "i386"


@pytest.mark.parametrize("write_size", ["byte", "short", "int"])
def test_exact_write_boundary_keeps_ordinary_expression_semantics(write_size):
    reached = []

    def formatter(offset, writes, **kwargs):
        assert context.arch == "amd64"
        assert offset == 6
        assert writes == {0x1000: 7, 0x1008: 8}
        assert kwargs == {"numbwritten": 0, "write_size": write_size}
        reached.append(True)
        return b"owned-formatter-result"

    private, context, imports = _private(formatter=formatter, _MAX_FMTSTR_WRITES=2)
    result = private._build_fmtstr_write({
        "offset": "position", "numbwritten": "sent", "write_size": write_size,
        "writes": {"base": "value", "base + 8": "value + 1"},
    }, {"position": 6, "sent": 0, "base": 0x1000, "value": 7})
    assert result == b"owned-formatter-result"
    assert reached == [True] and imports == ["pwn"]
    assert context.arch == "i386"


def test_raw_entry_budget_applies_before_alias_collapse():
    private, _, imports = _private(_MAX_FMTSTR_WRITES=2)
    with pytest.raises(ValueError, match="write count"):
        private._build_fmtstr_write({
            "offset": 6, "writes": {"base": "0", "base + 0": "0", "0 + base": "0"},
        }, {"base": 0x1000})
    assert imports == []


@pytest.mark.parametrize("writes", [None, {}, [], "invalid"])
def test_missing_or_invalid_write_map_refuses_before_import(writes):
    private, _, imports = _private()
    with pytest.raises(ValueError, match="writes dict required"):
        private._build_fmtstr_write({"offset": 6, "writes": writes}, {})
    assert imports == []


@pytest.mark.parametrize("over_input_budget", [False, True])
def test_probe_preserves_input_and_output_refusals_without_target_work(over_input_budget):
    proc = SimpleNamespace()
    owners, retired, built = [], [], []

    def spawn(argv):
        assert argv == ["INERT-NOT-EXECUTED"]
        owners.append(proc)
        return proc

    def formatter(*args, **kwargs):
        built.append(True)
        # An admitted map can still expand beyond the output allowance.
        return b"x" * (daemon._MAX_SEND_BYTES + 1)

    def forbidden(*args, **kwargs):
        raise AssertionError("refused format output reached target send")

    private, context, imports = _private(
        formatter=formatter, _MAX_FMTSTR_WRITES=2,
        _spawn_request_target=spawn, _retire_request_target=retired.append,
        _check_request_channel=lambda: None, _send_capped=forbidden,
    )
    count = 3 if over_input_budget else 1
    response = private._handle_probe({
        "target_argv": ["INERT-NOT-EXECUTED"],
        "steps": [{"build_fmtstr_write": {
            "offset": 6, "writes": {str(i): "0" for i in range(count)},
        }}],
    })
    assert response["ok"] is False and response["steps_completed"] == 0
    assert owners == retired == [proc]
    if over_input_budget:
        assert "write count" in response["error"]
        assert built == imports == []
    else:
        assert str(daemon._MAX_SEND_BYTES) in response["error"]
        assert built == [True] and imports == ["pwn"]
    assert context.arch == "i386"
