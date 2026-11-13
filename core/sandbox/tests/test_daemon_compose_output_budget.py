"""Compose output refuses before oversized binary decoding or accumulation."""

import struct
from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


class _Bytes:
    def __init__(self, decode):
        self.fromhex = decode

    def __call__(self, value):
        return bytes(value)


def test_oversized_hex_refuses_before_decoder():
    decoded = []

    def forbidden(value):
        decoded.append(len(value))
        raise AssertionError("oversized compose reached binary decoder")

    private = module_function_view(daemon, bindings={"bytes": _Bytes(forbidden)})
    chunks = [{"kind": "hex", "value": "41" * (daemon._MAX_SEND_BYTES + 1)}]
    with pytest.raises(ValueError, match="compose output"):
        private._render_compose(chunks, [])
    assert decoded == []


def test_cumulative_hex_budget_refuses_before_second_decode():
    decoded = []

    def decode(value):
        decoded.append(value)
        return bytes.fromhex(value)

    private = module_function_view(daemon, bindings={"bytes": _Bytes(decode), "_MAX_SEND_BYTES": 3})
    with pytest.raises(ValueError, match="compose output"):
        private._render_compose([
            {"kind": "hex", "value": "4142"},
            {"kind": "hex", "value": "4344"},
        ], [])
    assert decoded == ["4142"]


def test_whitespace_is_compacted_before_binary_decoder():
    decoded = []

    def decode(value):
        decoded.append(value)
        return bytes.fromhex(value)

    private = module_function_view(daemon, bindings={"bytes": _Bytes(decode), "_MAX_SEND_BYTES": 2})
    assert private._render_compose([{"kind": "hex", "value": "41" + "\t" * 4096 + "42"}], []) == b"AB"
    assert decoded == ["4142"]


@pytest.mark.parametrize("gap", [" ", "\t", "\r", "\v", "\f", "\n", " \t\r\v\f\n"])
def test_ascii_whitespace_keeps_exact_boundary(gap):
    value = gap.join(["41", "42"])
    private = module_function_view(daemon, bindings={"_MAX_SEND_BYTES": 2})
    assert private._render_compose([{"kind": "hex", "value": value}], []) == bytes.fromhex(value)


@pytest.mark.parametrize("gap", [" ", "\n"])
def test_existing_space_and_newline_normalization_is_preserved(gap):
    private = module_function_view(daemon, bindings={"_MAX_SEND_BYTES": 1})
    assert private._render_compose([{"kind": "hex", "value": "4" + gap + "1"}], []) == b"A"


@pytest.mark.parametrize("value", ["4\t1", "4\r1", "4\v1", "4\f1", "41\u00a042", "GG"])
def test_malformed_hex_is_not_accepted_by_compaction(value):
    private = module_function_view(daemon, bindings={"_MAX_SEND_BYTES": 8})
    with pytest.raises(ValueError):
        bytes.fromhex(value)
    with pytest.raises(ValueError):
        private._render_compose([{"kind": "hex", "value": value}], [])


def test_mixed_chunks_can_fill_the_exact_allowance():
    private = module_function_view(daemon, bindings={"_MAX_SEND_BYTES": 11})
    result = private._render_compose([
        {"kind": "hex", "value": "414243"},
        {"kind": "recv_le64", "recv_index": 0},
    ], [b"0X1"])
    assert result == b"ABC" + struct.pack("<Q", 1)


def test_fixed_word_refuses_before_reading_the_recv():
    class Unread:
        def decode(self, *args, **kwargs):
            raise AssertionError("over-budget compose inspected recv bytes")

    private = module_function_view(daemon, bindings={"_MAX_SEND_BYTES": 10})
    with pytest.raises(ValueError, match="compose output"):
        private._render_compose([
            {"kind": "hex", "value": "414243"},
            {"kind": "recv_le64", "recv_index": 0},
        ], [Unread()])


@pytest.mark.parametrize("bypass_renderer", [False, True])
def test_conversation_refuses_and_retires_owner_without_sending(bypass_renderer):
    proc = SimpleNamespace()
    started, retired = [], []

    def spawn(argv):
        assert argv == ["INERT-NOT-EXECUTED"]
        started.append(proc)
        return proc

    def forbidden(*args, **kwargs):
        raise AssertionError("refused compose reached target send")

    bindings = {"_MAX_SEND_BYTES": 2, "_spawn_request_target": spawn,
                "_retire_request_target": retired.append,
                "_check_request_channel": lambda: None, "_send_capped": forbidden}
    if bypass_renderer:
        bindings["_render_compose"] = lambda *args: b"ABC"
    private = module_function_view(daemon, bindings=bindings)
    response = private._handle_conversation({
        "target_argv": ["INERT-NOT-EXECUTED"],
        "sends": [{"compose": [{"kind": "hex", "value": "414243"}]}],
    })
    assert response["ok"] is False
    assert started == retired == [proc]
    assert ("rendered" if bypass_renderer else "compose render failed") in response["error"]
