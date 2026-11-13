"""Spawn/probe hexadecimal admission without target execution."""

from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


class _Reached(BaseException):
    pass


def _invoke(private, mode, text):
    if mode == "spawn":
        return private._handle_spawn({"argv": ["INERT"], "stdin_hex": text})
    return private._handle_probe({"target_argv": ["INERT"], "steps": [{"send_hex": text}]})


def _private(mode, decode):
    started, retired = [], []
    proc = SimpleNamespace()

    class Decoder(bytes):
        @staticmethod
        def fromhex(value):
            return decode(value)

    def spawn(argv):
        assert argv == ["INERT"]
        started.append(proc)
        if mode == "spawn":
            raise _Reached
        return proc

    def send(owner, data, *args):
        assert owner is proc
        raise _Reached

    private = module_function_view(daemon, bindings={
        "bytes": Decoder, "_MAX_STDIN_BYTES": 2, "_MAX_SEND_BYTES": 2,
        "_spawn_request_target": spawn, "_retire_request_target": retired.append,
        "_send_capped": send, "_check_request_channel": lambda: None,
    })
    return private, started, retired


@pytest.mark.parametrize("mode", ["spawn", "probe"])
def test_oversized_hex_refuses_before_decoder(mode):
    def forbidden(value):
        raise AssertionError("over-cap source reached binary decoder")

    private, started, retired = _private(mode, forbidden)
    response = _invoke(private, mode, "41\t42\r43")
    assert response["ok"] is False
    assert "3" in response["error"] and "2" in response["error"]
    assert len(started) == (0 if mode == "spawn" else 1)
    assert retired == started


@pytest.mark.parametrize("mode", ["spawn", "probe"])
@pytest.mark.parametrize("gap", ["", " ", "\t", "\r", "\v", "\f", "\n", " \t\r\v\f\n"])
def test_exact_boundary_keeps_ascii_whitespace(mode, gap):
    decoded = []

    def decode(text):
        result = bytes.fromhex(text)
        decoded.append(result)
        return result

    private, started, retired = _private(mode, decode)
    with pytest.raises(_Reached):
        _invoke(private, mode, gap + "41" + gap + "42" + gap)
    assert decoded == [b"AB"]
    assert len(started) == 1
    assert len(retired) == (0 if mode == "spawn" else 1)


@pytest.mark.parametrize("mode", ["spawn", "probe"])
@pytest.mark.parametrize("value", ["4\t1", "4\u00a01", "GG", "1"])
def test_invalid_under_cap_source_keeps_syntax_failure(mode, value):
    private, started, retired = _private(mode, bytes.fromhex)
    with pytest.raises(ValueError):
        _invoke(private, mode, value)
    assert len(started) == (0 if mode == "spawn" else 1)
    assert retired == started


def test_probe_keeps_existing_intra_byte_space_removal():
    decoded = []

    def decode(text):
        result = bytes.fromhex(text)
        decoded.append(result)
        return result

    private, started, retired = _private("probe", decode)
    with pytest.raises(_Reached):
        _invoke(private, "probe", "4 1")
    assert decoded == [b"A"]
    assert started == retired


def test_spawn_does_not_gain_intra_byte_space_removal():
    private, started, retired = _private("spawn", bytes.fromhex)
    with pytest.raises(ValueError):
        _invoke(private, "spawn", "4 1")
    assert started == retired == []


@pytest.mark.parametrize("mode", ["spawn", "probe"])
def test_postdecode_guard_is_retained(mode):
    private, started, retired = _private(mode, lambda text: b"ABC")
    response = _invoke(private, mode, "41")
    assert response["ok"] is False
    assert "3" in response["error"] and "2" in response["error"]
    assert retired == started
