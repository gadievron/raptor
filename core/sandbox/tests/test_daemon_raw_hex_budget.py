"""Raw conversation sends admit binary size before hexadecimal decoding."""

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


def _payload(value):
    return {"target_argv": ["INERT-NOT-EXECUTED"], "sends": [{"bytes_hex": value}]}


def test_oversized_raw_hex_refuses_before_decoder_or_target():
    class Decoder:
        @staticmethod
        def fromhex(value):
            raise AssertionError("oversized raw send reached binary decoder")

    def forbidden(*args, **kwargs):
        raise AssertionError("refused raw send reached target creation")

    private = module_function_view(daemon, bindings={
        "bytes": Decoder, "_MAX_SEND_BYTES": 2, "_spawn_request_target": forbidden,
    })
    result = private._handle_conversation(_payload("41\t42\r43"))
    assert result == {"ok": False, "error": "sends[0] 3 > 2"}


class _PreflightComplete(Exception):
    pass


@pytest.mark.parametrize("gap", ["", " ", "\n", "\t", "\r", "\v", "\f", " \t\r\v\f\n"])
def test_exact_boundary_reaches_target_creation_after_decode(gap):
    decoded = []

    class Decoder:
        @staticmethod
        def fromhex(value):
            result = bytes.fromhex(value)
            decoded.append(result)
            return result

    def stop(argv):
        assert argv == ["INERT-NOT-EXECUTED"]
        raise _PreflightComplete

    private = module_function_view(daemon, bindings={
        "bytes": Decoder, "_MAX_SEND_BYTES": 2, "_spawn_request_target": stop,
    })
    with pytest.raises(_PreflightComplete):
        private._handle_conversation(_payload(gap + "41" + gap + "42" + gap))
    assert decoded == [b"AB"]


@pytest.mark.parametrize("value", ["", "4 1", "4\n1"])
def test_existing_empty_and_intra_byte_normalisation_is_preserved(value):
    decoded = []

    class Decoder:
        @staticmethod
        def fromhex(text):
            result = bytes.fromhex(text)
            decoded.append(result)
            return result

    def stop(argv):
        raise _PreflightComplete

    private = module_function_view(daemon, bindings={
        "bytes": Decoder, "_MAX_SEND_BYTES": 1, "_spawn_request_target": stop,
    })
    with pytest.raises(_PreflightComplete):
        private._handle_conversation(_payload(value))
    assert decoded == [b"" if not value else b"A"]


@pytest.mark.parametrize("value", ["4\t1", "4\r1", "4\v1", "4\f1", "41\u00a042", "GG"])
def test_invalid_raw_hex_keeps_decoder_refusal(value):
    def forbidden(argv):
        raise AssertionError("invalid raw send reached target creation")

    private = module_function_view(daemon, bindings={
        "_MAX_SEND_BYTES": 8, "_spawn_request_target": forbidden,
    })
    response = private._handle_conversation(_payload(value))
    assert response["ok"] is False
    assert response["error"].startswith("sends[0].bytes_hex:")


def test_postdecode_size_defence_is_retained():
    class Decoder:
        @staticmethod
        def fromhex(value):
            return b"ABC"

    private = module_function_view(daemon, bindings={"bytes": Decoder, "_MAX_SEND_BYTES": 2})
    assert private._handle_conversation(_payload("41")) == {"ok": False, "error": "sends[0] 3 > 2"}
