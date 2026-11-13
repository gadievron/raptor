"""Repeated compose references do not multiply whole-token processing."""

import re
import struct
from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


class _Received(bytes):
    def __new__(cls, value):
        result = super().__new__(cls, value)
        result.decodes = 0
        return result

    def decode(self, *args, **kwargs):
        self.decodes += 1
        return super().decode(*args, **kwargs)


def _private(**bindings):
    matches = []

    def fullmatch(pattern, text):
        matches.append(len(text))
        return re.fullmatch(pattern, text)

    private = module_function_view(daemon, bindings={
        "re": SimpleNamespace(fullmatch=fullmatch, split=re.split, search=re.search), **bindings,
    })
    return private, matches


def _chunks(indices):
    return [{"kind": "recv_le64", "recv_index": index} for index in indices]


def _word(value):
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def test_repeated_reference_decodes_and_validates_once():
    received = _Received(b"0X1")
    private, matches = _private()
    result = private._render_compose(_chunks([0, 0]), [received])
    assert result == _word(1) * 2
    assert received.decodes == 1
    assert len(matches) == 1


def test_distinct_indices_and_negative_aliases_keep_values():
    first, second = _Received(b"0X1"), _Received(b"-0x2")
    private, matches = _private()
    result = private._render_compose(_chunks([0, -2, False, 1, -1, True]), [first, second])
    assert result == _word(1) * 3 + _word(-2) * 3
    assert first.decodes == second.decodes == 1
    assert len(matches) == 2


def test_float_index_is_not_admitted_by_numeric_cache_equality():
    received = _Received(b"0x1")
    private, matches = _private()
    with pytest.raises(TypeError):
        private._render_compose(_chunks([0, 0.0]), [received])
    assert received.decodes == 1 and len(matches) == 1


def test_cached_word_still_requires_output_allowance():
    received = _Received(b"0x1")
    private, matches = _private(_MAX_SEND_BYTES=8)
    with pytest.raises(ValueError, match="compose output"):
        private._render_compose(_chunks([0, 0]), [received])
    assert received.decodes == 1 and len(matches) == 1


def test_word_cache_is_local_to_each_render():
    first, second = _Received(b"0x1"), _Received(b"0x2")
    private, matches = _private()
    recvs = [first]
    assert private._render_compose(_chunks([0, 0]), recvs) == _word(1) * 2
    recvs[0] = second
    assert private._render_compose(_chunks([0, 0]), recvs) == _word(2) * 2
    assert first.decodes == second.decodes == 1
    assert len(matches) == 2
