"""Compose selects one token without materialising ignored tail fields."""

import struct

import pytest

from core.sandbox import _daemon as daemon


def _render(received):
    return daemon._render_compose([{"kind": "recv_le64", "recv_index": 0}], [received])


def _word(value):
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def test_projection_does_not_request_an_unbounded_split():
    splits, decodes = [], []

    class Captured(str):
        def strip(self, *args, **kwargs):
            return Captured(super().strip(*args, **kwargs))

        def split(self, sep=None, maxsplit=-1):
            splits.append(maxsplit)
            return super().split(sep, maxsplit)

    class Received(bytes):
        def decode(self, *args, **kwargs):
            decodes.append(True)
            return Captured(super().decode(*args, **kwargs))

    assert _render(Received(b"0X1 ignored tail fields")) == _word(1)
    assert decodes == [True]
    # A bounded split could also satisfy the projection contract. Do not
    # require a particular implementation, only exclude full tokenisation.
    assert all(limit > 0 for limit in splits)


@pytest.mark.parametrize("space", [" ", "\t", "\n", "\r", "\v", "\f", "\x1c", "\x85", "\u00a0", "\u2003"])
def test_whitespace_matches_small_standard_library_oracle(space):
    received = (space * 2 + "+0X_F_F" + space + "ignored tail" + space).encode()
    token = received.decode("utf-8", errors="replace").split()[0]
    assert _render(received) == _word(int(token, 16))


@pytest.mark.parametrize("received", [
    b"not-hex 0X1", b"\xff 0X1", b"\x00x1 0x2",
    "\ufeff0x1 0x2".encode(), "\u200b0x1 0x2".encode(),
])
def test_invalid_first_token_is_not_skipped(received):
    with pytest.raises(ValueError, match="not a hex integer"):
        _render(received)


def test_all_whitespace_keeps_empty_token_diagnostic():
    with pytest.raises(ValueError, match="empty after tokenization"):
        _render(" \t\r\n\x85\u00a0\u2003\x1c".encode())
