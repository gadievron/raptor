"""Unit tests for ``_extract_one_path``'s witness contract (no angr).

The per-path concrete input must never be truncated: a path can be
constrained on bytes beyond the cap, so a shortened witness may violate
the constraints it claims to satisfy — downstream replay (PoC seeds,
fuzz corpora) would then read a real finding as refuted.
"""

from __future__ import annotations

from core.symbolic._constraints import _extract_one_path


class _FakePosix:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def dumps(self, fd: int) -> bytes:
        return self._data


class _FakeSolver:
    constraints: list = []


class _FakeState:
    def __init__(self, data: bytes) -> None:
        self.posix = _FakePosix(data)
        self.solver = _FakeSolver()


def test_witness_within_cap_emitted_untouched() -> None:
    path = _extract_one_path(_FakeState(b"ABCD"), max_input_bytes=8)
    assert path["concrete_input_hex"] == b"ABCD".hex()
    assert path["concrete_input_over_cap"] is False


def test_witness_over_cap_withheld_never_truncated() -> None:
    path = _extract_one_path(_FakeState(b"A" * 16), max_input_bytes=8)
    assert path["concrete_input_hex"] is None
    assert path["concrete_input_over_cap"] is True
