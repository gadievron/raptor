"""Host-RPC compute budgets: the daemon's compute language is
magnitude- and time-budgeted.

The attack: ``_parse_bytes_to_int`` tries hex
first, and ``int(tok, 16)`` is exempt from CPython's
``int_max_str_digits`` guard — a hostile target printing ``0x`` + 8 MB
of hex minted a 33.5-Mbit int binding in 0.04 s. ``_safe_eval`` had no
compute budget: an LLM-authored ``x * x`` chain over that binding
burned 11.5 s → 23 s → 69 s per step (×64 steps allowed), and
``1 << leak`` with a moderate leak materialised gigabit ints. CPU DoS
of the sandbox host daemon.

Post-fix contract: hex parsing is digit-budgeted (over-budget runs are
no-match, never truncated), every binding/intermediate/result is
capped at ``_INT_BIT_CEILING`` bits, the fast-blowup operators are
pre-checked so the oversized value is never materialised, and a
wall-clock deadline bounds each expression. Legitimate exploit
arithmetic (64-bit leaks, masks, packing helpers) is regression-pinned
unchanged.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox._daemon import (  # noqa: E402
    _INT_BIT_CEILING,
    _MAX_HEX_DIGITS,
    _parse_bytes_to_int,
    _safe_eval,
)


class TestHexDigitBudget:
    def test_giant_hex_run_is_rejected_not_parsed(self):
        # The attack's exact shape: 8 MB of hex digits.
        t0 = time.monotonic()
        got = _parse_bytes_to_int(b"0x" + b"f" * (8 * 1024 * 1024))
        elapsed = time.monotonic() - t0
        assert got is None
        assert elapsed < 1.0

    def test_over_budget_hex_never_truncates(self):
        # One digit over budget: must be no-match, not a silently
        # truncated wrong-but-plausible value.
        raw = b"0x" + b"a" * (_MAX_HEX_DIGITS + 1)
        assert _parse_bytes_to_int(raw) is None

    def test_normal_leak_shapes_still_parse(self):
        assert _parse_bytes_to_int(b"leak=0x7ffff7a52390\n") == \
            0x7FFFF7A52390
        assert _parse_bytes_to_int(b"canary 0x" + b"a" * _MAX_HEX_DIGITS) \
            == int("a" * _MAX_HEX_DIGITS, 16)
        assert _parse_bytes_to_int(b"value: 140737348059024") == \
            140737348059024

    def test_giant_decimal_still_bounded_by_cpython(self):
        assert _parse_bytes_to_int(b"9" * (10 * 1024 * 1024)) is None


class TestComputeBudgets:
    def test_innocent_exploit_arithmetic_unchanged(self):
        leak = 0x7FFFF7A52390
        assert _safe_eval("leak << 12", {"leak": leak}) == leak << 12
        assert _safe_eval("leak & 0xffffffffffffffff", {"leak": leak}) == \
            leak
        assert _safe_eval("leak + 1", {"leak": leak}) == leak + 1
        assert _safe_eval("u64(p64(leak))", {"leak": leak}) == leak
        assert _safe_eval("p32(leak & 0xffffffff)", {"leak": leak}) == \
            (leak & 0xFFFFFFFF).to_bytes(4, "little")
        assert _safe_eval("raw[8:16]", {"raw": b"A" * 32}) == b"A" * 8

    def test_squaring_chain_is_cut_off(self):
        # An LLM-authored bind_as squaring chain: each step
        # doubles the bit length. Starting from a ceiling-adjacent
        # binding, the very first square must refuse fast — never
        # burn seconds materialising it.
        big = (1 << (_INT_BIT_CEILING - 1)) - 1
        t0 = time.monotonic()
        with pytest.raises(ValueError, match="bit budget"):
            _safe_eval("x * x", {"x": big})
        assert time.monotonic() - t0 < 1.0

    def test_lshift_bomb_never_materialised(self):
        # `1 << leak` with a moderate in-budget VALUE as shift count
        # used to allocate 2**33-bit (1 GiB) ints before any check.
        t0 = time.monotonic()
        with pytest.raises(ValueError, match="bit budget"):
            _safe_eval("1 << leak", {"leak": 2 ** 33})
        assert time.monotonic() - t0 < 1.0

    def test_repetition_bomb_bounded(self):
        with pytest.raises(ValueError, match="byte budget"):
            _safe_eval("pad * n", {"pad": b"A" * 1024, "n": 10 ** 9})

    def test_over_budget_binding_rejected_on_use(self):
        over = 1 << (_INT_BIT_CEILING + 8)
        with pytest.raises(ValueError, match="bit budget"):
            _safe_eval("x + 1", {"x": over})

    def test_result_at_ceiling_boundary_allowed(self):
        v = _safe_eval("1 << n", {"n": _INT_BIT_CEILING - 1})
        assert v.bit_length() == _INT_BIT_CEILING
