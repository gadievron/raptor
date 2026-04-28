"""Tests for core.smt_solver.rejection helpers."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

# core/smt_solver/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.smt_solver import (
    BV_C_UINT8,
    BV_C_UINT64,
    Rejection,
    RejectionKind,
    classify_solver_unknown,
    parse_literal_value,
    propagate,
)


# ---------------------------------------------------------------------------
# classify_solver_unknown
# ---------------------------------------------------------------------------

class TestClassifySolverUnknown:
    """Maps Z3's ``reason_unknown()`` text to SOLVER_TIMEOUT vs SOLVER_UNKNOWN."""

    def _mock(self, reason):
        m = MagicMock()
        m.reason_unknown.return_value = reason
        return m

    def test_timeout(self):
        assert classify_solver_unknown(self._mock("timeout")) is RejectionKind.SOLVER_TIMEOUT

    def test_canceled_us_spelling(self):
        assert classify_solver_unknown(self._mock("canceled")) is RejectionKind.SOLVER_TIMEOUT

    def test_cancelled_uk_spelling(self):
        assert classify_solver_unknown(self._mock("cancelled")) is RejectionKind.SOLVER_TIMEOUT

    def test_uppercase_normalised(self):
        # The classifier lowercases before matching.
        assert classify_solver_unknown(self._mock("TIMEOUT")) is RejectionKind.SOLVER_TIMEOUT

    def test_substring_match(self):
        # Z3 sometimes wraps the reason ("(canceled): ..."); substring is fine.
        assert classify_solver_unknown(self._mock("(canceled) per-call timeout")) is RejectionKind.SOLVER_TIMEOUT

    def test_other_reason_is_solver_unknown(self):
        assert classify_solver_unknown(self._mock("incomplete tactic")) is RejectionKind.SOLVER_UNKNOWN

    def test_empty_reason_is_solver_unknown(self):
        assert classify_solver_unknown(self._mock("")) is RejectionKind.SOLVER_UNKNOWN

    def test_none_reason_is_solver_unknown(self):
        # Some Z3 builds return None instead of "".  The helper coerces with
        # ``or ""`` so it still classifies cleanly.
        assert classify_solver_unknown(self._mock(None)) is RejectionKind.SOLVER_UNKNOWN

    def test_reason_unknown_raises(self):
        # Defensive: solver missing reason_unknown() shouldn't crash callers.
        m = MagicMock()
        m.reason_unknown.side_effect = AttributeError
        assert classify_solver_unknown(m) is RejectionKind.SOLVER_UNKNOWN


# ---------------------------------------------------------------------------
# propagate
# ---------------------------------------------------------------------------

class TestPropagate:
    """Re-anchors a sub-rejection's text on the parent input."""

    def test_replaces_text_keeps_other_fields(self):
        sub = Rejection("inner", RejectionKind.UNRECOGNIZED_OPERAND, "detail", "hint")
        out = propagate("full outer text", sub)
        assert out.text == "full outer text"
        assert out.kind is RejectionKind.UNRECOGNIZED_OPERAND
        assert out.detail == "detail"
        assert out.hint == "hint"

    def test_returns_new_instance(self):
        sub = Rejection("inner", RejectionKind.LEX_EMPTY)
        out = propagate("outer", sub)
        assert out is not sub


# ---------------------------------------------------------------------------
# parse_literal_value
# ---------------------------------------------------------------------------

class TestParseLiteralValue:
    """Centralised literal validation across all encoders."""

    def test_decimal(self):
        assert parse_literal_value("42", BV_C_UINT64) == 42

    def test_hex(self):
        assert parse_literal_value("0xff", BV_C_UINT64) == 0xff

    def test_hex_uppercase(self):
        assert parse_literal_value("0xFF", BV_C_UINT64) == 0xff

    def test_leading_zero_decimal_rejected(self):
        r = parse_literal_value("01234", BV_C_UINT64)
        assert isinstance(r, Rejection)
        assert r.kind is RejectionKind.LITERAL_AMBIGUOUS

    def test_zero_alone_accepted(self):
        # "0" has length 1 so the leading-zero check doesn't fire.
        assert parse_literal_value("0", BV_C_UINT64) == 0

    def test_out_of_range(self):
        # 0x100 doesn't fit in uint8 (range 0..0xff).
        r = parse_literal_value("0x100", BV_C_UINT8)
        assert isinstance(r, Rejection)
        assert r.kind is RejectionKind.LITERAL_OUT_OF_RANGE

    def test_unrecognised_token(self):
        r = parse_literal_value("notALiteral", BV_C_UINT64)
        assert isinstance(r, Rejection)
        assert r.kind is RejectionKind.UNRECOGNIZED_OPERAND
