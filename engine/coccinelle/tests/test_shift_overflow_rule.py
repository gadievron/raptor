"""Fixture tests for the shift_overflow rule.

Verification-role rule (fires mint confirmed CWE-682 verdicts):
shifting a literal by >= its type width is undefined behaviour.
The rule emits two ids: shift_overflow_int (int literal, >= 32)
and shift_overflow_long (long/long long literal, >= 64). The
negative pins the widest legal int shift (31).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "shift_overflow.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_int_shift_by_32_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int mask(void)
            {
                return 1 << 32;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "shift_overflow_int"
        assert results[0]["line"] == 3

    def test_long_long_shift_by_64_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned long long mask(void)
            {
                return 1ULL << 64;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "shift_overflow_long"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_int_shift_by_31_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int mask(void)
            {
                return 1 << 31;
            }
        """)
        assert results == []
