"""Fixture tests for the integer_overflow_alloc rule.

Negatives pin the sizeof-product exclusion: ``malloc(n * sizeof(T))``
and ``kmalloc(n * sizeof(*p), ...)`` are the idiomatic C array
allocation, and whether the count is range-limited is a caller-side
property the allocation site cannot decide — the rule must not report
them. Positives keep the genuine target firing: a product of two
non-sizeof operands with no overflow guard.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "integer_overflow_alloc.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_two_variable_product_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *bug(size_t rows, size_t cols)
            {
                return malloc(rows * cols);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "integer_overflow_alloc"

    def test_kmalloc_two_variable_product_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *bug(unsigned int count, unsigned int elem_size)
            {
                return kmalloc(count * elem_size, GFP_KERNEL);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_count_times_sizeof_type_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *ok(size_t n)
            {
                return malloc(n * sizeof(struct item));
            }
        """)
        assert results == []

    def test_count_times_sizeof_deref_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct p *ok(int n)
            {
                struct p *p = kmalloc(n * sizeof(*p), GFP_KERNEL);
                return p;
            }
        """)
        assert results == []

    def test_sizeof_first_operand_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *ok(size_t n)
            {
                return malloc(sizeof(struct item) * n);
            }
        """)
        assert results == []

    def test_constant_product_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *ok(void)
            {
                return malloc(16 * 32);
            }
        """)
        assert results == []

    def test_size_max_guard_suppresses(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *ok(size_t a, size_t b)
            {
                if (a > SIZE_MAX / b)
                    return 0;
                return malloc(a * b);
            }
        """)
        assert results == []
