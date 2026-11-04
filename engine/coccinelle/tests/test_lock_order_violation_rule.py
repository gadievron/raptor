"""Fixture tests for the lock_order_violation rule.

ABBA requires lock B still HELD when A is acquired on the reversed
path; an intervening release of B makes the two critical sections
non-overlapping and must not be reported.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "lock_order_violation.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_spin_abba_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void path_a(void)
            {
                spin_lock(&a);
                spin_lock(&b);
                do_work();
                spin_unlock(&b);
                spin_unlock(&a);
                spin_lock(&b);
                spin_lock(&a);
                do_other();
                spin_unlock(&a);
                spin_unlock(&b);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "lock_order_violation"

    def test_mutex_abba_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void path_m(void)
            {
                mutex_lock(&a);
                mutex_lock(&b);
                do_work();
                mutex_unlock(&b);
                mutex_unlock(&a);
                mutex_lock(&b);
                mutex_lock(&a);
                do_other();
                mutex_unlock(&a);
                mutex_unlock(&b);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_sequential_nonoverlapping_does_not_fire(self, tmp_path):
        # B is released before A is taken — no reversed nesting.
        results = _run_rule(tmp_path, """\
            void sequential(void)
            {
                spin_lock(&a);
                spin_lock(&b);
                do_work();
                spin_unlock(&b);
                spin_unlock(&a);
                spin_lock(&b);
                do_b_only();
                spin_unlock(&b);
                spin_lock(&a);
                do_a_only();
                spin_unlock(&a);
            }
        """)
        assert results == []

    def test_mutex_sequential_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void sequential(void)
            {
                mutex_lock(&a);
                mutex_lock(&b);
                do_work();
                mutex_unlock(&b);
                mutex_unlock(&a);
                mutex_lock(&b);
                do_b_only();
                mutex_unlock(&b);
                mutex_lock(&a);
                do_a_only();
                mutex_unlock(&a);
            }
        """)
        assert results == []
