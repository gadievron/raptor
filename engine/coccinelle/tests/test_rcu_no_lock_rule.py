"""Fixture tests for the rcu_no_lock rule.

Detection-role rule: callers may already hold a read-side lock. Explicit
check/protected APIs carry their own protection contracts and stay out of scope.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "rcu_no_lock.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_assignment_without_lock_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *peek(struct table *t)
            {
                void *entry;
                entry = rcu_dereference(t->head);
                return entry;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "rcu_no_lock"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_assignment_inside_lock_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *peek(struct table *t)
            {
                void *entry;
                rcu_read_lock();
                entry = rcu_dereference(t->head);
                rcu_read_unlock();
                return entry;
            }
        """)
        assert results == []


def test_checked_dereference_does_not_require_a_local_read_lock(tmp_path):
    rows = _run_rule(tmp_path, "void *f(void *head) { void *p; p = rcu_dereference_check(head, lockdep_is_held(&lock)); return p; }")
    assert rows == []
