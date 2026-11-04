"""Fixture tests for the rcu_dereference_outside_rcu rule.

Verification-role rule (fires mint confirmed CWE-416 verdicts):
rcu_dereference() outside an rcu_read_lock section races a
concurrent grace period. The positive pins a bare dereference (the
rule reports on stderr — _run_rule scans both streams); the
negative pins the dereference wrapped in the lock/unlock pair.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "rcu_dereference_outside_rcu.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_dereference_without_lock_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *peek(struct table *t)
            {
                void *entry = rcu_dereference(t->head);
                return entry;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "rcu_dereference_outside_rcu"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_dereference_inside_lock_does_not_fire(self, tmp_path):
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
