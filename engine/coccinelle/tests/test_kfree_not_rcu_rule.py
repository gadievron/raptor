"""Fixture tests for the kfree_not_rcu verification-grade rule.

The rule is promote-capable (@role: verification), so its match
condition must bind the freed pointer to the RCU-published one — a
free of an unrelated pointer after any publish, or a free behind a
grace period, must not fire.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "kfree_not_rcu.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(_RULE), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for line in proc.stdout.splitlines():
        if line.startswith("COCCIRESULT:"):
            results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


class TestPositives:
    def test_publish_then_free_same_pointer_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct cfg **head, struct cfg *newc)
            {
                rcu_assign_pointer(*head, newc);
                kfree(newc);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "kfree_not_rcu"

    def test_hlist_add_then_free_same_object_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct obj *o, struct hlist_head *h)
            {
                hlist_add_head_rcu(&o->node, h);
                kfree(o);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_free_of_unrelated_pointer_does_not_fire(self, tmp_path):
        # The original rule fired on ANY free after ANY publish in the
        # same function — false CWE-416 confirmations.
        results = _run_rule(tmp_path, """\
            void ok(struct cfg **head, struct cfg *newc, struct other *tmp)
            {
                rcu_assign_pointer(*head, newc);
                kfree(tmp);
            }
        """)
        assert results == []

    def test_grace_period_then_free_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct cfg **head, struct cfg *newc)
            {
                rcu_assign_pointer(*head, newc);
                synchronize_rcu();
                kfree(newc);
            }
        """)
        assert results == []

    def test_swap_and_free_old_after_sync_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct cfg **head, struct cfg *newc)
            {
                struct cfg *old = *head;
                rcu_assign_pointer(*head, newc);
                synchronize_rcu();
                kfree(old);
            }
        """)
        assert results == []

    def test_kfree_rcu_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct cfg **head, struct cfg *newc)
            {
                rcu_assign_pointer(*head, newc);
                kfree_rcu(newc, rcu);
            }
        """)
        assert results == []
