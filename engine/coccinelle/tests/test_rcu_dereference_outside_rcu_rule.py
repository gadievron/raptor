"""Fixture tests for the rcu_dereference_outside_rcu rule.

Verification-role rule (fires mint confirmed CWE-416 verdicts):
rcu_dereference() outside an rcu_read_lock section races a
concurrent grace period. The positive pins a bare dereference (the
rule reports on stderr — _run_rule scans both streams); the
negative pins the dereference wrapped in the lock/unlock pair.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "rcu_dereference_outside_rcu.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(rule), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


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
