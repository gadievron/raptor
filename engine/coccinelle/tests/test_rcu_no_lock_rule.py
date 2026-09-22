"""Fixture tests for the rcu_no_lock rule.

Verification-role rule (fires mint confirmed CWE-416 verdicts):
this rule matches the assignment form ptr = rcu_dereference(x)
with position discipline (safe set bound first, bugs are the
complement) and reports on stderr — _run_rule scans both streams.
The positive pins an unlocked assignment; the negative pins the
same assignment inside the lock/unlock pair.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "rcu_no_lock.cocci"
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
