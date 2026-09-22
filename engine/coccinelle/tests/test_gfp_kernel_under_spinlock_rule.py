"""Fixture tests for the gfp_kernel_under_spinlock rule.

Verification-role rule (fires mint confirmed CWE-764 verdicts):
GFP_KERNEL can sleep, and sleeping under a spinlock deadlocks. The
positive pins kmalloc(GFP_KERNEL) inside the lock; the negatives
pin the GFP_ATOMIC fix and an allocation moved after the unlock.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "gfp_kernel_under_spinlock.cocci"
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
    def test_gfp_kernel_inside_lock_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void reserve(struct ctx *c)
            {
                spin_lock(&c->lock);
                c->buf = kmalloc(64, GFP_KERNEL);
                spin_unlock(&c->lock);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "gfp_kernel_under_spinlock"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_gfp_atomic_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void reserve(struct ctx *c)
            {
                spin_lock(&c->lock);
                c->buf = kmalloc(64, GFP_ATOMIC);
                spin_unlock(&c->lock);
            }
        """)
        assert results == []

    def test_allocation_after_unlock_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void reserve(struct ctx *c)
            {
                spin_lock(&c->lock);
                c->pending = 1;
                spin_unlock(&c->lock);
                c->buf = kmalloc(64, GFP_KERNEL);
            }
        """)
        assert results == []
