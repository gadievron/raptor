"""Fixture tests for the atomic_check_then_act verification-grade rule.

The rule carries ``@role: verification`` — core/audit/sweep.py grants
it direct status promotion, so a false positive here mints a false
"confirmed" race verdict. The negatives pin the canonical race-free
refcount put ``if (atomic_dec_and_test(&o->cnt)) kfree(o);``: the
dec-and-test IS the atomic check-then-act, so the rule must never
report it. The positives keep the genuine two-step shape firing:
``atomic_read`` in a condition followed by a destructive action is a
real non-atomic check-then-act window.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "atomic_check_then_act.cocci"
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
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


class TestPositives:
    def test_atomic_read_then_kfree_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct obj *o)
            {
                if (atomic_read(&o->refcnt) == 0) {
                    kfree(o);
                }
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "atomic_check_then_act"
        assert "atomic_read" in results[0]["message"]

    def test_atomic_read_then_destructor_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct obj *o)
            {
                if (atomic_read(&o->refcnt) == 0) {
                    obj_destroy(o);
                }
            }
        """)
        assert len(results) == 1
        assert "obj_destroy" in results[0]["message"]


class TestNegatives:
    def test_dec_and_test_kfree_put_idiom_does_not_fire(self, tmp_path):
        # The canonical race-free refcount release: dec-and-test is
        # itself the atomic check-then-act.
        results = _run_rule(tmp_path, """\
            void put_obj(struct obj *o)
            {
                if (atomic_dec_and_test(&o->refcnt))
                    kfree(o);
            }
        """)
        assert results == []

    def test_dec_and_test_destructor_put_idiom_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void put_obj(struct obj *o)
            {
                if (atomic_dec_and_test(&o->refcnt))
                    obj_destroy(o);
            }
        """)
        assert results == []

    def test_atomic_read_under_lock_does_not_fire(self, tmp_path):
        # Lock held across check and act: no race window.
        results = _run_rule(tmp_path, """\
            void ok(struct obj *o)
            {
                spin_lock(&o->lock);
                if (atomic_read(&o->refcnt) == 0) {
                    kfree(o);
                }
                spin_unlock(&o->lock);
            }
        """)
        assert results == []
