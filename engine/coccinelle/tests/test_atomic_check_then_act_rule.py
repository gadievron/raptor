"""Native fixtures for atomic-read action review candidates.

Canonical dec-and-test releases remain quiet. Atomic-read/action shapes
remain visible, while callee behaviour and ownership need independent
review before treating a candidate as a race.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "atomic_check_then_act.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


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


@pytest.mark.parametrize("action", [
    pytest.param("kfree(o)", id="free"),
    pytest.param("obj_destroy(o)", id="destructor"),
])
def test_intervening_atomic_operations_keep_counter_identity(tmp_path, action):
    # Inert syntax matrix: a different object or field does not operate on
    # the counter checked by atomic_read. A same-counter exclusion does not
    # itself certify lifetime or concurrency safety.
    operations = [
        "atomic_dec({pointer})",
        "atomic_inc({pointer})",
        "atomic_set({pointer}, 1)",
        "atomic_add(1, {pointer})",
        "atomic_sub(1, {pointer})",
        "atomic_cmpxchg({pointer}, 1, 2)",
        "atomic_xchg({pointer}, 1)",
        "atomic_dec_and_test({pointer})",
        "atomic_inc_return({pointer})",
        "atomic_dec_return({pointer})",
    ]
    lines = [
        "typedef struct { int counter; } atomic_t;",
        "struct obj { atomic_t refcnt; atomic_t othercnt; };",
    ]
    expected_lines = set()
    for index, operation in enumerate(operations):
        for scope, pointer in enumerate((
            "&o->refcnt", "&o->othercnt", "&other->refcnt",
        )):
            lines += [
                f"void case_{index}_{scope}(struct obj *o, struct obj *other) {{",
                "if (o == other) return;",
                "if (atomic_read(&o->refcnt) > 0) {",
                operation.format(pointer=pointer) + ";",
                action + ";",
                "}",
                "}",
            ]
            if scope:
                expected_lines.add(len(lines) - 2)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert len(rows) == len(expected_lines)
    assert {row["line"] for row in rows} == expected_lines
    assert all(row["rule"] == "atomic_check_then_act" for row in rows)
