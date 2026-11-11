"""Fixture tests for the gfp_kernel_under_spinlock rule.

Verification-role rule (fires mint confirmed CWE-764 verdicts):
GFP_KERNEL can sleep, and sleeping under a spinlock deadlocks. The
positive pins kmalloc(GFP_KERNEL) inside the lock; the negatives
pin the GFP_ATOMIC fix and an allocation moved after the unlock.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "gfp_kernel_under_spinlock.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


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


_ALLOCATOR_CALLS = [
    pytest.param("kmalloc(64, GFP_KERNEL)", id="kmalloc"),
    pytest.param("kzalloc(64, GFP_KERNEL)", id="kzalloc"),
    pytest.param("kvmalloc(64, GFP_KERNEL)", id="kvmalloc"),
    pytest.param("kcalloc(2, 8, GFP_KERNEL)", id="kcalloc"),
    pytest.param("krealloc(old, 64, GFP_KERNEL)", id="krealloc"),
    pytest.param("kmalloc_array(2, 8, GFP_KERNEL)", id="kmalloc-array"),
]


@pytest.mark.parametrize("allocation", _ALLOCATOR_CALLS)
def test_allocator_flags_at_declared_position(tmp_path, allocation):
    results = _run_rule(tmp_path, f"""\
        void reserve(struct ctx *c, void *old)
        {{
            spin_lock(&c->lock);
            c->buf = {allocation};
            spin_unlock(&c->lock);
        }}
    """)
    assert [(row["rule"], row["line"]) for row in results] == [
        ("gfp_kernel_under_spinlock", 4),
    ]


@pytest.mark.parametrize("allocation", _ALLOCATOR_CALLS)
def test_each_allocator_after_unlock_is_quiet(tmp_path, allocation):
    results = _run_rule(tmp_path, f"""\
        void reserve(struct ctx *c, void *old)
        {{
            spin_lock(&c->lock);
            spin_unlock(&c->lock);
            c->buf = {allocation};
        }}
    """)
    assert results == []


@pytest.mark.parametrize("allocation", [
    pytest.param("kmalloc(GFP_KERNEL, GFP_ATOMIC)", id="kmalloc-size"),
    pytest.param("kzalloc(GFP_KERNEL, GFP_ATOMIC)", id="kzalloc-size"),
    pytest.param("kcalloc(GFP_KERNEL, 8, GFP_ATOMIC)", id="kcalloc-count"),
    pytest.param("kcalloc(2, GFP_KERNEL, GFP_ATOMIC)", id="kcalloc-size"),
    pytest.param("krealloc(old, GFP_KERNEL, GFP_ATOMIC)", id="krealloc-size"),
    pytest.param("kmalloc_array(GFP_KERNEL, 8, GFP_ATOMIC)", id="array-count"),
    pytest.param("kmalloc_array(2, GFP_KERNEL, GFP_ATOMIC)", id="array-size"),
])
def test_size_and_count_arguments_are_not_allocation_flags(tmp_path, allocation):
    # These are inert syntax controls. kvmalloc is deliberately excluded:
    # its API does not support GFP_ATOMIC or GFP_NOWAIT allocation flags.
    results = _run_rule(tmp_path, f"""\
        void reserve(struct ctx *c, void *old)
        {{
            spin_lock(&c->lock);
            c->buf = {allocation};
            spin_unlock(&c->lock);
        }}
    """)
    assert results == []
