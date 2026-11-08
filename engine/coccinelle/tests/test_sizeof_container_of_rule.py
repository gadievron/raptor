"""Fixture tests for the sizeof_container_of rule.

The allocated pointer and the container_of argument must be the
SAME expression: an allocation and an unrelated container_of elsewhere
in the function say nothing about each other, and the correct
round-trip container_of(&p->member, T, member) passes a field address,
not the allocation.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "sizeof_container_of.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_member_sized_alloc_passed_to_container_of_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct foo { int x; struct work_struct work; };
            void setup(void)
            {
                struct work_struct *w;
                struct foo *f;
                w = kmalloc(sizeof(*w), GFP_KERNEL);
                f = container_of(w, struct foo, work);
                f->x = 1;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "sizeof_container_of"

    def test_named_type_alloc_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct foo { int x; struct work_struct work; };
            void setup(void)
            {
                struct work_struct *w;
                struct foo *f;
                w = kzalloc(sizeof(struct work_struct), GFP_KERNEL);
                f = container_of(w, struct foo, work);
                f->x = 1;
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_unrelated_container_of_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct bar { int y; struct work_struct work; };
            void fine(struct work_struct *unrelated)
            {
                struct baz *p;
                struct bar *q;
                p = kmalloc(sizeof(*p), GFP_KERNEL);
                q = container_of(unrelated, struct bar, work);
                use(p, q);
            }
        """)
        assert results == []

    def test_roundtrip_field_address_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct bar { int y; struct work_struct work; };
            void roundtrip(void)
            {
                struct bar *b;
                struct bar *back;
                b = kmalloc(sizeof(*b), GFP_KERNEL);
                back = container_of(&b->work, struct bar, work);
                use2(back);
            }
        """)
        assert results == []


@pytest.mark.parametrize("declaration", [False, True], ids=["assigned", "declared"])
def test_allocation_origins_and_pointer_changes(tmp_path, declaration):
    changes = [("", True), ("p = other;", False), ("p += 1;", False),
               ("p++;", False), ("++p;", False), ("replace(&p);", False),
               ("p->x = 1;", True), ("if (choose) p = other;", True)]
    lines = ["struct inner { int x; };", "struct outer { long prefix; struct inner node; };"]
    expected = set()
    for api in ("kmalloc", "kzalloc"):
        for size in ("sizeof(*p)", "sizeof(struct inner)"):
            for change, candidate in changes:
                lines.append(f"void origin_{len(lines)}(struct inner *other, int choose) {{")
                if not declaration:
                    lines.append("  struct inner *p;")
                prefix = "struct inner *p" if declaration else "p"
                lines.append(f"  {prefix} = {api}({size}, 0);")
                if candidate:
                    expected.add(len(lines))
                if change:
                    lines.append(f"  {change}")
                lines += ["  consume(container_of(p, struct outer, node));", "}"]
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)


class TestDocumentedLimits:
    def test_whole_first_member_container_can_be_intentional(self, tmp_path):
        rows = _run_rule(tmp_path, """\
            struct inner { int x; };
            struct outer { struct inner first; };
            void f(void) {
                struct inner *p;
                p = kmalloc(sizeof(struct outer), 0);
                consume(container_of(p, struct outer, first));
            }
        """)
        assert len(rows) == 1
        assert "Candidate:" in rows[0]["message"]
