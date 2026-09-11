"""Fixture tests for the sizeof_container_of rule.

The allocated pointer and the container_of argument must be the
SAME expression: an allocation and an unrelated container_of elsewhere
in the function say nothing about each other, and the correct
round-trip container_of(&p->member, T, member) passes a field address,
not the allocation.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "sizeof_container_of.cocci"
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
