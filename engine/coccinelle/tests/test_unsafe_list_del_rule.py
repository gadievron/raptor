"""Fixture tests for the unsafe_list_del rule.

The rule needs ``exists`` semantics: the classic real bug is a
CONDITIONAL delete inside a non-_safe iteration, which forall-path
dots can never match. Delete-then-leave-the-loop shapes stay silent —
the invalidated cursor is only a bug if iteration continues.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "unsafe_list_del.cocci"
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
    def test_conditional_delete_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void prune(struct list_head *lh, int x)
            {
                struct entry *e;
                list_for_each_entry(e, lh, list) {
                    if (e->id == x)
                        list_del(&e->list);
                }
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "unsafe_list_del"

    def test_unconditional_delete_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void drain(struct list_head *lh)
            {
                struct entry *e;
                list_for_each_entry(e, lh, list) {
                    list_del(&e->list);
                }
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_safe_iterator_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void prune(struct list_head *lh, int x)
            {
                struct entry *e, *n;
                list_for_each_entry_safe(e, n, lh, list) {
                    if (e->id == x)
                        list_del(&e->list);
                }
            }
        """)
        assert results == []

    def test_delete_then_break_does_not_fire(self, tmp_path):
        # No next iteration ever dereferences the stale cursor.
        results = _run_rule(tmp_path, """\
            void remove_one(struct list_head *lh, int x)
            {
                struct entry *e;
                list_for_each_entry(e, lh, list) {
                    if (e->id == x) {
                        list_del(&e->list);
                        break;
                    }
                }
            }
        """)
        assert results == []
