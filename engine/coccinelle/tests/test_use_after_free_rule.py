"""Fixture tests for the use_after_free verification-grade rule.

The rule carries ``@role: verification`` — core/audit/sweep.py grants
it direct status promotion, so a false positive here mints a false
"confirmed" UAF verdict. The negative fixtures pin the U12-F1
regression: the header always claimed reassignment suppresses the
match, but the when-clause only excluded reassignment to an allocator
call or NULL, so the canonical safe list-free loop (the most common C
teardown idiom in existence) and plain ``p = q`` reassignment were
flagged as confirmed UAF.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "use_after_free.cocci"
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
    def test_deref_after_free_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct s *p)
            {
                free(p);
                p->x = 1;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "use_after_free"
        assert results[0]["line"] == 4

    def test_deref_after_kfree_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct s *p)
            {
                kfree(p);
                p->x = 1;
            }
        """)
        assert len(results) == 1

    def test_arg_pass_after_kfree_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct s *p)
            {
                kfree(p);
                use_it(p);
            }
        """)
        assert len(results) == 1
        assert "passed to use_it" in results[0]["message"]

    def test_delete_inside_non_safe_iterator_fires(self, tmp_path):
        # A NON-safe iterator advances by reading the freed node, so
        # kfree inside the body is a genuine UAF via the back edge —
        # the _safe-family suppression must not swallow it.
        results = _run_rule(tmp_path, """\
            void bug(struct list_head *head)
            {
                struct entry *e;
                list_for_each_entry(e, head, list) {
                    if (e->dead)
                        kfree(e);
                }
            }
        """)
        assert len(results) >= 1


class TestNegatives:
    def test_canonical_list_free_loop_does_not_fire(self, tmp_path):
        # U12-F1 verifier fixture: the loop back edge reassigns cur
        # before the next iteration's cur->next read.
        results = _run_rule(tmp_path, """\
            void teardown(struct node *head)
            {
                struct node *cur = head;
                struct node *nxt;
                while (cur) {
                    nxt = cur->next;
                    free(cur);
                    cur = nxt;
                }
            }
        """)
        assert results == []

    def test_plain_reassignment_after_free_does_not_fire(self, tmp_path):
        # U12-F1 verifier fixture: p = q is a fresh value — deref is
        # not a UAF, whatever q's provenance.
        results = _run_rule(tmp_path, """\
            void ok(struct node *p, struct node *q)
            {
                free(p);
                p = q;
                p->x = 1;
            }
        """)
        assert results == []

    def test_allocator_reassignment_still_suppresses(self, tmp_path):
        # Pre-fix behaviour preserved: reassignment from an allocator
        # call keeps suppressing.
        results = _run_rule(tmp_path, """\
            void ok(struct s *p)
            {
                kfree(p);
                p = kmalloc(sizeof(*p), GFP_KERNEL);
                p->x = 1;
            }
        """)
        assert results == []

    def test_safe_iterator_delete_idiom_does_not_fire(self, tmp_path):
        # The canonical CORRECT list deletion idiom: the _safe iterator
        # prefetches the next node, so the cursor is reassigned inside
        # the macro at every step. That hidden reassignment is
        # invisible to `when != E = E2`, and the loop back edge from
        # kfree(e) to the next iteration's e->fld read looked like a
        # UAF before the _safe-family suppression.
        results = _run_rule(tmp_path, """\
            void prune(struct list_head *head)
            {
                struct entry *e, *n;
                list_for_each_entry_safe(e, n, head, list) {
                    if (e->dead) {
                        list_del(&e->list);
                        kfree(e);
                    }
                }
            }
        """)
        assert results == []

    def test_hlist_safe_iterator_delete_idiom_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void prune(struct hlist_head *head)
            {
                struct entry *e;
                struct hlist_node *n;
                hlist_for_each_entry_safe(e, n, head, node) {
                    if (e->dead) {
                        hlist_del(&e->node);
                        kfree(e);
                    }
                }
            }
        """)
        assert results == []

    def test_unrelated_pointer_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct s *p, struct s *r)
            {
                free(p);
                r->x = 1;
            }
        """)
        assert results == []
