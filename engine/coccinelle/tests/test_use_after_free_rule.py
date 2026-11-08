"""Native heap-lifetime candidate contracts and ownership controls."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "use_after_free.cocci"
)

# Real-tool fixtures belong to engine CI's native integration partition.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("spatch") is None, reason="coccinelle not installed"),
]


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


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


class TestVocabRendered:
    """Behavioural pins for the vocab-rendered form.

    The report-script ``_safe`` suppression set spans multiple lines;
    a line-bound splice left it seed-only while the SmPL trigger
    alternations DID learn the project deallocator — so a learned
    ``my_free(o)`` after ``kfree(o)`` was reported as use-after-free
    (a double-free shape the seed design deliberately routes away
    from this rule), mislabelled, on every vocabulary-bearing audit.
    """

    def _run_rendered(
        self, tmp_path: Path, rendered: Path, source: str,
    ) -> list[dict]:
        return run_rule(tmp_path, source, rendered)

    def test_learned_deallocator_joins_the_safe_set(self, tmp_path):
        from core.audit.condition_smt import DomainVocabulary
        from engine.coccinelle.vocab_renderer import render

        vocab = DomainVocabulary(deallocators=frozenset({"my_project_free"}))
        rendered = render(_RULE, vocab)
        assert rendered is not None
        try:
            # A learned deallocator call after kfree is a DOUBLE-FREE
            # shape, not a use-after-free — the seed design routes it
            # away from this rule (kvfree after kfree stays silent),
            # and the learned lane must inherit that routing.
            silent = self._run_rendered(tmp_path, rendered, """\
                void teardown(struct s *o)
                {
                    kfree(o);
                    my_project_free(o);
                }
            """)
            assert silent == []
            # Control: a genuine use through a non-deallocator still
            # fires under the rendered rule.
            fires = self._run_rendered(tmp_path, rendered, """\
                void bug(struct s *o)
                {
                    kfree(o);
                    consume(o);
                }
            """)
            assert len(fires) == 1
            assert fires[0]["line"] == 4
        finally:
            rendered.unlink()


@pytest.mark.parametrize("use", ["p->value", "*p", "p[0]", "(*p).value", "p[0].value"])
def test_field_pointer_and_array_reads_report_one_access(tmp_path, use):
    rows = _run_rule(tmp_path, f"struct node {{ int value; }};\nvoid f(struct node *p) {{ free(p); inspect({use}); }}\n")
    assert len(rows) == 1
    assert rows[0]["message"].startswith("Candidate:")


def test_multiple_later_reads_survive_earlier_reads(tmp_path):
    lines = ["struct node { int value; };", "void f(struct node *p) {", "free(p);",
             "inspect(p->value);", "inspect(*p);", "inspect(p[0]);", "}"]
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == {lines.index(s) + 1 for s in ("inspect(p->value);", "inspect(*p);", "inspect(p[0]);")}
    assert len(rows) == 3


def test_ordinary_sizeof_is_not_a_runtime_access(tmp_path):
    rows = _run_rule(tmp_path, """
        struct node { int value; };
        void f(struct node *p) {
            kfree(p);
            inspect(sizeof(*p));
            inspect(sizeof(p->value));
            inspect(sizeof(p[0]));
            inspect(sizeof(p->value + 1));
            inspect(sizeof(1 + sizeof(p->value)));
            inspect(sizeof(record_address(p)));
            inspect(p->value);
        }
    """)
    assert len(rows) == 1
    assert "dereferenced" in rows[0]["message"]


def test_runtime_array_bound_is_not_blanket_suppressed_by_sizeof(tmp_path):
    rows = _run_rule(tmp_path, """
        struct node { int value; };
        void f(struct node *p) {
            free(p);
            inspect(sizeof(int[p->value]));
        }
    """)
    assert len(rows) == 1


def test_safe_iterator_does_not_hide_a_use_in_the_same_iteration(tmp_path):
    rows = _run_rule(tmp_path, """
        void f(struct list_head *head) {
            struct node *e, *next;
            list_for_each_entry_safe(e, next, head, list) {
                kfree(e);
                e->value = 1;
            }
        }
    """)
    assert len(rows) == 1


def test_opaque_callee_remains_a_review_candidate(tmp_path):
    rows = _run_rule(tmp_path, "void f(void *p) { kfree(p); record_address(p); }\n")
    assert len(rows) == 1
    assert "passed to record_address" in rows[0]["message"]
    assert "review callee behavior" in rows[0]["message"]
    assert "dereferenced" not in rows[0]["message"]
