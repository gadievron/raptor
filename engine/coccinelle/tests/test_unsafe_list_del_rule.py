"""Fixture tests for the unsafe_list_del rule.

The rule needs ``exists`` semantics: the classic real bug is a
CONDITIONAL delete inside a non-_safe iteration, which forall-path
dots can never match. Delete-then-leave-the-loop shapes stay silent —
the invalidated cursor is only a bug if iteration continues.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "unsafe_list_del.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


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

    def test_address_of_field_head_fires(self, tmp_path):
        # The dominant kernel spelling passes the head as an address
        # expression (&dev->items); an identifier-bound head never
        # matched it, leaving the rule dark on most real call sites.
        results = _run_rule(tmp_path, """\
            void prune(struct dev *d, int x)
            {
                struct entry *e;
                list_for_each_entry(e, &d->items, node) {
                    if (e->id == x)
                        list_del(&e->node);
                }
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "unsafe_list_del"

    def test_address_of_global_head_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static struct list_head alist;
            void drain(void)
            {
                struct entry *e;
                list_for_each_entry(e, &alist, node) {
                    list_del(&e->node);
                }
            }
        """)
        assert len(results) == 1

    def test_hlist_address_head_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void prune(struct bucket *b, int x)
            {
                struct entry *e;
                hlist_for_each_entry(e, &b->chain, node) {
                    if (e->id == x)
                        hlist_del(&e->node);
                }
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_non_cursor_delete_does_not_fire(self, tmp_path):
        # Deleting a DIFFERENT node does not invalidate the cursor's
        # ->next — only cursor deletion corrupts this traversal. Pins
        # the cursor anchoring of the delete arms (an un-anchored
        # list_del(...) arm would flag this).
        results = _run_rule(tmp_path, """\
            void prune(struct dev *d, struct entry *victim)
            {
                struct entry *e;
                list_for_each_entry(e, &d->items, node) {
                    if (e->id == victim->id)
                        list_del(&victim->node);
                }
            }
        """)
        assert results == []
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


@pytest.mark.slow
def test_cursor_repairs_require_traversal_review(tmp_path):
    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig

    cases = [
        ('plain', 'list_for_each_entry', 'list_del(&e->node);', True),
        ('repaired', 'list_for_each_entry',
         'if (list_is_first(&e->node, head)) continue;\nprevious = list_prev_entry(e, node);\nlist_del(&e->node);\ne = previous;', True),
        ('reverse_repaired', 'list_for_each_entry_reverse',
         'if (list_is_last(&e->node, head)) continue;\nprevious = list_next_entry(e, node);\nlist_del(&e->node);\ne = previous;', True),
        ('init', 'list_for_each_entry', 'list_del_init(&e->node);', True),
        ('other_node', 'list_for_each_entry', 'list_del(&other->node);', False),
        ('break', 'list_for_each_entry', 'list_del(&e->node);\nbreak;', False),
        ('return', 'list_for_each_entry', 'list_del(&e->node);\nreturn;', False),
        ('goto', 'list_for_each_entry', 'list_del(&e->node);\ngoto done;', False),
    ]
    lines = ['struct list_head { struct list_head *next, *prev; };',
             'struct entry { struct list_head node; };']
    expected, labelled = [], []
    for name, iterator, body, fires in cases:
        lines += [f'void {name}(struct list_head *head, struct entry *other) {{',
                  'struct entry *e, *previous;', f'{iterator}(e, head, node) {{']
        lines += body.splitlines()
        deletion = next(i+1 for i in range(len(lines)-len(body.splitlines()),len(lines)) if 'list_del' in lines[i])
        lines += ['}', 'done: return;', '}']
        labelled.append({'case':name, 'line':deletion, 'expected_match':fires})
        if fires:
            expected.append(deletion)
    source = '\n'.join(lines)+'\n'
    target = tmp_path / 'cursors.c'
    target.write_text(source)
    proc = run_pinned_subprocess(
        ['spatch', '--sp-file', str(_RULE), str(target), '--no-show-diff', '--no-includes'],
        timeout=45, context='List cursor repair candidate syntax',
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line.removeprefix('COCCIRESULT:'))
            for stream in (proc.stdout, proc.stderr) for line in stream.splitlines()
            if line.startswith('COCCIRESULT:')]
    assert sorted(row['line'] for row in rows) == expected
    assert all(row['rule'] == 'unsafe_list_del' for row in rows)
    assert all('review cursor identity' in row['message'] for row in rows)
