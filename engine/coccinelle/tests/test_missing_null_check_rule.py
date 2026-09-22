"""Fixture tests for the missing_null_check rule.

Both SmPL rules (``assign_alloc`` re-assignment and ``decl_alloc``
declaration-init) are pinned with a fire and a checked-silent shape.
The vocab-rendered lane pins two regressions at once: the
``@vocab-tmpl`` lines used to omit the trailing ``;`` (the rendered
form was an spatch parse error, so the ENTIRE rule — seed lanes
included — went dark on every vocabulary-bearing audit), and the
renderer indented star templates (an indented ``*`` line parses clean
but silently never matches, so the learned lane alone went dark).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from engine.coccinelle.vocab_renderer import render

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "missing_null_check.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


@dataclass
class _FakeVocab:
    allocators: frozenset = field(default_factory=frozenset)
    deallocators: frozenset = field(default_factory=frozenset)
    lock_acquires: frozenset = field(default_factory=frozenset)
    lock_releases: frozenset = field(default_factory=frozenset)
    refcount_gets: frozenset = field(default_factory=frozenset)
    refcount_puts: frozenset = field(default_factory=frozenset)
    callback_cancels: frozenset = field(default_factory=frozenset)


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
    def test_assigned_alloc_deref_without_check_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct s { int x; };
            int f(void)
            {
                struct s *a;
                a = kmalloc(sizeof(*a), 0);
                a->x = 1;
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "missing_null_check"
        assert results[0]["line"] == 5

    def test_declared_alloc_deref_without_check_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int g(void)
            {
                char *p = malloc(10);
                *p = 'a';
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 3


class TestNegatives:
    def test_null_checked_alloc_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct s { int x; };
            int f(void)
            {
                struct s *a;
                a = kmalloc(sizeof(*a), 0);
                if (!a)
                    return -12;
                a->x = 1;
                return 0;
            }
        """)
        assert results == []

    def test_null_compare_checked_decl_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int g(void)
            {
                char *p = malloc(10);
                if (p == NULL)
                    return -1;
                *p = 'a';
                return 0;
            }
        """)
        assert results == []

    def test_non_allocator_assignment_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct s { int x; };
            int f(struct s *src)
            {
                struct s *a;
                a = src;
                a->x = 1;
                return 0;
            }
        """)
        assert results == []


class TestVocabRendered:
    def test_rendered_rule_seed_and_learned_lanes_fire(self, tmp_path):
        vocab = _FakeVocab(allocators=frozenset({"xnew"}))
        rendered = render(_RULE, vocab)
        assert rendered is not None
        try:
            # The seed lane must survive rendering (the missing-';'
            # regression made the whole rendered rule a parse error)...
            seed = _run_rule(tmp_path, """\
                int f(void)
                {
                    char *p;
                    p = malloc(10);
                    *p = 'a';
                    return 0;
                }
            """, rule=rendered)
            assert len(seed) == 1
            assert seed[0]["line"] == 4
            # ...and the learned allocator must actually match (the
            # indented-star regression left this lane silently dead).
            learned = _run_rule(tmp_path, """\
                struct s { int x; };
                int f(void)
                {
                    struct s *a;
                    a = xnew(10);
                    a->x = 1;
                    return 0;
                }
            """, rule=rendered)
            assert len(learned) == 1
            assert learned[0]["line"] == 5
            # Checked project-vocabulary code stays silent.
            checked = _run_rule(tmp_path, """\
                struct s { int x; };
                int f(void)
                {
                    struct s *a;
                    a = xnew(10);
                    if (!a)
                        return -12;
                    a->x = 1;
                    return 0;
                }
            """, rule=rendered)
            assert checked == []
        finally:
            rendered.unlink()
