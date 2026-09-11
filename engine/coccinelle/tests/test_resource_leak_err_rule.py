"""Fixture tests for the resource_leak_err rule.

The rule used to flag the mandatory allocation-failure check itself
(``if (!ptr) return -ENOMEM;``), joined allocation and error return
across DIFFERENT functions by identifier name only, and ignored a free
placed before the error check. All three shapes are pinned here, plus
the vocab-rendered variant (learned allocator/deallocator names must
extend the trigger AND both suppression guards together).
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
    Path(__file__).resolve().parents[1] / "rules" / "resource_leak_err.cocci"
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
    def test_error_return_after_successful_alloc_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int leak_on_error(int cond)
            {
                char *ptr;
                ptr = kmalloc(10, 0);
                if (!ptr)
                    return -12;
                if (cond)
                    return -22;
                kfree(ptr);
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "resource_leak_err"
        assert results[0]["line"] == 8

    def test_error_return_without_failure_check_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int leak_on_error(int cond)
            {
                char *ptr;
                ptr = kmalloc(10, 0);
                if (cond)
                    return -22;
                kfree(ptr);
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 6


class TestNegatives:
    def test_allocation_failure_check_does_not_fire(self, tmp_path):
        # Nothing was allocated on the failure path — the mandatory
        # `if (!ptr) return -ENOMEM;` is not a leak.
        results = _run_rule(tmp_path, """\
            int ok_failcheck(void)
            {
                char *ptr;
                ptr = kmalloc(10, 0);
                if (!ptr)
                    return -12;
                kfree(ptr);
                return 0;
            }
        """)
        assert results == []

    def test_free_before_error_check_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok_freed_before(int cond)
            {
                char *ptr;
                ptr = kmalloc(10, 0);
                kfree(ptr);
                if (cond)
                    return -22;
                return 0;
            }
        """)
        assert results == []

    def test_free_inside_error_branch_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok_freed_in_branch(int cond)
            {
                char *ptr;
                ptr = kmalloc(10, 0);
                if (!ptr)
                    return -12;
                if (cond) {
                    kfree(ptr);
                    return -22;
                }
                kfree(ptr);
                return 0;
            }
        """)
        assert results == []

    def test_alloc_and_error_return_in_different_functions(self, tmp_path):
        # Allocation and error return must sit in the SAME function; a
        # name-only join across functions is not a leak.
        results = _run_rule(tmp_path, """\
            int alloc_here(void)
            {
                char *ptr;
                ptr = kmalloc(10, 0);
                kfree(ptr);
                return 0;
            }
            int other_func(char *ptr, int cond)
            {
                ptr = get_buf();
                if (cond)
                    return -22;
                return 0;
            }
        """)
        assert results == []


class TestVocabRendered:
    def test_learned_names_extend_trigger_and_suppression(self, tmp_path):
        vocab = _FakeVocab(
            allocators=frozenset({"xmalloc"}),
            deallocators=frozenset({"xfree"}),
        )
        rendered = render(_RULE, vocab)
        assert rendered is not None
        try:
            # Balanced project-vocabulary code must stay silent...
            balanced = _run_rule(tmp_path, """\
                int ok_vocab(int cond)
                {
                    char *ptr;
                    ptr = xmalloc(10);
                    if (!ptr)
                        return -12;
                    if (cond) {
                        xfree(ptr);
                        return -22;
                    }
                    xfree(ptr);
                    return 0;
                }
            """, rule=rendered)
            assert balanced == []
            # ...while a genuine leak through the learned allocator fires.
            leaky = _run_rule(tmp_path, """\
                int leak_vocab(int cond)
                {
                    char *ptr;
                    ptr = xmalloc(10);
                    if (cond)
                        return -22;
                    xfree(ptr);
                    return 0;
                }
            """, rule=rendered)
            assert len(leaky) == 1
            assert leaky[0]["line"] == 6
        finally:
            rendered.unlink()
