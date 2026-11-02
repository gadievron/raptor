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
import re
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
    assert proc.returncode == 0, proc.stderr
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


    def test_one_record_per_report_site(self, tmp_path):
        # Both branches allocate, one error return leaks: the report
        # script used to emit one record per (return, allocation) pair
        # — same site, near-identical messages — leaving dedup to the
        # consumer.
        results = _run_rule(tmp_path, """\
            int f(int a, int b)
            {
                char *p;
                if (a)
                    p = kmalloc(8, 1);
                else
                    p = kzalloc(16, 1);
                if (b) {
                    return -1;
                }
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 9

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


# Compile/parse-only controls; unsafe functions must not be executed. Names
# encode the independently reviewed expected leak, not a source-line pin.
_PATH_CONTROLS = r"""
extern void *kmalloc(unsigned long, int);
extern void *kzalloc(unsigned long, int);
extern void *kcalloc(unsigned long, unsigned long, int);
extern void *kmalloc_array(unsigned long, unsigned long, int);
extern void *vmalloc(unsigned long);
extern void *kvmalloc(unsigned long, int);
extern void kfree(void *);
extern void kvfree(void *);
extern void vfree(void *);
extern void kfree_sensitive(void *);
extern void mutate(int **, int *);
extern int *other(void);
extern void consume(int *);
extern void take_int(int *);

int safe_fallback(int heap, int fail) {
  int local[4], *ptr = local;
  if (heap) {
    ptr = kmalloc(64, 0);
    if (!ptr)
      return -12;
  }
  if (fail) {
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  if (ptr != local)
    kfree(ptr);
  return 0;
}
int safe_fallback_swapped(int heap, int fail) {
  int local[4], *ptr = local;
  if (heap) {
    ptr = kmalloc(64, 0);
    if (!ptr)
      return -12;
  }
  if (fail) {
    if (local != ptr)
      kfree(ptr);
    return -1;
  }
  if (local != ptr)
    kfree(ptr);
  return 0;
}
int safe_fallback_later_error(int heap, int fail, int later) {
  int local[4], *ptr = local;
  if (heap) {
    ptr = kmalloc(64, 0);
    if (!ptr)
      return -12;
  }
  if (fail) {
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  if (ptr != local)
    kfree(ptr);
  if (later)
    return -2;
  return 0;
}
int safe_sensitive(int fail) {
  int *ptr;
  ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  kfree_sensitive(ptr);
  if (fail)
    return -1;
  return 0;
}
int safe_init_failure(void) {
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  kfree(ptr);
  return 0;
}
int safe_init_freed(int fail) {
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail) {
    kfree(ptr);
    return -1;
  }
  kfree(ptr);
  return 0;
}
int safe_heap_compared_array(int fail) {
  int local[4];
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail) {
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  kfree(ptr);
  return 0;
}
int unsafe_init(int fail) {
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail)
    return -1;
  kfree(ptr);
  return 0;
}
int unsafe_assign(int fail) {
  int *ptr;
  ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail)
    return -1;
  kfree(ptr);
  return 0;
}
int unsafe_release_flag(int fail, int release) {
  int *ptr;
  ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail) {
    if (release)
      kfree(ptr);
    return -1;
  }
  kfree(ptr);
  return 0;
}
int unsafe_outer_flag(int fail, int release) {
  int local[4];
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail) {
    if (release) {
      if (ptr != local)
        kfree(ptr);
    }
    return -1;
  }
  kfree(ptr);
  return 0;
}
int unsafe_wrong_array_condition(int fail) {
  int local[4];
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail) {
    if (ptr == local)
      kfree(ptr);
    return -1;
  }
  kfree(ptr);
  return 0;
}
int unsafe_address_after(int fail) {
  int local[4];
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  mutate(&ptr, local);
  if (fail) {
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  return 0;
}
int unsafe_alias_before(int fail) {
  int local[4];
  int *ptr;
  int **alias = &ptr;
  ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  mutate(alias, local);
  if (fail) {
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  return 0;
}
int unsafe_rebind_branch(int fail, int rebind) {
  int local[4];
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail) {
    if (rebind)
      ptr = local;
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  kfree(ptr);
  return 0;
}
int unsafe_arithmetic(int fail) {
  int local[4];
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail) {
    ptr++;
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  kfree(ptr);
  return 0;
}
int unsafe_shadow_inner(int fail) {
  int local[4];
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail) {
    int *local = ptr;
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  kfree(ptr);
  return 0;
}
int unsafe_shadow_parameter(int *local, int fail) {
  {
    int local[4];
    (void)local;
  }
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  local = ptr;
  if (fail) {
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  kfree(ptr);
  return 0;
}
int unsafe_unrelated_cleanup(int fail) {
  int local[4];
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (!fail) {
    if (ptr != local)
      kfree(ptr);
  }
  if (fail)
    return -1;
  return 0;
}
int unsafe_only_one_branch(int fail, int release) {
  int local[4];
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail) {
    if (release) {
      if (ptr != local)
        kfree(ptr);
      return -1;
    }
    return -2;
  }
  kfree(ptr);
  return 0;
}
int unsafe_pointer_fallback(int *local, int fail) {
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  local = ptr;
  if (fail) {
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  kfree(ptr);
  return 0;
}
int unsafe_wrong_pointer_free(int fail) {
  int *ptr = kmalloc(64, 0);
  int *second = other();
  if (!ptr)
    return -12;
  if (fail) {
    kfree(second);
    return -1;
  }
  kfree(ptr);
  return 0;
}
int unsafe_unrelated_same_comparison(int fail, int release) {
  int local[4];
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (ptr != local)
    (void)ptr;
  if (fail) {
    if (release) {
      if (ptr != local)
        kfree(ptr);
    }
    return -1;
  }
  kfree(ptr);
  return 0;
}
int safe_phi_heap(int first, int fail) {
  int local[4];
  int *ptr;
  if (first)
    ptr = kmalloc(64, 0);
  else
    ptr = kzalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail) {
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  kfree(ptr);
  return 0;
}
int unsafe_phi_conditional_cleanup(int first, int fail, int release) {
  int local[4];
  int *ptr;
  if (first)
    ptr = kmalloc(64, 0);
  else
    ptr = kzalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail) {
    if (release) {
      if (ptr != local)
        kfree(ptr);
    }
    return -1;
  }
  kfree(ptr);
  return 0;
}
int safe_unrelated_address(int fail) {
  int local[4];
  int value;
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  take_int(&value);
  if (fail) {
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  kfree(ptr);
  return 0;
}
int unsafe_arithmetic_argument(int fail) {
  int local[4];
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  consume(ptr++);
  if (fail) {
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  return 0;
}
int unsafe_arithmetic_initializer(int fail) {
  int local[4];
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  int *old = ptr++;
  (void)old;
  if (fail) {
    if (ptr != local)
      kfree(ptr);
    return -1;
  }
  return 0;
}
int unsafe_reuse_after_free(int fail) {
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  kfree(ptr);
  ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail)
    return -1;
  kfree(ptr);
  return 0;
}
int unsafe_init_kmalloc(int fail) {
  int *ptr = kmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail)
    return -1;
  kfree(ptr);
  return 0;
}
int unsafe_init_kzalloc(int fail) {
  int *ptr = kzalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail)
    return -1;
  kfree(ptr);
  return 0;
}
int unsafe_init_kcalloc(int fail) {
  int *ptr = kcalloc(1, 64, 0);
  if (!ptr)
    return -12;
  if (fail)
    return -1;
  kfree(ptr);
  return 0;
}
int unsafe_init_kmalloc_array(int fail) {
  int *ptr = kmalloc_array(1, 64, 0);
  if (!ptr)
    return -12;
  if (fail)
    return -1;
  kfree(ptr);
  return 0;
}
int unsafe_init_vmalloc(int fail) {
  int *ptr = vmalloc(64);
  if (!ptr)
    return -12;
  if (fail)
    return -1;
  kfree(ptr);
  return 0;
}
int unsafe_init_kvmalloc(int fail) {
  int *ptr = kvmalloc(64, 0);
  if (!ptr)
    return -12;
  if (fail)
    return -1;
  kfree(ptr);
  return 0;
}
"""


@pytest.mark.parametrize("learned", [False, True], ids=["shipped", "rendered"])
def test_error_path_controls(tmp_path, learned):
    source = _PATH_CONTROLS
    rendered = None
    rule = _RULE
    if learned:
        # Exercise BOTH initializer/assignment trigger forms, the direct
        # suppression guards and the array-cleanup proof with learned names.
        source = source.replace("kmalloc(", "project_alloc(")
        source = source.replace("kfree(", "project_free(")
        rendered = render(_RULE, _FakeVocab(
            allocators=frozenset({"project_alloc"}),
            deallocators=frozenset({"project_free"}),
        ))
        assert rendered is not None
        rule = rendered
    try:
        rows = _run_rule(tmp_path, source, rule=rule)
    finally:
        if rendered is not None:
            rendered.unlink()

    headers = [
        (number, match.group(1))
        for number, line in enumerate(textwrap.dedent(source).splitlines(), 1)
        if (match := re.match(r"int ((?:un)?safe_\w+)\(", line))
    ]
    assert headers, "fixture definitions must be seen"
    reported = set()
    for row in rows:
        assert Path(row["file"]).resolve() == (tmp_path / "target.c").resolve()
        owners = [name for start, name in headers if start <= row["line"]]
        assert owners, row
        reported.add(owners[-1])
    assert reported == {name for _, name in headers if name.startswith("unsafe_")}


def test_cleanup_proof_does_not_cross_files(tmp_path):
    # The embedded interpreter can persist across files in a directory run.
    # Same spellings/coordinates in another file must not suppress its leak.
    safe = """int f(int cond) {
        int stack[4], *ptr = stack;
        ptr = kmalloc(64, 0);
        if (!ptr) return -12;
        if (cond) { if (ptr != stack) kfree(ptr); return -1; }
        if (ptr != stack) kfree(ptr);
        return 0;
    }
    """
    cleanup = "if (ptr != stack) kfree(ptr);"
    leaky = safe.replace(cleanup, " " * len(cleanup))
    (tmp_path / "a.c").write_text(safe)
    (tmp_path / "b.c").write_text(leaky)
    proc = subprocess.run(
        ["spatch", "--sp-file", str(_RULE), "--dir", str(tmp_path),
         "--no-includes", "--very-quiet"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line[len("COCCIRESULT:"):])
            for line in proc.stderr.splitlines() if line.startswith("COCCIRESULT:")]
    assert [Path(row["file"]).name for row in rows] == ["b.c"]


@pytest.mark.parametrize("filename", ["target.cpp", "target.h", "target.C"])
@pytest.mark.parametrize("initializer", [False, True], ids=["assignment", "initializer"])
def test_cpp_reference_alias_remains_reportable(tmp_path, filename, initializer):
    allocation = ("int *ptr = kmalloc(64, 0);" if initializer else
                  "int *ptr; ptr = kmalloc(64, 0);")
    source = """extern int *kmalloc(unsigned long, int);
        extern void kfree(void *);
        int f(int cond) {
            int stack[4];
            ALLOCATION
            if (!ptr) return -12;
            int *&alias = ptr;
            alias = stack;
            if (cond) { if (ptr != stack) kfree(ptr); return -1; }
            return 0;
        }
    """.replace("ALLOCATION", allocation)
    src = tmp_path / filename
    src.write_text(source)
    proc = subprocess.run(
        ["spatch", "--c++", "--sp-file", str(_RULE), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line[len("COCCIRESULT:"):])
            for line in proc.stderr.splitlines() if line.startswith("COCCIRESULT:")]
    assert len(rows) == 1
    assert Path(rows[0]["file"]).resolve() == src.resolve()
