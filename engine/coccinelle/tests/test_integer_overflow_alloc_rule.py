"""Fixture tests for the integer_overflow_alloc rule.

Negatives pin the sizeof-product exclusion: ``malloc(n * sizeof(T))``
and ``kmalloc(n * sizeof(*p), ...)`` are the idiomatic C array
allocation, and whether the count is range-limited is a caller-side
property the allocation site cannot decide — the rule must not report
them. Positives keep the genuine target firing: a product of two
non-sizeof operands with no overflow guard.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "integer_overflow_alloc.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_two_variable_product_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *bug(size_t rows, size_t cols)
            {
                return malloc(rows * cols);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "integer_overflow_alloc"

    def test_kmalloc_two_variable_product_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *bug(unsigned int count, unsigned int elem_size)
            {
                return kmalloc(count * elem_size, GFP_KERNEL);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_count_times_sizeof_type_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *ok(size_t n)
            {
                return malloc(n * sizeof(struct item));
            }
        """)
        assert results == []

    def test_count_times_sizeof_deref_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct p *ok(int n)
            {
                struct p *p = kmalloc(n * sizeof(*p), GFP_KERNEL);
                return p;
            }
        """)
        assert results == []

    def test_sizeof_first_operand_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *ok(size_t n)
            {
                return malloc(sizeof(struct item) * n);
            }
        """)
        assert results == []

    def test_constant_product_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *ok(void)
            {
                return malloc(16 * 32);
            }
        """)
        assert results == []

    def test_size_max_guard_suppresses(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *ok(size_t a, size_t b)
            {
                if (a > SIZE_MAX / b)
                    return 0;
                return malloc(a * b);
            }
        """)
        assert results == []


@pytest.mark.parametrize("allocation", [
    "malloc(a * b)", "kmalloc(a * b, GFP_KERNEL)",
    "kzalloc(a * b, GFP_KERNEL)", "vmalloc(a * b)",
    "realloc(old, a * b)", "krealloc(old, a * b, GFP_KERNEL)",
])
@pytest.mark.parametrize("guard", [
    "if (a > SIZE_MAX / b) return 0;",
    "if (check_mul_overflow(a, b, &size)) return 0;",
    "if (__builtin_mul_overflow(a, b, &size)) return 0;",
])
def test_guard_must_reject_overflow_and_cover_all_paths(tmp_path, guard, allocation):
    cases = [
        (guard, False),
        (guard.replace("return 0", "warn()"), True),
        ("if (optional) { " + guard + " }", True),
        (guard + " a = next;", True),
        (guard + " b++;", True),
        (guard + " a += next;", True),
        (guard + " mutate(&a);", True),
        (guard + " mutate(&b);", True),
        (guard + " if (optional) b = next;", True),
        (guard.replace("return 0", "if (optional) return 0"), True),
        (guard.replace("&size", "&a"), "&size" in guard),
        (guard.replace("&size", "&b"), "&size" in guard),
        (guard.replace("a, b", "b, a"), False),
        (guard + " unrelated();", False),
        (guard.replace("if (", "(void)(").replace(") return 0;", ");"), True),
        ("if (optional) { " + guard + " } else { " + guard + " }", False),
    ]
    lines = []
    expected = set()
    for index, (before, reports) in enumerate(cases):
        lines += [f"void *case_{index}(size_t a, size_t b, size_t next, void *old, int optional) {{",
                  "size_t size;", before, f"return {allocation};", "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}


@pytest.mark.parametrize("guard", [
    "if (a > SIZE_MAX / b) return 0;",
    "if (__builtin_mul_overflow(a, b, &size)) return 0;",
])
def test_guards_are_correlated_with_each_allocation(tmp_path, guard):
    lines = [
        "void *f(size_t a, size_t b, int optional) {",
        "size_t size;",
        "void *unchecked = malloc(a * b);",
        guard,
        "if (optional) return malloc(a * b);",
        "return 0;",
        "}",
    ]
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert len(rows) == 1
    assert rows[0]["line"] == lines.index("void *unchecked = malloc(a * b);") + 1


@pytest.mark.integration
def test_allocation_guard_checks_keep_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "allocation.c"
    source.write_text(
        "void *unchecked(size_t a, size_t b) { return malloc(a * b); }\n"
        "void *ignored(size_t a, size_t b) { size_t size; "
        "__builtin_mul_overflow(a, b, &size); return malloc(a * b); }\n"
        "void *guarded(size_t a, size_t b) { size_t size; "
        "if (__builtin_mul_overflow(a, b, &size)) return 0; return malloc(a * b); }\n"
        "void *double_scale(size_t n) { return malloc(n * sizeof(int) * sizeof(int)); }\n",
        encoding="utf-8",
    )
    original = runner._confined_default_runner
    invocations = []

    def observe(*args, **kwargs):
        execute = original(*args, **kwargs)

        def invoke(argv, **options):
            invocations.append(tuple(argv))
            return execute(argv, **options)

        return invoke

    monkeypatch.setattr(runner, "_confined_default_runner", observe)
    results = runner.run_rules_batched(
        source, [_RULE, _RULE.with_name("double_sizeof.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"integer_overflow_alloc", "double_sizeof"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["integer_overflow_alloc"].matches) == 2
    assert len(results["double_sizeof"].matches) == 1
    assert len(invocations) == 1, invocations


@pytest.mark.parametrize("condition", [
    "a > SIZE_MAX / b", "__builtin_mul_overflow(a, b, &size)",
])
@pytest.mark.parametrize("value", ["malloc(a * b)", "wrap(malloc(a * b))"])
def test_overflow_branch_allocation_is_not_protected(tmp_path, condition, value):
    rows = _run_rule(tmp_path, f"""
        void *f(size_t a, size_t b) {{
            size_t size;
            if ({condition}) return {value};
            return 0;
        }}
    """)
    assert len(rows) == 1
    assert rows[0]["rule"] == "integer_overflow_alloc"
