"""Native controls for integer use-before-zero-test review candidates.

A later check is a hint, not proof of the caller's reachable value range.
Protective control flow and value continuity must remain correlated with
an individual division or modulo use.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "division_by_zero.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_divide_then_zero_check_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(int total, int count)
            {
                int a = total / count;
                if (count == 0)
                    return 0;
                return a;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "division_by_zero_param"

    def test_modulo_then_not_check_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int bug(unsigned int h, unsigned int nbuckets)
            {
                unsigned int i = h % nbuckets;
                if (!nbuckets)
                    return 0;
                return i;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "modulo_by_zero_param"


class TestNegatives:
    def test_bare_unguarded_division_does_not_fire(self, tmp_path):
        # No in-function zero test at all: the divisor's range is a
        # caller-side invariant the rule cannot see.
        results = _run_rule(tmp_path, """\
            int avg(int total, int count)
            {
                return total / count;
            }
        """)
        assert results == []

    def test_bare_unguarded_modulo_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int pick(unsigned int h, unsigned int nbuckets)
            {
                return h % nbuckets;
            }
        """)
        assert results == []

    def test_prechecked_division_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int safe(int total, int count)
            {
                if (count == 0)
                    return 0;
                return total / count;
            }
        """)
        assert results == []

    def test_precheck_plus_redundant_late_check_does_not_fire(self, tmp_path):
        # A pre-division guard makes the division safe; the extra
        # late test is redundancy, not a contradiction.
        results = _run_rule(tmp_path, """\
            int safe(int total, int count)
            {
                int r;
                if (!count)
                    return 0;
                r = total / count;
                if (count == 0)
                    return r;
                return r;
            }
        """)
        assert results == []


@pytest.mark.parametrize("operator", ["/", "%", "/=", "%="], ids=["divide", "modulo", "divide-assign", "modulo-assign"])
def test_guard_effects_and_divisor_continuity(tmp_path, operator):
    use = f"result {operator} count;" if operator.endswith("=") else f"result = total {operator} count;"
    cases = [
        ("", use, "", True),
        ("if (!count) return 0;", use, "", False),
        ("if (!count) warn();", use, "", True),
        ("if (count != 0) warn();", use, "", True),
        ("if (!next) return 0;", use, "", True),
        ("if (optional) { if (!count) return 0; }", use, "", True),
        ("if (!count) { if (optional) return 0; }", use, "", True),
        ("if (!count) return 0; count = next;", use, "", True),
        ("if (!count) return 0; ++count;", use, "", True),
        ("if (!count) return 0; mutate(&count);", use, "", True),
        ("if (!count) return 0; count = next; if (!count) return 0;", use, "", False),
        ("if (!count) count = 1;", use, "", False),
        ("count = 1;", use, "", False),
        ("", "if (count != 0) { " + use + " }", "", False),
        ("", "if (count != 0) { if (optional) count = 0; " + use + " }", "", True),
        ("", "if (count != 0) { count = 1; " + use + " }", "", False),
        ("", "if (count != 0) { if (optional) { " + use + " } }", "", False),
        ("", "if (count) " + use, "", False),
        ("", "if (count != 0) { " + use + " } else result = 0;", "", False),
        ("", "if (!count) result = 0; else { " + use + " }", "", False),
        ("", "if (count != 0) result = 0; else { " + use + " }", "", True),
        ("", use, "count = 0;", False),
        ("", use, "count += 1;", False),
        ("", use, "next++;", True),
        ("", use, "count++;", False),
        ("", use, "--count;", False),
        ("", use, "mutate(&count);", False),
        ("", use, "int *alias = &count;", False),
        ("", use, "if (optional) count = 0;", True),
        ("", use, "if (optional) count = 0; else count = 1;", False),
    ]
    lines = []
    expected = set()
    for index, (before, operation, after, reports) in enumerate(cases):
        lines += [f"int case_{index}(int total, int count, int next, int optional) {{",
                  "int result = total;", before, operation, after,
                  "if (!count) warn();", "return result;", "}"]
        if reports:
            expected.add(len(lines) - 4)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)
    rule = "modulo_by_zero_param" if "%" in operator else "division_by_zero_param"
    assert all(row["rule"] == rule and row["message"].startswith("Candidate:") for row in rows)


@pytest.mark.parametrize("parameter_type", ["char", "unsigned short", "long long", "unsigned long long", "uint32_t", "int64_t"], ids=["char", "ushort", "long-long", "ulong-long", "u32", "i64"])
def test_common_integer_parameters_keep_zero_test_requirement(tmp_path, parameter_type):
    rows = _run_rule(tmp_path, f"""
        long candidate({parameter_type} count) {{
            long result = 99 / count;
            if (!count) warn();
            return result;
        }}
        long bare({parameter_type} count) {{ return 99 / count; }}
    """)
    assert len(rows) == 1
    assert rows[0]["rule"] == "division_by_zero_param"


def test_distinct_operations_keep_their_own_protection(tmp_path):
    lines = [
        "int f(int total, int count) {",
        "int unchecked = total / count;",
        "if (!count) return 0;",
        "int checked = total / count;",
        "if (!count) warn();",
        "return unchecked + checked;",
        "}",
    ]
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert len(rows) == 1
    assert rows[0]["line"] == lines.index("int unchecked = total / count;") + 1


@pytest.mark.parametrize("operation", [
    "count = total / count;", "count += total / count;",
    "count = wrap(total % count);", "count /= count;", "count %= count;",
], ids=["assign", "add-assign", "wrapped", "divide-self", "modulo-self"])
def test_use_that_rebinds_divisor_cannot_borrow_later_zero_test(tmp_path, operation):
    rows = _run_rule(tmp_path, f"""
        int f(int total, int count) {{
            {operation}
            if (!count) warn();
            return count;
        }}
    """)
    assert rows == []


def test_noninteger_and_unrelated_zero_tests_stay_quiet(tmp_path):
    rows = _run_rule(tmp_path, """
        float f(float total, float count) {
            float result = total / count;
            if (!count) warn();
            return result;
        }
        int g(int total, int count, int next) {
            int result = total / count;
            if (!next) warn();
            return result;
        }
        int dead_check(int total, int count) {
            return total / count;
            if (!count) warn();
        }
    """)
    assert rows == []


@pytest.mark.integration
def test_divisor_candidates_keep_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "divisors.c"
    source.write_text(
        "int divide(int a, int n) { int r = a / n; if (!n) warn(); return r; }\n"
        "int modulo(int a, int n) { int r = a; r %= n; if (!n) warn(); return r; }\n"
        "int guarded(int a, int n) { if (!n) return 0; int r = a / n; if (!n) warn(); return r; }\n"
        "int bare(int a, int n) { return a / n; }\n"
        "void *allocation(size_t a, size_t b) { return malloc(a * b); }\n",
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
        source, [_RULE, _RULE.with_name("integer_overflow_alloc.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"division_by_zero", "integer_overflow_alloc"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert {match.rule for match in results["division_by_zero"].matches} == {
        "division_by_zero_param", "modulo_by_zero_param",
    }
    assert len(results["division_by_zero"].matches) == 2
    assert all(match.message.startswith("Candidate:") for match in results["division_by_zero"].matches)
    assert len(results["integer_overflow_alloc"].matches) == 1
    assert len(invocations) == 1, invocations
