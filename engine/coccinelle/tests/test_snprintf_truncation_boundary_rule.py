"""Fixture tests for the snprintf_truncation_boundary rule.

Detection-role rule: a strict boundary comparison needs review of whether
complete output is required. Native cases verify value provenance and the
supported complete equality guards without granting confirmation authority.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules"
    / "snprintf_truncation_boundary.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_gt_guard_on_snprintf_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n > sz)
                    return -1;
                return n;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "snprintf_truncation_boundary"
        assert results[0]["line"] == 5

    def test_flipped_operands_fire(self, tmp_path):
        # SZ < ret is the same wrong boundary via the comparison
        # isomorphism the rule header documents.
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s)
            {
                int n;
                n = vsnprintf(buf, sz, "%s", s);
                if (sz < n)
                    return -1;
                return n;
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 5


class TestNegatives:
    def test_ge_guard_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n >= sz)
                    return -1;
                return n;
            }
        """)
        assert results == []

    def test_gt_size_minus_one_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n > sz - 1)
                    return -1;
                return n;
            }
        """)
        assert results == []

    def test_ret_reassigned_before_check_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s, int m)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                n = m;
                if (n > sz)
                    return -1;
                return n;
            }
        """)
        assert results == []

    def test_different_size_expression_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, unsigned long lim,
                    const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n > lim)
                    return -1;
                return n;
            }
        """)
        assert results == []

    def test_separate_exact_fit_statement_does_not_fire(self, tmp_path):
        # The boundary IS handled, just as its own statement instead of
        # >= or else-if — an unidiomatic but correct spelling.
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n > sz)
                    return -1;
                if (n == sz)
                    return -2;
                return n;
            }
        """)
        assert results == []

    def test_exact_fit_statement_before_gt_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n == sz)
                    return -2;
                if (n > sz)
                    return -1;
                return n;
            }
        """)
        assert results == []

    def test_unrelated_eq_check_keeps_gt_firing(self, tmp_path):
        # Recall guard for the handled-boundary suppression: an ==
        # check against a DIFFERENT bound does not handle the exact
        # fit, so the > guard still fires.
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, unsigned long lim,
                    const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n == lim)
                    return -2;
                if (n > sz)
                    return -1;
                return n;
            }
        """)
        assert len(results) == 1


@pytest.mark.parametrize("declaration", [False, True], ids=["assignment", "declaration"])
@pytest.mark.parametrize("formatter", ["snprintf", "vsnprintf"])
def test_boundary_value_and_guard_contracts(tmp_path, declaration, formatter):
    cases = [
        ("", "if (n > sz) return -1;", True),
        ("", "if (sz < n) return -1;", True),
        ("", "if (n >= sz) return -1;", False),
        ("", "if (n > sz - 1) return -1;", False),
        ("", "if (n > sz || n == sz) return -1;", False),
        ("", "if (n == sz || n > sz) return -1;", False),
        ("", "if (n > sz || (n == sz && enabled)) return -1;", True),
        ("if (n == sz) return -2;", "if (n > sz) return -1;", False),
        ("", "if (n > sz) return -1; if (n == sz) return -2;", False),
        ("if (n == sz) log_size(n);", "if (n > sz) return -1;", True),
        ("", "if (n > sz) return -1; if (n == sz) log_size(n);", True),
        ("if (n == sz) { if (enabled) return -2; }", "if (n > sz) return -1;", True),
        ("if (n == other) return -2;", "if (n > sz) return -1;", True),
        ("if (enabled) { if (n == sz) return -2; }", "if (n > sz) return -1;", True),
        ("", "if (n > sz) return -1; if (enabled) { if (n == sz) return -2; }", True),
        ("", "if (n > sz) return -1; n++; if (n == sz) return -2;", True),
        ("", "if (n > sz) return -1; sz++; if (n == sz) return -2;", True),
        ("other += 1;", "if (n > sz) return -1;", True),
        ("", "if (n > other) return -1;", False),
    ]
    for operand in ("n", "sz"):
        for operator in ("=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|="):
            cases.append((f"{operand} {operator} other;", "if (n > sz) return -1;", False))
        for mutation in (f"{operand}++;", f"++{operand};", f"{operand}--;", f"--{operand};", f"rewrite(&{operand});"):
            cases.append((mutation, "if (n > sz) return -1;", False))
    lines, expected = [], set()
    for index, (between, check, reports) in enumerate(cases):
        lines.append(f"int case_{index}(char *buf, int sz, int other, int enabled) {{")
        if not declaration:
            lines.append("int n;")
        lines.append(f'{"int " if declaration else ""}n = {formatter}(buf, sz, "%s", "text");')
        lines.append(between)
        lines.append(check)
        if reports:
            expected.add(len(lines))
        lines.append("return n; }")
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in results}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(results) == len(expected)
    assert all(row["rule"] == "snprintf_truncation_boundary" for row in results)
    assert all(row["message"].startswith("Candidate:") for row in results)


@pytest.mark.integration
def test_boundary_and_cursor_checks_share_production_invocation(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        'int boundary(char *b, int sz) { int n = snprintf(b, sz, "%s", "x"); if (n > sz) return -1; return n; }\n'
        'int inclusive(char *b, int sz) { int n = snprintf(b, sz, "%s", "x"); if (n > sz || n == sz) return -1; return n; }\n'
        'void advance(char *b, int sz) { b += snprintf(b, sz, "%s", "x"); }\n',
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
        source, [_RULE, _RULE.with_name("snprintf_advance.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"snprintf_truncation_boundary", "snprintf_advance"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["snprintf_truncation_boundary"].matches) == 1
    assert len(results["snprintf_advance"].matches) == 1
    assert len(invocations) == 1, invocations
