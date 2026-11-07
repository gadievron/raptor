"""Fixture tests for the strncpy_no_nul candidate rule.

Two shapes must stay silent: a copy sized ``strlen(src) + 1`` (the
terminator is included by construction) and a later snprintf that
takes the buffer as its DESTINATION (an overwrite, not a string read).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "strncpy_no_nul.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_unterminated_then_printf_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *dst, char *src, int n)
            {
                strncpy(dst, src, n);
                printf("%s", dst);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "strncpy_no_nul"

    def test_buffer_read_by_snprintf_format_arg_fires(self, tmp_path):
        # The buffer as a VALUE argument (after dest and size) is a
        # genuine string read.
        results = _run_rule(tmp_path, """\
            void bug(char *dst, char *src, int n, char *out, int sz)
            {
                strncpy(dst, src, n);
                snprintf(out, sz, "%s", dst);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_strlen_plus_one_size_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(char *dst, char *src)
            {
                strncpy(dst, src, strlen(src) + 1);
                printf("%s", dst);
            }
        """)
        assert results == []

    def test_snprintf_overwrite_of_dest_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(char *buf, char *s, int n, int sz)
            {
                strncpy(buf, s, n);
                snprintf(buf, sz, "reset");
            }
        """)
        assert results == []

    def test_manual_nul_then_use_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(char *dst, char *src, int n)
            {
                strncpy(dst, src, n);
                dst[n - 1] = '\\0';
                printf("%s", dst);
            }
        """)
        assert results == []


@pytest.mark.parametrize("slot", ["first", "second"])
def test_string_read_roles_and_destination_tracking(tmp_path, slot):
    other = "other"
    pair = f"dst, {other}" if slot == "first" else f"{other}, dst"
    cases = [
        ("", f"strcmp({pair});", True),
        ("", f"strcat({pair});", True),
        ("", f"strncmp({pair}, n);", False),
        ("", f"strncat({pair}, n);", slot == "first"),
        ("", f"strncmp({pair}, limit);", True),
        ("strncpy(dst, src, 4);", f"strncmp({pair}, 4);", False),
        ("strncpy(dst, src, 4);", f"strncmp({pair}, 8);", True),
        ("strncpy(dst, src, n + 1); n++;", f"strncmp({pair}, n + 1);", True),
        ("if (stop) n++;", f"strncmp({pair}, n);", True),
        ("if (stop) n += 1;", f"strncmp({pair}, n);", True),
        ("n++;", f"strncmp({pair}, n);", True),
        ("n += 1;", f"strncmp({pair}, n);", True),
        ("rewrite_count(&n);", f"strncmp({pair}, n);", True),
        ("", "strlen(dst);", True),
        ("memset(dst, 65, n);", "strlen(dst);", True),
        ("memset(dst, 0, 0);", "strlen(dst);", True),
        ("memset(dst, 0, 1);", "strlen(dst);", False),
        ("memset(dst, 0, sizeof(dst));", "strlen(dst);", False),
        ("memset(dst, 0, 32);", "strlen(dst);", False),
        ("memset(dst, 0, 32U);", "strlen(dst);", False),
        ("memset(dst, 0, n);", "strlen(dst);", True),
        ("memset(dst, 65, 32);", "strlen(dst);", True),
        ("memset(dst, '\\0', 1);", "strlen(dst);", False),
        ("dst[0] = 0;", "strlen(dst);", False),
        ("dst[0] = 65;", "strlen(dst);", True),
        ("dst = other;", "strlen(dst);", False),
        ("dst += 1;", "strlen(dst);", False),
        ("dst -= 1;", "strlen(dst);", False),
        ("dst++;", "strlen(dst);", False),
        ("++dst;", "strlen(dst);", False),
        ("dst--;", "strlen(dst);", False),
        ("--dst;", "strlen(dst);", False),
        ("replace(&dst);", "strlen(dst);", False),
        ("strncpy(dst, src, strlen(src) + 1);", "strlen(dst);", False),
        ("other += 1;", "strlen(dst);", True),
    ]
    lines, expected = [], set()
    for index, (between, use, reports) in enumerate(cases):
        lines += [f"void case_{index}(char *dst, char *src, char *other, int n, int limit, int stop) {{",
                  "strncpy(dst, src, n);", between, use, "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)
    assert all(row["rule"] == "strncpy_no_nul" for row in rows)
    assert all(row["message"].startswith("Candidate:") for row in rows)


@pytest.mark.integration
def test_copy_and_boundary_candidates_share_production_invocation(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        'void read_second(char *d, char *s, char *o, int n) { strncpy(d, s, n); strcmp(o, d); }\n'
        'void bounded(char *d, char *s, char *o, int n) { strncpy(d, s, n); strncmp(o, d, n); }\n'
        'void display(char *d, char *s) { strncpy(d, s, 4); printf("%p", d); }\n'
        'void string_read(char *d, char *s) { strncpy(d, s, 4); printf("%s", d); }\n'
        'void bounded_format(char *d, char *s) { strncpy(d, s, 4); printf("%.4s", d); }\n'
        'void dynamic_format(char *d, char *s, char *fmt) { strncpy(d, s, 4); printf(fmt, d); }\n'
        'int boundary(char *b, int sz) { int n = snprintf(b, sz, "%s", "x"); if (n > sz) return -1; return n; }\n',
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
        source, [_RULE, _RULE.with_name("snprintf_truncation_boundary.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"strncpy_no_nul", "snprintf_truncation_boundary"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["strncpy_no_nul"].matches) == 3
    assert len(results["snprintf_truncation_boundary"].matches) == 1
    assert len(invocations) == 1, invocations


@pytest.mark.parametrize("family", ["printf", "fprintf", "snprintf", "syslog"])
def test_formatted_argument_conversion_contracts(tmp_path, family):
    cases = [
        ('"%s", dst', True),
        ('"%p", dst', False),
        ('"%d", dst', False),
        ('"%%s", dst', False),
        ('"plain", dst', False),
        ('"%p %s", dst, other', False),
        ('"%s %p", dst, other', True),
        ('"%p %s", other, dst', True),
        ('"%s %p", other, dst', False),
        ('"%4s", dst', True),
        ('"%*s", 10, dst', True),
        ('"%*p", 10, dst', False),
        ('"%2$s %1$p", other, dst', True),
        ('"%2$p %1$s", other, dst', False),
        ('"%2$*1$s", 10, dst', True),
        ('"%1$p %1$s", dst', True),
        ('"%.4s", dst', False),
        ('"%.5s", dst', True),
        ('"%.0s", dst', False),
        ('"%.*s", 4, dst', False),
        ('"%.*s", -1, dst', True),
        ('"%.*s", limit, dst', True),
        ('"%2$.*1$s", 4, dst', False),
        ('"%2$.*1$s", -1, dst', True),
        ('"%3$*1$.*2$s", 10, 4, dst', False),
        ('"%3$*1$.*2$s", 10, -1, dst', True),
        ('"%ls", dst', True),
        ('"%n", dst', False),
        ('"%m%s", dst', True),
        ('"%Q", dst', True),
        ('"%llp", dst', True),
        ('"%s %2$p", dst, other', True),
        ('fmt, dst', True),
        ('"prefix " "%s", dst', True),
        ('"prefix " "%p", dst', False),
        ('"\\x25s", dst', True),
        ('"%p %", dst', True),
        ('"%2$s", dst', True),
        ('"%2$p", other, dst', True),
        ('"%s", nested(1, 2), dst', False),
        ('"%p %s", nested(1, 2), dst', True),
        ('"%p %s", (one, two), dst', True),
        ('"' + 'x' * 8200 + '%p", dst', True),
        ('"%p", ' + ', '.join(['other'] * 129 + ['dst']), True),
    ]
    lines, expected = [], set()
    for index, (arguments, reports) in enumerate(cases):
        prefix = {"printf": "", "fprintf": "stream, ", "snprintf": "out, 64, ", "syslog": "priority, "}[family]
        lines += [f"void case_{index}(char *dst, char *src, char *other, char *fmt, int limit) {{",
                  "strncpy(dst, src, 4);", f"{family}({prefix}{arguments});", "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)


@pytest.mark.parametrize("family", ["printf", "fprintf", "snprintf", "syslog"])
def test_format_argument_itself_still_requires_termination(tmp_path, family):
    prefix = {"printf": "", "fprintf": "stream, ", "snprintf": "out, 64, ", "syslog": "priority, "}[family]
    rows = _run_rule(tmp_path, f"void f(char *dst, char *src, int n) {{ strncpy(dst, src, n); {family}({prefix}dst, 1); }}")
    assert len(rows) == 1


def test_each_formatted_string_operand_has_its_own_location(tmp_path):
    rows = _run_rule(tmp_path, 'void f(char *dst, char *src) { strncpy(dst, src, 4); printf("%p %s %s", dst, dst, dst); }')
    assert len(rows) == 2
    assert len({(row["line"], row["col"]) for row in rows}) == 2
