"""Fixture tests for the snprintf_advance rule.

The rules are some-path (`exists`): an advance guarded by the WRONG
condition (`if (n > 0) buf += n;`) is still unchecked on that path,
and the direct `buf += snprintf(...)` form leaves no room for any
check at all. Only supported exits or guarded update branches are excluded.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "snprintf_advance.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_plain_advance_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *buf, int remaining)
            {
                int n;
                n = snprintf(buf, remaining, "x");
                buf += n;
            }
        """)
        assert len(results) == 1

    def test_wrongly_guarded_advance_fires(self, tmp_path):
        # `n > 0` is a guard, but not the truncation check — the
        # advance is still unchecked on the taken path.
        results = _run_rule(tmp_path, """\
            void bug(char *buf, int remaining)
            {
                int n;
                n = snprintf(buf, remaining, "x");
                if (n > 0)
                    buf += n;
            }
        """)
        assert len(results) == 1

    def test_direct_advance_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *buf, int remaining)
            {
                buf += snprintf(buf, remaining, "x");
            }
        """)
        assert len(results) == 1
        assert "Candidate: snprintf return value used directly" in results[0]["message"]


class TestNegatives:
    def test_truncation_checked_advance_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(char *buf, int remaining)
            {
                int n;
                n = snprintf(buf, remaining, "x");
                if (n >= remaining)
                    return;
                buf += n;
            }
        """)
        assert results == []

    def test_unused_return_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(char *buf, int remaining)
            {
                snprintf(buf, remaining, "x");
            }
        """)
        assert results == []


@pytest.mark.parametrize("api", ["snprintf", "vsnprintf"])
@pytest.mark.parametrize("declaration", [False, True], ids=["assignment", "declaration"])
def test_cursor_return_value_relationships(tmp_path, api, declaration):
    arguments = '"%s", fmt' if api == "snprintf" else "fmt, ap"
    call = f'{api}(buf, remaining, {arguments})'
    updates = ("buf += n;", "buf = buf + n;", "buf = n + buf;",
               "remaining -= n;", "remaining = remaining - n;")
    barriers = (
        "", "n = 0;", "n = clamp(n, remaining);", "rewrite(&n);",
        "n += 1;", "n -= 1;", "n *= 0;", "n /= 2;", "n %= 2;",
        "n <<= 1;", "n >>= 1;", "n &= 0;", "n ^= 1;", "n |= 1;",
        "n++;", "++n;", "n--;", "--n;",
        "buf = other;", "replace(&buf);", "buf++;", "buf += 1;",
        "remaining = other_size;", "rewrite(&remaining);",
        "remaining++;", "remaining &= mask;",
    )
    signature = "char *buf, char *other, int remaining, int other_size, int mask, const char *fmt, va_list ap"
    lines = ["#include <stdarg.h>", "#include <stdio.h>"]
    expected = set()
    for update in updates:
        for barrier in barriers:
            lines += [f"void case_{len(lines)}({signature}) {{"]
            if not declaration:
                lines += ["int n;"]
            lines += [f'{"int " if declaration else ""}n = {call};']
            call_line = len(lines)
            lines += [barrier, update, "}"]
            if not barrier:
                expected.add(call_line)
    for destination in ("NULL", "0", "(void *)0", "((void *)0)"):
        lines += [f"void length_only_{len(lines)}({signature}) {{"]
        if not declaration:
            lines += ["int n;"]
        null_call = call.replace("(buf,", f"({destination},", 1)
        lines += [f'{"int " if declaration else ""}n = {null_call};', "remaining -= n;", "}"]
    for index in range(24):
        lines += [f"void repeated_{index}({signature}) {{"]
        if not declaration:
            lines += ["int n;"]
        lines += [f'{"int " if declaration else ""}n = {call};']
        expected.add(len(lines))
        lines += ["buf += n;", "remaining -= n;", "}"]
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in results}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(results) == len(expected)


@pytest.mark.parametrize("api", ["snprintf", "vsnprintf"])
def test_inline_cursor_and_budget_updates_exclude_length_tallies(tmp_path, api):
    def call(destination, size):
        arguments = '"%s", fmt' if api == "snprintf" else "fmt, ap"
        return f"{api}({destination}, {size}, {arguments})"

    own = call("buf", "remaining")
    other = call("other", "other_size")
    cases = (
        (f"buf += {own};", True),
        (f"buf = buf + {own};", True),
        (f"buf = {own} + buf;", True),
        (f"remaining -= {own};", True),
        (f"remaining = remaining - {own};", True),
        (f"buf += {other};", False),
        (f"buf = {other} + buf;", False),
        (f"total += {own};", False),
        (f"total = total + {own};", False),
        (f'total += {call("NULL", "0")};', False),
        (f'remaining -= {call("NULL", "remaining")};', False),
        (f'remaining -= {call("0", "remaining")};', False),
        (f'remaining -= {call("(void *)0", "remaining")};', False),
        (f'remaining -= {call("((void *)0)", "remaining")};', False),
        (f'buf += {call("other", "remaining")};', False),
        (f'remaining -= {call("other", "other_size")};', False),
    )
    lines = ["#include <stdarg.h>", "#include <stdio.h>"]
    expected = set()
    signature = "char *buf, char *other, int remaining, int other_size, const char *fmt, va_list ap"
    for body, should_report in cases:
        lines += [f"void inline_{len(lines)}({signature}) {{", "int total = 0;", body, "}"]
        if should_report:
            expected.add(len(lines) - 1)
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in results}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(results) == len(expected)


@pytest.mark.integration
def test_cursor_relationships_keep_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        '#include <stdarg.h>\n'
        '#include <stdio.h>\n'
        'void cursor(char *buf, int left) { buf += snprintf(buf, left, "x"); }\n'
        'void budget(char *buf, int left, const char *fmt, va_list ap) { left -= vsnprintf(buf, left, fmt, ap); }\n'
        'void replaced(char *buf, int left) { int n = snprintf(buf, left, "x"); n = clamp(n, left); buf += n; }\n'
        'void tally(char *buf, int left) { int total = 0; total += snprintf(buf, left, "x"); }\n'
        'void logged(char *buf, int left) { int n = snprintf(buf, left, "x"); if (n >= left) log_size(n); buf += n; }\n'
        'void guarded(char *buf, int left) { int n = snprintf(buf, left, "x"); if (n >= left) return; buf += n; }\n'
        'void changed_count(char *d, char *s, char *o, int n, int stop) { strncpy(d, s, n); if (stop) n++; strncmp(d, o, n); }\n'
        'void bounded_count(char *d, char *s, char *o, int n) { strncpy(d, s, n); strncmp(d, o, n); }\n'
        'void twice(int fd) { close(fd); close(fd); }\n',
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
        source, [_RULE, _RULE.with_name("double_close.cocci"),
                 _RULE.with_name("strncpy_no_nul.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"snprintf_advance", "double_close", "strncpy_no_nul"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["snprintf_advance"].matches) == 3
    assert len(results["double_close"].matches) == 1
    assert len(results["strncpy_no_nul"].matches) == 1
    assert len(invocations) == 1, invocations


@pytest.mark.parametrize("api", ["snprintf", "vsnprintf"])
@pytest.mark.parametrize("declaration", [False, True], ids=["assignment", "declaration"])
def test_truncation_guards_require_effect_and_cover_the_actual_update(tmp_path, api, declaration):
    bodies = [
        ("buf += n;", True),
        ("if (stop) { buf += n; } else { remaining -= n; }", True),
        ("if (n >= remaining) log_size(n); buf += n;", True),
        ("(void)(n >= remaining); buf += n;", True),
        ("if (n >= remaining) buf += n;", True),
        ("if (n >= remaining && stop) return; buf += n;", True),
        ("if (stop) { if (n >= remaining) return; } buf += n;", True),
        ("if (n >= remaining) { if (stop) return; } buf += n;", True),
        ("if (n >= remaining) { log_size(n); return; } buf += n;", False),
        ("if (n >= remaining) return; buf += n;", False),
        ("if (n >= remaining) return; log_size(n); buf += n;", False),
        ("if (n < remaining) { log_size(n); buf += n; }", False),
        ("if (n < 0 || n >= remaining) return; buf += n;", False),
        ("if (n >= remaining || n < 0) return; remaining -= n;", False),
        ("if (remaining <= n) return; buf = n + buf;", False),
        ("if (n < remaining) { buf += n; }", False),
        ("if (n >= 0 && n < remaining) { remaining -= n; }", False),
        ("if (n < remaining && n >= 0) { buf = buf + n; }", False),
        ("if (n >= remaining) log_size(n); else { buf += n; }", False),
        ("if (n < 0 || n >= remaining) log_size(n); else { remaining -= n; }", False),
        ("if (n >= 0 && n < remaining && stop) { buf += n; }", True),
        ("if (n > remaining) return; buf += n;", True),
        ("if (n < 0) return; buf += n;", True),
        ("if (n >= other_size) return; buf += n;", True),
        ("buf += n; if (n >= remaining) return;", True),
        ("if (n < remaining) { buf += n; } else { buf += n; }", True),
        ("if (n < remaining) { remaining -= n; } buf += n;", True),
        ("if (n >= remaining) { remaining -= n; return; } buf += n;", True),
    ]
    lines = ["#include <stdarg.h>", "#include <stdio.h>"]
    expected = set()
    for index, (body, reports) in enumerate(bodies):
        lines.append(f"void guard_{index}(char *buf, int remaining, int stop, int other_size, const char *fmt, va_list ap) {{")
        if not declaration:
            lines.append("int n;")
        arguments = '"%s", "x"' if api == "snprintf" else "fmt, ap"
        lines.append(f'{"int " if declaration else ""}n = {api}(buf, remaining, {arguments});')
        if reports:
            expected.add(len(lines))
        lines += [body, "}"]
    # A guard for an older value cannot cover a fresh formatting result.
    signature = "char *buf, int remaining, const char *fmt, va_list ap"
    call = f"{api}(buf, remaining, {arguments})"
    lines += [f"void reformat({signature}) {{", f"int n = {call};",
              "if (n >= remaining) return;", f"n = {call};"]
    expected.add(len(lines))
    lines += ["buf += n;", "}"]
    lines += [f"void prechecked({signature}) {{", "int n = 0;",
              "if (n >= remaining) return;", "{",
              f'{"int " if declaration else ""}n = {call};']
    expected.add(len(lines))
    lines += ["buf += n;", "}", "}"]
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)


@pytest.mark.integration
@pytest.mark.parametrize("other_hit", [False, True], ids=["file-empty", "other-function-hit"])
def test_partial_buffer_silence_is_inconclusive(tmp_path, other_hit):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    helper = 'int format_count(char *dst, int size) { return snprintf(dst, size, "x"); }\n'
    source = helper + 'void partial(char *dst, int size) { int count = format_count(dst, size); dst += count; }' + "\n"
    line = 1 + helper.count("\n")
    if other_hit:
        source += 'void other(char *dst, int size) { int count = snprintf(dst, size, "x"); dst += count; }' + "\n"
    (tmp_path / "partial.c").write_text(source)
    result = run_coccinelle_file_sweep(target_path=tmp_path, file_path="partial.c", cocci_rule=str(_RULE), language="c")
    assert not result.errors, result.errors
    assert result.outcome == ("confirmed" if other_hit else "inconclusive")
    assert len(result.matches) == int(other_hit)
    if other_hit:
        assert result.matches[0]["line"] > line
        assert result.matches[0]["rule"] == 'snprintf_advance'
    assert result.details["confirm_only"]
    scoped = scope_coccinelle_result(result, target_path=tmp_path, function_name="partial", line_start=line, line_end=line, language="c")
    assert scoped.outcome == "inconclusive"
    assert not scoped.matches
    assert scoped.details["confirm_only"]
    assert len(result.matches) == int(other_hit)
