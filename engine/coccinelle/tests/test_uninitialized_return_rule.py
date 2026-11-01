"""Fixture tests for the uninitialized_return rule.

Pattern 2's domination scan must treat an unconditional assignment
BETWEEN the declaration and the switch as initialising: whatever the
default-less switch does, the variable is already set at the return.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "uninitialized_return.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(_RULE), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


def _switch_results(results: list[dict]) -> list[dict]:
    return [r for r in results if "switch without default" in r["message"]]


class TestPositives:
    def test_switch_without_default_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(int mode)
            {
                int err;
                switch (mode) {
                case 1:
                    err = do_one();
                    break;
                case 2:
                    err = do_two();
                    break;
                }
                return err;
            }
        """)
        assert len(_switch_results(results)) == 1

    def test_conditional_init_before_switch_still_fires(self, tmp_path):
        # An init nested inside an if does NOT dominate the return.
        results = _run_rule(tmp_path, """\
            int bug(int mode, int flag)
            {
                int err;
                if (flag) {
                    err = 5;
                }
                switch (mode) {
                case 1:
                    err = do_one();
                    break;
                }
                return err;
            }
        """)
        assert len(_switch_results(results)) == 1


class TestNegatives:
    def test_unconditional_init_before_switch_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(int mode)
            {
                int err;
                err = 0;
                switch (mode) {
                case 1:
                    err = do_one();
                    break;
                case 2:
                    err = do_two();
                    break;
                }
                return err;
            }
        """)
        assert _switch_results(results) == []

    def test_switch_with_default_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(int mode)
            {
                int err;
                switch (mode) {
                case 1:
                    err = do_one();
                    break;
                default:
                    err = -1;
                    break;
                }
                return err;
            }
        """)
        assert _switch_results(results) == []


def test_iterator_cursor_returns_are_position_scoped(tmp_path):
    cases = {
        "list_cursor": "struct node *cursor; list_for_each_entry(cursor, head, link) { if (pick()) return cursor; } return 0;",
        "reverse_cursor": "struct node *cursor; list_for_each_entry_reverse(cursor, head, link) { return cursor; } return 0;",
        "safe_cursor": "struct node *cursor, *next; list_for_each_entry_safe(cursor, next, head, link) { return cursor; } return 0;",
        "hlist_cursor": "struct node *cursor; hlist_for_each_entry(cursor, head, link) { return cursor; } return 0;",
        "hlist_safe_cursor": "struct node *cursor, *next; hlist_for_each_entry_safe(cursor, next, head, link) { return cursor; } return 0;",
        "uninitialized_local": "struct node *cursor; return cursor; // finding",
        "unrelated_in_body": "struct node *cursor; struct node *other; list_for_each_entry(cursor, head, link) { return other; // finding\n} return 0;",
        "head_is_not_cursor": "struct node *cursor; struct node *other; list_for_each_entry(cursor, other, link) { return other; // finding\n} return 0;",
        "return_before_loop": "struct node *cursor;\nif (pick()) return cursor; // finding\nlist_for_each_entry(cursor, head, link) { return cursor; } return 0;",
        "conditional_loop": "struct node *cursor; if (pick()) { list_for_each_entry(cursor, head, link) { use(cursor); } } return cursor; // finding",
        "unknown_call": "struct node *cursor; observe(cursor); return cursor; // finding",
        "other_cursor_loop": "struct node *cursor; struct node *other; list_for_each_entry(other, head, link) { use(other); } return cursor; // finding",
        "inner_shadow": "struct node *cursor; list_for_each_entry(cursor, head, link) { struct node *cursor; return cursor; // finding\n} return 0;",
        "unicode_prefix": "struct node *cursor; /* π */ list_for_each_entry(cursor, head, link) { return cursor; } return 0;",
        "unbraced_if": "struct node *cursor; list_for_each_entry(cursor, head, link) if (pick()) return cursor; return 0;",
        "unbraced_return": "struct node *cursor; list_for_each_entry(cursor, head, link) return cursor; return 0;",
        "unbraced_else": "struct node *cursor; list_for_each_entry(cursor, head, link) if (pick()) return 0; else return cursor; return 0;",
        "unbraced_conditional_loop": "struct node *cursor; if (pick()) list_for_each_entry(cursor, head, link) use(cursor); return cursor; // finding",
        "switch_cursor": "struct node *cursor; list_for_each_entry(cursor, head, link) { switch (pick()) { case 1: cursor = head; break; } return cursor; } return 0;",
    }
    lines = ["struct node { struct node *link; };", "int pick(void);"]
    for name, body in cases.items():
        body = body.replace("; ", ";\n").replace(";\n// finding", "; // finding")
        lines += [f"struct node *{name}(struct node *head) {{", body, "}"]
    source = "\n".join(lines) + "\n"
    expected = {i for i, line in enumerate(source.splitlines(), 1) if "// finding" in line}
    results = _run_rule(tmp_path, source)
    assert {r["line"] for r in results} == expected


@pytest.mark.parametrize("directive", [
    "#define list_for_each_entry(cursor, head, link) for (; pick(); )",
    "# /**/ define /**/ list_for_each_entry(cursor, head, link) for (; pick(); )",
    "#undef list_for_each_entry",
])
def test_local_iterator_override_does_not_hide_uninitialized_return(tmp_path, directive):
    results = _run_rule(tmp_path, directive + "\n" + textwrap.dedent("""\
        struct node { struct node *link; };
        struct node *bug(struct node *head)
        {
            struct node *cursor;
            list_for_each_entry(cursor, head, link) {
                return cursor; // finding
            }
            return 0;
        }
    """))
    assert len(results) == 1
    assert "'cursor'" in results[0]["message"]


@pytest.mark.parametrize("noise", [
    '/* #define list_for_each_entry(a,b,c) fake */',
    '// #undef list_for_each_entry',
    '#define UNUSED(x) ' + chr(92) + '\n (x)',
    'const char *text = "#define list_for_each_entry(a,b,c) fake";',
    'const char *text = "/*"; // #undef list_for_each_entry',
])
def test_comments_and_literals_do_not_override_iterator_model(tmp_path, noise):
    results = _run_rule(tmp_path, noise + "\n" + textwrap.dedent("""\
        struct node { struct node *link; };
        struct node *ok(struct node *head)
        {
            struct node *cursor;
            list_for_each_entry(cursor, head, link) {
                return cursor;
            }
            return 0;
        }
    """))
    assert results == []
