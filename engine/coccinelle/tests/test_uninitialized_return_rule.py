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



_LOOP_CASES = (
    ("int value; for (value = 0; value < limit; value++) { use(value); } return value;", False),
    ("int value; for (;;) { value = work(); if (done()) break; } return value;", False),
    ("int value; while (1) { value = work(); if (done()) break; } return value;", False),
    ("int value; do { value = work(); } while (done()); return value;", False),
    ("int value; for (;;) { if (flag) value = 1; else value = 2; break; } return value;", False),
    ("int value; for (; (value = work()); ) { use(value); } return value;", False),
    ("int value; for (; limit; value = work()) { if (flag) break; } return value;", True),
    ("int value; while (limit--) { value = work(); } return value;", True),
    ("int value; for (; limit; ) { value = work(); } return value;", True),
    ("int value; for (;;) { if (flag) break; value = work(); if (done()) break; } return value;", True),
    ("int value; do { if (flag) break; value = work(); } while (done()); return value;", True),
    ("int value; for (;;) { if (flag) value = work(); break; } return value;", True),
    ("int value; if (flag) { for (value = 0; value < limit; value++) {} } return value;", True),
    ("int value; if (flag) goto out; for (value = 0; value < limit; value++) {} out: return value;", True),
    ("int value; for (int value = 0; value < limit; value++) {} return value;", True),
    ("int value; for (value = 0; value < limit; value++) { int value; return value; } return 0;", True),
    ("int value; if (flag) value = 0; return value;", True),
    ("int value; if (flag) return -1; for (value = 0; value < limit; value++) {} if (value > 0) return value; return 0;", False),
    ("int value; if (flag) return value; for (value = 0; value < limit; value++) {} return value;", True),
    ("int value; for (value = value + 1; value < limit; value++) {} return value;", True),
    ("int value; for (;;) { value = work(value); if (done()) break; } return value;", True),
    ("int value; if (flag) goto inside; for (;;) { value = work(); inside: break; } return value;", True),
    ("int value; switch (flag) { case 1: value = 0; break; } return value;", True),
    ("int value; while (limit--) { for (value = 0; value < limit; value++) {} } return value;", True),
    ("int value; for (;;) { if (flag) break; for (value = 0; value < limit; value++) {} break; } return value;", True),
    ("int value; while (limit--) { if (flag) continue; for (value = 0; value < limit; value++) {} } return value;", True),
    ("int value; for (value = 0; value < limit; value++) {} { int value; return value; }", True),
)


@pytest.mark.parametrize("compact", [False, True])
@pytest.mark.parametrize("batch", range((len(_LOOP_CASES) + 2) // 3))
def test_loop_initialization_paths(tmp_path, compact, batch):
    # Share spatch startup across a few independent functions without making
    # one test phase a heavyweight scan. Attribute by generated source spans;
    # no external file layout or fixed line number is part of the contract.
    lines = []
    line_to_case = {}
    expected = set()
    for index, (body, fires) in enumerate(_LOOP_CASES[batch * 3:batch * 3 + 3]):
        layout = body if compact else body.replace("; ", ";\n")
        function = f"int sample_{index}(int limit, int flag) {{ " + layout + " }"
        for line in function.splitlines():
            lines.append(line)
            line_to_case[len(lines)] = index
        if fires:
            expected.add(index)
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {line_to_case[result["line"]] for result in results} == expected


@pytest.mark.integration
@pytest.mark.parametrize("other_hit", [False, True], ids=["file-empty", "other-function-hit"])
def test_partial_data_silence_is_inconclusive(tmp_path, other_hit):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    prefix = 'struct packet { int first; int second; };\n'
    source = prefix + 'int partial(void) { struct packet value; return value.second; }' + "\n"
    line = 1 + prefix.count("\n")
    if other_hit:
        source += 'int other(void) { int result; return result; }' + "\n"
    (tmp_path / "partial.c").write_text(source)
    result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path="partial.c", cocci_rule=str(_RULE), language="c",
    )
    assert not result.errors, result.errors
    assert result.outcome == ("confirmed" if other_hit else "inconclusive")
    assert len(result.matches) == int(other_hit)
    if other_hit:
        assert result.matches[0]["line"] > line
        assert result.matches[0]["rule"] == 'uninitialized_return'
    assert result.details["confirm_only"]
    scoped = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="partial",
        line_start=line, line_end=line, language="c",
    )
    assert scoped.outcome == "inconclusive"
    assert not scoped.matches
    assert scoped.details["confirm_only"]
    assert len(result.matches) == int(other_hit)
