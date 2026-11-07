"""Fixture tests for the va_arg_mismatch rule.

Verification-role rule (fires mint confirmed CWE-686 verdicts):
va_arg with a type that undergoes default argument promotion
(char/short/float) reads the wrong size from the stack. The
positive pins va_arg(ap, char) — reported id va_arg_promoted_type;
the negative pins the promoted-type va_arg(ap, int).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "va_arg_mismatch.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_va_arg_char_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            char first_char(int count, ...)
            {
                va_list ap;
                char c;
                va_start(ap, count);
                c = va_arg(ap, char);
                va_end(ap);
                return c;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "va_arg_promoted_type"
        assert results[0]["line"] == 6


class TestNegatives:
    def test_va_arg_int_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int first_int(int count, ...)
            {
                va_list ap;
                int v;
                va_start(ap, count);
                v = va_arg(ap, int);
                va_end(ap);
                return v;
            }
        """)
        assert results == []


@pytest.mark.parametrize("operand", ["ap", "(ap)", "state.args", "ctx->args", "(*ctx).args", "*pap", "slots[0]"],
                         ids=["local", "parenthesized", "field", "pointer-field", "dereferenced-field", "indirect-list", "array-element"])
def test_argument_list_operands_and_extraction_types(tmp_path, operand):
    cases = (
        ("char", "va_arg_promoted_type"),
        ("signed char", "va_arg_promoted_type"),
        ("unsigned char", "va_arg_promoted_type"),
        ("short", "va_arg_promoted_type_short"),
        ("signed short", "va_arg_promoted_type_short"),
        ("unsigned short", "va_arg_promoted_type_short"),
        ("short int", "va_arg_promoted_type_short"),
        ("signed short int", "va_arg_promoted_type_short"),
        ("unsigned short int", "va_arg_promoted_type_short"),
        ("float", "va_arg_promoted_type_float"),
        ("_Bool", "va_arg_promoted_type_bool"),
        ("int", None), ("unsigned int", None),
        ("long", None), ("unsigned long", None),
        ("double", None), ("long double", None),
        ("char *", None), ("short *", None),
        ("float *", None), ("_Bool *", None),
        ("struct payload", None), ("float _Complex", None),
        ("bool", None),
    )
    # A C typedef named bool can be int; its spelling alone proves no promotion.
    lines = ["#include <stdarg.h>", "typedef int bool;",
             "struct holder { va_list args; };", "struct payload { int value; };"]
    setups = {
        "ap": "va_list ap;", "(ap)": "va_list ap;",
        "state.args": "struct holder state;",
        "ctx->args": "struct holder storage; struct holder *ctx = &storage;",
        "(*ctx).args": "struct holder storage; struct holder *ctx = &storage;",
        "*pap": "va_list storage; va_list *pap = &storage;",
        "slots[0]": "va_list slots[2];",
    }
    expected = set()
    for api in ("va_arg", "__builtin_va_arg"):
        for extraction_type, rule_id in cases:
            lines += [f"void case_{len(lines)}(int count, ...) {{", setups[operand],
                      f"va_start({operand}, count);", f"(void){api}({operand}, {extraction_type});",
                      f"va_end({operand});", "}"]
            if rule_id:
                expected.add((len(lines) - 2, rule_id))
    for index in range(32):
        lines += [f"void repeated_{index}(int count, ...) {{", setups[operand],
                  f"va_start({operand}, count);", f"(void)va_arg({operand}, _Bool);",
                  f"va_end({operand});", "}"]
        expected.add((len(lines) - 2, "va_arg_promoted_type_bool"))
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {(row["line"], row["rule"]) for row in results}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(results) == len(expected)


@pytest.mark.integration
def test_promoted_type_aliases_keep_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        '#include <stdarg.h>\n'
        'typedef int bool;\n'
        'struct holder { va_list args; };\n'
        'void extract(int count, ...) { struct holder h; va_list *pap = &h.args;\n'
        'va_start(h.args, count);\n'
        '(void)va_arg(h.args, char);\n'
        '(void)va_arg(*pap, unsigned short int);\n'
        '(void)__builtin_va_arg(h.args, float);\n'
        '(void)va_arg(h.args, _Bool);\n'
        '(void)va_arg(h.args, int);\n'
        '(void)va_arg(h.args, bool);\n'
        '(void)va_arg(h.args, float _Complex);\n'
        'va_end(h.args); }\n'
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
        source, [_RULE, _RULE.with_name("double_close.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"va_arg_mismatch", "double_close"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert {match.rule for match in results["va_arg_mismatch"].matches} == {
        "va_arg_promoted_type", "va_arg_promoted_type_short",
        "va_arg_promoted_type_float", "va_arg_promoted_type_bool",
    }
    assert len(results["va_arg_mismatch"].matches) == 4
    assert len(results["double_close"].matches) == 1
    assert len(invocations) == 1, invocations
