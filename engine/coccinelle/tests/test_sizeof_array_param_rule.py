"""Native controls for sizeof on adjusted array-notation parameters.

These are review candidates: pointer-width sizeof can be intentional.
Recognised local shadows are excluded; conservative shadow handling may
also omit a later outer-parameter use after the nested scope closes.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "sizeof_array_param.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_sizeof_on_sized_param_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void fill(char buf[256])
            {
                memset(buf, 0, sizeof(buf));
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "sizeof_array_param"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_sizeof_on_local_array_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void fill(void)
            {
                char buf[256];
                memset(buf, 0, sizeof(buf));
            }
        """)
        assert results == []


def test_sized_unsized_and_variable_bounds(tmp_path):
    cases = [
        ("char buf[32]", "sizeof_array_param"),
        ("char buf[n]", "sizeof_array_param"),
        ("char buf[n + 1]", "sizeof_array_param"),
        ("const char buf[n]", "sizeof_array_param"),
        ("int buf[n]", "sizeof_array_param"),
        ("char buf[]", "sizeof_array_param_unsized"),
    ]
    lines = []
    expected = set()
    for parameter, rule_id in cases:
        lines += [f"void parameter_{len(lines)}(int n, {parameter}) {{", "  consume(sizeof(buf));"]
        expected.add((len(lines), rule_id))
        lines.append("}")
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {(row["line"], row["rule"]) for row in results} == expected
    assert len(results) == len(expected)


@pytest.mark.parametrize("parameter", ["char buf[32]", "char buf[n]", "char buf[]"],
                         ids=["constant", "variable", "unsized"])
def test_local_shadows_are_not_parameter_uses(tmp_path, parameter):
    declarations = [
        "char buf[8];", 'char buf[8] = "x";', 'char buf[] = "x";',
        "char *buf;", 'char *buf = "x";', "unsigned long buf = 1;",
        "char other[8], buf[4];",
    ]
    lines = []
    for declaration in declarations:
        lines += [f"void shadow_{len(lines)}(int n, {parameter}) {{", "  {", f"    {declaration}",
                  "    consume(sizeof(buf));", "  }", "}"]
    assert _run_rule(tmp_path, "\n".join(lines) + "\n") == []


def test_unrelated_declarations_and_earlier_parameter_uses_still_match(tmp_path):
    lines = ["void f(char buf[32]) {", "  char other[8];", "  consume(sizeof(buf));",
             "  { char buf[8]; consume(sizeof(buf)); }", "}"]
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in results} == {lines.index("  consume(sizeof(buf));") + 1}
    assert len(results) == 1


class TestDocumentedLimits:
    def test_later_outer_use_after_shadowing_is_conservatively_omitted(self, tmp_path):
        source = (
            "void f(char buf[32]) {\n"
            "  { char buf[8]; consume(sizeof(buf)); }\n"
            "  consume(sizeof(buf));\n"
            "}\n"
        )
        assert _run_rule(tmp_path, source) == []
