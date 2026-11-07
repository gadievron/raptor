"""Fixture tests for the is_err_not_ptr_err rule.

Detection-role rule (errno return contracts require independent review):
returning IS_ERR(p) from an error path yields boolean 1 instead of
the embedded errno. The positive pins return IS_ERR(p) inside the
IS_ERR check; the negative pins the correct return PTR_ERR(p).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "is_err_not_ptr_err.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_return_is_err_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int setup(struct dev *d)
            {
                void *clk = get_clk(d);
                if (IS_ERR(clk)) {
                    return IS_ERR(clk);
                }
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "is_err_not_ptr_err"
        assert results[0]["line"] == 5


class TestNegatives:
    def test_return_ptr_err_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int setup(struct dev *d)
            {
                void *clk = get_clk(d);
                if (IS_ERR(clk)) {
                    return PTR_ERR(clk);
                }
                return 0;
            }
        """)
        assert results == []


@pytest.mark.parametrize("return_type", ["int", "bool", "_Bool", "static bool"],
                         ids=["errno-candidate", "bool-predicate", "builtin-bool", "static-predicate"])
def test_returned_values_and_explicit_boolean_contracts(tmp_path, return_type):
    cases = (
        ("return IS_ERR(p);", True),
        ("return -IS_ERR(p);", True),
        ("ret = IS_ERR(p); return ret;", True),
        ("ret = -IS_ERR(p); return ret;", True),
        ("int err = IS_ERR(p); return err;", True),
        ("int err = -IS_ERR(p); return err;", True),
        ("ret = IS_ERR(p); return PTR_ERR(p);", False),
        ("ret = IS_ERR(p); ret = PTR_ERR(p); return ret;", False),
        ("ret = IS_ERR(p); rewrite(&ret); return ret;", False),
        ("ret = IS_ERR(p); ret += delta; return ret;", False),
        ("ret = IS_ERR(p); ret -= delta; return ret;", False),
        ("ret = IS_ERR(p); ret *= -EIO; return ret;", False),
        ("ret = IS_ERR(p); ret /= delta; return ret;", False),
        ("ret = IS_ERR(p); ret %= delta; return ret;", False),
        ("ret = IS_ERR(p); ret <<= delta; return ret;", False),
        ("ret = IS_ERR(p); ret >>= delta; return ret;", False),
        ("ret = IS_ERR(p); ret &= delta; return ret;", False),
        ("ret = IS_ERR(p); ret ^= delta; return ret;", False),
        ("ret = IS_ERR(p); ret |= delta; return ret;", False),
        ("ret = IS_ERR(p); ret++; return ret;", False),
        ("ret = IS_ERR(p); ++ret; return ret;", False),
        ("ret = IS_ERR(p); ret--; return ret;", False),
        ("ret = IS_ERR(p); --ret; return ret;", False),
        ("ret = IS_ERR(p); return other_value;", False),
        ("p = other; return IS_ERR(p);", False),
        ("p++; return IS_ERR(p);", False),
        ("++p; return IS_ERR(p);", False),
        ("p--; return IS_ERR(p);", False),
        ("--p; return IS_ERR(p);", False),
        ("p -= delta; return IS_ERR(p);", False),
        ("p += delta; return IS_ERR(p);", False),
        ("rewrite_ptr(&p); return IS_ERR(p);", False),
        ("return PTR_ERR(p);", False),
        ("ret = -IS_ERR(p); ret = -EIO; return ret;", False),
        ("int err = IS_ERR(p); return -EIO;", False),
        ("int err = -IS_ERR(p); err = PTR_ERR(p); return err;", False),
    )
    lines = ["typedef _Bool bool;"]
    expected = set()
    for body, should_report in cases:
        lines += [f"{return_type} case_{len(lines)}(void *p, void *other, int delta, int other_value) {{",
                  "int ret = 0;", "if (IS_ERR(p)) {", body, "}", "return 0;", "}"]
        if should_report and return_type == "int":
            expected.add(len(lines) - 3)
    for index in range(32):
        lines += [f"{return_type} repeated_{index}(void *p) {{",
                  "if (IS_ERR(p)) {", "return IS_ERR(p);", "}", "return 0;", "}"]
        if return_type == "int":
            expected.add(len(lines) - 3)
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in results}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(results) == len(expected)
    assert {row["rule"] for row in results} <= {"is_err_not_ptr_err"}


@pytest.mark.integration
def test_error_return_candidates_keep_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        'typedef _Bool bool;\n'
        'int candidate(void *p) { if (IS_ERR(p)) { int ret = -IS_ERR(p); return ret; } return 0; }\n'
        'bool predicate(void *p) { if (IS_ERR(p)) { return IS_ERR(p); } return 0; }\n'
        'int overwritten(void *p) { int ret; if (IS_ERR(p)) { ret = IS_ERR(p); ret = PTR_ERR(p); return ret; } return 0; }\n'
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
    assert set(results) == {"is_err_not_ptr_err", "double_close"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["is_err_not_ptr_err"].matches) == 1
    assert len(results["double_close"].matches) == 1
    assert len(invocations) == 1, invocations
