"""Fixture tests for the shift_overflow rule.

Detection-role rule: conventional literal widths are ABI assumptions,
not target-layout evidence. Signed negative counts are separate candidates;
unsigned unary negation and nonliteral counts need type-aware analysis.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "shift_overflow.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_int_shift_by_32_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int mask(void)
            {
                return 1 << 32;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "shift_overflow_int"
        assert results[0]["line"] == 3

    def test_long_long_shift_by_64_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned long long mask(void)
            {
                return 1ULL << 64;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "shift_overflow_long"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_int_shift_by_31_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int mask(void)
            {
                return 1 << 31;
            }
        """)
        assert results == []


@pytest.mark.parametrize("operator", ["<<", ">>"], ids=["left", "right"])
@pytest.mark.parametrize("suffix", ["", "U", "u", "L", "l", "UL", "uL", "Lu", "lU", "LL", "ll", "ULL", "uLL", "llU", "LLu"], ids=["plain", "U", "u", "L", "l", "UL", "uL", "Lu", "lU", "LL", "ll", "ULL", "uLL", "llU", "LLu"])
def test_literal_spellings_and_boundaries(tmp_path, operator, suffix):
    threshold = 64 if "l" in suffix.lower() else 32
    counts = [
        (str(threshold - 1), False), (str(threshold), True),
        (f"{threshold}U", True), (f"{threshold}UL", True),
        (hex(threshold) + "uLL", True), ("0" + format(threshold, "o") + "U", True),
        ("(" + str(threshold) + ")", True),
        ("((" + str(threshold) + "))", True),
        ("+" + str(threshold) + "U", True),
        ("count", False), ("count + 1", False),
    ]
    lines = []
    expected = set()
    for index, (count, reports) in enumerate(counts):
        lines += [f"unsigned long long case_{index}(int count) {{",
                  f"return 1{suffix} {operator} {count};", "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)
    expected_rule = "shift_overflow_long" if threshold == 64 else "shift_overflow_int"
    assert all(row["rule"] == expected_rule and row["message"].startswith("Candidate:") for row in rows)


@pytest.mark.parametrize("operator", ["<<", ">>"], ids=["left", "right"])
def test_negative_count_requires_signed_literal_semantics(tmp_path, operator):
    cases = [
        ("1", "-1", True), ("0", "-1", True), ("7UL", "(-1)", True),
        ("1ULL", "-32LL", True), ("1", "-040", True),
        ("1", "-32768", True), ("1", "-0x7fff", True),
        ("1", "-0x8000", False), ("1", "-0xffffffff", False),
        ("1", "-1U", False), ("1", "-1ULL", False), ("1", "-0", False),
        ("1", "-(count)", False), ("value", "-1", False),
        ("1", "1 - 2", False),
    ]
    lines = []
    expected = set()
    for index, (left, count, reports) in enumerate(cases):
        lines += [f"unsigned long long case_{index}(int count, int value) {{",
                  f"return {left} {operator} {count};", "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)
    assert all(row["rule"] == "shift_overflow_negative" for row in rows)


@pytest.mark.parametrize("operator", ["<<", ">>"], ids=["left", "right"])
def test_radix_spelled_literal_one_is_covered(tmp_path, operator):
    lines = []
    expected = set()
    for index, value in enumerate(("01", "0x1", "0x1U", "01UL", "0x1uLL")):
        lines += [f"unsigned long long case_{index}(void) {{", f"return {value} {operator} 64U;", "}"]
        expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)


@pytest.mark.integration
def test_literal_shift_checks_keep_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "shifts.c"
    source.write_text(
        "unsigned int int_width(void) { return 1U << 32UL; }\n"
        "unsigned long long long_width(void) { return 1uLL >> 64U; }\n"
        "unsigned int negative(void) { return 7 >> -1; }\n"
        "unsigned int sign_bit(void) { return 1U << 31; }\n"
        "unsigned long target_width(void) { return 1UL << 32; }\n"
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
    assert set(results) == {"shift_overflow", "integer_overflow_alloc"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert {match.rule for match in results["shift_overflow"].matches} == {
        "shift_overflow_int", "shift_overflow_long", "shift_overflow_negative",
    }
    assert len(results["shift_overflow"].matches) == 3
    assert all(match.message.startswith("Candidate:") for match in results["shift_overflow"].matches)
    assert len(results["integer_overflow_alloc"].matches) == 1
    assert len(invocations) == 1, invocations



def test_oversized_numeric_spelling_does_not_drop_other_matches(tmp_path):
    huge = "0x" + "f" * 6000
    source = (
        f"unsigned f(void) {{ return 1 << {huge}; }}\n"
        f"unsigned g(void) {{ return {huge} << -1; }}\n"
        "unsigned h(void) { return 1U << 32U; }\n"
    )
    rows = _run_rule(tmp_path, source)
    assert len(rows) == 1
    assert rows[0]["rule"] == "shift_overflow_int"
    assert rows[0]["line"] == source.splitlines().index("unsigned h(void) { return 1U << 32U; }") + 1


@pytest.mark.integration
@pytest.mark.parametrize("other_hit", [False, True], ids=["file-empty", "other-function-hit"])
def test_partial_integer_rule_silence_is_inconclusive(tmp_path, other_hit):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    source = "unsigned int partial(int count) { return 1U << count; }\n"
    if other_hit:
        source += "unsigned int other(void) { return 1 << 32; }\n"
    (tmp_path / "partial.c").write_text(source)
    result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path="partial.c", cocci_rule=str(_RULE), language="c",
    )
    assert result.outcome == ("confirmed" if other_hit else "inconclusive"), result.errors
    assert len(result.matches) == int(other_hit)
    assert result.details["confirm_only"]
    scoped = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="partial",
        line_start=1, line_end=1, language="c",
    )
    assert scoped.outcome == "inconclusive"
    assert scoped.details["confirm_only"]
    assert not scoped.matches
