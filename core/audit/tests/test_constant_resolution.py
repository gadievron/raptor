"""Tests for the uniqueness-gated constant resolution module.

Adversarial tests from the safety contract's documented blind spots:
- Conditional #define
- Multi-definition with different values
- Macro composition / identifier references
- Function-like macros
- Contract compliance (boost-only, never suppress)
"""

from __future__ import annotations

import time

import pytest
from pathlib import Path

from core.audit.constant_resolution import (
    build_unique_constants,
    clear_cache,
    _try_evaluate,
    _compute_conditional_depths,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    clear_cache()
    yield
    clear_cache()


def _write_file(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


# ── Evaluation ───────────────────────────────────────────────────────


class TestTryEvaluate:
    def test_decimal_literal(self):
        assert _try_evaluate("256") == 256

    def test_hex_literal(self):
        assert _try_evaluate("0xFF") == 0xFF

    def test_negative_literal(self):
        assert _try_evaluate("-1") == -1

    def test_parenthesized(self):
        assert _try_evaluate("(256)") == 256

    def test_arithmetic(self):
        assert _try_evaluate("4 * 1024") == 4096

    def test_complex_arithmetic(self):
        assert _try_evaluate("(1 << 12)") == 4096

    def test_hex_arithmetic(self):
        assert _try_evaluate("0x100 - 1") == 255

    def test_rejects_identifier(self):
        assert _try_evaluate("PAGE_SIZE") is None

    def test_rejects_mixed_ident_arithmetic(self):
        assert _try_evaluate("4 * PAGE_SIZE") is None

    def test_rejects_sizeof(self):
        assert _try_evaluate("sizeof(int)") is None

    def test_rejects_cast(self):
        assert _try_evaluate("(unsigned long)0xFF") is None

    def test_rejects_function_call(self):
        assert _try_evaluate("max(4, 8)") is None

    def test_rejects_empty(self):
        assert _try_evaluate("") is None

    def test_rejects_string(self):
        assert _try_evaluate('"hello"') is None

    def test_typical_flag_bit(self):
        assert _try_evaluate("(1 << 31)") == 1 << 31

    def test_all_ones_32(self):
        assert _try_evaluate("0xFFFFFFFF") == 0xFFFFFFFF

    def test_all_ones_64(self):
        assert _try_evaluate("0xFFFFFFFFFFFFFFFF") == 2**64 - 1

    def test_invert(self):
        assert _try_evaluate("~0") == -1

    def test_modulo(self):
        assert _try_evaluate("7 % 3") == 1

    def test_floor_division(self):
        assert _try_evaluate("8 // 2") == 4

    def test_bitwise_ops(self):
        assert _try_evaluate("1 | 2") == 3
        assert _try_evaluate("6 & 3") == 2
        assert _try_evaluate("5 ^ 1") == 4

    def test_unary_plus(self):
        assert _try_evaluate("+7") == 7

    def test_rejects_power(self):
        assert _try_evaluate("2**64") is None
        assert _try_evaluate("2 ** 10") is None

    def test_rejects_true_division(self):
        # Python `/` yields a float; the old eval-based path rejected
        # the non-int result, and the AST path rejects the operator.
        assert _try_evaluate("4/2") is None

    def test_rejects_division_by_zero(self):
        assert _try_evaluate("1 // 0") is None
        assert _try_evaluate("1 % 0") is None

    def test_rejects_comparison(self):
        # The eval-based path returned bool(True) for `1<2`; the AST
        # walker rejects comparisons — a comparison is not a macro
        # constant this resolver should feed into SMT.
        assert _try_evaluate("1<2") is None
        assert _try_evaluate("(1>2)") is None


# ── Bounded evaluation caps ──────────────────────────────────────────


class TestEvaluationCaps:
    """_try_evaluate is an AST walker with explicit literal/shift/result
    caps — a hostile body like ``(1<<999999999999)`` must return None
    quickly instead of forcing a huge bigint."""

    def test_huge_shift_returns_none_quickly(self):
        t0 = time.monotonic()
        assert _try_evaluate("(1<<999999999999)") is None
        assert time.monotonic() - t0 < 1.0

    def test_shift_past_cap(self):
        assert _try_evaluate("1 << 257") is None
        assert _try_evaluate("1 << 300") is None

    def test_negative_shift(self):
        assert _try_evaluate("1 << -1") is None

    def test_shift_at_result_cap_boundary(self):
        assert _try_evaluate("1 << 128") == 1 << 128
        assert _try_evaluate("1 << 129") is None

    def test_chained_shift_result_cap(self):
        # Each shift amount is under the cap; the intermediate-result
        # magnitude cap must still stop the chain.
        assert _try_evaluate("(1<<100)<<100") is None

    def test_multiplication_result_cap(self):
        assert _try_evaluate("(1<<100) * (1<<100)") is None

    def test_oversized_literal(self):
        assert _try_evaluate(str(2**65)) is None

    def test_literal_at_cap_boundary(self):
        assert _try_evaluate(str(2**64)) == 2**64

    def test_oversized_body_length(self):
        assert _try_evaluate("9" * 600) is None
        assert _try_evaluate("1+" * 400 + "1") is None

    def test_negative_oversized_literal(self):
        assert _try_evaluate(f"-{2**65}") is None


class TestTryEvaluateBounds:
    """The evaluator is an AST walker with explicit literal/shift/
    result caps — hostile macro bodies must not force bigint work or
    resolve truth values as constants."""

    def test_hex_shift_bomb_returns_none_quickly(self):
        import time
        start = time.monotonic()
        assert _try_evaluate("1<<0x7fffffff") is None
        assert time.monotonic() - start < 1.0

    def test_decimal_shift_bomb(self):
        assert _try_evaluate("(1<<999999999999)") is None

    def test_shift_past_cap(self):
        assert _try_evaluate("1 << 257") is None

    def test_negative_shift(self):
        assert _try_evaluate("1 << -1") is None

    def test_wide_shift_within_result_cap_ok(self):
        assert _try_evaluate("1 << 100") == 1 << 100

    def test_nested_shift_bomb(self):
        assert _try_evaluate("(1<<200) << (1<<200)") is None

    def test_oversized_literal(self):
        assert _try_evaluate(str(1 << 80)) is None

    def test_oversized_result_via_multiplication(self):
        assert _try_evaluate(f"{(1 << 64) - 1} * {(1 << 64) - 1} * 4") is None

    def test_oversized_body(self):
        assert _try_evaluate("1 + " * 400 + "1") is None

    def test_comparison_not_a_constant(self):
        # A truth value is not a constant — `<` / `>` are shift chars
        # to the charset gate but comparisons must not resolve.
        assert _try_evaluate("1 < 2") is None
        assert _try_evaluate("2 > 1") is None

    def test_typical_kernel_constants_still_resolve(self):
        assert _try_evaluate("(1 << 31)") == 1 << 31
        assert _try_evaluate("0xFFFFFFFF") == 0xFFFFFFFF
        assert _try_evaluate("~0") == -1
        assert _try_evaluate("(4 * 1024) - 1") == 4095


# ── Conditional depth tracking ───────────────────────────────────────


class TestConditionalDepths:
    def test_unconditional(self):
        src = "#define FOO 1\n#define BAR 2\n"
        depths = _compute_conditional_depths(src)
        assert depths[1] == 0
        assert depths[2] == 0

    def test_inside_ifdef(self):
        src = (
            "#ifdef DEBUG\n"
            "#define FOO 1\n"
            "#endif\n"
        )
        depths = _compute_conditional_depths(src)
        assert depths[2] == 1

    def test_nested_ifdef(self):
        src = (
            "#ifdef A\n"
            "#ifdef B\n"
            "#define FOO 1\n"
            "#endif\n"
            "#endif\n"
        )
        depths = _compute_conditional_depths(src)
        assert depths[3] == 2

    def test_after_endif(self):
        src = (
            "#ifdef DEBUG\n"
            "#define FOO 1\n"
            "#endif\n"
            "#define BAR 2\n"
        )
        depths = _compute_conditional_depths(src)
        assert depths[2] == 1
        assert depths[4] == 0

    def test_ifndef(self):
        src = (
            "#ifndef HEADER_GUARD\n"
            "#define HEADER_GUARD\n"
            "#define FOO 1\n"
            "#endif\n"
        )
        depths = _compute_conditional_depths(src)
        assert depths[2] == 1
        assert depths[3] == 1

    def test_if_defined(self):
        src = (
            "#if defined(FEATURE)\n"
            "#define FOO 1\n"
            "#endif\n"
        )
        depths = _compute_conditional_depths(src)
        assert depths[2] == 1


# ── Uniqueness gate — adversarial ────────────────────────────────────


class TestConditionalDefine:
    """Safety contract blind spot: conditional #define."""

    def test_ifdef_rejects(self, tmp_path):
        _write_file(tmp_path, "a.h", (
            "#ifdef DEBUG\n"
            "#define MAX_SIZE 100\n"
            "#endif\n"
        ))
        table = build_unique_constants(tmp_path)
        assert "MAX_SIZE" not in table.unique
        assert "conditional" in table.rejected.get("MAX_SIZE", "")

    def test_unconditional_same_file_as_ifdef_accepts(self, tmp_path):
        _write_file(tmp_path, "a.h", (
            "#define BUF_SIZE 256\n"
            "#ifdef DEBUG\n"
            "#define DEBUG_BUF 512\n"
            "#endif\n"
        ))
        table = build_unique_constants(tmp_path)
        assert "BUF_SIZE" in table.unique
        assert table.unique["BUF_SIZE"].value == 256
        assert "DEBUG_BUF" not in table.unique

    def test_header_guard_rejects_nested_defines(self, tmp_path):
        _write_file(tmp_path, "a.h", (
            "#ifndef A_H\n"
            "#define A_H\n"
            "#define FOO 42\n"
            "#endif\n"
        ))
        table = build_unique_constants(tmp_path)
        assert "A_H" not in table.unique
        assert "FOO" not in table.unique


class TestMultiDefinition:
    """Safety contract blind spot: redefinition."""

    def test_different_value_rejects(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define MAX 100\n")
        _write_file(tmp_path, "b.h", "#define MAX 200\n")
        table = build_unique_constants(tmp_path)
        assert "MAX" not in table.unique
        assert "redefined" in table.rejected.get("MAX", "")

    def test_same_value_accepts(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define MAX 100\n")
        _write_file(tmp_path, "b.h", "#define MAX 100\n")
        table = build_unique_constants(tmp_path)
        assert "MAX" in table.unique
        assert table.unique["MAX"].value == 100

    def test_function_like_rejects(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define MAX(a, b) ((a) > (b) ? (a) : (b))\n")
        table = build_unique_constants(tmp_path)
        assert "MAX" not in table.unique
        assert "function-like" in table.rejected.get("MAX", "")

    def test_object_vs_function_like_rejects(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define FOO 42\n")
        _write_file(tmp_path, "b.h", "#define FOO(x) (x)\n")
        table = build_unique_constants(tmp_path)
        assert "FOO" not in table.unique


class TestMacroComposition:
    """Safety contract blind spot: macro composition."""

    def test_identifier_in_body_rejects(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define BUF_SIZE (4 * PAGE_SIZE)\n")
        table = build_unique_constants(tmp_path)
        assert "BUF_SIZE" not in table.unique

    def test_pure_arithmetic_accepts(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define BUF_SIZE (4 * 1024)\n")
        table = build_unique_constants(tmp_path)
        assert "BUF_SIZE" in table.unique
        assert table.unique["BUF_SIZE"].value == 4096

    def test_shift_arithmetic_accepts(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define PAGE_SIZE (1 << 12)\n")
        table = build_unique_constants(tmp_path)
        assert "PAGE_SIZE" in table.unique
        assert table.unique["PAGE_SIZE"].value == 4096

    def test_sizeof_rejects(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define ELEMENT_SIZE sizeof(struct entry)\n")
        table = build_unique_constants(tmp_path)
        assert "ELEMENT_SIZE" not in table.unique


class TestEnumConstants:
    def test_simple_enum(self, tmp_path):
        _write_file(tmp_path, "a.h", (
            "enum {\n"
            "    FOO = 1,\n"
            "    BAR = 2,\n"
            "};\n"
        ))
        table = build_unique_constants(tmp_path)
        assert table.unique["FOO"].value == 1
        assert table.unique["BAR"].value == 2

    def test_named_enum(self, tmp_path):
        _write_file(tmp_path, "a.h", (
            "enum limits {\n"
            "    MAX_BUF = 256,\n"
            "    MAX_NAME = 64,\n"
            "};\n"
        ))
        table = build_unique_constants(tmp_path)
        assert table.unique["MAX_BUF"].value == 256
        assert table.unique["MAX_NAME"].value == 64

    def test_negative_enum(self, tmp_path):
        _write_file(tmp_path, "a.h", (
            "enum {\n"
            "    ERR_PERM = -1,\n"
            "    ERR_IO = -5,\n"
            "};\n"
        ))
        table = build_unique_constants(tmp_path)
        assert table.unique["ERR_PERM"].value == -1
        assert table.unique["ERR_IO"].value == -5

    def test_hex_enum(self, tmp_path):
        _write_file(tmp_path, "a.h", (
            "enum flags {\n"
            "    FLAG_READ = 0x01,\n"
            "    FLAG_WRITE = 0x02,\n"
            "};\n"
        ))
        table = build_unique_constants(tmp_path)
        assert table.unique["FLAG_READ"].value == 1
        assert table.unique["FLAG_WRITE"].value == 2

    def test_enum_inside_ifdef_rejects(self, tmp_path):
        _write_file(tmp_path, "a.h", (
            "#ifdef FEATURE\n"
            "enum { FEAT_VAL = 99 };\n"
            "#endif\n"
        ))
        table = build_unique_constants(tmp_path)
        assert "FEAT_VAL" not in table.unique


class TestBasicResolution:
    def test_simple_define(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define MAX_SIZE 256\n")
        table = build_unique_constants(tmp_path)
        assert "MAX_SIZE" in table.unique
        rc = table.unique["MAX_SIZE"]
        assert rc.value == 256
        assert rc.name == "MAX_SIZE"

    def test_hex_define(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define FLAGS 0xFF\n")
        table = build_unique_constants(tmp_path)
        assert table.unique["FLAGS"].value == 0xFF

    def test_no_c_files(self, tmp_path):
        _write_file(tmp_path, "a.py", "MAX_SIZE = 256\n")
        table = build_unique_constants(tmp_path)
        assert len(table.unique) == 0

    def test_empty_dir(self, tmp_path):
        table = build_unique_constants(tmp_path)
        assert len(table.unique) == 0

    def test_as_int_dict(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define A 1\n#define B 2\n")
        table = build_unique_constants(tmp_path)
        d = table.as_int_dict()
        assert d == {"A": 1, "B": 2}


class TestCaching:
    def test_cache_hit(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define X 1\n")
        t1 = build_unique_constants(tmp_path)
        t2 = build_unique_constants(tmp_path)
        assert t1 is t2

    def test_clear_cache(self, tmp_path):
        _write_file(tmp_path, "a.h", "#define X 1\n")
        t1 = build_unique_constants(tmp_path)
        clear_cache()
        t2 = build_unique_constants(tmp_path)
        assert t1 is not t2


# ── Safety contract compliance ───────────────────────────────────────


class TestContractCompliance:
    def test_assert_boost_only_succeeds(self):
        from core.audit.safety_contract import assert_boost_only
        assert_boost_only("constant_resolution")

    def test_suppress_evidence_raises(self):
        from core.audit.safety_contract import ContractViolation, SuppressEvidence
        with pytest.raises(ContractViolation):
            SuppressEvidence(
                source="constant_resolution",
                verdict="resolved",
                reason="test",
            )

    def test_boost_evidence_allowed(self):
        from core.audit.safety_contract import BoostEvidence
        ev = BoostEvidence(
            source="constant_resolution",
            action="inject_context",
            description="resolved MAX_SIZE=256",
        )
        assert ev.source == "constant_resolution"
        assert ev.action == "inject_context"
