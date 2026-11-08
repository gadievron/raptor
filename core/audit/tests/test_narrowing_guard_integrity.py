"""Unresolved constants and mutable reads cannot suppress narrowing leads."""

import pytest

from core.audit import condition_smt
from core.audit.condition_extraction import _get_parser


@pytest.fixture(autouse=True)
def diagnostic_only(monkeypatch):
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


def check(source):
    parser = _get_parser("c")
    if parser is None:
        pytest.skip("C grammar required")
    assert not parser.parse(source.encode()).root_node.has_error, source
    return condition_smt.check_integer_narrowing(source, language="c")


@pytest.mark.parametrize("header,prefix", [
    ("int Read(size_t wide, size_t INT_MAX)", ""),
    ("int Read(size_t wide)", "size_t INT_MAX = 4294967295;"),
    ("int Read(size_t wide)", "enum { INT_MAX = 4294967295ULL };"),
    ("size_t INT_MAX;\nint Read(size_t wide)", ""),
    ("int Read(size_t wide)", "extern size_t INT_MAX;"),
], ids=["parameter", "local", "enumerator", "global", "extern"])
def test_bound_name_does_not_borrow_the_standard_limit(header, prefix):
    source = header + "{\n" + prefix + "\nif(wide>INT_MAX)return 0;\nint small=wide;\nreturn small;\n}"
    assert check(source).narrowing_found


@pytest.mark.parametrize("prefix", [
    "if(wide>INT_MAX)return 0;\n__asm__(\"\" : \"+r\"(wide));",
    "if(wide>INT_MAX)return 0;\n__asm__(\"\" : \"=r\"(wide));",
    "if(wide>INT_MAX)return 0;\n__asm__ volatile(\"\" ::: \"memory\");",
], ids=["read-write", "write", "memory"])
def test_assembly_invalidates_previous_range_facts(prefix):
    source = "int Read(size_t wide){\n" + prefix + "\nint small=wide;\nreturn small;\n}"
    assert check(source).narrowing_found


@pytest.mark.parametrize("qualifier", ["volatile", "const volatile", "_Atomic"])
def test_repeated_reads_of_qualified_storage_do_not_earn_guard_credit(qualifier):
    source = f"int Read({qualifier} size_t wide){{\nif(wide>INT_MAX)return 0;\nint small=wide;\nreturn small;\n}}"
    assert check(source).narrowing_found


def test_a_fresh_guard_after_assembly_can_protect_an_ordinary_value():
    source = "int Read(size_t wide){\n__asm__(\"\" : \"+r\"(wide));\nif(wide>INT_MAX)return 0;\nint small=wide;\nreturn small;\n}"
    assert not check(source).narrowing_found


def test_out_of_scope_limit_spelling_does_not_hide_a_standard_limit():
    source = "int Read(size_t wide){\n{size_t INT_MAX=0;}\nif(wide>INT_MAX)return 0;\nint small=wide;\nreturn small;\n}"
    assert not check(source).narrowing_found


def test_a_const_source_still_accepts_a_supported_guard():
    source = "int Read(const size_t wide){\nif(wide>INT_MAX)return 0;\nint small=wide;\nreturn small;\n}"
    assert not check(source).narrowing_found


@pytest.mark.parametrize("write", [
    "++_Generic(wide, default: wide);",
    "--_Generic(wide, default: wide);",
], ids=["increment", "decrement"])
def test_an_indirect_lvalue_update_invalidates_a_previous_guard(write):
    source = "int Read(size_t wide){\nif(wide>INT_MAX)return 0;\n" + write + "\nint small=wide;\nreturn small;\n}"
    assert check(source).narrowing_found


def test_a_direct_write_to_an_unrelated_scalar_keeps_the_checked_range():
    source = "int Read(size_t wide){\nsize_t other=0;\nif(wide>INT_MAX)return 0;\n++other;\nint small=wide;\nreturn small;\n}"
    assert not check(source).narrowing_found


def test_a_declared_lower_bound_does_not_borrow_the_standard_signed_minimum():
    source = "int Read(int64_t wide, int64_t INT_MIN){\nif(wide<INT_MIN || wide>INT_MAX)return 0;\nint small=wide;\nreturn small;\n}"
    assert check(source).narrowing_found


def test_a_declared_limit_does_not_hide_narrowing_to_an_unsigned_destination():
    source = "int Read(uint32_t wide, uint32_t UINT8_MAX){\nif(wide>UINT8_MAX)return 0;\nuint8_t small=wide;\nreturn small;\n}"
    assert check(source).narrowing_found


@pytest.mark.parametrize("bound", [
    "-0x80000000", "-020000000000", "-0b10000000000000000000000000000000",
    "-0x80000000U", "-0x80000000UL", "-0x80000000ULL",
])
def test_unsigned_negation_does_not_hide_an_out_of_range_value(bound):
    source = f"int Read(int64_t wide){{\nif(wide<INT_MIN || wide>{bound})return 0;\nint small=wide;\nreturn small;\n}}"
    assert check(source).narrowing_found


@pytest.mark.parametrize("bound", [
    "-2147483648", "-0x80000000L", "-0x80000000LL", "-020000000000L",
    "-0x7fffffff", "-017777777777",
])
def test_signed_negative_literals_retain_guard_credit(bound):
    source = f"int Read(int64_t wide){{\nif(wide<INT_MIN || wide>{bound})return 0;\nint small=wide;\nreturn small;\n}}"
    assert not check(source).narrowing_found


@pytest.mark.parametrize("bound", ["UINT_MIN", "UCHAR_MIN", "UINT8_MIN", "ULONG_MIN"])
def test_nonstandard_unsigned_minimum_names_do_not_supply_zero(bound):
    source = f"int Read(uint64_t wide){{\nif(wide>{bound})return 0;\nuint8_t small=wide;\nreturn small;\n}}"
    assert check(source).narrowing_found
