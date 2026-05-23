"""Tests for ``packages.source_intel.aliases``."""

from __future__ import annotations


from packages.source_intel.aliases import (
    ALL_WUR_ALIASES,
    WUR_ALIASES_BY_ORIGIN,
    wur_alias_in,
    wur_alias_origin,
)


def test_all_aliases_present():
    """Confirm the v1 curated set covers the expected origins."""
    flat = set(ALL_WUR_ALIASES)
    # Sanity: every spelling appears in exactly one origin group.
    seen = set()
    for spellings in WUR_ALIASES_BY_ORIGIN.values():
        for s in spellings:
            assert s not in seen, f"duplicate alias spelling: {s}"
            seen.add(s)
    assert seen == flat


def test_kernel_must_check_recognised():
    assert wur_alias_in("static __must_check int foo(void);")


def test_glibc_wur_recognised():
    assert wur_alias_in("extern char *strdup(const char *) __wur;")


def test_cpp_nodiscard_recognised():
    assert wur_alias_in("[[nodiscard]] int validate(void);")


def test_gcc_clang_cpp_attribute_recognised():
    assert wur_alias_in("[[gnu::warn_unused_result]] int x(void);")
    assert wur_alias_in("[[clang::warn_unused_result]] int x(void);")


def test_literal_gcc_form_recognised():
    """The literal GCC form must match even though the cocci rule
    also handles it — alias-scan is the backup path."""
    assert wur_alias_in(
        "int foo(void) __attribute__((warn_unused_result));"
    )


def test_random_unrelated_text_not_matched():
    """No false positives on unrelated text."""
    assert not wur_alias_in("int foo(void); // no annotations here")
    assert not wur_alias_in("__must_have_received  // different macro")


def test_wur_alias_origin_classifies():
    assert wur_alias_origin("__must_check") == "kernel"
    assert wur_alias_origin("__wur") == "glibc"
    assert wur_alias_origin("[[nodiscard]]") == "cpp_attribute"
    assert wur_alias_origin("__result_use_check") == "bsd"
    assert wur_alias_origin(
        "__attribute__((warn_unused_result))"
    ) == "literal_gcc"


def test_wur_alias_origin_unknown_for_outside_set():
    assert wur_alias_origin("FOO_NOTREAL") == "unknown"
