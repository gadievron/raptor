"""Tests for ``packages.source_intel.discovery``."""

from __future__ import annotations


from packages.source_intel.discovery import (
    PER_FAMILY_ALIAS_CAP,
    DiscoveryResult,
    discover_aliases,
)


# =====================================================================
# Skip / empty paths
# =====================================================================


def test_missing_target_returns_empty(tmp_path):
    nonexistent = tmp_path / "no-such-dir"
    result = discover_aliases(nonexistent)
    assert isinstance(result, DiscoveryResult)
    assert all(names == () for names in result.aliases_by_family.values())
    assert result.headers_scanned == 0


def test_no_headers_returns_empty(tmp_path):
    """Target with only C source files (no .h) → no aliases discovered."""
    (tmp_path / "main.c").write_text("int main(void) { return 0; }\n")
    result = discover_aliases(tmp_path)
    assert result.headers_scanned == 0
    assert all(names == () for names in result.aliases_by_family.values())


# =====================================================================
# Single-family discovery
# =====================================================================


def test_discovers_simple_wur_alias(tmp_path):
    """Classic kernel-style: __must_check expands to warn_unused_result."""
    (tmp_path / "compiler.h").write_text(
        "#define __must_check __attribute__((__warn_unused_result__))\n"
    )
    (tmp_path / "alloc.c").write_text(
        "__must_check int alloc(int sz);\n"
        "__must_check int validate(int *p);\n"
    )
    result = discover_aliases(tmp_path)
    assert "__must_check" in result.aliases_by_family["wur"]


def test_discovers_simple_nonnull_alias(tmp_path):
    """glibc-style: __nonnull expands to nonnull."""
    (tmp_path / "macros.h").write_text(
        "#define __nonnull(p) __attribute__((nonnull p))\n"
    )
    (tmp_path / "use.c").write_text(
        "extern int strlen(const char *s) __nonnull((1));\n"
    )
    result = discover_aliases(tmp_path)
    assert "__nonnull" in result.aliases_by_family["nonnull"]


def test_discovers_alloc_size_alias(tmp_path):
    (tmp_path / "alloc_macros.h").write_text(
        "#define __wur_alloc(n) __attribute__((alloc_size(n)))\n"
    )
    (tmp_path / "alloc.c").write_text(
        "__wur_alloc(1) void *mem(int sz);\n"
    )
    result = discover_aliases(tmp_path)
    assert "__wur_alloc" in result.aliases_by_family["alloc_size"]


def test_discovers_returns_nonnull_alias(tmp_path):
    (tmp_path / "h.h").write_text(
        "#define __must_succeed __attribute__((returns_nonnull))\n"
    )
    (tmp_path / "u.c").write_text(
        "__must_succeed void *get_or_die(void);\n"
    )
    result = discover_aliases(tmp_path)
    assert "__must_succeed" in result.aliases_by_family["returns_nonnull"]


# =====================================================================
# Recursive macro resolution
# =====================================================================


def test_resolves_two_hop_macro_chain(tmp_path):
    """A macro expanding to another macro that resolves to the
    attribute — discovery follows the chain (depth ≤ 3)."""
    (tmp_path / "a.h").write_text(
        "#define __WUR_INNER __attribute__((warn_unused_result))\n"
        "#define MUST_CHECK __WUR_INNER\n"
    )
    (tmp_path / "u.c").write_text("MUST_CHECK int foo(void);\n")
    result = discover_aliases(tmp_path)
    assert "MUST_CHECK" in result.aliases_by_family["wur"]


def test_cycle_safe_macro_chain(tmp_path):
    """Self-referential / circular macro definitions must NOT loop.
    Resolution bottoms out via the visited-set + depth cap."""
    (tmp_path / "cycle.h").write_text(
        "#define A B\n"
        "#define B A\n"  # cycle: A → B → A
        "#define WORKING __attribute__((warn_unused_result))\n"
    )
    (tmp_path / "u.c").write_text(
        "WORKING int legit(void);\n"
    )
    # Should not hang; should still pick up WORKING.
    result = discover_aliases(tmp_path)
    assert "WORKING" in result.aliases_by_family["wur"]


def test_depth_cap_stops_resolution(tmp_path):
    """Macros that resolve beyond the depth cap don't appear — by
    design, prevents pathological pre-pass cost."""
    # 5-deep chain, cap is 3.
    (tmp_path / "deep.h").write_text(
        "#define L0 __attribute__((warn_unused_result))\n"
        "#define L1 L0\n"
        "#define L2 L1\n"
        "#define L3 L2\n"
        "#define L4 L3\n"
        "#define L5 L4\n"
    )
    (tmp_path / "u.c").write_text("L5 int deep(void);\n")
    result = discover_aliases(tmp_path)
    # L0-L2 resolved (depth ≤ 3); L3-L5 not resolved.
    # L5 used in source but its expansion at depth 3 is "L2" (not
    # containing "warn_unused_result"), so it doesn't classify.
    assert "L5" not in result.aliases_by_family["wur"]


# =====================================================================
# Usage frequency + cap
# =====================================================================


def test_frequency_ordering(tmp_path):
    """Aliases sorted descending by usage count in source files."""
    (tmp_path / "h.h").write_text(
        "#define MUST_A __attribute__((warn_unused_result))\n"
        "#define MUST_B __attribute__((warn_unused_result))\n"
        "#define MUST_C __attribute__((warn_unused_result))\n"
    )
    (tmp_path / "u.c").write_text(
        "MUST_B int b1(void);\n"
        "MUST_B int b2(void);\n"
        "MUST_B int b3(void);\n"
        "MUST_C int c1(void);\n"
        "MUST_A int a1(void);\n"
    )
    result = discover_aliases(tmp_path)
    aliases = result.aliases_by_family["wur"]
    # B (3 uses) > C (1 use) > A (1 use, alphabetical tiebreak).
    assert aliases[0] == "MUST_B"
    # A and C both have count 1 — alphabetical tiebreak.
    assert aliases[1:3] == ("MUST_A", "MUST_C")


def test_zero_usage_filtered_out(tmp_path):
    """Macros defined but never used in source files are dropped."""
    (tmp_path / "h.h").write_text(
        "#define ORPHAN __attribute__((warn_unused_result))\n"
        "#define USED __attribute__((warn_unused_result))\n"
    )
    (tmp_path / "u.c").write_text("USED int used(void);\n")
    result = discover_aliases(tmp_path)
    assert "USED" in result.aliases_by_family["wur"]
    assert "ORPHAN" not in result.aliases_by_family["wur"]


def test_per_family_cap_enforced(tmp_path):
    """When more than 30 aliases are discovered in a family, only the
    top 30 by usage frequency are retained."""
    define_lines = "\n".join(
        f"#define ALIAS_{i:03d} __attribute__((warn_unused_result))"
        for i in range(40)
    )
    (tmp_path / "h.h").write_text(define_lines + "\n")
    # All 40 used in source — same frequency (1 each).
    use_lines = "\n".join(
        f"ALIAS_{i:03d} int f{i}(void);"
        for i in range(40)
    )
    (tmp_path / "u.c").write_text(use_lines + "\n")
    result = discover_aliases(tmp_path)
    assert len(result.aliases_by_family["wur"]) == PER_FAMILY_ALIAS_CAP


# =====================================================================
# Line continuations + macro args
# =====================================================================


def test_handles_line_continuations(tmp_path):
    """Macros split over multiple lines via backslash continuation."""
    (tmp_path / "h.h").write_text(
        "#define WIDE \\\n"
        "    __attribute__((warn_unused_result))\n"
    )
    (tmp_path / "u.c").write_text("WIDE int foo(void);\n")
    result = discover_aliases(tmp_path)
    assert "WIDE" in result.aliases_by_family["wur"]


def test_parameterised_macros_classified(tmp_path):
    """Macros with parameters (like __nonnull(p)) still match the
    define regex and get classified by their expansion."""
    (tmp_path / "h.h").write_text(
        "#define MARK_AS(n) __attribute__((nonnull(n)))\n"
    )
    (tmp_path / "u.c").write_text(
        "MARK_AS(1) int validate(void *p);\n"
    )
    result = discover_aliases(tmp_path)
    assert "MARK_AS" in result.aliases_by_family["nonnull"]


# =====================================================================
# Word-boundary usage counting (substring false positives)
# =====================================================================


def test_word_boundary_prevents_substring_false_positives(tmp_path):
    """``CHECK`` defined; ``CHECK_RETURN`` used — discovery must NOT
    count ``CHECK_RETURN`` toward ``CHECK``'s usage."""
    (tmp_path / "h.h").write_text(
        "#define CHECK __attribute__((warn_unused_result))\n"
    )
    (tmp_path / "u.c").write_text(
        "void *CHECK_RETURN(void);\n"  # unrelated identifier
    )
    result = discover_aliases(tmp_path)
    # CHECK has 0 word-boundary usage → filtered out.
    assert "CHECK" not in result.aliases_by_family["wur"]


# =====================================================================
# Headers-scanned + sources-scanned counters
# =====================================================================


def test_counters_reflect_scan_extent(tmp_path):
    (tmp_path / "a.h").write_text("#define X __attribute__((nonnull))\n")
    (tmp_path / "b.h").write_text("#define Y __attribute__((nonnull))\n")
    (tmp_path / "u.c").write_text("X int foo(void);\nY int bar(void);\n")
    result = discover_aliases(tmp_path)
    assert result.headers_scanned == 2
    assert result.sources_scanned >= 3  # a.h, b.h, u.c (headers also count as sources for usage)
