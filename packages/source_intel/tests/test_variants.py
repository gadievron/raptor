"""Tests for axis-5 variant analysis (checked vs unchecked
allocator-call ratio).

Phase 9 ships axis 5 as informational evidence — the data is
exposed via ``SourceIntelResult.variant_ratio()`` and ``checked_allocations``
but doesn't currently change the verdict. Stage D LLM consumes
the ratio as soft context.
"""

from __future__ import annotations

import shutil

import pytest

from packages.source_intel.analyze import (
    CheckedAllocationEvidence,
    SourceIntelResult,
    analyze,
)


# =====================================================================
# Real-spatch E2E — checked_alloc.cocci fires on `if (!p)` shape
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_checked_alloc_fires_on_bang_check(tmp_path):
    src = tmp_path / "checked.c"
    src.write_text(
        "extern char *kstrdup(const char *s, int gfp);\n"
        "\n"
        "int checked(const char *s) {\n"
        "    char *p;\n"
        "    p = kstrdup(s, 0);\n"
        "    if (!p) return -1;\n"
        "    return 0;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert r.checked_allocations, (
        f"expected at least one CheckedAllocationEvidence; got "
        f"{r.checked_allocations!r}"
    )
    assert r.checked_allocations[0].allocator == "kstrdup"


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_checked_alloc_fires_on_eq_null(tmp_path):
    src = tmp_path / "checked.c"
    src.write_text(
        "extern char *kstrdup(const char *s, int gfp);\n"
        "\n"
        "int checked(const char *s) {\n"
        "    char *p;\n"
        "    p = kstrdup(s, 0);\n"
        "    if (p == NULL) return -1;\n"
        "    return 0;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert r.checked_allocations
    assert r.checked_allocations[0].allocator == "kstrdup"


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_unchecked_does_not_emit_checked_alloc(tmp_path):
    src = tmp_path / "unchecked.c"
    src.write_text(
        "extern char *kstrdup(const char *s, int gfp);\n"
        "\n"
        "int unchecked(const char *s) {\n"
        "    char *p;\n"
        "    p = kstrdup(s, 0);\n"
        "    return p[0];\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert not r.checked_allocations, (
        f"expected no CheckedAllocationEvidence on unchecked-only file; "
        f"got {r.checked_allocations!r}"
    )


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_mixed_yields_correct_variant_ratio(tmp_path):
    """Two checked sites, one unchecked → ratio (2, 1)."""
    src = tmp_path / "mixed.c"
    src.write_text(
        "extern char *kstrdup(const char *s, int gfp);\n"
        "\n"
        "int a(const char *s) {\n"
        "    char *p;\n"
        "    p = kstrdup(s, 0);\n"
        "    if (!p) return -1;\n"
        "    return 0;\n"
        "}\n"
        "\n"
        "int b(const char *s) {\n"
        "    char *p;\n"
        "    p = kstrdup(s, 0);\n"
        "    if (p == NULL) return -1;\n"
        "    return 0;\n"
        "}\n"
        "\n"
        "int c(const char *s) {\n"
        "    char *p;\n"
        "    p = kstrdup(s, 0);\n"
        "    return p[0];\n"
        "}\n"
    )
    r = analyze(tmp_path)
    checked, unchecked = r.variant_ratio("kstrdup")
    assert checked == 2, f"expected checked=2, got {checked}"
    assert unchecked == 1, f"expected unchecked=1, got {unchecked}"


# =====================================================================
# variant_ratio accessor — pure-data tests (no spatch)
# =====================================================================


def test_variant_ratio_empty_returns_zeros():
    r = SourceIntelResult()
    assert r.variant_ratio("kstrdup") == (0, 0)


def test_variant_ratio_per_allocator_isolated():
    """Counts MUST be per-allocator — kstrdup checked sites don't
    contribute to kmalloc's denominator."""
    r = SourceIntelResult(
        checked_allocations=(
            CheckedAllocationEvidence(
                allocator="kstrdup", location=("/x.c", 5),
            ),
            CheckedAllocationEvidence(
                allocator="kmalloc", location=("/x.c", 10),
            ),
        ),
    )
    assert r.variant_ratio("kstrdup") == (1, 0)
    assert r.variant_ratio("kmalloc") == (1, 0)
    assert r.variant_ratio("vmalloc") == (0, 0)
