"""Tests for axis-3 size-source classification (Tier 2.3)."""

from __future__ import annotations

import shutil

import pytest

from packages.source_intel.analyze import (
    _classify_arg_shape,
    _classify_size_source,
    analyze,
)


def test_classify_arg_shape_literal():
    assert _classify_arg_shape("8") == "literal"
    assert _classify_arg_shape("-1") == "literal"
    assert _classify_arg_shape("0xdead") == "literal"
    assert _classify_arg_shape("128u") == "literal"


def test_classify_arg_shape_sizeof():
    assert _classify_arg_shape("sizeof(struct foo)") == "sizeof"
    assert _classify_arg_shape("sizeof(*p)") == "sizeof"


def test_classify_arg_shape_variable():
    assert _classify_arg_shape("unknown_var") == "variable"
    assert _classify_arg_shape("my_size") == "variable"


def test_classify_arg_shape_user_controlled():
    assert _classify_arg_shape("n") == "user_controlled"
    assert _classify_arg_shape("len") == "user_controlled"
    assert _classify_arg_shape("count") == "user_controlled"
    assert _classify_arg_shape("cnt") == "user_controlled"


def test_classify_arg_shape_multiplied():
    assert _classify_arg_shape("n * sizeof(*p)") == "user_controlled"
    assert _classify_arg_shape("sizeof(*p) * n") == "user_controlled"
    assert _classify_arg_shape("count * sizeof(int)") == "user_controlled"


def test_classify_arg_shape_multiplied_no_user_name():
    """Multiplication with non-user-name vars → plain multiplied."""
    assert _classify_arg_shape("custom_var * sizeof(int)") == "multiplied"
    assert _classify_arg_shape("max_pkts * sizeof(*pkt)") == "multiplied"


def test_classify_arg_shape_handles_empty_and_garbage():
    assert _classify_arg_shape("") is None
    assert _classify_arg_shape("   ") is None
    assert _classify_arg_shape("???") is None


def test_classify_size_source_handles_missing_file():
    assert _classify_size_source("/no.c", 5, "kmalloc") is None


def test_classify_size_source_handles_missing_call(tmp_path):
    f = tmp_path / "x.c"
    f.write_text("void op(void) { return; }\n")
    # No kmalloc on line 1
    assert _classify_size_source(str(f), 1, "kmalloc") is None


def test_classify_size_source_recognizes_literal(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "extern void *kmalloc(unsigned long, int);\n"
        "void op(void) {\n"
        "    void *p = kmalloc(16, 0);\n"
        "}\n"
    )
    assert _classify_size_source(str(f), 3, "kmalloc") == "literal"


def test_classify_size_source_recognizes_sizeof(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "extern void *kmalloc(unsigned long, int);\n"
        "void op(void) {\n"
        "    void *p = kmalloc(sizeof(struct foo), 0);\n"
        "}\n"
    )
    assert _classify_size_source(str(f), 3, "kmalloc") == "sizeof"


def test_classify_size_source_recognizes_user_controlled_multiplied(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "extern void *kmalloc(unsigned long, int);\n"
        "void op(int n) {\n"
        "    void *p = kmalloc(n * sizeof(int), 0);\n"
        "}\n"
    )
    assert _classify_size_source(str(f), 3, "kmalloc") == "user_controlled"


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_allocation_evidence_carries_size_source(tmp_path):
    """End-to-end: analyze() populates size_source on
    AllocationEvidence records."""
    src = tmp_path / "x.c"
    src.write_text(
        "extern void *kmalloc(unsigned long, int);\n"
        "extern void use(void *);\n"
        "void op(int n) {\n"
        "    void *p;\n"
        "    p = kmalloc(n * sizeof(int), 0);\n"
        "    use(p);\n"
        "}\n"
    )
    r = analyze(tmp_path)
    user_controlled = [
        a for a in r.allocations if a.size_source == "user_controlled"
    ]
    assert user_controlled, (
        f"expected user_controlled size_source; got "
        f"{[(a.allocator, a.size_source) for a in r.allocations]!r}"
    )
