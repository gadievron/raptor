"""Tests for axis-3 paired-free detection (Tier 2.4-slim).

Informational only — no verdict change. Verifies cocci emits the
right evidence shape and the parser/result wiring is correct.
"""

from __future__ import annotations

import shutil

import pytest

from packages.source_intel.analyze import (
    SourceIntelResult,
    analyze,
)


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_paired_free_fires_on_kmalloc_kfree(tmp_path):
    src = tmp_path / "p.c"
    src.write_text(
        "extern void *kmalloc(unsigned long, int);\n"
        "extern void kfree(void *);\n"
        "void op(void) {\n"
        "    void *p;\n"
        "    p = kmalloc(16, 0);\n"
        "    if (!p) return;\n"
        "    kfree(p);\n"
        "}\n"
    )
    r = analyze(tmp_path)
    pairs = [(p.allocator, p.free_fn) for p in r.paired_frees]
    assert ("kmalloc", "kfree") in pairs


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_paired_free_fires_on_vmalloc_vfree(tmp_path):
    src = tmp_path / "p.c"
    src.write_text(
        "extern void *vmalloc(unsigned long);\n"
        "extern void vfree(void *);\n"
        "void op(void) {\n"
        "    void *p;\n"
        "    p = vmalloc(4096);\n"
        "    if (!p) return;\n"
        "    vfree(p);\n"
        "}\n"
    )
    r = analyze(tmp_path)
    pairs = [(p.allocator, p.free_fn) for p in r.paired_frees]
    assert ("vmalloc", "vfree") in pairs


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_paired_free_skipped_on_unpaired_alloc(tmp_path):
    """Alloc without subsequent free → no paired_free evidence."""
    src = tmp_path / "p.c"
    src.write_text(
        "extern void *kmalloc(unsigned long, int);\n"
        "void op(void) {\n"
        "    void *p;\n"
        "    p = kmalloc(16, 0);\n"
        "    if (!p) return;\n"
        "    /* leak */\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert not r.paired_frees, f"got {r.paired_frees!r}"


def test_paired_free_empty_when_no_alloc():
    r = SourceIntelResult()
    assert r.paired_frees == ()
