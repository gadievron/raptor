"""Tests for axis-2 sub-class evidence (warn-class + null-guards).

Both are INFORMATIONAL only — no verdict change. Tests verify the
cocci rules fire on canonical patterns, the parsers map evidence
correctly, and SourceIntelResult exposes the new fields.
"""

from __future__ import annotations

import shutil

import pytest

from packages.source_intel.analyze import (
    SourceIntelResult,
    analyze,
)


# =====================================================================
# warn_class
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_warn_class_fires(tmp_path):
    src = tmp_path / "w.c"
    src.write_text(
        "extern void WARN_ON(int);\n"
        "extern int pr_warn(const char *, ...);\n"
        "void op(int x) {\n"
        "    WARN_ON(x < 0);\n"
        "    pr_warn(\"value %d\\n\", x);\n"
        "}\n"
    )
    r = analyze(tmp_path)
    fns = {w.warn_fn for w in r.warns}
    assert "WARN_ON" in fns
    assert "pr_warn" in fns


def test_warn_evidence_empty_when_no_warns():
    r = SourceIntelResult()
    assert r.warns == ()


# =====================================================================
# null_guards
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_null_guards_fires_on_bang(tmp_path):
    src = tmp_path / "ng.c"
    src.write_text(
        "extern void use(void *);\n"
        "int op(void *p) {\n"
        "    if (!p) { return -1; }\n"
        "    use(p);\n"
        "    return 0;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    kinds = {g.kind for g in r.null_guards}
    assert "bang" in kinds, f"got {kinds!r}"


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_null_guards_fires_on_is_err(tmp_path):
    src = tmp_path / "ng.c"
    src.write_text(
        "extern int IS_ERR(void *);\n"
        "extern int IS_ERR_OR_NULL(void *);\n"
        "extern void use(void *);\n"
        "int op(void *p, void *q) {\n"
        "    if (IS_ERR(p)) { return -1; }\n"
        "    if (IS_ERR_OR_NULL(q)) { return -1; }\n"
        "    use(p); use(q);\n"
        "    return 0;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert any(g.kind == "is_err" for g in r.null_guards)


def test_null_guard_evidence_empty_when_no_guards():
    r = SourceIntelResult()
    assert r.null_guards == ()
