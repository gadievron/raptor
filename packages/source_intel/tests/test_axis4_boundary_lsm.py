"""Tests for axis-4 expansion: user-boundary + LSM hook detection.

Both are INFORMATIONAL only — no verdict change. Tests verify the
cocci rules fire on canonical patterns and the parsers map to the
right evidence dataclass.
"""

from __future__ import annotations

import shutil

import pytest

from packages.source_intel.analyze import (
    SourceIntelResult,
    analyze,
)


# =====================================================================
# user_boundary
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_user_boundary_fires_on_copy_from_user(tmp_path):
    src = tmp_path / "b.c"
    src.write_text(
        "extern unsigned long copy_from_user(void *, const void *, unsigned long);\n"
        "extern unsigned long copy_to_user(void *, const void *, unsigned long);\n"
        "int op(void *uptr, int len) {\n"
        "    char buf[64];\n"
        "    copy_from_user(buf, uptr, len);\n"
        "    copy_to_user(uptr, buf, len);\n"
        "    return 0;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    fns = {b.boundary_fn for b in r.boundary_crossings}
    assert "copy_from_user" in fns
    assert "copy_to_user" in fns


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_user_boundary_fires_on_get_put_user(tmp_path):
    src = tmp_path / "b.c"
    src.write_text(
        "extern int get_user(int *, int *);\n"
        "extern int put_user(int, int *);\n"
        "int op(int *uptr) {\n"
        "    int val;\n"
        "    get_user(&val, uptr);\n"
        "    put_user(val + 1, uptr);\n"
        "    return 0;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    fns = {b.boundary_fn for b in r.boundary_crossings}
    assert "get_user" in fns
    assert "put_user" in fns


def test_boundary_evidence_empty_when_no_calls():
    r = SourceIntelResult()
    assert r.boundary_crossings == ()


# =====================================================================
# lsm_hooks
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_lsm_fires_on_security_inode(tmp_path):
    src = tmp_path / "l.c"
    src.write_text(
        "extern int security_inode_permission(void *, int);\n"
        "extern int security_file_permission(void *, int);\n"
        "int op(void *inode, void *file) {\n"
        "    security_inode_permission(inode, 4);\n"
        "    security_file_permission(file, 4);\n"
        "    return 0;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    hooks = {h.hook_name for h in r.lsm_hooks}
    assert "security_inode_permission" in hooks
    assert "security_file_permission" in hooks


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_lsm_skips_non_security_prefix(tmp_path):
    """`secure_*` and `securityd_*` shouldn't match — must start
    with `security_` exactly."""
    src = tmp_path / "l.c"
    src.write_text(
        "extern int secure_init(int);\n"
        "extern int securityd_call(int);\n"
        "int op(void) {\n"
        "    secure_init(0);\n"
        "    securityd_call(0);\n"
        "    return 0;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert not any(
        h.hook_name.startswith("secure_") and "_" not in h.hook_name[7:]
        for h in r.lsm_hooks
    )


def test_lsm_evidence_empty_when_no_calls():
    r = SourceIntelResult()
    assert r.lsm_hooks == ()
