"""Tests for build-exclusion detection (Gap 1: build_excluded witness)."""

from __future__ import annotations

from core.inventory.build_membership import BuildExcluded, detect_build_excluded


def test_go_modern_build_ignore():
    src = "//go:build ignore\n\npackage main\nfunc main(){}\n"
    r = detect_build_excluded("go", src)
    assert isinstance(r, BuildExcluded)
    assert r.summary == "//go:build ignore"
    assert r.line == 1


def test_go_legacy_build_ignore():
    src = "// +build ignore\n\npackage main\nfunc main(){}\n"
    r = detect_build_excluded("go", src)
    assert r is not None and r.summary == "// +build ignore"


def test_go_normal_file_not_excluded():
    assert detect_build_excluded("go", "package main\nfunc main(){}\n") is None


def test_go_satisfiable_constraint_not_excluded():
    # `ignore || linux` builds on linux → satisfiable → not excluded.
    assert detect_build_excluded(
        "go", "//go:build ignore || linux\npackage main\n") is None


def test_go_legacy_multi_term_not_excluded():
    # `// +build ignore foo` == (ignore OR foo) → satisfiable.
    assert detect_build_excluded(
        "go", "// +build ignore foo\n\npackage main\n") is None


def test_go_constraint_after_package_ignored():
    # Build constraints are only valid before the package clause.
    assert detect_build_excluded(
        "go", "package main\n//go:build ignore\nfunc main(){}\n") is None


def test_go_other_tag_not_excluded():
    # A real platform constraint is not a never-built marker.
    assert detect_build_excluded(
        "go", "//go:build linux\npackage main\n") is None


def test_non_go_languages_return_none():
    # Detector is Go-only for now; other langs degrade to None.
    for lang in ("c", "cpp", "rust", "python", "javascript"):
        assert detect_build_excluded(lang, "//go:build ignore\n") is None


def test_empty_content():
    assert detect_build_excluded("go", "") is None


# --- C/C++ translation-unit membership (compile_commands) ------------------

def test_tu_membership_none_when_no_manifest():
    from core.inventory.build_membership import tu_membership_excluded
    assert tu_membership_excluded("/p/x.c", None) is None


def test_tu_membership_source_absent_is_excluded():
    from core.inventory.build_membership import (
        tu_membership_excluded, BuildExcluded,
    )
    r = tu_membership_excluded("/p/unbuilt.c", frozenset({"/p/built.c"}))
    assert isinstance(r, BuildExcluded)
    assert r.summary == "not in compile_commands.json"


def test_tu_membership_source_present_not_excluded():
    from core.inventory.build_membership import tu_membership_excluded
    assert tu_membership_excluded(
        "/p/built.c", frozenset({"/p/built.c"})) is None


def test_tu_membership_headers_exempt():
    # Headers are never TUs — absent from compile_commands but reachable via
    # the .c files that #include them. Must never be excluded by membership.
    from core.inventory.build_membership import tu_membership_excluded
    for h in ("/p/u.h", "/p/u.hpp", "/p/u.hh", "/p/u.hxx"):
        assert tu_membership_excluded(h, frozenset({"/p/built.c"})) is None, h


def test_tu_membership_non_c_exempt():
    from core.inventory.build_membership import tu_membership_excluded
    for other in ("/p/a.py", "/p/a.go", "/p/a.rs", "/p/a.txt"):
        assert tu_membership_excluded(other, frozenset({"/p/b.c"})) is None


def test_tu_membership_cpp_source_extensions_covered():
    from core.inventory.build_membership import tu_membership_excluded
    for ext in (".cc", ".cpp", ".cxx", ".c++", ".m", ".mm"):
        assert tu_membership_excluded(
            f"/p/x{ext}", frozenset({"/p/y.c"})) is not None, ext


# --- Rust crate-module membership ------------------------------------------

def test_crate_module_none_when_unknown():
    from core.inventory.build_membership import crate_module_excluded
    assert crate_module_excluded("/p/x.rs", None) is None


def test_crate_module_orphan_excluded():
    from core.inventory.build_membership import (
        crate_module_excluded, BuildExcluded,
    )
    r = crate_module_excluded("/p/orphan.rs", frozenset({"/p/lib.rs"}))
    assert isinstance(r, BuildExcluded)
    assert "mod path" in r.summary


def test_crate_module_in_tree_not_excluded():
    from core.inventory.build_membership import crate_module_excluded
    assert crate_module_excluded(
        "/p/lib.rs", frozenset({"/p/lib.rs"})) is None


def test_crate_module_non_rs_exempt():
    from core.inventory.build_membership import crate_module_excluded
    for other in ("/p/a.c", "/p/a.go", "/p/a.py"):
        assert crate_module_excluded(other, frozenset({"/p/lib.rs"})) is None
