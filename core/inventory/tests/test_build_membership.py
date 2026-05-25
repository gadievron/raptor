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
