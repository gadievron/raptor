"""Tests for the binary_oracle auto-detect heuristic (Phase 4)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from core.inventory.binary_oracle_autodetect import (
    detect_binaries,
    _classify_candidate,
    _has_dwarf,
)


@pytest.fixture
def build_tree(tmp_path: Path) -> Path:
    """A target tree shaped like a real autotools / CMake build.
    Synthesises ELF binaries with DWARF via a tiny compile."""
    import subprocess as _sp

    # Source file shared by all binaries.
    src = tmp_path / "x.c"
    src.write_text("int f(int x){return x+1;}\nint main(void){return f(0);}\n")

    # Top-level executable (autotools-style: binary in source root)
    _sp.run(["gcc", "-g", str(src), "-o", str(tmp_path / "example")],
            check=True)
    # Top-level library
    lib_src = tmp_path / "lib.c"
    lib_src.write_text("int lib_fn(int x){return x*2;}\n")
    _sp.run(["gcc", "-g", "-shared", "-fPIC", str(lib_src),
             "-o", str(tmp_path / "libfoo.so")], check=True)
    # build/ subdir with another executable
    (tmp_path / "build").mkdir()
    _sp.run(["gcc", "-g", str(src),
             "-o", str(tmp_path / "build" / "build_exe")], check=True)
    # Stripped binary — should be filtered out
    _sp.run(["gcc", str(src), "-s",
             "-o", str(tmp_path / "stripped_no_dwarf")], check=True)
    # A shell script — should be filtered out even though executable
    (tmp_path / "script.sh").write_text("#!/bin/sh\necho hi\n")
    os.chmod(tmp_path / "script.sh", 0o755)

    return tmp_path


def test_detect_hybrid_returns_both_libs_and_exes(build_tree: Path) -> None:
    paths = detect_binaries(build_tree, "hybrid")
    names = sorted(p.name for p in paths)
    assert "libfoo.so" in names
    assert "example" in names
    assert "build_exe" in names
    # Stripped binary excluded (no .debug_info)
    assert "stripped_no_dwarf" not in names
    # Shell script excluded
    assert "script.sh" not in names


def test_detect_library_filters_to_libs_only(build_tree: Path) -> None:
    paths = detect_binaries(build_tree, "library")
    names = sorted(p.name for p in paths)
    assert names == ["libfoo.so"]


def test_detect_application_filters_to_exes_only(build_tree: Path) -> None:
    paths = detect_binaries(build_tree, "application")
    names = sorted(p.name for p in paths)
    assert "libfoo.so" not in names
    assert "example" in names
    assert "build_exe" in names


def test_detect_returns_libraries_first(build_tree: Path) -> None:
    """Libraries before executables — they're typically the deployed
    surface, so they sort first in the displayed list."""
    paths = detect_binaries(build_tree, "hybrid")
    # First entry should be a library
    assert paths[0].name.startswith("lib")


def test_detect_caps_results(build_tree: Path) -> None:
    """Capped at max_results so an operator pointing at a large
    test-binary tree doesn't trigger a 30-second classification."""
    paths = detect_binaries(build_tree, "hybrid", max_results=2)
    assert len(paths) <= 2


def test_detect_missing_root_returns_empty(tmp_path: Path) -> None:
    """Defensive: nonexistent target → empty list, no crash."""
    assert detect_binaries(tmp_path / "does-not-exist", "auto") == []


def test_detect_skips_dotted_dirs(build_tree: Path) -> None:
    """``.git``, ``.cache``, etc. — skip walking them."""
    import subprocess as _sp
    src = build_tree / "x.c"
    git_dir = build_tree / "build" / ".git"
    git_dir.mkdir(parents=True, exist_ok=True)
    _sp.run(["gcc", "-g", str(src),
             "-o", str(git_dir / "should_be_skipped")], check=True)
    paths = detect_binaries(build_tree, "hybrid")
    names = [p.name for p in paths]
    assert "should_be_skipped" not in names


def test_classify_candidate_picks_library_extension() -> None:
    assert _classify_candidate(Path("libfoo.so")).kind == "library"
    assert _classify_candidate(Path("libfoo.a")).kind == "library"
    assert _classify_candidate(Path("libfoo.so.1.3.1")).kind == "library"
    # Non-lib dotfile patterns aren't libraries.
    assert _classify_candidate(Path("notlib.txt")) is None


def test_classify_candidate_rejects_split_debug_and_templates(
    tmp_path: Path,
) -> None:
    """Adversarial review P0-D-3: the library-name regex must reject
    split-debug companion files (``.so.debug``, ``.dwo``, ``.dwp``),
    autoconf templates (``.so.in``), build artefacts (``.so.tmpl``)
    and backups. The prior contains-check (``".so" in name``) matched
    all of these, feeding companion files into the classifier as
    though they were the shipped artefact."""
    # Create real files so the executable-bit fallback path doesn't
    # accidentally classify them as executables.
    for name in (
        "libfoo.so.debug",
        "libfoo.so.in",
        "libfoo.so.tmpl",
        "libfoo.so.bak",
        "libfoo.dwo",
        "libfoo.dwp",
        "libsomething.tar.gz",
    ):
        (tmp_path / name).write_text("not a binary")
        # No executable bit → also fails the executable path.
        result = _classify_candidate(tmp_path / name)
        assert result is None, (
            f"{name} should NOT be classified as a library "
            f"(got kind={result.kind if result else None})")


def test_has_dwarf_distinguishes_stripped(tmp_path: Path) -> None:
    import subprocess as _sp
    src = tmp_path / "x.c"
    src.write_text("int main(void){return 0;}\n")
    debug = tmp_path / "with_dwarf"
    stripped = tmp_path / "stripped"
    _sp.run(["gcc", "-g", str(src), "-o", str(debug)], check=True)
    _sp.run(["gcc", str(src), "-s", "-o", str(stripped)], check=True)
    assert _has_dwarf(debug) is True
    assert _has_dwarf(stripped) is False
