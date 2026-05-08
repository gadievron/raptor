"""Tests for the CMake FetchContent_Declare parser."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.cmake_fetchcontent import parse_cmake_lists


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "CMakeLists.txt"
    p.write_text(body)
    return p


# ---------------------------------------------------------------------------
# GIT_REPOSITORY shape
# ---------------------------------------------------------------------------


def test_github_git_repository_with_tag(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        cmake_minimum_required(VERSION 3.20)
        project(myapp)
        include(FetchContent)
        FetchContent_Declare(
          googletest
          GIT_REPOSITORY https://github.com/google/googletest.git
          GIT_TAG        release-1.12.1
        )
        FetchContent_MakeAvailable(googletest)
    """)
    deps = parse_cmake_lists(p)
    assert len(deps) == 1
    d = deps[0]
    assert d.ecosystem == "GitHub"
    assert d.name == "google/googletest"
    assert d.version == "release-1.12.1"
    assert d.purl == "pkg:github/google/googletest@release-1.12.1"
    assert d.pin_style == PinStyle.EXACT


def test_github_git_repository_without_tag_marks_wildcard(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        FetchContent_Declare(
          fmt
          GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        )
    """)
    deps = parse_cmake_lists(p)
    assert len(deps) == 1
    assert deps[0].pin_style == PinStyle.WILDCARD
    assert deps[0].version is None


def test_non_github_git_repository_falls_back_to_generic(tmp_path: Path) -> None:
    """A self-hosted git repo gets ``ecosystem=CMake-FetchContent``
    + a ``pkg:generic/`` purl (no OSV matching today)."""
    p = _write(tmp_path, """
        FetchContent_Declare(
          intern
          GIT_REPOSITORY https://gitlab.example.com/team/intern.git
          GIT_TAG        v1.0
        )
    """)
    deps = parse_cmake_lists(p)
    assert deps[0].ecosystem == "CMake-FetchContent"
    assert deps[0].name == "intern"
    assert deps[0].purl == "pkg:generic/intern@v1.0"


# ---------------------------------------------------------------------------
# URL shape
# ---------------------------------------------------------------------------


def test_url_archive_extracts_tag_from_path(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        FetchContent_Declare(
          json
          URL https://github.com/nlohmann/json/archive/v3.11.3.tar.gz
          URL_HASH SHA256=deadbeef
        )
    """)
    deps = parse_cmake_lists(p)
    assert len(deps) == 1
    d = deps[0]
    assert d.ecosystem == "GitHub"
    assert d.name == "nlohmann/json"
    assert d.version == "v3.11.3"
    assert d.purl == "pkg:github/nlohmann/json@v3.11.3"


def test_url_zip_archive(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        FetchContent_Declare(
          asio
          URL https://github.com/chriskohlhoff/asio/archive/asio-1-28-0.zip
        )
    """)
    deps = parse_cmake_lists(p)
    assert deps[0].version == "asio-1-28-0"


def test_url_unknown_shape_returns_no_version(tmp_path: Path) -> None:
    """A URL we can't parse a tag from: dep is captured but version
    falls back to None."""
    p = _write(tmp_path, """
        FetchContent_Declare(
          mylib
          URL https://example.com/mylib-bundle.tar.gz
        )
    """)
    deps = parse_cmake_lists(p)
    assert len(deps) == 1
    assert deps[0].version is None


# ---------------------------------------------------------------------------
# Multiple declarations
# ---------------------------------------------------------------------------


def test_multiple_declarations_all_extracted(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        FetchContent_Declare(
          a
          GIT_REPOSITORY https://github.com/x/a.git
          GIT_TAG v1
        )
        FetchContent_Declare(
          b
          GIT_REPOSITORY https://github.com/y/b.git
          GIT_TAG v2
        )
        FetchContent_Declare(
          c
          URL https://github.com/z/c/archive/v3.tar.gz
        )
    """)
    deps = parse_cmake_lists(p)
    by_purl = {d.purl: d for d in deps}
    assert "pkg:github/x/a@v1" in by_purl
    assert "pkg:github/y/b@v2" in by_purl
    assert "pkg:github/z/c@v3" in by_purl


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_no_fetchcontent_declarations_returns_empty(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        cmake_minimum_required(VERSION 3.20)
        project(myapp)
        add_executable(myapp main.cpp)
    """)
    assert parse_cmake_lists(p) == []


def test_declaration_without_repo_or_url_is_skipped(tmp_path: Path) -> None:
    """A FetchContent_Declare with only ``SOURCE_DIR`` (e.g.
    pulling from a sibling checkout) is real but doesn't give us a
    pinpoint upstream — skipped."""
    p = _write(tmp_path, """
        FetchContent_Declare(
          local
          SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/extern/local
        )
    """)
    assert parse_cmake_lists(p) == []


def test_inline_comments_stripped(tmp_path: Path) -> None:
    """``#`` comments inside a Declare block don't poison the
    KEY VALUE parsing."""
    p = _write(tmp_path, """
        FetchContent_Declare(
          fmt
          GIT_REPOSITORY https://github.com/fmtlib/fmt.git  # upstream
          GIT_TAG 9.1.0  # latest stable
        )
    """)
    deps = parse_cmake_lists(p)
    assert deps[0].name == "fmtlib/fmt"
    assert deps[0].version == "9.1.0"


def test_case_insensitive_keyword(tmp_path: Path) -> None:
    """CMake is case-insensitive on the function name; ours
    matches both."""
    p = _write(tmp_path, """
        fetchcontent_declare(
          x
          git_repository https://github.com/x/x.git
          git_tag v1
        )
    """)
    deps = parse_cmake_lists(p)
    assert len(deps) == 1
    assert deps[0].purl == "pkg:github/x/x@v1"


def test_dispatch_through_filename_registry(tmp_path: Path) -> None:
    """The filename-based parser registry resolves
    ``CMakeLists.txt`` to this module's parser."""
    from packages.sca.parsers import _resolve

    p = _write(tmp_path, "")
    fn = _resolve(p)
    assert fn is not None
    assert fn.__name__ == "parse_cmake_lists"


def test_unreadable_file_returns_empty(tmp_path: Path) -> None:
    """Permission denied / missing file → no findings, no
    exception."""
    fake = tmp_path / "nonexistent.cmake"
    assert parse_cmake_lists(fake) == []
