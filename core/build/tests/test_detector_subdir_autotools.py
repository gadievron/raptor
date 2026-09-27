"""Detector regressions from the GNU screen Stage E re-run.

Three findings, one target shape: a C git checkout whose autotools
live one directory down (``src/configure.ac``, no generated
``./configure`` at any level, nothing build-shaped at the root).
Before the fixes the detector returned nothing for it three separate
ways: "c" had no BUILD_SYSTEMS key, the exact-file scan looked at the
root only, and even a found ``configure.ac`` synthesized
``./configure && make`` — which cannot run in a checkout that ships
only ``configure.ac`` + ``autogen.sh``.
"""

from __future__ import annotations

from pathlib import Path

from core.build.build_detector import BuildDetector


def _screen_shaped(tmp_path: Path) -> Path:
    """Root holds no build files; the autotools live in src/."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "COPYING").write_text("GPL\n")
    (repo / "src" / "configure.ac").write_text("AC_INIT([screen], [5])\n")
    (repo / "src" / "Makefile.in").write_text("all:\n")
    (repo / "src" / "autogen.sh").write_text("#!/bin/sh\nautoreconf -fi\n")
    return repo


class TestCLanguageAlias:
    def test_c_is_a_real_table_key_aliasing_cpp(self):
        assert BuildDetector.BUILD_SYSTEMS["c"] \
            is BuildDetector.BUILD_SYSTEMS["cpp"]

    def test_c_hint_detects_autotools_directly(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "configure.ac").write_text("AC_INIT([x], [1])\n")
        bs = BuildDetector(repo).detect_build_system("c")
        assert bs is not None
        assert bs.type == "autotools"


class TestDepthOneSubdirScan:
    def test_screen_shaped_layout_detected_in_src(self, tmp_path):
        repo = _screen_shaped(tmp_path)
        bs = BuildDetector(repo).detect_build_system("c")
        assert bs is not None
        assert bs.type == "autotools"
        assert bs.working_dir == repo / "src"

    def test_root_detection_wins_over_subdir(self, tmp_path):
        # The fallback is exactly that: a root hit must keep the root
        # working_dir even when a subdir would also match.
        repo = _screen_shaped(tmp_path)
        (repo / "configure.ac").write_text("AC_INIT([outer], [1])\n")
        bs = BuildDetector(repo).detect_build_system("c")
        assert bs is not None
        assert bs.working_dir == repo

    def test_hidden_and_symlink_subdirs_are_skipped(self, tmp_path):
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        (repo / ".git" / "configure.ac").write_text("AC_INIT([x], [1])\n")
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "configure.ac").write_text("AC_INIT([x], [1])\n")
        (repo / "link").symlink_to(outside)
        assert BuildDetector(repo).detect_build_system("c") is None


class TestAutoreconfPrepend:
    def test_git_checkout_without_configure_gets_autoreconf(self, tmp_path):
        repo = _screen_shaped(tmp_path)
        bs = BuildDetector(repo).detect_build_system("c")
        assert bs is not None
        assert bs.command.startswith("autoreconf -fi && ")
        assert "./configure && make" in bs.command

    def test_release_tarball_with_configure_is_untouched(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "configure.ac").write_text("AC_INIT([x], [1])\n")
        (repo / "configure").write_text("#!/bin/sh\n")
        bs = BuildDetector(repo).detect_build_system("c")
        assert bs is not None
        assert "autoreconf" not in bs.command
