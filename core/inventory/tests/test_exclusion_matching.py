"""Exclusion-pattern matching shapes.

Directory-shaped patterns describe directories and must never match a
FILE basename; basename-shaped globs must never match across ``/``.
Both miss directions are covered: files that must stay in, and
directories/files that must stay out.
"""

from __future__ import annotations

from core.inventory.exclusions import (
    DEFAULT_EXCLUDES,
    match_exclusion_reason,
    should_exclude,
)


class TestDirPatternsNeverMatchFileBasenames:
    """A file named after a build dir is a file, not a directory."""

    def test_extensionless_dispatch_scripts_stay_in(self):
        # Shebang dispatch scripts commonly carry dir-colliding names.
        assert not should_exclude("build", DEFAULT_EXCLUDES)
        assert not should_exclude("script/test", DEFAULT_EXCLUDES)
        assert not should_exclude("tools/dist", DEFAULT_EXCLUDES)

    def test_glob_dir_patterns_skip_file_basenames(self):
        assert not should_exclude(
            "scripts/cmake-build-helper.py", DEFAULT_EXCLUDES)
        assert not should_exclude("pkg.egg-info", DEFAULT_EXCLUDES)

    def test_directories_still_excluded(self):
        assert should_exclude("build/x.py", DEFAULT_EXCLUDES)
        assert should_exclude("a/tests/t.py", DEFAULT_EXCLUDES)
        assert should_exclude("a/cmake-build-debug/x.c", DEFAULT_EXCLUDES)
        assert should_exclude("x.egg-info/PKG-INFO", DEFAULT_EXCLUDES)

    def test_root_anchored_dir_still_excluded_but_not_top_level_file(self):
        # docs/ dir at top level: excluded. A FILE named docs: kept.
        assert should_exclude("docs/readme.py", DEFAULT_EXCLUDES)
        assert not should_exclude("docs", DEFAULT_EXCLUDES)

    def test_reason_variant_agrees(self):
        excluded, reason, pattern = match_exclusion_reason(
            "script/test", DEFAULT_EXCLUDES)
        assert not excluded
        excluded, reason, pattern = match_exclusion_reason(
            "build/x.py", DEFAULT_EXCLUDES)
        assert excluded and reason == "pattern_match" and pattern == "build/"


class TestBasenameGlobsDoNotCrossSeparators:
    """fnmatch's ``*`` crosses ``/``; a basename-shaped glob applied to
    the full path excluded entire first-party top-level trees."""

    def test_first_party_trees_stay_in(self):
        assert not should_exclude("test_utils/prod/main.py", DEFAULT_EXCLUDES)
        assert not should_exclude("mock_server/handler.py", DEFAULT_EXCLUDES)
        assert not should_exclude("mock_server/deep/a/b.c", DEFAULT_EXCLUDES)

    def test_basename_globs_still_match_files(self):
        assert should_exclude("a/test_foo.py", DEFAULT_EXCLUDES)
        assert should_exclude("mock_server.py", DEFAULT_EXCLUDES)
        assert should_exclude("x/y/util_test.go", DEFAULT_EXCLUDES)

    def test_path_shaped_globs_still_full_path_match(self):
        # An operator writing a separator into the glob asked for a
        # path match — that stays.
        assert should_exclude("src/deep/x.js", ["src/*"])
        assert not should_exclude("other/deep/x.js", ["src/*"])
