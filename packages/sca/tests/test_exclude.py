"""Tests for ``packages.sca._exclude`` — the shared ``--exclude <glob>``
matcher used by the SCA write paths (``fix`` backends + ``bump``).

Pins the matching semantics the operator-facing help documents:
target-relative fnmatch where ``*`` spans ``/``, plus the leading
``**/`` root-anchor (``**/test/**`` must also match a root-level
``test/`` directory — raw fnmatch alone would not).
"""

from __future__ import annotations

from pathlib import Path

from packages.sca._exclude import matches_exclude, partition_excluded


def test_no_patterns_matches_nothing() -> None:
    assert not matches_exclude(Path("tests/requirements.txt"), None)
    assert not matches_exclude(Path("tests/requirements.txt"), [])


def test_nested_dir_glob_matches() -> None:
    assert matches_exclude(
        Path("packages/sca/tests/fixtures/requirements.txt"),
        ["**/tests/**"],
    )


def test_leading_doublestar_anchors_at_root() -> None:
    # Raw fnmatch of '**/test/**' translates to '.*/test/.*' which
    # misses a root-level 'test/' dir — the matcher must cover it.
    assert matches_exclude(
        Path("test/data/sca-e2e/py-app/fixture/Dockerfile.fixture"),
        ["**/test/**"],
    )
    assert matches_exclude(Path("testdata/Dockerfile"), ["**/testdata/**"])


def test_star_spans_slash() -> None:
    # Same convention as bump policy path rules: '*' spans '/'.
    assert matches_exclude(
        Path("a/b/fixtures/c/pom.xml"), ["*fixtures/*"],
    )


def test_non_matching_paths_kept() -> None:
    assert not matches_exclude(Path("requirements.txt"), ["**/tests/**"])
    # Substring components must not match: 'test-utils' is not 'test'.
    assert not matches_exclude(
        Path("test-utils/requirements.txt"), ["**/test/**"],
    )


def test_absolute_path_anchored_at_root(tmp_path: Path) -> None:
    p = tmp_path / "repo" / "tests" / "fixtures" / "requirements.txt"
    assert matches_exclude(p, ["**/tests/**"], root=tmp_path / "repo")
    # Root-relative matching: a prod manifest at the root must not be
    # caught even though the ABSOLUTE path (/tmp/pytest-*/...) exists.
    assert not matches_exclude(
        tmp_path / "repo" / "requirements.txt",
        ["**/tests/**"], root=tmp_path / "repo",
    )


def test_partition_excluded_preserves_order(tmp_path: Path) -> None:
    root = tmp_path
    paths = [
        root / "Dockerfile",
        root / "testdata" / "Dockerfile",
        root / "sub" / "Dockerfile",
        root / "tests" / "Dockerfile",
    ]
    kept, excluded = partition_excluded(
        paths, ["**/testdata/**", "**/tests/**"], root=root,
    )
    assert kept == [root / "Dockerfile", root / "sub" / "Dockerfile"]
    assert excluded == [
        root / "testdata" / "Dockerfile",
        root / "tests" / "Dockerfile",
    ]


def test_partition_no_patterns_keeps_all(tmp_path: Path) -> None:
    paths = [tmp_path / "tests" / "a", tmp_path / "b"]
    kept, excluded = partition_excluded(paths, None, root=tmp_path)
    assert kept == paths
    assert excluded == []
