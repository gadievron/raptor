"""Symlinked-manifest handling in ``packages.sca.parsers._safe_read``.

``follow_symlinks=False`` refuses symlinks outright — the right
default for attacker-controlled paths — but monorepos (pnpm / nix /
Bazel layouts) legitimately symlink shared manifests within the
tree. With a declared scan root the read is allowed when the fully-
resolved target stays inside that root, refused when it escapes.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.parsers._safe_read import read_bounded, scan_root_context


def test_symlink_refused_without_scan_root(tmp_path: Path) -> None:
    real = tmp_path / "real.lock"
    real.write_text("content", encoding="utf-8")
    link = tmp_path / "composer.lock"
    link.symlink_to(real)
    assert read_bounded(link, follow_symlinks=False) is None


def test_symlink_inside_scan_root_allowed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "shared").mkdir(parents=True)
    real = repo / "shared" / "composer.lock"
    real.write_text('{"packages": []}', encoding="utf-8")
    link = repo / "composer.lock"
    link.symlink_to(real)
    with scan_root_context(repo):
        assert read_bounded(link, follow_symlinks=False) == '{"packages": []}'


def test_symlink_escaping_scan_root_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.lock"
    outside.write_text("secret", encoding="utf-8")
    link = repo / "composer.lock"
    link.symlink_to(outside)
    with scan_root_context(repo):
        assert read_bounded(link, follow_symlinks=False) is None


def test_dangling_symlink_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    link = repo / "composer.lock"
    link.symlink_to(repo / "gone.lock")
    with scan_root_context(repo):
        assert read_bounded(link, follow_symlinks=False) is None


def test_context_cleared_after_exit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    real = repo / "real.lock"
    real.write_text("x", encoding="utf-8")
    link = repo / "composer.lock"
    link.symlink_to(real)
    with scan_root_context(repo):
        assert read_bounded(link, follow_symlinks=False) == "x"
    # Outside the context the strict refusal is back.
    assert read_bounded(link, follow_symlinks=False) is None


def test_regular_file_unaffected(tmp_path: Path) -> None:
    f = tmp_path / "composer.lock"
    f.write_text("plain", encoding="utf-8")
    assert read_bounded(f, follow_symlinks=False) == "plain"
    with scan_root_context(tmp_path):
        assert read_bounded(f, follow_symlinks=False) == "plain"
