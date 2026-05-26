"""Regression tests for discovery exclusion rules."""

from __future__ import annotations

from pathlib import Path

from packages.sca.discovery import EXCLUDED_DIR_NAMES, find_manifests


def test_top_level_packages_dir_not_excluded(tmp_path: Path) -> None:
    """`packages/` is a legitimate monorepo layout (raptor, rush, lerna).

    A previous version of the exclude list dropped it silently, hiding
    real manifests. Guard against the regression.
    """
    repo = tmp_path / "proj"
    (repo / "packages" / "web").mkdir(parents=True)
    (repo / "packages" / "web" / "requirements.txt").write_text(
        "django==4.2.7\n", encoding="utf-8")
    (repo / "requirements.txt").write_text("requests==2.31.0\n",
                                            encoding="utf-8")

    manifests = find_manifests(repo)
    paths = {str(m.path.relative_to(repo)) for m in manifests}
    assert "packages/web/requirements.txt" in paths
    assert "requirements.txt" in paths


def test_node_modules_still_excluded(tmp_path: Path) -> None:
    """``node_modules`` must stay excluded — it's vendored deps."""
    repo = tmp_path / "proj"
    (repo / "node_modules" / "lodash").mkdir(parents=True)
    (repo / "node_modules" / "lodash" / "package.json").write_text(
        '{"name":"lodash","version":"4.17.21"}\n', encoding="utf-8")
    (repo / "package.json").write_text(
        '{"name":"app","dependencies":{"lodash":"^4"}}\n', encoding="utf-8")

    manifests = find_manifests(repo)
    paths = {str(m.path.relative_to(repo)) for m in manifests}
    assert "package.json" in paths
    assert not any("node_modules" in p for p in paths)


def test_packages_not_in_excludes() -> None:
    """Belt-and-braces: bare 'packages' must not be in EXCLUDED_DIR_NAMES."""
    assert "packages" not in EXCLUDED_DIR_NAMES


def test_claude_dir_excluded() -> None:
    """.claude/ contains agent worktrees — must not be scanned."""
    assert ".claude" in EXCLUDED_DIR_NAMES


def test_claude_worktrees_skipped(tmp_path: Path) -> None:
    """Manifests inside .claude/worktrees/ must not be discovered."""
    (tmp_path / ".claude" / "worktrees" / "agent-abc123").mkdir(parents=True)
    (tmp_path / ".claude" / "worktrees" / "agent-abc123" / "requirements.txt").write_text(
        "requests>=2.31.0\n"
    )
    (tmp_path / "requirements.txt").write_text("flask>=2.3.0\n")
    manifests = find_manifests(tmp_path)
    paths = [str(m.path) for m in manifests]
    assert any("flask" in Path(p).read_text() for p in paths)
    assert not any(".claude" in p for p in paths)


# ---------------------------------------------------------------------------
# Test-path exclusion — addresses the Semgrep stress-fixture bug
# ---------------------------------------------------------------------------

def test_manifest_in_tests_dir_excluded_by_default(tmp_path: Path) -> None:
    """Manifests under a ``tests/`` ancestor are excluded by default.

    Regression: Semgrep ships ``cli/tests/performance/targets_perf_sca/
    100k/Gemfile.lock`` with 100,000 synthetic ``package0`` ...
    ``package99999`` entries. Pre-fix SCA discovered + parsed that file
    and queried rubygems.org for every fake name — 23,000+ bogus 404s
    surfaced in the May 2026 200-project ad-hoc sweep before the
    process was killed. Default-skipping test paths closes that bug
    while leaving the operator override for the rare case where they
    DO want test-tree manifests scanned.
    """
    # Real root-level manifest — must be found.
    (tmp_path / "requirements.txt").write_text("flask>=2.3.0\n")
    # Synthetic stress-test manifest under tests/ — must NOT be found.
    perf = tmp_path / "tests" / "performance" / "100k"
    perf.mkdir(parents=True)
    (perf / "Gemfile.lock").write_text(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        + "".join(
            f"    package{i} (1.0.0)\n" for i in range(50)
        ),
        encoding="utf-8",
    )
    manifests = find_manifests(tmp_path)
    paths = [str(m.path) for m in manifests]
    assert any("requirements.txt" in p for p in paths)
    assert not any("Gemfile.lock" in p for p in paths), (
        f"test-path Gemfile.lock leaked into discovery: {paths}"
    )


def test_manifest_in_tests_dir_kept_with_include_test_paths(
    tmp_path: Path,
) -> None:
    """Override: ``include_test_paths=True`` brings test manifests
    back into scope. For operators auditing a security-research repo
    where the test corpus IS the analysis target."""
    perf = tmp_path / "tests" / "fixtures"
    perf.mkdir(parents=True)
    (perf / "requirements.txt").write_text("flask==1.0\n")
    manifests = find_manifests(tmp_path, include_test_paths=True)
    assert any("tests/fixtures/requirements.txt" in str(m.path)
                for m in manifests)


def test_root_manifest_with_word_test_in_dir_name_kept(
    tmp_path: Path,
) -> None:
    """``test`` substring in a dir name doesn't trigger exclusion
    when the dir isn't literally named ``test``/``tests``/etc. (e.g.
    ``test-utils-pkg/`` is NOT a test dir under our convention)."""
    sub = tmp_path / "test-utils-pkg"
    sub.mkdir()
    (sub / "package.json").write_text('{"name": "x"}', encoding="utf-8")
    manifests = find_manifests(tmp_path)
    assert any("test-utils-pkg" in str(m.path) for m in manifests)
