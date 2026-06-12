"""Tests for cve_env.config._find_repo_root layout-independent finder.

Closes BUG-010 (pre-existing pip-install path-resolution bug surfaced
during the BUG-008 path-drift cleanup): the previous
``REPO_ROOT = Path(__file__).resolve().parents[2]`` worked from a clone
(<repo>/src/cve_env/config.py) but resolved to <lib>/python3.X/ when
the package was pip-installed at <site-packages>/cve_env/config.py.

The new ``_find_repo_root`` walks up from ``__file__`` looking for a
``pyproject.toml`` or ``.git`` marker, with an env-var escape hatch
(``CVE_ENV_REPO_ROOT``) for pip-installed users.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch


from cve_env.config import REPO_ROOT, _find_repo_root


def test_repo_root_resolves_to_existing_ancestor() -> None:
    """REPO_ROOT resolves to a real directory that is an ancestor of the
    config module. After the raptor integration the package no longer
    lives in a standalone ``src/cve_env`` repo, so we assert the
    layout-independent invariant (a real ancestor dir) rather than a
    specific repo shape. Artifact output is decoupled from REPO_ROOT via
    CVE_ENV_OUTPUT_ROOT (see config._find_output_root)."""
    import cve_env.config as _cfg

    config_file = Path(_cfg.__file__).resolve()
    assert REPO_ROOT.is_dir(), f"REPO_ROOT={REPO_ROOT} should be a real dir"
    assert REPO_ROOT in config_file.parents, (
        f"REPO_ROOT={REPO_ROOT} should be an ancestor of {config_file}"
    )


def test_finder_walks_up_to_marker(tmp_path: Path) -> None:
    """_find_repo_root walks from a deeply-nested file path up to the
    first ancestor containing a marker file."""
    root = tmp_path / "myproject"
    nested = root / "deeply" / "nested" / "package" / "module.py"
    nested.parent.mkdir(parents=True)
    nested.write_text("# fake module")
    (root / "pyproject.toml").write_text("[project]\nname='x'\n")

    with patch("cve_env.config.__file__", str(nested)):
        result = _find_repo_root()

    assert result == root, f"expected {root}, got {result}"


def test_finder_finds_git_marker_when_no_pyproject(tmp_path: Path) -> None:
    """A bare git checkout without pyproject.toml is also a valid root."""
    root = tmp_path / "git_only"
    nested = root / "src" / "pkg" / "config.py"
    nested.parent.mkdir(parents=True)
    nested.write_text("# fake")
    (root / ".git").mkdir()  # marker as directory

    with patch("cve_env.config.__file__", str(nested)):
        result = _find_repo_root()

    assert result == root


def test_finder_honors_env_var_override(tmp_path: Path) -> None:
    """CVE_ENV_REPO_ROOT env var is the escape hatch for pip-installed
    mode where no marker is reachable upward from the package location."""
    custom_root = tmp_path / "user_workspace"
    custom_root.mkdir()

    with patch.dict(os.environ, {"CVE_ENV_REPO_ROOT": str(custom_root)}):
        result = _find_repo_root()

    assert result == custom_root.resolve()


def test_finder_env_var_takes_precedence_over_marker(tmp_path: Path) -> None:
    """Even when a marker exists upward, env var wins."""
    root_with_marker = tmp_path / "real_root"
    nested = root_with_marker / "src" / "pkg" / "config.py"
    nested.parent.mkdir(parents=True)
    nested.write_text("# fake")
    (root_with_marker / "pyproject.toml").write_text("[project]\nname='x'\n")

    custom_root = tmp_path / "override"
    custom_root.mkdir()

    with patch("cve_env.config.__file__", str(nested)), patch.dict(
        os.environ, {"CVE_ENV_REPO_ROOT": str(custom_root)}
    ):
        result = _find_repo_root()

    assert result == custom_root.resolve()


def test_finder_falls_back_when_no_marker_anywhere(tmp_path: Path) -> None:
    """Last-resort fallback when neither env var nor markers are present
    (the pip-install scenario before user sets CVE_ENV_REPO_ROOT). The
    fallback is parents[2] of __file__ — same as the legacy behavior, so
    this change introduces no regression for pip-installed users (who
    were already required to use --audit-root). The test ensures we
    don't silently raise instead."""
    # tmp_path has no pyproject.toml or .git anywhere upward
    isolated_file = tmp_path / "a" / "b" / "c" / "module.py"
    isolated_file.parent.mkdir(parents=True)
    isolated_file.write_text("# fake")

    # Strip env var if set in test env
    env_clean = {k: v for k, v in os.environ.items() if k != "CVE_ENV_REPO_ROOT"}
    with patch("cve_env.config.__file__", str(isolated_file)), patch.dict(
        os.environ, env_clean, clear=True
    ):
        result = _find_repo_root()

    # Fallback semantics: parents[2] of the (mocked) __file__
    assert result == isolated_file.resolve().parents[2]
