"""Oversize-file bounds for the SCA text/TOML/YAML/XML target parsers.

Companion to ``test_supply_chain_bounded_reads.py`` (same shape, same
red-before-fix construction): every parser here reads a text-format
manifest from the scanned — attacker-controlled — repository. The
reads go through ``packages.sca.parsers._safe_read.read_bounded``
(``follow_symlinks=False``), which stat-gates size BEFORE the read
and refuses symlinked paths.

Each oversize fixture is a sparse file truncated past the 50 MB cap,
and each test asserts the gate's refusal warning — a whole-file read
that merely fails to parse cannot satisfy it, which is what makes
these red before the migration and green after.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

from packages.sca.parsers._safe_read import _MAX_PARSER_BYTES

_SAFE_READ_LOGGER = "packages.sca.parsers._safe_read"
_REFUSAL = "refusing to read"


def _sparse_oversize(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        os.truncate(fh.fileno(), _MAX_PARSER_BYTES + 1)
    return path


@contextmanager
def _expect_refusal(caplog: pytest.LogCaptureFixture) -> Iterator[None]:
    """Assert the size/symlink gate refused the read — the degraded
    result must come from the bound, not from a failed parse of a
    fully-buffered file."""
    with caplog.at_level(logging.WARNING, logger=_SAFE_READ_LOGGER):
        yield
    assert _REFUSAL in caplog.text or "refusing symlinked" in caplog.text


class TestPnpmWorkspaceCatalogBound:
    """pnpm-workspace.yaml → yaml.safe_load was the last unbounded,
    symlink-following read-then-parse of a target manifest in the
    package."""

    def _get(self, root: Path):
        from packages.sca.parsers import _pnpm_catalog
        _pnpm_catalog._clear_cache()
        return _pnpm_catalog.get_catalogs(root)

    def test_oversize_workspace_yaml_no_catalogs(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        _sparse_oversize(tmp_path / "pnpm-workspace.yaml")
        with _expect_refusal(caplog):
            assert self._get(tmp_path) == {}

    def test_symlinked_workspace_yaml_refused(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        real = outside / "pnpm-workspace.yaml"
        real.write_text("catalog:\n  react: ^18.2.0\n", encoding="utf-8")
        ws = tmp_path / "repo"
        ws.mkdir()
        (ws / "pnpm-workspace.yaml").symlink_to(real)
        with _expect_refusal(caplog):
            assert self._get(ws) == {}

    def test_small_workspace_yaml_still_parses(self, tmp_path: Path) -> None:
        pytest.importorskip("yaml")
        (tmp_path / "pnpm-workspace.yaml").write_text(
            "catalog:\n  react: ^18.2.0\ncatalogs:\n  react17:\n"
            "    react: ^17.0.0\n",
            encoding="utf-8",
        )
        catalogs = self._get(tmp_path)
        assert catalogs[""]["react"] == "^18.2.0"
        assert catalogs["react17"]["react"] == "^17.0.0"


# One (module, entry-point, fixture-filename, empty-result) row per
# migrated text/TOML/YAML/XML parser. Every entry point degrades to
# its documented empty result when the gate refuses the read.
_SWEEP_CASES = [
    ("cmake_fetchcontent", "parse_cmake_lists", "CMakeLists.txt", []),
    ("gemfile", "parse_manifest", "Gemfile", []),
    ("gemfile", "parse_lockfile", "Gemfile.lock", []),
    ("helm_chart", "parse", "Chart.yaml", []),
    ("compose", "parse", "docker-compose.yml", []),
    ("gomod", "parse_manifest", "go.mod", []),
    ("gomod", "parse_lockfile", "go.sum", []),
    ("gradle_dsl", "parse", "build.gradle", []),
    ("gradle_lockfile", "parse", "gradle.lockfile", []),
    ("kubernetes", "parse", "deployment.yaml", []),
    ("requirements", "parse", "requirements.txt", []),
    ("gitmodules", "parse", ".gitmodules", []),
    ("pom", "parse", "pom.xml", []),
    ("gitlab_ci", "parse", ".gitlab-ci.yml", []),
    ("yarn_lock", "parse", "yarn.lock", []),
    ("precommit", "parse", ".pre-commit-config.yaml", []),
    ("pyproject", "parse", "pyproject.toml", []),
    ("poetry_lock", "parse", "poetry.lock", []),
    ("cargo", "parse_manifest", "Cargo.toml", []),
    ("cargo", "parse_lockfile", "Cargo.lock", []),
    ("uv_lock", "parse", "uv.lock", []),
]


class TestTextParserSweepBound:
    """Every raw read_text/read_bytes text-format parser now routes
    through the bounded, symlink-refusing reader."""

    @pytest.mark.parametrize(
        ("module_name", "func_name", "filename", "empty"),
        _SWEEP_CASES,
        ids=[f"{m}.{f}" for m, f, _, _ in _SWEEP_CASES],
    )
    def test_oversize_file_refused(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
        module_name: str, func_name: str, filename: str, empty: object,
    ) -> None:
        import importlib
        mod = importlib.import_module(f"packages.sca.parsers.{module_name}")
        target = _sparse_oversize(tmp_path / filename)
        with _expect_refusal(caplog):
            assert getattr(mod, func_name)(target) == empty

    def test_oversize_pnpm_lock_refused(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        pytest.importorskip("yaml")  # read happens after the PyYAML gate
        from packages.sca.parsers import pnpm_lock
        target = _sparse_oversize(tmp_path / "pnpm-lock.yaml")
        with _expect_refusal(caplog):
            assert pnpm_lock.parse(target) == []

    def test_symlinked_manifest_refused(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Representative symlink case: a go.mod symlinked out of tree
        must be refused, not followed."""
        from packages.sca.parsers import gomod
        real = tmp_path / "outside-go.mod"
        real.write_text("module example.com/x\nrequire foo.bar/a v1.0.0\n")
        link = tmp_path / "repo" / "go.mod"
        link.parent.mkdir()
        link.symlink_to(real)
        with _expect_refusal(caplog):
            assert gomod.parse_manifest(link) == []

    def test_small_files_still_parse(self, tmp_path: Path) -> None:
        """Control: the bound does not disturb normal parses (spot
        checks; the full parser suites cover the rest)."""
        from packages.sca.parsers import gomod, gradle_lockfile
        gm = tmp_path / "go.mod"
        gm.write_text(
            "module example.com/x\n\nrequire (\n"
            "\tgithub.com/foo/bar v1.2.3\n)\n",
        )
        deps = gomod.parse_manifest(gm)
        assert [d.name for d in deps] == ["github.com/foo/bar"]

        gl = tmp_path / "gradle.lockfile"
        gl.write_text(
            "com.example:widget:2.0.1=compileClasspath\n"
            "empty=\n",
        )
        deps = gradle_lockfile.parse(gl)
        assert [d.name for d in deps] == ["com.example:widget"]

    def test_gitmodules_ref_reads_bounded(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The .git/modules HEAD pin read is bounded too — an oversize
        HEAD degrades to no-pin instead of buffering."""
        from packages.sca.parsers.gitmodules import _resolve_submodule_sha
        head = tmp_path / ".git" / "modules" / "libfoo" / "HEAD"
        head.parent.mkdir(parents=True)
        _sparse_oversize(head)
        with _expect_refusal(caplog):
            assert _resolve_submodule_sha(tmp_path, "libfoo") is None


class TestScanRootSymlinkContainment:
    """In-tree symlinked manifests keep parsing when the scan root is
    declared (monorepo layouts) — refusal applies only to links that
    escape the root. harden's parse loop and the Helm repo-host
    derivation both declare the root now, like the pipeline."""

    def test_in_tree_symlink_parses_under_scan_root(
        self, tmp_path: Path,
    ) -> None:
        from packages.sca.parsers import gomod
        from packages.sca.parsers._safe_read import scan_root_context
        shared = tmp_path / "shared" / "go.mod"
        shared.parent.mkdir()
        shared.write_text(
            "module example.com/x\n\nrequire (\n"
            "\tgithub.com/foo/bar v1.2.3\n)\n",
        )
        member = tmp_path / "member"
        member.mkdir()
        link = member / "go.mod"
        link.symlink_to(shared)
        with scan_root_context(tmp_path):
            deps = gomod.parse_manifest(link)
        assert [d.name for d in deps] == ["github.com/foo/bar"]
