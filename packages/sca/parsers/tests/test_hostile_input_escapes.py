"""Hostile-input escape classes at the parser boundaries.

The parsers document a never-raise contract (warn + return []), but
narrow per-library catches let two classes escape on crafted input:

- RecursionError from recursive-descent parsing of deeply nested
  documents (tomllib, PyYAML);
- bare ValueError from CPython's int digit limit firing inside
  packaging's version normalisation.

Each escape reached the dispatch catch-all as an anonymous "parser
raised an unhandled exception" anomaly and the crafted file's
dependency set silently dropped out of SCA. These fixtures pin the
contract at the parse() entry itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("packaging")

DEEP_TOML = "x = " + "[" * 5000
HUGE_VERSION = "9" * 100_000


def test_pyproject_deep_toml_nesting(tmp_path: Path, caplog) -> None:
    from packages.sca.parsers.pyproject import parse
    p = tmp_path / "pyproject.toml"
    p.write_text(DEEP_TOML)
    with caplog.at_level("WARNING"):
        assert parse(p) == []
    # Degrades through the standard collector-visible warning, not
    # the dispatch catch-all.
    assert any("parse failed for" in m for m in caplog.messages)


def test_pyproject_digit_limit_version(tmp_path: Path) -> None:
    from packages.sca.parsers.pyproject import parse
    p = tmp_path / "pyproject.toml"
    p.write_text(
        '[project]\nname = "demo"\n'
        f'dependencies = ["p=={HUGE_VERSION}", "requests==2.31.0"]\n'
    )
    deps = parse(p)
    # The crafted row degrades; honest siblings still extract.
    assert [d.name for d in deps] == ["requests"]


def test_poetry_lock_deep_toml_nesting(tmp_path: Path) -> None:
    from packages.sca.parsers.poetry_lock import parse
    p = tmp_path / "poetry.lock"
    p.write_text(DEEP_TOML)
    assert parse(p) == []


def test_uv_lock_deep_toml_nesting(tmp_path: Path) -> None:
    from packages.sca.parsers.uv_lock import parse
    p = tmp_path / "uv.lock"
    p.write_text(DEEP_TOML)
    assert parse(p) == []


def test_pipfile_deep_toml_nesting(tmp_path: Path) -> None:
    from packages.sca.parsers.pipfile import parse
    p = tmp_path / "Pipfile"
    p.write_text(DEEP_TOML)
    assert parse(p) == []


def test_gradle_version_catalog_deep_toml_nesting(tmp_path: Path) -> None:
    from packages.sca.parsers.gradle_version_catalog import (
        parse_libs_versions_toml,
    )
    p = tmp_path / "libs.versions.toml"
    p.write_text(DEEP_TOML)
    # Contract for the walk-up helper is None on failure, not [].
    assert parse_libs_versions_toml(p) is None


def test_requirements_digit_limit_version(tmp_path: Path) -> None:
    from packages.sca.parsers.requirements import parse
    p = tmp_path / "requirements.txt"
    p.write_text(f"p=={HUGE_VERSION}\nrequests==2.31.0\n")
    deps = parse(p)
    assert [d.name for d in deps] == ["requests"]


def test_pep440_compare_digit_limit_raises_versionerror() -> None:
    from packages.sca.versions import VersionError
    from packages.sca.versions.pep440 import compare
    with pytest.raises(VersionError):
        compare(HUGE_VERSION, "1.0")


def test_pyproject_valid_after_hostile(tmp_path: Path) -> None:
    # Other direction: the widened catches must not eat honest input.
    from packages.sca.parsers.pyproject import parse
    p = tmp_path / "pyproject.toml"
    p.write_text('[project]\nname = "d"\ndependencies = ["django==4.2.7"]\n')
    assert [d.name for d in parse(p)] == ["django"]
