"""Tests for the pyproject.toml parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.models import PinStyle
from packages.sca.parsers.pyproject import extract_project_license, parse


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "pyproject.toml"
    p.write_text(body, encoding="utf-8")
    return p


def test_pep621_dependencies(tmp_path: Path) -> None:
    body = """\
[project]
name = "demo"
version = "0.1.0"
dependencies = [
    "django==4.2.7",
    "requests~=2.31",
    "click",
]

[project.optional-dependencies]
dev = ["pytest>=7"]
"""
    deps = {(d.name, d.scope): d for d in parse(_write(tmp_path, body))}
    assert deps[("django", "main")].pin_style is PinStyle.EXACT
    assert deps[("requests", "main")].pin_style is PinStyle.TILDE
    assert deps[("click", "main")].pin_style is PinStyle.WILDCARD
    assert deps[("pytest", "optional")].pin_style is PinStyle.RANGE


def test_pep735_dependency_groups(tmp_path: Path) -> None:
    body = """\
[project]
name = "demo"
dependencies = ["requests==2.34.2"]

[dependency-groups]
test = ["pytest==9.1.1", "z3-solver==4.15.4.0"]
dev = [{ include-group = "test" }, "ruff==0.15.12"]
"""
    deps = {(d.name, d.scope): d for d in parse(_write(tmp_path, body))}
    assert deps[("requests", "main")].pin_style is PinStyle.EXACT
    assert deps[("pytest", "dev")].pin_style is PinStyle.EXACT
    assert deps[("z3-solver", "dev")].pin_style is PinStyle.EXACT
    assert deps[("ruff", "dev")].pin_style is PinStyle.EXACT


def test_poetry_string_and_dict_specs(tmp_path: Path) -> None:
    body = """\
[tool.poetry.dependencies]
python = "^3.10"
django = "^4.2"
requests = { version = ">=2.31,<3", optional = true }
internal = { path = "../internal" }
fork = { git = "https://github.com/u/r.git", tag = "v1.0" }

[tool.poetry.dev-dependencies]
pytest = "~7.4.0"

[tool.poetry.group.docs.dependencies]
sphinx = "*"
"""
    by_name = {d.name: d for d in parse(_write(tmp_path, body))}
    assert "python" not in by_name  # Poetry's project-python constraint
    assert by_name["django"].pin_style is PinStyle.CARET
    assert by_name["django"].version == "4.2"
    assert by_name["requests"].pin_style is PinStyle.RANGE
    assert by_name["internal"].pin_style is PinStyle.PATH
    assert by_name["fork"].pin_style is PinStyle.GIT
    assert by_name["fork"].version == "v1.0"
    assert by_name["pytest"].scope == "dev"
    assert by_name["pytest"].pin_style is PinStyle.TILDE
    assert by_name["sphinx"].scope == "dev"
    assert by_name["sphinx"].pin_style is PinStyle.WILDCARD


def test_pdm_dev_dependencies(tmp_path: Path) -> None:
    body = """\
[tool.pdm.dev-dependencies]
test = ["pytest>=7", "pytest-cov"]
lint = ["ruff>=0.1"]
"""
    deps = parse(_write(tmp_path, body))
    by_name = {d.name: d for d in deps}
    assert by_name["pytest"].scope == "dev"
    assert by_name["ruff"].scope == "dev"


def test_build_system_requires(tmp_path: Path) -> None:
    body = """\
[build-system]
requires = ["setuptools>=61", "wheel"]
build-backend = "setuptools.build_meta"
"""
    deps = parse(_write(tmp_path, body))
    by_name = {d.name: d for d in deps}
    assert by_name["setuptools"].scope == "build"
    assert by_name["setuptools"].pin_style is PinStyle.RANGE
    assert by_name["wheel"].scope == "build"


def test_combined_pep621_plus_poetry_block(tmp_path: Path) -> None:
    # A real-world hybrid: PEP 621 [project] + Poetry tool table.
    body = """\
[project]
name = "demo"
dependencies = ["django==4.2.7"]

[tool.poetry.dependencies]
requests = "^2.31"
"""
    deps = parse(_write(tmp_path, body))
    by_name = {d.name: d for d in deps}
    assert by_name["django"].pin_style is PinStyle.EXACT
    assert by_name["requests"].pin_style is PinStyle.CARET


def test_poetry_multi_constraint_list(tmp_path: Path) -> None:
    body = """\
[tool.poetry.dependencies]
foo = [
    { version = "^1.0", python = ">=3.10" },
    { version = "^0.9", python = "<3.10" },
]
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    d = deps[0]
    assert d.name == "foo"
    assert d.pin_style is PinStyle.CARET
    assert d.parser_confidence.level == "medium"


def test_pep621_range_records_corridor(tmp_path: Path) -> None:
    pytest.importorskip("packaging")
    body = (
        '[project]\nname = "x"\n'
        'dependencies = ["foo>=1.0,<2.0", "bar==1.5", "baz"]\n'
    )
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["foo"].version_floor == "1.0"
    assert deps["foo"].version_ceiling == "2.0"
    assert deps["foo"].pin_style is PinStyle.RANGE
    # Exact pins and wildcards carry no corridor.
    assert (deps["bar"].version_floor, deps["bar"].version_ceiling) == (None, None)
    assert (deps["baz"].version_floor, deps["baz"].version_ceiling) == (None, None)


def test_build_system_requires_records_corridor(tmp_path: Path) -> None:
    pytest.importorskip("packaging")
    body = '[build-system]\nrequires = ["setuptools>=61,<70"]\n'
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    d = deps["setuptools"]
    assert d.scope == "build"
    assert d.version_floor == "61"
    assert d.version_ceiling == "70"


def test_poetry_range_records_corridor(tmp_path: Path) -> None:
    pytest.importorskip("packaging")
    body = (
        "[tool.poetry.dependencies]\n"
        'ranged = ">=2.0,<3.0"\n'
        'caret = "^1.2"\n'
        'exact = "4.1.0"\n'
    )
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["ranged"].version_floor == "2.0"
    assert deps["ranged"].version_ceiling == "3.0"
    # Caret implies its own ceiling via pin_style — left unbounded.
    assert deps["caret"].pin_style is PinStyle.CARET
    assert (deps["caret"].version_floor, deps["caret"].version_ceiling) == (None, None)
    assert (deps["exact"].version_floor, deps["exact"].version_ceiling) == (None, None)


def test_poetry_dict_form_range_records_corridor(tmp_path: Path) -> None:
    pytest.importorskip("packaging")
    body = (
        "[tool.poetry.dependencies]\n"
        'foo = {version = ">=1.1,<1.9", optional = true}\n'
    )
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["foo"].version_floor == "1.1"
    assert deps["foo"].version_ceiling == "1.9"


def test_poetry_unparseable_range_fails_safe(tmp_path: Path) -> None:
    """A Poetry range string PEP 440 can't parse leaves the corridor
    unset rather than raising."""
    pytest.importorskip("packaging")
    body = (
        "[tool.poetry.dependencies]\n"
        'weird = ">=1.0 <2.0"\n'
    )
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    d = deps["weird"]
    assert (d.version_floor, d.version_ceiling) == (None, None)


def test_pep503_normalisation(tmp_path: Path) -> None:
    body = """\
[project]
dependencies = ["Foo_Bar.Baz==1.0"]
"""
    deps = parse(_write(tmp_path, body))
    assert deps[0].name == "foo-bar-baz"
    assert deps[0].purl == "pkg:pypi/foo-bar-baz@1.0"


def test_malformed_toml_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "pyproject.toml"
    p.write_text("[project\nname = bad", encoding="utf-8")
    assert parse(p) == []


def test_empty_pyproject_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "pyproject.toml"
    p.write_text("", encoding="utf-8")
    assert parse(p) == []


# ---------------------------------------------------------------------------
# Project license — describes the project itself, never its deps
# ---------------------------------------------------------------------------


def test_extract_project_license_pep639_string(tmp_path: Path) -> None:
    body = """\
[project]
name = "demo"
license = "MIT"
"""
    assert extract_project_license(_write(tmp_path, body)) == "MIT"


def test_extract_project_license_pep621_table(tmp_path: Path) -> None:
    body = """\
[project]
name = "demo"
license = { text = "Apache-2.0" }
"""
    assert extract_project_license(_write(tmp_path, body)) == "Apache-2.0"


def test_extract_project_license_poetry(tmp_path: Path) -> None:
    body = """\
[tool.poetry]
name = "demo"
license = "BSD-3-Clause"
"""
    assert extract_project_license(_write(tmp_path, body)) == "BSD-3-Clause"


def test_extract_project_license_absent(tmp_path: Path) -> None:
    body = """\
[project]
name = "demo"
"""
    assert extract_project_license(_write(tmp_path, body)) is None


def test_extract_project_license_malformed_toml(tmp_path: Path) -> None:
    p = tmp_path / "pyproject.toml"
    p.write_text("[project\nlicense = bad", encoding="utf-8")
    assert extract_project_license(p) is None


def test_dep_rows_never_carry_the_project_license(tmp_path: Path) -> None:
    # [project].license describes the project itself, not its deps —
    # a dep's declared_license only ever comes from data that
    # describes that dep (registry enrichment), or stays None.
    # Attaching the project's own license to every dep row poisoned
    # license-policy evaluation AND suppressed the registry fetch
    # (enrich_licenses skips rows that already have a value).
    body = """\
[project]
name = "demo"
license = "MIT"
dependencies = ["django==4.2.7"]

[project.optional-dependencies]
dev = ["pytest>=7"]

[tool.poetry.dependencies]
requests = "^2.31"
"""
    deps = parse(_write(tmp_path, body))
    assert deps
    assert all(d.declared_license is None for d in deps)


# ---------------------------------------------------------------------------
# Specifier classification shared with the requirements parser
# ---------------------------------------------------------------------------

def test_exact_pin_among_multiple_clauses(tmp_path: Path) -> None:
    # ``foo>=1,==1.5,<2`` pins exactly 1.5 — the == operand must win
    # over the range classification (same rule as requirements.txt).
    body = '[project]\nname = "x"\ndependencies = ["foo>=1,==1.5,<2"]\n'
    [d] = parse(_write(tmp_path, body))
    assert d.pin_style is PinStyle.EXACT
    assert d.version == "1.5"
    assert (d.version_floor, d.version_ceiling) == ("1", "2")


def test_exclusion_operand_not_recorded_as_version(tmp_path: Path) -> None:
    # ``bar!=2.0`` excludes 2.0; recording it as the installed version
    # flagged advisories for the one version guaranteed absent.
    body = '[project]\nname = "x"\ndependencies = ["bar!=2.0", "baz==3.1"]\n'
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["bar"].version is None
    assert deps["bar"].pin_style is PinStyle.RANGE
    # Other direction: == still records its operand.
    assert deps["baz"].version == "3.1"
    assert deps["baz"].pin_style is PinStyle.EXACT


def test_string_dependencies_value_not_iterated_charwise(tmp_path: Path) -> None:
    # ``dependencies = "requests==1.0"`` (scalar, not array) used to be
    # iterated character-wise — single letters are valid PEP 508 names,
    # so it emitted one phantom dep per character.
    body = '[project]\nname = "x"\ndependencies = "requests==1.0"\n'
    assert parse(_write(tmp_path, body)) == []


def test_list_dependencies_still_parse(tmp_path: Path) -> None:
    body = '[project]\nname = "x"\ndependencies = ["requests==1.0"]\n'
    [d] = parse(_write(tmp_path, body))
    assert (d.name, d.version) == ("requests", "1.0")


def test_string_build_requires_not_iterated_charwise(tmp_path: Path) -> None:
    body = '[build-system]\nrequires = "setuptools"\n'
    assert parse(_write(tmp_path, body)) == []
