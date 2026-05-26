"""Tests for the pyproject.toml parser."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.pyproject import parse


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
