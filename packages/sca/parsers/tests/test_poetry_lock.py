"""Tests for the poetry.lock parser."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.poetry_lock import parse


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "poetry.lock"
    p.write_text(body, encoding="utf-8")
    return p


def test_basic_packages_legacy_category(tmp_path: Path) -> None:
    body = """\
[[package]]
name = "django"
version = "4.2.7"
category = "main"
optional = false

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"
optional = false
"""
    deps = {(d.name, d.scope): d for d in parse(_write(tmp_path, body))}
    assert deps[("django", "main")].pin_style is PinStyle.EXACT
    assert deps[("django", "main")].version == "4.2.7"
    assert deps[("django", "main")].is_lockfile is True
    assert deps[("pytest", "dev")].version == "7.4.0"


def test_modern_lockfile_no_category(tmp_path: Path) -> None:
    """Poetry >=1.5 drops ``category``; we default to main, high confidence
    on the version itself but the join with pyproject.toml is what restores
    group info."""
    body = """\
[[package]]
name = "rich"
version = "13.7.0"
optional = false
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].scope == "main"
    assert deps[0].pin_style is PinStyle.EXACT


def test_git_source(tmp_path: Path) -> None:
    body = """\
[[package]]
name = "fork"
version = "0.0.0"

[package.source]
type = "git"
url = "https://github.com/u/r.git"
reference = "main"
resolved_reference = "deadbeef"
"""
    deps = parse(_write(tmp_path, body))
    assert deps[0].pin_style is PinStyle.GIT
    assert deps[0].version == "deadbeef"


def test_directory_source(tmp_path: Path) -> None:
    body = """\
[[package]]
name = "local"
version = "0.1.0"

[package.source]
type = "directory"
url = "../local"
"""
    deps = parse(_write(tmp_path, body))
    assert deps[0].pin_style is PinStyle.PATH


def test_malformed_toml_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "poetry.lock"
    p.write_text("[[package\nname=bad", encoding="utf-8")
    assert parse(p) == []


def test_pep503_name_normalisation(tmp_path: Path) -> None:
    body = """\
[[package]]
name = "Foo_Bar.Baz"
version = "1.0"
"""
    deps = parse(_write(tmp_path, body))
    assert deps[0].name == "foo-bar-baz"
