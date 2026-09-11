"""Tests for the Pipfile (pipenv manifest) parser."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.pipfile import parse


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "Pipfile"
    p.write_text(body, encoding="utf-8")
    return p


def test_basic_shapes(tmp_path: Path) -> None:
    body = (
        "[packages]\n"
        'requests = "*"\n'
        'django = "==4.2.7"\n'
        'flask = ">=1.0,<2.0"\n'
        "\n"
        "[dev-packages]\n"
        'pytest = "*"\n'
    )
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["requests"].pin_style is PinStyle.WILDCARD
    assert deps["django"].pin_style is PinStyle.EXACT
    assert deps["django"].version == "4.2.7"
    assert deps["flask"].pin_style is PinStyle.RANGE
    assert (deps["flask"].version_floor, deps["flask"].version_ceiling) \
        == ("1.0", "2.0")
    assert deps["pytest"].scope == "dev"
    assert all(d.ecosystem == "PyPI" for d in deps.values())


def test_dict_specs(tmp_path: Path) -> None:
    body = (
        "[packages]\n"
        'fancy = {version = "~=2.0", extras = ["s"]}\n'
        'gitpkg = {git = "https://github.com/o/r.git", ref = "main"}\n'
        'localpkg = {path = "."}\n'
    )
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["fancy"].pin_style is PinStyle.TILDE
    assert deps["fancy"].version == "2.0"
    assert deps["gitpkg"].pin_style is PinStyle.GIT
    assert deps["gitpkg"].version == "main"
    assert deps["localpkg"].pin_style is PinStyle.PATH


def test_exclusion_operand_not_recorded_as_version(tmp_path: Path) -> None:
    # Shared classifier semantics: ``!=`` excludes its operand.
    body = '[packages]\nfoo = "!=1.5"\n'
    [d] = parse(_write(tmp_path, body))
    assert d.version is None
    assert d.pin_style is PinStyle.RANGE


def test_malformed_toml_returns_empty(tmp_path: Path) -> None:
    assert parse(_write(tmp_path, "[packages\nbroken")) == []


def test_dispatch_via_registry(tmp_path: Path) -> None:
    # Discovery classifies Pipfile as a PyPI manifest; the dispatcher
    # must find this parser (previously the file was silently dropped
    # with no parser registered).
    from packages.sca.parsers import _resolve
    p = _write(tmp_path, '[packages]\nrequests = "*"\n')
    fn = _resolve(p)
    assert fn is not None
    assert fn.__module__.endswith(".pipfile")
