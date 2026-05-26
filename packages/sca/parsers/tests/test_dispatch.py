"""Tests for parser dispatch (``parse_manifest`` registry)."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import Manifest
from packages.sca.parsers import parse_manifest


def _make_manifest(path: Path, ecosystem: str, is_lockfile: bool = False) -> Manifest:
    return Manifest(path=path, ecosystem=ecosystem, is_lockfile=is_lockfile)


def test_dispatch_pom(tmp_path: Path) -> None:
    p = tmp_path / "pom.xml"
    p.write_text("""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies><dependency>
    <groupId>g</groupId><artifactId>a</artifactId><version>1.0</version>
  </dependency></dependencies>
</project>""", encoding="utf-8")
    deps = parse_manifest(_make_manifest(p, "Maven"))
    assert len(deps) == 1
    assert deps[0].ecosystem == "Maven"


def test_dispatch_package_json(tmp_path: Path) -> None:
    p = tmp_path / "package.json"
    p.write_text('{"dependencies": {"x": "1.0.0"}}', encoding="utf-8")
    deps = parse_manifest(_make_manifest(p, "npm"))
    assert deps[0].ecosystem == "npm"


def test_dispatch_pyproject(tmp_path: Path) -> None:
    p = tmp_path / "pyproject.toml"
    p.write_text('[project]\ndependencies=["x==1.0"]\n', encoding="utf-8")
    deps = parse_manifest(_make_manifest(p, "PyPI"))
    assert deps[0].ecosystem == "PyPI"
    assert deps[0].name == "x"


def test_dispatch_requirements_default_name(tmp_path: Path) -> None:
    p = tmp_path / "requirements.txt"
    p.write_text("django==4.2.7\n", encoding="utf-8")
    deps = parse_manifest(_make_manifest(p, "PyPI"))
    assert deps[0].name == "django"


def test_dispatch_requirements_variant_name(tmp_path: Path) -> None:
    # requirements-dev.txt, requirements_test.txt, requirements.in — all
    # the discovery layer feeds in must dispatch via the predicate.
    p = tmp_path / "requirements-dev.txt"
    p.write_text("pytest>=7\n", encoding="utf-8")
    deps = parse_manifest(_make_manifest(p, "PyPI"))
    assert len(deps) == 1
    assert deps[0].name == "pytest"


def test_dispatch_unknown_filename_is_empty(tmp_path: Path) -> None:
    p = tmp_path / "unknown.toml"
    p.write_text("", encoding="utf-8")
    deps = parse_manifest(_make_manifest(p, "PyPI"))
    assert deps == []


def test_parser_exception_does_not_propagate(tmp_path: Path, monkeypatch) -> None:
    """A parser blowing up must not abort dispatch."""
    from packages.sca.parsers import _REGISTRY

    def boom(_: Path):
        raise RuntimeError("synthetic")

    p = tmp_path / "package.json"
    p.write_text("{}", encoding="utf-8")
    monkeypatch.setitem(_REGISTRY, "package.json", boom)
    deps = parse_manifest(_make_manifest(p, "npm"))
    assert deps == []
