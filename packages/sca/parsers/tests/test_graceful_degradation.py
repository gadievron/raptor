"""Graceful-degradation tests for parsers with optional dependencies.

When ``defusedxml``, ``packaging``, ``tomli``/``tomllib``, or ``PyYAML`` are
missing, the affected parser must (a) still import without error, (b)
return ``[]`` for any input, and (c) not crash the wider pipeline. We
simulate "missing" by patching the module's availability flag.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.parsers import gradle_lockfile  # noqa: F401 — sanity
from packages.sca.parsers import (
    pipfile_lock,
    pnpm_lock,
    poetry_lock,
    pom,
    pyproject,
    requirements,
    yarn_lock,
)


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_pom_skips_when_defusedxml_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(pom, "_AVAILABLE", False)
    p = _write(tmp_path, "pom.xml", "<project/>")
    assert pom.parse(p) == []


def test_requirements_skips_when_packaging_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(requirements, "_AVAILABLE", False)
    p = _write(tmp_path, "requirements.txt", "django==4.2.7\n")
    assert requirements.parse(p) == []


def test_pyproject_skips_when_tomllib_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(pyproject, "_tomllib", None)
    p = _write(tmp_path, "pyproject.toml", '[project]\ndependencies=["x"]\n')
    assert pyproject.parse(p) == []


def test_pyproject_pep508_skipped_when_packaging_missing(
    tmp_path, monkeypatch
) -> None:
    """Without packaging, PEP 508 specs are skipped but Poetry tool tables
    are still parsed (they don't need PEP 508)."""
    monkeypatch.setattr(pyproject, "_HAS_PACKAGING", False)
    p = _write(tmp_path, "pyproject.toml", """\
[project]
dependencies = ["django==4.2.7"]

[tool.poetry.dependencies]
rich = "^13.7"
""")
    deps = pyproject.parse(p)
    names = [d.name for d in deps]
    # The PEP 621 dep is silently dropped; the Poetry dep survives.
    assert names == ["rich"]


def test_poetry_lock_skips_when_tomllib_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(poetry_lock, "_tomllib", None)
    p = _write(tmp_path, "poetry.lock", '[[package]]\nname="x"\nversion="1"\n')
    assert poetry_lock.parse(p) == []


def test_pnpm_lock_skips_when_pyyaml_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(pnpm_lock, "_AVAILABLE", False)
    p = _write(tmp_path, "pnpm-lock.yaml", "lockfileVersion: '6.0'\n")
    assert pnpm_lock.parse(p) == []


def test_yarn_classic_works_without_pyyaml(tmp_path, monkeypatch) -> None:
    """Yarn classic v1 is line-based; missing PyYAML must not block it."""
    monkeypatch.setattr(yarn_lock, "_HAS_YAML", False)
    p = _write(tmp_path, "yarn.lock", """\
# yarn lockfile v1

lodash@^4:
  version "4.17.21"
""")
    deps = yarn_lock.parse(p)
    assert len(deps) == 1
    assert deps[0].name == "lodash"


def test_yarn_berry_skips_without_pyyaml(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(yarn_lock, "_HAS_YAML", False)
    p = _write(tmp_path, "yarn.lock", """\
__metadata:
  version: 6

"lodash@npm:^4":
  version: 4.17.21
""")
    assert yarn_lock.parse(p) == []


def test_pipfile_lock_unaffected_by_optional_libs(tmp_path) -> None:
    """Pipfile.lock only uses stdlib (json) and is unaffected by the
    optional-deps story; included here as a regression marker."""
    p = _write(tmp_path, "Pipfile.lock",
               '{"default": {"x": {"version": "==1.0"}}}')
    deps = pipfile_lock.parse(p)
    assert len(deps) == 1 and deps[0].name == "x"
