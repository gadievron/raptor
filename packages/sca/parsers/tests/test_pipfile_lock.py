"""Tests for the Pipfile.lock parser."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.pipfile_lock import parse


def _write(tmp_path: Path, body: dict) -> Path:
    p = tmp_path / "Pipfile.lock"
    p.write_text(json.dumps(body), encoding="utf-8")
    return p


def test_default_and_develop_sections(tmp_path: Path) -> None:
    body = {
        "_meta": {"hash": {"sha256": "x"}},
        "default": {
            "django": {"version": "==4.2.7", "hashes": []},
        },
        "develop": {
            "pytest": {"version": "==7.4.0", "markers": "x"},
        },
    }
    deps = {(d.name, d.scope): d for d in parse(_write(tmp_path, body))}
    assert deps[("django", "main")].version == "4.2.7"
    assert deps[("django", "main")].pin_style is PinStyle.EXACT
    assert deps[("django", "main")].is_lockfile is True
    assert deps[("django", "main")].direct is False
    assert deps[("pytest", "dev")].version == "7.4.0"
    assert deps[("pytest", "dev")].purl == "pkg:pypi/pytest@7.4.0"


def test_git_source_uses_ref(tmp_path: Path) -> None:
    body = {
        "default": {
            "fork": {"git": "https://github.com/u/r.git", "ref": "abc123"},
        },
    }
    deps = parse(_write(tmp_path, body))
    assert deps[0].pin_style is PinStyle.GIT
    assert deps[0].version == "abc123"


def test_path_source(tmp_path: Path) -> None:
    body = {"default": {"local": {"path": "../local"}}}
    deps = parse(_write(tmp_path, body))
    assert deps[0].pin_style is PinStyle.PATH


def test_pep503_normalisation(tmp_path: Path) -> None:
    body = {"default": {"Foo_Bar.Baz": {"version": "==1.0"}}}
    deps = parse(_write(tmp_path, body))
    assert deps[0].name == "foo-bar-baz"
    assert deps[0].purl == "pkg:pypi/foo-bar-baz@1.0"


def test_invalid_json_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "Pipfile.lock"
    p.write_text("not json", encoding="utf-8")
    assert parse(p) == []
