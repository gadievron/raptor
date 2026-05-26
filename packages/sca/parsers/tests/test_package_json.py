"""Tests for the npm package.json parser."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.package_json import parse


def _write(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "package.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_basic_dependencies_dev_peer_optional(tmp_path: Path) -> None:
    p = _write(tmp_path, {
        "name": "x",
        "version": "1.0.0",
        "dependencies":          {"lodash": "^4.17.21"},
        "devDependencies":       {"jest": "~29.0.0"},
        "peerDependencies":      {"react": ">=17 <19"},
        "optionalDependencies":  {"fsevents": "*"},
    })
    deps = {(d.name, d.scope): d for d in parse(p)}
    assert deps[("lodash", "main")].pin_style is PinStyle.CARET
    assert deps[("lodash", "main")].version == "4.17.21"
    assert deps[("jest", "dev")].pin_style is PinStyle.TILDE
    assert deps[("react", "peer")].pin_style is PinStyle.RANGE
    assert deps[("fsevents", "optional")].pin_style is PinStyle.WILDCARD
    assert deps[("fsevents", "optional")].version is None


def test_scoped_package_keeps_at_prefix_and_purl(tmp_path: Path) -> None:
    p = _write(tmp_path, {
        "dependencies": {"@types/node": "20.10.0"},
    })
    deps = parse(p)
    assert len(deps) == 1
    d = deps[0]
    assert d.name == "@types/node"
    assert d.pin_style is PinStyle.EXACT
    assert d.purl == "pkg:npm/@types/node@20.10.0"


def test_git_url_is_classified_as_git(tmp_path: Path) -> None:
    p = _write(tmp_path, {
        "dependencies": {
            "x": "git+https://github.com/u/x.git#v1.2.3",
            "y": "github:user/repo#commit-sha",
        },
    })
    deps = {d.name: d for d in parse(p)}
    assert deps["x"].pin_style is PinStyle.GIT
    assert deps["x"].version == "v1.2.3"
    assert deps["y"].pin_style is PinStyle.GIT
    assert deps["y"].version == "commit-sha"


def test_local_path_is_path_pin(tmp_path: Path) -> None:
    p = _write(tmp_path, {
        "dependencies": {
            "a": "file:./libs/a",
            "b": "../sibling-pkg",
        },
    })
    deps = {d.name: d for d in parse(p)}
    assert deps["a"].pin_style is PinStyle.PATH
    assert deps["b"].pin_style is PinStyle.PATH


def test_npm_alias_records_real_target(tmp_path: Path) -> None:
    p = _write(tmp_path, {
        "dependencies": {"my-lodash": "npm:lodash@^4.17.21"},
    })
    deps = parse(p)
    assert len(deps) == 1
    d = deps[0]
    # Name keeps the alias so the user sees what they wrote, but the
    # purl reflects the real installed package.
    assert d.name == "my-lodash"
    assert d.pin_style is PinStyle.CARET
    assert d.version == "4.17.21"
    assert d.purl == "pkg:npm/lodash@4.17.21"


def test_bundle_dependencies_is_recorded(tmp_path: Path) -> None:
    p = _write(tmp_path, {
        "dependencies": {"x": "1.0.0"},
        "bundledDependencies": ["x"],
    })
    deps = parse(p)
    # x appears once in dependencies and once as a bundle entry —
    # downstream dedup will collapse on (name, version); the parser is
    # honest about both signals.
    assert len(deps) == 2
    assert any(d.parser_confidence.reason.startswith("bundleDependencies")
               for d in deps)


def test_invalid_json_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "package.json"
    p.write_text("{ not json", encoding="utf-8")
    assert parse(p) == []


def test_top_level_array_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "package.json"
    p.write_text("[]", encoding="utf-8")
    assert parse(p) == []


def test_non_string_spec_is_skipped(tmp_path: Path) -> None:
    p = _write(tmp_path, {
        "dependencies": {
            "ok": "1.0.0",
            "weird": {"version": "1.0.0"},  # lockfile-style; not valid here
        },
    })
    deps = parse(p)
    assert len(deps) == 1
    assert deps[0].name == "ok"
