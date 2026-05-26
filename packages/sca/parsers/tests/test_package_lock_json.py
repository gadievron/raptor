"""Tests for the package-lock.json parser (npm v1, v2, v3)."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.package_lock_json import parse


def _write(tmp_path: Path, body: dict) -> Path:
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(body), encoding="utf-8")
    return p


def test_v3_packages_map_root_and_node_modules(tmp_path: Path) -> None:
    body = {
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "demo",
                "version": "1.0.0",
                "dependencies":     {"lodash": "^4.17.21"},
                "devDependencies":  {"jest": "~29.0.0"},
            },
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                "integrity": "sha512-x",
            },
            "node_modules/jest": {
                "version": "29.0.3",
                "dev": True,
            },
            "node_modules/@types/node": {
                "version": "20.10.5",
                "dev": True,
            },
        },
    }
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["lodash"].version == "4.17.21"
    assert deps["lodash"].direct is True
    assert deps["lodash"].scope == "main"
    assert deps["jest"].direct is True
    assert deps["jest"].scope == "dev"
    # @types/node is transitive — not in root deps.
    assert deps["@types/node"].direct is False


def test_v3_workspace_link_skipped(tmp_path: Path) -> None:
    body = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {}},
            "packages/inner": {"link": True, "version": "1.0"},
            "node_modules/inner": {
                "resolved": "packages/inner",
                "version": "1.0",
                "link": True,
            },
        },
    }
    deps = parse(_write(tmp_path, body))
    # Both link entries are skipped.
    assert deps == []


def test_v2_falls_back_to_packages_when_present(tmp_path: Path) -> None:
    body = {
        "lockfileVersion": 2,
        "packages": {
            "": {"dependencies": {"a": "^1"}},
            "node_modules/a": {"version": "1.2.3"},
        },
        "dependencies": {
            # The legacy tree is also present in v2 — must NOT be
            # double-counted; we prefer "packages".
            "a": {"version": "1.2.3"},
        },
    }
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].name == "a"
    assert deps[0].direct is True


def test_v1_legacy_tree(tmp_path: Path) -> None:
    body = {
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash",
            },
            "jest": {
                "version": "29.0.3",
                "dev": True,
                "dependencies": {
                    "deep-dep": {"version": "0.0.1", "dev": True},
                },
            },
        },
    }
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["lodash"].direct is True
    assert deps["lodash"].scope == "main"
    assert deps["jest"].scope == "dev"
    assert deps["deep-dep"].direct is False
    assert deps["deep-dep"].scope == "dev"


def test_git_resolved_url_classified(tmp_path: Path) -> None:
    body = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"x": "github:u/x"}},
            "node_modules/x": {
                "version": "0.0.0",
                "resolved": "git+https://github.com/u/x.git#abc123",
            },
        },
    }
    deps = parse(_write(tmp_path, body))
    assert deps[0].pin_style is PinStyle.GIT


def test_invalid_json_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "package-lock.json"
    p.write_text("{ broken", encoding="utf-8")
    assert parse(p) == []
