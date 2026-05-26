"""Tests for the Composer (PHP) parser."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.composer import parse_lockfile, parse_manifest


def _write_json(tmp_path: Path, body: dict, name: str) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(body), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# composer.json — manifest
# ---------------------------------------------------------------------------

def test_basic_require(tmp_path: Path) -> None:
    p = _write_json(tmp_path, {
        "require": {
            "symfony/console": "^6.4",
            "monolog/monolog": "3.5.0",
        }
    }, "composer.json")
    by_name = {d.name: d for d in parse_manifest(p)}
    assert by_name["symfony/console"].pin_style is PinStyle.CARET
    assert by_name["symfony/console"].version == "6.4"
    assert by_name["monolog/monolog"].pin_style is PinStyle.EXACT


def test_require_dev_separate_scope(tmp_path: Path) -> None:
    p = _write_json(tmp_path, {
        "require": {"symfony/console": "^6.4"},
        "require-dev": {"phpunit/phpunit": "^10.0"},
    }, "composer.json")
    by_name = {d.name: d for d in parse_manifest(p)}
    assert by_name["symfony/console"].scope == "main"
    assert by_name["phpunit/phpunit"].scope == "dev"


def test_platform_requirements_skipped(tmp_path: Path) -> None:
    """``php``, ``ext-*``, ``lib-*``, ``hhvm`` are not Packagist deps."""
    p = _write_json(tmp_path, {
        "require": {
            "php": ">=8.1",
            "ext-mbstring": "*",
            "ext-json": "*",
            "lib-pcre": "*",
            "hhvm": "*",
            "symfony/console": "^6.4",
        }
    }, "composer.json")
    deps = parse_manifest(p)
    assert {d.name for d in deps} == {"symfony/console"}


def test_tilde_pin(tmp_path: Path) -> None:
    p = _write_json(tmp_path, {
        "require": {"foo/bar": "~1.2.3"}
    }, "composer.json")
    deps = parse_manifest(p)
    assert deps[0].pin_style is PinStyle.TILDE


def test_range_with_pipe_or_comma(tmp_path: Path) -> None:
    p = _write_json(tmp_path, {
        "require": {
            "foo/or": "^1.0|^2.0",
            "foo/and": ">=1.0,<2.0",
        }
    }, "composer.json")
    by_name = {d.name: d for d in parse_manifest(p)}
    assert by_name["foo/or"].pin_style is PinStyle.RANGE
    assert by_name["foo/and"].pin_style is PinStyle.RANGE


def test_dev_branch_treated_as_git(tmp_path: Path) -> None:
    p = _write_json(tmp_path, {
        "require": {"foo/bar": "dev-master"}
    }, "composer.json")
    deps = parse_manifest(p)
    assert deps[0].pin_style is PinStyle.GIT
    assert deps[0].version == "dev-master"


def test_wildcard(tmp_path: Path) -> None:
    p = _write_json(tmp_path, {
        "require": {"foo/bar": "*"}
    }, "composer.json")
    deps = parse_manifest(p)
    assert deps[0].pin_style is PinStyle.WILDCARD


def test_v_prefixed_exact(tmp_path: Path) -> None:
    p = _write_json(tmp_path, {
        "require": {"foo/bar": "v1.2.3"}
    }, "composer.json")
    deps = parse_manifest(p)
    assert deps[0].pin_style is PinStyle.EXACT
    assert deps[0].version == "v1.2.3"


def test_malformed_json_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "composer.json"
    p.write_text("{not valid json", encoding="utf-8")
    assert parse_manifest(p) == []


# ---------------------------------------------------------------------------
# composer.lock — lockfile
# ---------------------------------------------------------------------------

def test_lockfile_basic(tmp_path: Path) -> None:
    p = _write_json(tmp_path, {
        "packages": [
            {"name": "symfony/console", "version": "v6.4.0",
             "source": {"type": "git", "url": "...", "reference": "abc"}},
            {"name": "monolog/monolog", "version": "3.5.0"},
        ],
        "packages-dev": [
            {"name": "phpunit/phpunit", "version": "10.0.0"},
        ],
    }, "composer.lock")
    deps = parse_lockfile(p)
    by_name = {d.name: d for d in deps}
    assert by_name["symfony/console"].version == "v6.4.0"
    # Release tag in source=git → still EXACT (not GIT) since it's a tag.
    assert by_name["symfony/console"].pin_style is PinStyle.EXACT
    assert by_name["phpunit/phpunit"].scope == "dev"
    assert by_name["monolog/monolog"].is_lockfile is True


def test_lockfile_dev_branch_keeps_git_pin(tmp_path: Path) -> None:
    """``dev-master`` from a git source stays GIT (not a release tag)."""
    p = _write_json(tmp_path, {
        "packages": [
            {"name": "foo/bar", "version": "dev-master",
             "source": {"type": "git", "url": "...", "reference": "abc"}},
        ]
    }, "composer.lock")
    deps = parse_lockfile(p)
    assert deps[0].pin_style is PinStyle.GIT


# ---------------------------------------------------------------------------
# Discovery → parser dispatch
# ---------------------------------------------------------------------------

def test_dispatch_via_discovery(tmp_path: Path) -> None:
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import parse_manifest as dispatch
    repo = tmp_path / "php-proj"
    repo.mkdir()
    (repo / "composer.json").write_text(
        json.dumps({"require": {"symfony/console": "^6.4"}}),
        encoding="utf-8",
    )
    manifests = find_manifests(repo)
    cj = next(m for m in manifests if m.path.name == "composer.json")
    assert cj.ecosystem == "Packagist"
    deps = dispatch(cj)
    assert deps and deps[0].name == "symfony/console"
