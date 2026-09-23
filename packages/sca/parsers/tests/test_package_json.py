"""Tests for the npm package.json parser."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.package_json import extract_project_license, parse


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
    # ``name`` is the REAL installed package — OSV queries key on it,
    # so recording the alias spelling hid lodash's advisories in
    # lockfile-less projects. The manifest spelling survives in
    # ``alias_name`` for display and fix-materialisation.
    assert d.name == "lodash"
    assert d.alias_name == "my-lodash"
    assert d.pin_style is PinStyle.CARET
    assert d.version == "4.17.21"
    assert d.purl == "pkg:npm/lodash@4.17.21"
    # The corridor comes from the range after the alias target.
    assert d.version_floor == "4.17.21"


def test_npm_alias_scoped_target(tmp_path: Path) -> None:
    p = _write(tmp_path, {
        "dependencies": {"legacy-form": "npm:@scope/real@~1.2.3"},
    })
    deps = parse(p)
    assert len(deps) == 1
    d = deps[0]
    assert d.name == "@scope/real"
    assert d.alias_name == "legacy-form"
    assert d.pin_style is PinStyle.TILDE
    assert d.purl == "pkg:npm/@scope/real@1.2.3"


def test_npm_alias_self_alias_and_protocol_form(tmp_path: Path) -> None:
    # ``npm:lodash@^4`` under the same name is a version-forcing
    # self-alias — no alias_name; ``npm:^4.17.21`` is the bare
    # protocol-range form, whose range must never become a name.
    p = _write(tmp_path, {
        "dependencies": {
            "lodash": "npm:lodash@^4.17.21",
            "ms": "npm:^2.1.3",
        },
    })
    deps = {d.name: d for d in parse(p)}
    assert set(deps) == {"lodash", "ms"}
    assert deps["lodash"].alias_name is None
    assert deps["lodash"].version == "4.17.21"
    assert deps["ms"].alias_name is None
    assert deps["ms"].pin_style is PinStyle.CARET
    assert deps["ms"].purl == "pkg:npm/ms@2.1.3"


def test_non_aliased_dep_unchanged_by_alias_handling(tmp_path: Path) -> None:
    p = _write(tmp_path, {
        "dependencies": {"lodash": "^4.17.21"},
    })
    deps = parse(p)
    assert len(deps) == 1
    d = deps[0]
    assert d.name == "lodash"
    assert d.alias_name is None
    assert d.pin_style is PinStyle.CARET
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


# ---------------------------------------------------------------------------
# Project license — describes the project itself, never its deps
# ---------------------------------------------------------------------------


def test_extract_project_license_spdx_string(tmp_path: Path) -> None:
    p = _write(tmp_path, {"name": "x", "license": "MIT"})
    assert extract_project_license(p) == "MIT"


def test_extract_project_license_legacy_object(tmp_path: Path) -> None:
    p = _write(tmp_path, {"license": {"type": "ISC", "url": "https://x"}})
    assert extract_project_license(p) == "ISC"


def test_extract_project_license_deprecated_array(tmp_path: Path) -> None:
    p = _write(tmp_path, {"licenses": [{"type": "MIT"}, {"type": "ISC"}]})
    assert extract_project_license(p) == "MIT OR ISC"


def test_extract_project_license_absent(tmp_path: Path) -> None:
    p = _write(tmp_path, {"dependencies": {"lodash": "^4.17.21"}})
    assert extract_project_license(p) is None


def test_extract_project_license_malformed_json(tmp_path: Path) -> None:
    p = tmp_path / "package.json"
    p.write_text("{ not json", encoding="utf-8")
    assert extract_project_license(p) is None


def test_dep_rows_never_carry_the_project_license(tmp_path: Path) -> None:
    # Manifest-level license describes the project itself, not its
    # deps — a dep's declared_license only ever comes from data that
    # describes that dep (registry enrichment), or stays None.
    p = _write(tmp_path, {
        "license": "MIT",
        "dependencies": {"lodash": "^4.17.21"},
        "devDependencies": {"jest": "~29.0.0"},
    })
    deps = parse(p)
    assert deps
    assert all(d.declared_license is None for d in deps)


def test_npm_alias_digit_leading_target(tmp_path: Path) -> None:
    p = _write(tmp_path, {
        "dependencies": {"zip": "npm:7zip-bin@^5.0.0"},
    })
    [d] = parse(p)
    assert d.name == "7zip-bin"
    assert d.alias_name == "zip"
    assert d.pin_style is PinStyle.CARET
    assert d.purl == "pkg:npm/7zip-bin@5.0.0"


def test_npm_protocol_bare_version_not_a_name(tmp_path: Path) -> None:
    # ``npm:4.17.21`` / ``npm:1.x`` pin a version of the declared
    # package — a version token must never become the canonical name.
    p = _write(tmp_path, {
        "dependencies": {"lodash": "npm:4.17.21", "ms": "npm:2.x"},
    })
    deps = {d.name: d for d in parse(p)}
    assert set(deps) == {"lodash", "ms"}
    assert deps["lodash"].version == "4.17.21"
    assert deps["lodash"].alias_name is None
    assert deps["ms"].alias_name is None


def test_npm_malformed_scope_target_stays_unknown(tmp_path: Path) -> None:
    # ``npm:@scope`` (scope marker, no name) — neither a name nor a
    # range; the scope marker must not leak into version/purl.
    p = _write(tmp_path, {"dependencies": {"x": "npm:@scope"}})
    [d] = parse(p)
    assert d.name == "x"
    assert d.version is None
    assert d.purl == "pkg:npm/x"
    assert d.pin_style is PinStyle.UNKNOWN


def test_all_digit_bare_version_is_exact_not_git(tmp_path):
    """"1234567" is hex-shaped but far likelier a bare version than a
    commit that spells only digits — a git classification suppressed
    the EXACT pin (and its registry lookup) for a real version."""
    p = tmp_path / "package.json"
    p.write_text(
        '{"dependencies": {"leftpad": "1234567", '
        '"pinned": "deadbeefcafe"}}',
        encoding="utf-8",
    )
    deps = {d.name: d for d in parse(p)}
    assert deps["leftpad"].pin_style is PinStyle.EXACT
    assert deps["leftpad"].version == "1234567"
    # A sha with hex letters keeps the git classification.
    assert deps["pinned"].pin_style is PinStyle.GIT
