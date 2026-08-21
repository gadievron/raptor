"""Tests for the pnpm-lock.yaml parser."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.pnpm_lock import parse


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "pnpm-lock.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_v6_importers_format(tmp_path: Path) -> None:
    body = """\
lockfileVersion: '6.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21
    devDependencies:
      jest:
        specifier: ~29.0.0
        version: 29.0.3

packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-x}
    dev: false
  /jest@29.0.3:
    resolution: {integrity: sha512-y}
    dev: true
  /@types/node@20.10.5:
    resolution: {integrity: sha512-z}
    dev: true
"""
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["lodash"].version == "4.17.21"
    assert deps["lodash"].direct is True
    assert deps["lodash"].scope == "main"
    assert deps["jest"].scope == "dev"
    assert deps["jest"].direct is True
    # @types/node is not in importers — transitive.
    assert deps["@types/node"].direct is False
    assert deps["@types/node"].scope == "dev"


def test_v5_slash_format(tmp_path: Path) -> None:
    body = """\
lockfileVersion: 5.4

dependencies:
  lodash: 4.17.21

packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-x}
  /@types/node/20.10.5:
    resolution: {integrity: sha512-z}
    dev: true
"""
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["lodash"].version == "4.17.21"
    assert deps["lodash"].direct is True
    assert deps["@types/node"].direct is False
    assert deps["@types/node"].scope == "dev"


def test_peer_resolution_suffix_stripped(tmp_path: Path) -> None:
    """pnpm encodes peer-dep resolution into the key like
    ``29.0.3(typescript@5.0)``; the OSV-relevant version is the prefix."""
    body = """\
lockfileVersion: '6.0'
packages:
  /jest@29.0.3(typescript@5.0):
    resolution: {integrity: sha512-x}
"""
    deps = parse(_write(tmp_path, body))
    assert deps[0].name == "jest"
    assert deps[0].version == "29.0.3"


_V9_BODY = """\
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21
    devDependencies:
      jest:
        specifier: ~29.0.0
        version: 29.0.3(typescript@5.0.4)

packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-x}
  jest@29.0.3:
    resolution: {integrity: sha512-y}
  '@types/node@20.10.5':
    resolution: {integrity: sha512-z}

snapshots:
  lodash@4.17.21: {}
  jest@29.0.3(typescript@5.0.4):
    dependencies:
      '@types/node': 20.10.5
  '@types/node@20.10.5': {}
"""


def test_v9_no_slash_keys(tmp_path: Path) -> None:
    """lockfileVersion 9 drops the leading slash from packages keys and
    moves the resolved graph to ``snapshots``."""
    deps = {d.name: d for d in parse(_write(tmp_path, _V9_BODY))}
    assert deps["lodash"].version == "4.17.21"
    assert deps["lodash"].direct is True
    assert deps["jest"].version == "29.0.3"
    assert deps["jest"].direct is True
    # Scoped name, only reachable transitively.
    assert deps["@types/node"].version == "20.10.5"
    assert deps["@types/node"].direct is False


def test_v9_snapshot_only_entry_and_peer_suffix(tmp_path: Path) -> None:
    """Snapshot keys carry the peer suffix; an entry present only under
    ``snapshots`` still produces a row (transitive resolution)."""
    body = """\
lockfileVersion: '9.0'
packages:
  jest@29.0.3:
    resolution: {integrity: sha512-y}
snapshots:
  jest@29.0.3(typescript@5.0.4): {}
  '@scope/only-in-snapshots@1.2.3(react@18.2.0)': {}
"""
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["jest"].version == "29.0.3"
    assert deps["@scope/only-in-snapshots"].version == "1.2.3"
    # Peer-suffixed snapshot of the same (name, version) dedupes.
    assert len([d for d in parse(_write(tmp_path, body))
                if d.name == "jest"]) == 1


def test_v9_non_registry_version_token(tmp_path: Path) -> None:
    """``file:`` / ``link:`` version tokens are not registry versions —
    no fake OSV match key is recorded."""
    body = """\
lockfileVersion: '9.0'
packages:
  mylocal@file:packages/mylocal:
    resolution: {directory: packages/mylocal, type: directory}
"""
    deps = parse(_write(tmp_path, body))
    assert deps[0].name == "mylocal"
    assert deps[0].version is None


def test_zero_parse_with_nonempty_packages_warns(
    tmp_path: Path, caplog,
) -> None:
    """A packages map that yields no rows is a parse failure, not a
    clean project — the operator must see why."""
    import logging
    body = """\
lockfileVersion: '99.0'
packages:
  '???unrecognised-key-shape???':
    resolution: {integrity: sha512-x}
"""
    with caplog.at_level(logging.WARNING,
                         logger="packages.sca.parsers.pnpm_lock"):
        deps = parse(_write(tmp_path, body))
    assert deps == []
    assert any("none parsed" in r.getMessage() for r in caplog.records)


def test_git_resolution(tmp_path: Path) -> None:
    body = """\
lockfileVersion: '6.0'
packages:
  /fork@0.0.0:
    resolution:
      repo: https://github.com/u/x.git
      commit: deadbeef
"""
    deps = parse(_write(tmp_path, body))
    assert deps[0].pin_style is PinStyle.GIT


def test_malformed_yaml_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "pnpm-lock.yaml"
    p.write_text("[: not yaml :", encoding="utf-8")
    assert parse(p) == []
