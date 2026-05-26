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
