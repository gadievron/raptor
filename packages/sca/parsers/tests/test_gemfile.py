"""Tests for the RubyGems parser (Gemfile + Gemfile.lock)."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.gemfile import parse_lockfile, parse_manifest


def _write(tmp_path: Path, body: str, name: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Gemfile — manifest
# ---------------------------------------------------------------------------

def test_unpinned(tmp_path: Path) -> None:
    body = """\
source 'https://rubygems.org'

gem 'rails'
"""
    p = _write(tmp_path, body, "Gemfile")
    deps = parse_manifest(p)
    assert len(deps) == 1
    assert deps[0].name == "rails"
    assert deps[0].version is None
    assert deps[0].pin_style is PinStyle.WILDCARD


def test_exact_pin(tmp_path: Path) -> None:
    body = """gem 'rails', '7.1.2'\n"""
    p = _write(tmp_path, body, "Gemfile")
    deps = parse_manifest(p)
    assert deps[0].version == "7.1.2"
    assert deps[0].pin_style is PinStyle.EXACT


def test_tilde_arrow_pin(tmp_path: Path) -> None:
    """``~>`` is RubyGems' "twiddle-wakka" — tilde semantics."""
    body = """gem 'rails', '~> 7.1'\n"""
    p = _write(tmp_path, body, "Gemfile")
    deps = parse_manifest(p)
    assert deps[0].pin_style is PinStyle.TILDE
    assert deps[0].version == "7.1"


def test_range_pin(tmp_path: Path) -> None:
    body = """gem 'rails', '>= 7.0', '< 8.0'\n"""
    p = _write(tmp_path, body, "Gemfile")
    deps = parse_manifest(p)
    assert deps[0].pin_style is PinStyle.RANGE


def test_git_dependency(tmp_path: Path) -> None:
    body = """gem 'rails', git: 'https://github.com/rails/rails', tag: 'v7.1'\n"""
    p = _write(tmp_path, body, "Gemfile")
    deps = parse_manifest(p)
    assert len(deps) == 1
    assert deps[0].pin_style is PinStyle.GIT


def test_github_shorthand_dependency(tmp_path: Path) -> None:
    body = """gem 'rails', github: 'rails/rails'\n"""
    p = _write(tmp_path, body, "Gemfile")
    deps = parse_manifest(p)
    assert deps[0].pin_style is PinStyle.GIT


def test_path_dependency(tmp_path: Path) -> None:
    body = """gem 'mygem', path: '../local-mygem'\n"""
    p = _write(tmp_path, body, "Gemfile")
    deps = parse_manifest(p)
    assert deps[0].pin_style is PinStyle.PATH


def test_double_quoted_form(tmp_path: Path) -> None:
    body = """gem "rails", "~> 7.1"\n"""
    p = _write(tmp_path, body, "Gemfile")
    deps = parse_manifest(p)
    assert deps[0].name == "rails"
    assert deps[0].pin_style is PinStyle.TILDE


def test_comment_line_skipped(tmp_path: Path) -> None:
    body = """\
# gem 'should-not-appear'
gem 'rails', '7.1.2'
"""
    p = _write(tmp_path, body, "Gemfile")
    deps = parse_manifest(p)
    assert len(deps) == 1
    assert deps[0].name == "rails"


def test_inline_comment_stripped(tmp_path: Path) -> None:
    body = """gem 'rails', '7.1.2'  # latest stable\n"""
    p = _write(tmp_path, body, "Gemfile")
    deps = parse_manifest(p)
    assert deps[0].version == "7.1.2"


def test_control_flow_lowers_confidence(tmp_path: Path) -> None:
    """A Gemfile with ``if`` blocks gets medium confidence to flag that
    we may have missed a conditionally-included gem."""
    body = """\
if ENV['RAILS_ENV'] == 'production'
  gem 'rails', '7.1.2'
end
"""
    p = _write(tmp_path, body, "Gemfile")
    deps = parse_manifest(p)
    assert deps[0].parser_confidence.level == "medium"


# ---------------------------------------------------------------------------
# Gemfile.lock — lockfile
# ---------------------------------------------------------------------------

def test_lockfile_extracts_top_level_gems(tmp_path: Path) -> None:
    body = """\
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.1.2)
      activesupport (= 7.1.2)
      rack (>= 2.2.4)
    actionview (7.1.2)
      activesupport (= 7.1.2)
    activesupport (7.1.2)

PLATFORMS
  ruby

DEPENDENCIES
  rails

BUNDLED WITH
   2.4.10
"""
    p = _write(tmp_path, body, "Gemfile.lock")
    deps = parse_lockfile(p)
    by_name = {d.name: d for d in deps}
    assert "actionpack" in by_name
    assert "actionview" in by_name
    assert "activesupport" in by_name
    # Inner-indented deps (rack, the runtime requirement of actionpack)
    # only count when they appear as their own top-level row — which
    # rack does NOT in this fixture, so it shouldn't be present.
    assert "rack" not in by_name
    assert by_name["actionpack"].version == "7.1.2"
    assert by_name["actionpack"].pin_style is PinStyle.EXACT
    assert by_name["actionpack"].is_lockfile is True


def test_lockfile_dedup(tmp_path: Path) -> None:
    body = """\
GEM
  specs:
    foo (1.0)
    foo (1.0)
"""
    p = _write(tmp_path, body, "Gemfile.lock")
    deps = parse_lockfile(p)
    assert len(deps) == 1


# ---------------------------------------------------------------------------
# Discovery → parser dispatch
# ---------------------------------------------------------------------------

def test_dispatch_via_discovery(tmp_path: Path) -> None:
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import parse_manifest as dispatch

    repo = tmp_path / "ruby-proj"
    repo.mkdir()
    (repo / "Gemfile").write_text(
        "gem 'rails', '7.1.2'\n", encoding="utf-8")
    manifests = find_manifests(repo)
    gf = next(m for m in manifests if m.path.name == "Gemfile")
    assert gf.ecosystem == "RubyGems"
    deps = dispatch(gf)
    assert deps and deps[0].name == "rails"


# ---------------------------------------------------------------------------
# Gemfile.lock variants — release-time / migration lockfiles
# ---------------------------------------------------------------------------

_VARIANT_LOCK_BODY = """\
GEM
  remote: https://rubygems.org/
  specs:
    activerecord (7.1.2)
    activesupport (7.1.2)

PLATFORMS
  ruby

DEPENDENCIES
  activerecord
"""


def test_lockfile_release_variant_parses(tmp_path: Path) -> None:
    """ManageIQ ships ``Gemfile.lock.release`` instead of ``Gemfile.lock``."""
    p = _write(tmp_path, _VARIANT_LOCK_BODY, "Gemfile.lock.release")
    deps = parse_lockfile(p)
    by_name = {d.name: d for d in deps}
    assert "activerecord" in by_name
    assert by_name["activerecord"].version == "7.1.2"
    assert by_name["activerecord"].is_lockfile is True


def test_lockfile_next_variant_parses(tmp_path: Path) -> None:
    """Some Rails monoliths use ``Gemfile.lock.next`` during gem migrations."""
    p = _write(tmp_path, _VARIANT_LOCK_BODY, "Gemfile.lock.next")
    deps = parse_lockfile(p)
    assert {d.name for d in deps} == {"activerecord", "activesupport"}


def test_discovery_routes_lockfile_variant(tmp_path: Path) -> None:
    """End-to-end: discovery classifies Gemfile.lock.release + dispatcher
    finds the right parser via predicate."""
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import parse_manifest as dispatch

    repo = tmp_path / "miq-like"
    repo.mkdir()
    (repo / "Gemfile").write_text(
        "gem 'activerecord'\n", encoding="utf-8")
    (repo / "Gemfile.lock.release").write_text(
        _VARIANT_LOCK_BODY, encoding="utf-8")

    manifests = find_manifests(repo)
    lock = next(m for m in manifests
                if m.path.name == "Gemfile.lock.release")
    assert lock.ecosystem == "RubyGems"
    assert lock.is_lockfile is True
    deps = dispatch(lock)
    assert {d.name for d in deps} == {"activerecord", "activesupport"}


def test_discovery_does_not_route_gemfile_modules(tmp_path: Path) -> None:
    """``Gemfile.modules`` (OpenProject DSL fragment, NOT a lockfile)
    must not be misclassified as a RubyGems lockfile."""
    from packages.sca.discovery import find_manifests

    repo = tmp_path / "op-like"
    repo.mkdir()
    (repo / "Gemfile.modules").write_text(
        "# DSL fragment, not a lockfile\n", encoding="utf-8")

    manifests = find_manifests(repo)
    # Either skipped entirely, or classified as something other than a
    # RubyGems lockfile (current behaviour: not classified at all).
    misclassified = [
        m for m in manifests
        if m.path.name == "Gemfile.modules"
        and m.ecosystem == "RubyGems"
        and m.is_lockfile
    ]
    assert misclassified == []
