"""Tests for the ``libs.versions.toml`` rewriter."""

from __future__ import annotations

from pathlib import Path

from packages.sca.rewriters import RewriteEdit, rewrite
from packages.sca.rewriters.gradle_version_catalog import (
    rewrite_libs_versions_toml,
)


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "libs.versions.toml"
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# [versions] section
# ---------------------------------------------------------------------------

def test_rewrites_versions_table_entry(tmp_path: Path):
    """Most common bumper target: update a ``[versions]`` entry
    so every library that uses ``version.ref = "spring-boot"``
    picks up the new value."""
    p = _write(tmp_path, """\
[versions]
spring-boot = "3.1.0"
junit = "5.9.0"

[libraries]
spring-boot-starter = { module = "org.springframework.boot:spring-boot-starter", version.ref = "spring-boot" }
""")
    results = rewrite_libs_versions_toml(p, [RewriteEdit(
        locator="version:spring-boot",
        old_value="3.1.0", new_value="3.2.0",
    )])
    assert results[0].applied is True
    body = p.read_text()
    assert 'spring-boot = "3.2.0"' in body
    # Adjacent entries untouched.
    assert 'junit = "5.9.0"' in body


def test_versions_value_mismatch(tmp_path: Path):
    p = _write(tmp_path, """\
[versions]
spring = "3.2.0"
""")
    results = rewrite_libs_versions_toml(p, [RewriteEdit(
        locator="version:spring",
        old_value="3.1.0", new_value="3.2.0",
    )])
    assert results[0].applied is False
    assert "value_mismatch" in results[0].reason


def test_versions_not_found(tmp_path: Path):
    p = _write(tmp_path, """\
[versions]
spring = "3.1.0"
""")
    results = rewrite_libs_versions_toml(p, [RewriteEdit(
        locator="version:missing",
        old_value="1.0.0", new_value="2.0.0",
    )])
    assert results[0].applied is False
    assert results[0].reason == "not_found"


# ---------------------------------------------------------------------------
# [libraries] section
# ---------------------------------------------------------------------------

def test_rewrites_inline_library_version(tmp_path: Path):
    """``alias = { module = "g:a", version = "x" }`` — inline
    version, NO version.ref. Bumper targets THIS line; no
    [versions] table involvement."""
    p = _write(tmp_path, """\
[libraries]
foo = { module = "com.example:foo", version = "1.2.3" }
""")
    results = rewrite_libs_versions_toml(p, [RewriteEdit(
        locator="library:foo",
        old_value="1.2.3", new_value="1.2.4",
    )])
    assert results[0].applied is True
    assert 'version = "1.2.4"' in p.read_text()


def test_rewrites_string_shorthand_library(tmp_path: Path):
    """``alias = "g:a:v"`` shorthand — update the trailing
    version segment of the string."""
    p = _write(tmp_path, """\
[libraries]
guava = "com.google.guava:guava:32.1.2-jre"
""")
    results = rewrite_libs_versions_toml(p, [RewriteEdit(
        locator="library:guava",
        old_value="32.1.2-jre", new_value="32.2.0-jre",
    )])
    assert results[0].applied is True
    assert '"com.google.guava:guava:32.2.0-jre"' in p.read_text()


def test_library_value_mismatch(tmp_path: Path):
    p = _write(tmp_path, """\
[libraries]
guava = "com.google.guava:guava:32.2.0-jre"
""")
    results = rewrite_libs_versions_toml(p, [RewriteEdit(
        locator="library:guava",
        old_value="32.1.2-jre", new_value="33.0.0-jre",
    )])
    assert results[0].applied is False
    assert "value_mismatch" in results[0].reason


# ---------------------------------------------------------------------------
# [plugins] section
# ---------------------------------------------------------------------------

def test_rewrites_plugin_inline_version(tmp_path: Path):
    p = _write(tmp_path, """\
[plugins]
spotless = { id = "com.diffplug.spotless", version = "6.20.0" }
""")
    results = rewrite_libs_versions_toml(p, [RewriteEdit(
        locator="plugin:spotless",
        old_value="6.20.0", new_value="6.21.0",
    )])
    assert results[0].applied is True
    assert 'version = "6.21.0"' in p.read_text()


# ---------------------------------------------------------------------------
# Dispatch + multi-edit invariants
# ---------------------------------------------------------------------------

def test_dispatch_via_registry(tmp_path: Path):
    p = _write(tmp_path, """\
[versions]
foo = "1.0.0"
""")
    results = rewrite(p, [RewriteEdit(
        locator="version:foo",
        old_value="1.0.0", new_value="1.1.0",
    )])
    assert results[0].applied is True


def test_unknown_section_returns_helpful_reason(tmp_path: Path):
    p = _write(tmp_path, "[versions]\nfoo = \"1.0\"\n")
    results = rewrite_libs_versions_toml(p, [RewriteEdit(
        locator="bogus:foo", old_value="1.0", new_value="2.0",
    )])
    assert results[0].applied is False
    assert "unknown locator section" in results[0].reason


def test_multi_edit_in_one_pass(tmp_path: Path):
    p = _write(tmp_path, """\
[versions]
spring = "3.1.0"
junit = "5.9.0"

[libraries]
guava = "com.google.guava:guava:32.1.2-jre"
""")
    results = rewrite_libs_versions_toml(p, [
        RewriteEdit(locator="version:spring",
                    old_value="3.1.0", new_value="3.2.0"),
        RewriteEdit(locator="library:guava",
                    old_value="32.1.2-jre", new_value="33.0.0-jre"),
    ])
    assert all(r.applied for r in results)
    body = p.read_text()
    assert 'spring = "3.2.0"' in body
    assert '"com.google.guava:guava:33.0.0-jre"' in body
