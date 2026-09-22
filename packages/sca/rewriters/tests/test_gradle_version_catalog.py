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


class TestMultilineStringBlindness:
    """A TOML multiline string whose CONTENT carries a key = "…" line
    must never be spliced: the MULTILINE ^ anchors match inside
    string content, so a hostile (or merely documentation-bearing)
    catalog had its string mutated while the run reported applied."""

    def test_key_line_inside_multiline_string_not_spliced(
        self, tmp_path,
    ):
        from packages.sca.rewriters import RewriteEdit
        from packages.sca.rewriters.gradle_version_catalog import (
            rewrite_libs_versions_toml,
        )
        cat = tmp_path / "libs.versions.toml"
        original = (
            "[versions]\n"
            'doc = """\n'
            'junit = "4.0.0"\n'
            '"""\n'
            "[libraries]\n"
        )
        cat.write_text(original)
        results = rewrite_libs_versions_toml(cat, [RewriteEdit(
            locator="version:junit", old_value="4.0.0",
            new_value="5.9.0",
        )])
        assert results[0].applied is False
        assert cat.read_text() == original

    def test_real_key_after_multiline_string_still_bumped(
        self, tmp_path,
    ):
        from packages.sca.rewriters import RewriteEdit
        from packages.sca.rewriters.gradle_version_catalog import (
            rewrite_libs_versions_toml,
        )
        cat = tmp_path / "libs.versions.toml"
        cat.write_text(
            "[versions]\n"
            "doc = '''\n"
            'junit = "1.0.0"\n'
            "'''\n"
            'junit = "4.0.0"\n'
        )
        results = rewrite_libs_versions_toml(cat, [RewriteEdit(
            locator="version:junit", old_value="4.0.0",
            new_value="5.9.0",
        )])
        assert results[0].applied is True
        text = cat.read_text()
        assert 'junit = "5.9.0"\n' in text
        # The string content is untouched.
        assert 'junit = "1.0.0"\n' in text


def test_blank_line_run_is_fast(tmp_path: Path) -> None:
    """Sibling of the helm rewriter's blank-run quadratic — the
    MULTILINE ``^\\s*`` idiom on the header / lookahead / key-line
    anchors. The firing shape is a MISSING key over a trailing blank
    run: the search walks every anchor of the run looking for the key
    line and re-scanned the remainder from each — quadratic.
    Horizontal-only indent is linear. Both-direction bound: the miss
    is fast AND a present key still bumps."""
    import time

    p = _write(tmp_path,
               '[versions]\njunit = "1.0"\n'
               + "\n" * (1 << 17) + "# end\n")
    start = time.monotonic()
    results = rewrite_libs_versions_toml(p, [RewriteEdit(
        locator="version:spring-boot",
        old_value="3.1.0", new_value="3.2.0",
    )])
    assert time.monotonic() - start < 5.0
    assert results[0].applied is False
    assert results[0].reason == "not_found"

    p2 = _write(tmp_path,
                '[versions]\nspring-boot = "3.1.0"\n'
                + "\n" * (1 << 17))
    start = time.monotonic()
    results = rewrite_libs_versions_toml(p2, [RewriteEdit(
        locator="version:spring-boot",
        old_value="3.1.0", new_value="3.2.0",
    )])
    assert time.monotonic() - start < 5.0
    assert results[0].applied is True
    assert 'spring-boot = "3.2.0"' in p2.read_text()


def test_blank_run_directly_after_header_is_fast(tmp_path: Path) -> None:
    """Adversarial sibling of the trailing-run shape above: the blank
    run sits DIRECTLY after the section header and the requested key
    is missing. A ``\\s*$`` header TAIL swallows the run; when the
    mandatory key line then fails, backtracking re-runs the lazy
    ``inter`` scan from every ``$`` stop inside the run — quadratic
    (tens of seconds at 32K lines). A horizontal tail ([^\\S\\n]*$)
    is linear. Both-direction bound: the miss is fast AND a key
    placed after the run still bumps."""
    import time

    p = _write(tmp_path,
               '[versions]\n' + "\n" * (1 << 17) + 'junit = "1.0"\n')
    start = time.monotonic()
    results = rewrite_libs_versions_toml(p, [RewriteEdit(
        locator="version:spring-boot",
        old_value="3.1.0", new_value="3.2.0",
    )])
    assert time.monotonic() - start < 5.0
    assert results[0].applied is False
    assert results[0].reason == "not_found"

    start = time.monotonic()
    results = rewrite_libs_versions_toml(p, [RewriteEdit(
        locator="version:junit",
        old_value="1.0", new_value="1.1",
    )])
    assert time.monotonic() - start < 5.0
    assert results[0].applied is True
    assert 'junit = "1.1"' in p.read_text()
