"""Tests for ``packages.sca.parsers.gradle_version_catalog`` —
the Gradle 7+ libs.versions.toml reader and the
``parse_msbuild_project``-equivalent ``parse`` integration in
``gradle_dsl.py``.

Pins:
  * Both library shapes (string shorthand + inline table).
  * ``version.ref`` resolution + missing-ref warning behaviour.
  * Plugin coordinate emission (gradle plugin marker artifact).
  * Accessor → alias mapping (Gradle replaces ``-``/``_`` with
    ``.``).
  * DSL integration — ``libs.spring.boot.starter`` accessor in
    build.gradle.kts resolves to the catalog entry.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.parsers.gradle_version_catalog import (
    CatalogLibrary,
    CatalogPlugin,
    _reset_cache_for_tests,
    find_default_catalog,
    parse_libs_versions_toml,
)


@pytest.fixture(autouse=True)
def _reset_cache():
    _reset_cache_for_tests()
    yield
    _reset_cache_for_tests()


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def test_versions_table_parsed(tmp_path: Path):
    p = tmp_path / "libs.versions.toml"
    p.write_text("""\
[versions]
spring-boot = "3.1.0"
junit = "5.9.0"
""", encoding="utf-8")
    c = parse_libs_versions_toml(p)
    assert c is not None
    assert c.versions == {"spring-boot": "3.1.0", "junit": "5.9.0"}


def test_libraries_string_shorthand(tmp_path: Path):
    p = tmp_path / "libs.versions.toml"
    p.write_text("""\
[libraries]
guava = "com.google.guava:guava:32.1.2-jre"
slf4j = "org.slf4j:slf4j-api:2.0.7"
""", encoding="utf-8")
    c = parse_libs_versions_toml(p)
    assert c.libraries["guava"] == CatalogLibrary(
        alias="guava", group="com.google.guava", artifact="guava",
        version="32.1.2-jre", version_via_ref=False,
        version_ref_name="",
    )
    assert c.libraries["slf4j"].artifact == "slf4j-api"


def test_libraries_inline_module_with_version_ref(tmp_path: Path):
    p = tmp_path / "libs.versions.toml"
    p.write_text("""\
[versions]
spring-boot = "3.1.0"

[libraries]
spring-boot-starter = { module = "org.springframework.boot:spring-boot-starter", version.ref = "spring-boot" }
""", encoding="utf-8")
    c = parse_libs_versions_toml(p)
    lib = c.libraries["spring-boot-starter"]
    assert lib.group == "org.springframework.boot"
    assert lib.artifact == "spring-boot-starter"
    assert lib.version == "3.1.0"
    assert lib.version_via_ref is True
    assert lib.version_ref_name == "spring-boot"


def test_libraries_inline_module_with_inline_version(tmp_path: Path):
    p = tmp_path / "libs.versions.toml"
    p.write_text("""\
[libraries]
foo = { module = "com.example:foo", version = "1.2.3" }
""", encoding="utf-8")
    lib = parse_libs_versions_toml(p).libraries["foo"]
    assert lib.version == "1.2.3"
    assert lib.version_via_ref is False


def test_libraries_expanded_group_name_form(tmp_path: Path):
    """Legacy shape: ``{group = "g", name = "a", version = "v"}``
    instead of the modern ``module`` form."""
    p = tmp_path / "libs.versions.toml"
    p.write_text("""\
[libraries]
foo = { group = "com.example", name = "foo", version = "1.0.0" }
""", encoding="utf-8")
    lib = parse_libs_versions_toml(p).libraries["foo"]
    assert lib.group == "com.example"
    assert lib.artifact == "foo"
    assert lib.version == "1.0.0"


def test_missing_version_ref_keeps_via_ref_flag(tmp_path: Path):
    """A typo in version.ref pointing at a missing [versions] key
    must emit a warning but still register the library with the
    via-ref flag set (so the bumper can surface the unresolved
    ref later)."""
    p = tmp_path / "libs.versions.toml"
    p.write_text("""\
[versions]
spring = "3.1.0"

[libraries]
typo = { module = "g:a", version.ref = "sprng" }
""", encoding="utf-8")
    lib = parse_libs_versions_toml(p).libraries["typo"]
    assert lib.version is None
    assert lib.version_via_ref is True
    assert lib.version_ref_name == "sprng"


def test_version_strictly_require_prefer(tmp_path: Path):
    """Gradle accepts ``strictly`` / ``require`` / ``prefer``
    constraints inside the version inline-table. Use the first
    one we recognise as the representative numeric."""
    p = tmp_path / "libs.versions.toml"
    p.write_text("""\
[libraries]
strict = { module = "g:a", version = { strictly = "1.2.3" } }
require = { module = "g:b", version = { require = "2.0.0" } }
prefer = { module = "g:c", version = { prefer = "3.0.0" } }
""", encoding="utf-8")
    libs = parse_libs_versions_toml(p).libraries
    assert libs["strict"].version == "1.2.3"
    assert libs["require"].version == "2.0.0"
    assert libs["prefer"].version == "3.0.0"


def test_plugins_table(tmp_path: Path):
    p = tmp_path / "libs.versions.toml"
    p.write_text("""\
[versions]
kotlin = "1.9.0"

[plugins]
kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }
spotless = { id = "com.diffplug.spotless", version = "6.20.0" }
""", encoding="utf-8")
    c = parse_libs_versions_toml(p)
    assert c.plugins["kotlin-jvm"] == CatalogPlugin(
        alias="kotlin-jvm",
        plugin_id="org.jetbrains.kotlin.jvm",
        version="1.9.0", version_via_ref=True,
        version_ref_name="kotlin",
    )
    assert c.plugins["spotless"].version == "6.20.0"


def test_bundles_table(tmp_path: Path):
    p = tmp_path / "libs.versions.toml"
    p.write_text("""\
[libraries]
a = "g:a:1"
b = "g:b:1"

[bundles]
group = ["a", "b"]
""", encoding="utf-8")
    c = parse_libs_versions_toml(p)
    assert c.bundles == {"group": ["a", "b"]}


def test_accessor_to_alias_normalises_separators(tmp_path: Path):
    p = tmp_path / "libs.versions.toml"
    p.write_text("""\
[libraries]
spring-boot-starter = "org.springframework.boot:spring-boot-starter:3.1.0"
my_underscore_lib = "com.example:thing:1.0"
""", encoding="utf-8")
    c = parse_libs_versions_toml(p)
    accessor = c.accessor_to_alias()
    assert accessor == {
        "spring.boot.starter": "spring-boot-starter",
        "my.underscore.lib": "my_underscore_lib",
    }


def test_malformed_toml_returns_none(tmp_path: Path):
    p = tmp_path / "libs.versions.toml"
    p.write_text("[libraries] foo = ", encoding="utf-8")  # broken
    assert parse_libs_versions_toml(p) is None


def test_missing_file_returns_none(tmp_path: Path):
    assert parse_libs_versions_toml(tmp_path / "nope.toml") is None


def test_cache_returns_same_object(tmp_path: Path):
    p = tmp_path / "libs.versions.toml"
    p.write_text("[versions]\nx = \"1.0\"\n", encoding="utf-8")
    a = parse_libs_versions_toml(p)
    b = parse_libs_versions_toml(p)
    assert a is b


def test_find_default_catalog(tmp_path: Path):
    """Documented default: ``<repo>/gradle/libs.versions.toml``."""
    assert find_default_catalog(tmp_path) is None
    (tmp_path / "gradle").mkdir()
    catalog = tmp_path / "gradle" / "libs.versions.toml"
    catalog.write_text("[versions]\n", encoding="utf-8")
    assert find_default_catalog(tmp_path) == catalog


# ---------------------------------------------------------------------------
# DSL integration — catalog accessor in build.gradle.kts
# ---------------------------------------------------------------------------

def test_dsl_resolves_catalog_accessor(tmp_path: Path):
    """``implementation(libs.spring.boot.starter)`` in
    build.gradle.kts must resolve to the catalog entry with the
    correct group / artifact / version."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "gradle").mkdir()
    (tmp_path / "gradle" / "libs.versions.toml").write_text("""\
[versions]
spring-boot = "3.1.0"

[libraries]
spring-boot-starter = { module = "org.springframework.boot:spring-boot-starter", version.ref = "spring-boot" }
""", encoding="utf-8")
    script = tmp_path / "build.gradle.kts"
    script.write_text("""\
dependencies {
    implementation(libs.spring.boot.starter)
}
""", encoding="utf-8")
    from packages.sca.parsers.gradle_dsl import parse
    deps = parse(script)
    assert len(deps) == 1
    d = deps[0]
    assert d.name == "org.springframework.boot/spring-boot-starter"
    assert d.version == "3.1.0"
    assert d.source_extra["origin"] == "gradle_catalog_ref"
    assert d.source_extra["catalog_alias"] == "spring-boot-starter"
    assert d.source_extra["version_ref_name"] == "spring-boot"
    assert d.parser_confidence.level == "high"


def test_dsl_resolves_catalog_inline_version(tmp_path: Path):
    """``[libraries]`` with inline version (no version.ref) sets
    ``source_extra.origin = "gradle_catalog_inline"``."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "gradle").mkdir()
    (tmp_path / "gradle" / "libs.versions.toml").write_text("""\
[libraries]
guava = "com.google.guava:guava:32.1.2-jre"
""", encoding="utf-8")
    script = tmp_path / "build.gradle.kts"
    script.write_text("""\
dependencies { implementation(libs.guava) }
""", encoding="utf-8")
    from packages.sca.parsers.gradle_dsl import parse
    deps = parse(script)
    assert deps[0].source_extra["origin"] == "gradle_catalog_inline"


def test_dsl_resolves_plugin_accessor(tmp_path: Path):
    """``alias(libs.plugins.kotlin.jvm)`` resolves to a Maven
    coordinate using Gradle's plugin marker-artifact pattern."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "gradle").mkdir()
    (tmp_path / "gradle" / "libs.versions.toml").write_text("""\
[versions]
kotlin = "1.9.0"

[plugins]
kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }
""", encoding="utf-8")
    script = tmp_path / "build.gradle.kts"
    script.write_text("""\
plugins {
    alias(libs.plugins.kotlin.jvm)
}
""", encoding="utf-8")
    from packages.sca.parsers.gradle_dsl import parse
    deps = parse(script)
    assert len(deps) == 1
    d = deps[0]
    # Gradle's plugin marker-artifact convention: the artifact
    # name is ``<plugin_id>.gradle.plugin`` under the group
    # equal to the plugin id.
    assert d.name == (
        "org.jetbrains.kotlin.jvm/org.jetbrains.kotlin.jvm.gradle.plugin"
    )
    assert d.version == "1.9.0"
    assert d.source_extra["origin"] == "gradle_catalog_plugin_ref"


def test_dsl_inline_form_still_works(tmp_path: Path):
    """Existing inline form (``implementation 'g:a:v'``) must
    still produce a Dependency — catalog support is additive,
    not replacement."""
    script = tmp_path / "build.gradle"
    script.write_text("""\
dependencies {
    implementation 'com.google.guava:guava:32.1.2-jre'
}
""", encoding="utf-8")
    from packages.sca.parsers.gradle_dsl import parse
    deps = parse(script)
    assert len(deps) == 1
    assert deps[0].version == "32.1.2-jre"
    assert deps[0].source_extra["origin"] == "gradle_inline"
