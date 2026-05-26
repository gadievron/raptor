"""Tests for the Gradle DSL parser."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.gradle_dsl import parse


def _write(tmp_path: Path, body: str, name: str = "build.gradle") -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_groovy_single_string(tmp_path: Path) -> None:
    body = """\
dependencies {
    implementation 'org.springframework:spring-core:6.0.0'
    api 'com.google.guava:guava:32.1.0-jre'
}
"""
    p = _write(tmp_path, body)
    by_name = {d.name: d for d in parse(p)}
    assert by_name["org.springframework/spring-core"].version == "6.0.0"
    assert by_name["org.springframework/spring-core"].pin_style is PinStyle.EXACT
    assert by_name["com.google.guava/guava"].version == "32.1.0-jre"


def test_kotlin_dsl_parens_form(tmp_path: Path) -> None:
    body = """\
dependencies {
    implementation("org.springframework:spring-core:6.0.0")
    api("com.google.guava:guava:32.1.0-jre")
}
"""
    p = _write(tmp_path, body, name="build.gradle.kts")
    by_name = {d.name: d for d in parse(p)}
    assert by_name["org.springframework/spring-core"].version == "6.0.0"


def test_named_args_groovy(tmp_path: Path) -> None:
    body = """\
dependencies {
    api group: 'org.foo', name: 'bar', version: '1.2.3'
    testImplementation group: 'junit', name: 'junit', version: '4.13.2'
}
"""
    p = _write(tmp_path, body)
    by_name = {d.name: d for d in parse(p)}
    assert by_name["org.foo/bar"].scope == "main"
    assert by_name["junit/junit"].scope == "test"
    assert by_name["junit/junit"].version == "4.13.2"


def test_string_interpolation_unknown_pin(tmp_path: Path) -> None:
    body = """\
dependencies {
    implementation "org.foo:bar:$version"
}
"""
    p = _write(tmp_path, body)
    deps = parse(p)
    assert len(deps) == 1
    assert deps[0].pin_style is PinStyle.UNKNOWN


def test_dynamic_version_range_pin(tmp_path: Path) -> None:
    body = """\
dependencies {
    implementation 'org.foo:bar:1.+'
}
"""
    p = _write(tmp_path, body)
    deps = parse(p)
    assert deps[0].pin_style is PinStyle.RANGE


def test_maven_range_pin(tmp_path: Path) -> None:
    body = """\
dependencies {
    implementation 'org.foo:bar:[1.0,2.0)'
}
"""
    p = _write(tmp_path, body)
    deps = parse(p)
    assert deps[0].pin_style is PinStyle.RANGE


def test_unrecognised_configuration_skipped(tmp_path: Path) -> None:
    """Configurations like ``customConfig`` we don't know about — skip."""
    body = """\
dependencies {
    customWeirdConfig 'org.foo:bar:1.0.0'
    implementation 'org.foo:keep:1.0.0'
}
"""
    p = _write(tmp_path, body)
    deps = parse(p)
    assert len(deps) == 1
    assert deps[0].name == "org.foo/keep"


def test_unversioned_dep(tmp_path: Path) -> None:
    body = """\
dependencies {
    testImplementation 'junit:junit'
}
"""
    p = _write(tmp_path, body)
    deps = parse(p)
    assert deps[0].version is None
    assert deps[0].pin_style is PinStyle.WILDCARD


def test_kapt_marked_as_build_scope(tmp_path: Path) -> None:
    body = """\
dependencies {
    kapt 'com.google.dagger:dagger-compiler:2.50'
}
"""
    p = _write(tmp_path, body)
    deps = parse(p)
    assert deps[0].scope == "build"


def test_dispatch_via_discovery(tmp_path: Path) -> None:
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import parse_manifest as dispatch
    repo = tmp_path / "java-proj"
    repo.mkdir()
    (repo / "build.gradle").write_text(
        "dependencies { implementation 'g:a:1.0' }\n",
        encoding="utf-8")
    manifests = find_manifests(repo)
    bg = next(m for m in manifests if m.path.name == "build.gradle")
    assert bg.ecosystem == "Maven"
    deps = dispatch(bg)
    assert deps and deps[0].name == "g/a"
