"""Tests for the gradle.lockfile parser."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.gradle_lockfile import parse


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "gradle.lockfile"
    p.write_text(body, encoding="utf-8")
    return p


def test_basic_runtime_classpath(tmp_path: Path) -> None:
    body = """\
# This is a Gradle generated file for dependency locking.
ch.qos.logback:logback-classic:1.4.11=compileClasspath,runtimeClasspath
ch.qos.logback:logback-core:1.4.11=runtimeClasspath
empty=annotationProcessor
"""
    deps = parse(_write(tmp_path, body))
    by_name = {d.name: d for d in deps}
    assert by_name["ch.qos.logback:logback-classic"].version == "1.4.11"
    assert by_name["ch.qos.logback:logback-classic"].scope == "main"
    assert by_name["ch.qos.logback:logback-classic"].pin_style is PinStyle.EXACT
    assert by_name["ch.qos.logback:logback-classic"].is_lockfile is True
    assert by_name["ch.qos.logback:logback-classic"].purl == \
        "pkg:maven/ch.qos.logback/logback-classic@1.4.11"


def test_test_only_dep_is_test_scope(tmp_path: Path) -> None:
    body = "junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath\n"
    deps = parse(_write(tmp_path, body))
    assert deps[0].scope == "test"


def test_annotation_processor_is_build_scope(tmp_path: Path) -> None:
    body = "org.projectlombok:lombok:1.18.30=annotationProcessor\n"
    deps = parse(_write(tmp_path, body))
    assert deps[0].scope == "build"


def test_main_takes_precedence_over_test(tmp_path: Path) -> None:
    body = "x:y:1=runtimeClasspath,testRuntimeClasspath\n"
    deps = parse(_write(tmp_path, body))
    assert deps[0].scope == "main"


def test_empty_sentinel_is_skipped(tmp_path: Path) -> None:
    body = "empty=annotationProcessor,compileClasspath\n"
    deps = parse(_write(tmp_path, body))
    assert deps == []


def test_malformed_line_skipped(tmp_path: Path) -> None:
    body = """\
just-two-colons:no-version=runtimeClasspath
group:artifact:1.0=runtimeClasspath
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].name == "group:artifact"
