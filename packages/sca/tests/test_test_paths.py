"""Tests for the shared test-path predicate (``packages.sca._test_paths``).

Pins the cross-ecosystem filename conventions so consolidating a
scanner's private copy into the shared predicate can't silently
change what pre-existing consumers classify as test code.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca._test_paths import is_test_path, is_test_resident

_TARGET = Path("/proj")


@pytest.mark.parametrize("rel", [
    # Python
    "src/test_util.py",
    "src/util_test.py",
    "src/util.test.py",
    "src/util.spec.py",
    # JS / TS
    "src/app.test.js",
    "src/app.spec.ts",
    "src/app.test.jsx",
    "src/app.spec.tsx",
    "src/app.test.mjs",
    "src/app.spec.cjs",
    # Go / Ruby / Rust
    "pkg/handler_test.go",
    "lib/model_test.rb",
    "lib/model_spec.rb",
    "src/parser_test.rs",
    # Java / Kotlin / C# / PHP
    "src/FooTest.java",
    "src/FooTests.kt",
    "src/FooIT.java",
    "src/FooTest.cs",
    "src/FooTest.php",
    # Directory ancestors
    "tests/anything.js",
    "test/anything.py",
    "__tests__/anything.ts",
    "spec/anything.rb",
    "e2e/anything.go",
])
def test_preexisting_conventions_still_match(rel: str) -> None:
    assert is_test_path(_TARGET / rel, _TARGET) is True


@pytest.mark.parametrize("rel", [
    "src/util.py",
    "src/app.js",
    "src/contest.py",       # 'test' substring, not a convention
    "src/latest.ts",
    "src/protester.go",
    "src/module.mts",       # non-test TS-variant sources stay clean
    "src/module.cts",
])
def test_non_test_sources_still_clean(rel: str) -> None:
    assert is_test_path(_TARGET / rel, _TARGET) is False


@pytest.mark.parametrize("rel", [
    # .mts / .cts (TS module / CommonJS variants) — folded in when
    # the nodejs reachability scanner's private regex was
    # consolidated into this shared predicate.
    "src/app.test.mts",
    "src/app.spec.mts",
    "src/app.test.cts",
    "src/app.spec.cts",
])
def test_ts_module_variants_recognised(rel: str) -> None:
    assert is_test_path(_TARGET / rel, _TARGET) is True


def test_write_path_predicate_unchanged() -> None:
    """``is_test_resident`` stays a strict superset: everything
    ``is_test_path`` matches plus fixture-data directories."""
    assert is_test_resident(_TARGET / "src/app.test.mts", _TARGET) is True
    assert is_test_resident(_TARGET / "testdata/pin.lock", _TARGET) is True
    assert is_test_resident(_TARGET / "fixtures/old.json", _TARGET) is True
    assert is_test_resident(_TARGET / "src/app.js", _TARGET) is False
