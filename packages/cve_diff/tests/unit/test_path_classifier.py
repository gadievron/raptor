"""Tests for ``cve_diff.core.path_classifier.is_test_path``.

The classifier is the single source of truth for ``FileChange.is_test``
across all four extractors (clone, GitHub API, GitLab API, patch URL),
so any drift here was a real-world bug pre-2026-05-01.

Moved from ``tests/unit/test_extractor_tier1.py`` (where the helper
originally lived inside ``extractor.py``) when the helper got promoted
to ``cve_diff/core/`` and the module was renamed away from the
pytest-collected ``test_path.py`` to ``path_classifier.py``.
"""
from __future__ import annotations

import pytest

from cve_diff.core.path_classifier import is_test_path


# ---------- clear positives ----------

@pytest.mark.parametrize("path", [
    "tests/test_foo.py",
    "src/tests/runner.c",
    "foo_test.go",
    "parser.spec.ts",
    "__tests__/util.js",
    "test_helper.rb",
    "testing/fixtures.py",
    "fixtures/sample.json",       # plural fixture dir
    "src/fixture/data.bin",       # singular fixture dir
    "spec/auth_spec.rb",          # singular spec dir
    "Tests/Foo.cs",               # case-insensitive directory
])
def test_clear_positives(path: str) -> None:
    assert is_test_path(path) is True


# ---------- clear negatives ----------

@pytest.mark.parametrize("path", [
    "src/main.c",
    "lib/auth.go",
    "README.md",
    "foo.yaml",
    "MyTests/foo.py",             # 'tests' substring inside another word — no match
    "pretests/foo.py",            # similarly: 'tests' must follow ^ or '/'
    "foo.test",                   # missing trailing extension after .test
    "",                           # empty path is not a test
])
def test_clear_negatives(path: str) -> None:
    assert is_test_path(path) is False


# ---------- documented quirks (extension-agnostic on purpose) ----------

@pytest.mark.parametrize("path", [
    "test_helper_not_py.txt",     # ``test_*`` matches regardless of suffix
    "test_data.json",             # fixtures legitimately use .json
    "test_payload.bin",           # binary fixtures
])
def test_extension_agnostic_test_prefix_matches(path: str) -> None:
    """Per the module docstring: ``test_*`` and ``*_test.*`` filenames
    match regardless of suffix because legitimate test fixtures use
    ``.txt`` / ``.json`` / ``.bin`` as often as source extensions.
    Callers needing source-language filtering compose their own check."""
    assert is_test_path(path) is True
