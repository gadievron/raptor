"""Tests for the shared CWE normalisation helpers."""

from __future__ import annotations

import pytest

from core.cve.cwe import canonicalize_cwe, cwe_dir_slug, format_cwe


class TestCanonicalize:
    @pytest.mark.parametrize("raw,expected", [
        ("CWE-121", "CWE-121"),
        ("cwe-121", "CWE-121"),
        ("cwe121", "CWE-121"),
        ("CWE121", "CWE-121"),
        ("  CWE-416  ", "CWE-416"),
        ("Cwe-134", "CWE-134"),
        # SARIF and the population routing surface both hand us
        # loose shapes — space separator (from parsed SARIF taxa)
        # and underscore (from some SCA producers). The canonicaliser
        # accepts both so leave-one-out retrieval keys and routing
        # filters agree across producers.
        ("CWE 121", "CWE-121"),
        ("cwe_121", "CWE-121"),
    ])
    def test_valid(self, raw, expected):
        assert canonicalize_cwe(raw) == expected

    @pytest.mark.parametrize("raw", [
        None, "", "  ", "not-a-cwe", "CWE-", "CWE-abc",
        "121", "cwe--121",
    ])
    def test_invalid(self, raw):
        assert canonicalize_cwe(raw) is None


class TestDirSlug:
    @pytest.mark.parametrize("raw,expected", [
        ("CWE-121", "cwe-121"),
        ("cwe121", "cwe-121"),
        ("CWE-416", "cwe-416"),
    ])
    def test_valid(self, raw, expected):
        assert cwe_dir_slug(raw) == expected

    def test_invalid_returns_none(self):
        assert cwe_dir_slug("garbage") is None


class TestFormatCwe:
    @pytest.mark.parametrize("raw,expected", [
        (121, "CWE-121"),
        ("121", "CWE-121"),
        ("  416  ", "CWE-416"),
    ])
    def test_valid(self, raw, expected):
        assert format_cwe(raw) == expected

    @pytest.mark.parametrize("raw", [
        None, "", "abc", "-1", "0", "1.5",
    ])
    def test_invalid_returns_none(self, raw):
        assert format_cwe(raw) is None
