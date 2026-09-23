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


class TestUnicodeDigits:
    """CWE ids arrive from SARIF taxa / SCA producers over untrusted
    repos. Non-ASCII decimal digits (Unicode Nd — Arabic-Indic and
    friends) pass an un-pinned ``\\d`` and ``int()`` both, so without
    ``re.ASCII`` the trio disagreed inside one module: canonicalize
    kept the raw non-ASCII spelling (two spellings of one CWE never
    join), the slug helper minted a non-ASCII directory name, and
    format_cwe int-normalised. One doctrine, all three lanes: ASCII
    digits only (the epss/vulnrichment sibling regexes carry the same
    pin)."""

    @pytest.mark.parametrize("helper", [canonicalize_cwe, cwe_dir_slug])
    def test_non_ascii_digits_rejected(self, helper):
        assert helper("CWE-١٢١") is None       # Arabic-Indic
        assert helper("cwe-۱۲۱") is None       # Extended Arabic-Indic
        assert helper("CWE-１２１") is None     # fullwidth

    def test_format_cwe_rejects_non_ascii_digit_strings(self):
        # ``int("١٢١")`` == 121, so the int() lane alone would mint
        # "CWE-121" from a spelling the canonicaliser refuses.
        assert format_cwe("١٢١") is None
        assert format_cwe("۱۲۱") is None

    def test_format_cwe_int_lane_unchanged(self):
        assert format_cwe(121) == "CWE-121"
        assert format_cwe("121") == "CWE-121"
        assert format_cwe(" 416 ") == "CWE-416"
