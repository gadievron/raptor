"""Tests for ``packages.sca.ecosystems``.

Three call sites depend on this module (purl, whatif, review); a
case-folding regression silently routes invalid OSV queries.
"""

from __future__ import annotations

import pytest

from packages.sca import ecosystems


class TestCanonicalise:

    @pytest.mark.parametrize("input_eco,expected", [
        ("PyPI", "PyPI"),
        ("pypi", "PyPI"),
        ("PYPI", "PyPI"),
        ("npm", "npm"),
        ("NPM", "npm"),
        ("Maven", "Maven"),
        ("MAVEN", "Maven"),
        ("Cargo", "Cargo"),
        ("Go", "Go"),
        ("RubyGems", "RubyGems"),
        ("rubygems", "RubyGems"),
        ("NuGet", "NuGet"),
        ("Packagist", "Packagist"),
    ])
    def test_canonicalises_known_ecosystems(self, input_eco, expected):
        assert ecosystems.canonicalise(input_eco) == expected

    def test_unknown_returns_none(self):
        assert ecosystems.canonicalise("Bogus") is None
        assert ecosystems.canonicalise("") is None
        assert ecosystems.canonicalise("debian") is None

    def test_canonical_form_is_osv_form(self):
        """The canonical form must be exactly what OSV accepts.

        OSV is case-sensitive: ``PyPI`` works, ``pypi`` returns 400.
        Regression-protect by asserting against the known-good set.
        """
        for input_eco in ("pypi", "PYPI", "PyPI"):
            assert ecosystems.canonicalise(input_eco) == "PyPI"


class TestKnownList:

    def test_returns_string(self):
        result = ecosystems.known_list()
        assert isinstance(result, str)

    def test_contains_all_ecosystems(self):
        result = ecosystems.known_list()
        for eco in ecosystems.KNOWN_ECOSYSTEMS:
            assert eco in result

    def test_sorted(self):
        """Output must be sorted for stable error messages."""
        items = [s.strip() for s in ecosystems.known_list().split(",")]
        assert items == sorted(items)
