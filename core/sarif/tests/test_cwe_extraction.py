"""Tests for CWE extraction from SARIF rule metadata."""

from core.sarif.parser import _extract_cwe_from_rule


class TestExtractCweFromRule:

    def test_cwe_in_tags(self):
        """CodeQL-style tag: external/cwe/cwe-89."""
        rule = {"properties": {"tags": ["external/cwe/cwe-89", "security"]}}
        assert _extract_cwe_from_rule(rule) == "CWE-89"

    def test_cwe_in_tags_uppercase(self):
        rule = {"properties": {"tags": ["CWE-79"]}}
        assert _extract_cwe_from_rule(rule) == "CWE-79"

    def test_cwe_direct_property(self):
        rule = {"properties": {"cwe": "CWE-120"}}
        assert _extract_cwe_from_rule(rule) == "CWE-120"

    def test_cwe_direct_takes_precedence(self):
        """Direct cwe property checked before tags."""
        rule = {"properties": {"cwe": "CWE-120", "tags": ["external/cwe/cwe-89"]}}
        assert _extract_cwe_from_rule(rule) == "CWE-120"

    def test_no_cwe(self):
        rule = {"properties": {"tags": ["security", "correctness"]}}
        assert _extract_cwe_from_rule(rule) is None

    def test_no_properties(self):
        rule = {"id": "some-rule"}
        assert _extract_cwe_from_rule(rule) is None

    def test_empty_rule(self):
        assert _extract_cwe_from_rule({}) is None

    def test_semgrep_style_tag(self):
        """Semgrep tags like cwe-78."""
        rule = {"properties": {"tags": ["cwe-78"]}}
        assert _extract_cwe_from_rule(rule) == "CWE-78"

    def test_non_string_tags_ignored(self):
        rule = {"properties": {"tags": [123, None, "external/cwe/cwe-22"]}}
        assert _extract_cwe_from_rule(rule) == "CWE-22"

    def test_invalid_cwe_property(self):
        """Non-CWE format in cwe property falls through to tags."""
        rule = {"properties": {"cwe": "not-a-cwe", "tags": ["external/cwe/cwe-89"]}}
        assert _extract_cwe_from_rule(rule) == "CWE-89"
