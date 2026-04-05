"""Tests for auto-download of missing CodeQL query packs."""

from packages.codeql.query_runner import _extract_missing_pack


class TestExtractMissingPack:

    def test_standard_error(self):
        stderr = "Query pack codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls cannot be found."
        assert _extract_missing_pack(stderr) == "codeql/javascript-queries"

    def test_with_version(self):
        stderr = "Error: query pack codeql/python-queries@0.9.0 cannot be found"
        assert _extract_missing_pack(stderr) == "codeql/python-queries"

    def test_without_suite(self):
        stderr = "A fatal error occurred: Query pack codeql/cpp-queries cannot be found. Check the spelling of the pack."
        assert _extract_missing_pack(stderr) == "codeql/cpp-queries"

    def test_no_match(self):
        stderr = "Something else went wrong"
        assert _extract_missing_pack(stderr) is None

    def test_wrong_suite_not_matched(self):
        # "Could not read" means the pack exists but the suite path is wrong — don't download
        stderr = 'A fatal error occurred: Could not read /path/to/nonexistent-suite.qls'
        assert _extract_missing_pack(stderr) is None

    def test_empty(self):
        assert _extract_missing_pack("") is None
