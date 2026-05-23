"""Direct tests for ``cve_diff.oracle.cross_check`` pure helpers.

Pre-fix: this file targeted a 288-LOC module with zero direct test
coverage — the only signal came incidentally via bench-driven
integration paths that needed real OSV/NVD network calls to
exercise. The integration coverage is good for end-to-end shape
verification but doesn't pin down the per-helper edge cases
(malformed OSV references, slug + sha parsing, bench-status
classification). Without per-helper tests, a refactor of the
URL regex or the references-list defensive handling could regress
silently.

This file targets the pure (no-IO) helpers:

* ``_GH_COMMIT_URL`` — the GitHub commit-URL regex
* ``_load_pick_from_osv_file`` — fed a fixture OSV JSON on disk
* ``_classify_bench_status`` — pure dict → status string

Network-touching ``_verify_one`` and ``main`` belong in an
integration suite (gated with ``@pytest.mark.integration``) and
are out of scope here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cve_diff.oracle import cross_check


class TestGhCommitUrlRegex:
    """The compiled ``_GH_COMMIT_URL`` regex.

    Used to extract ``(slug, sha)`` from OSV reference URLs. The
    captured slug must NOT end in ``.git`` (consumers strip it
    separately), and the sha must be 7-40 hex chars.
    """

    def test_extracts_slug_and_sha_https(self):
        m = cross_check._GH_COMMIT_URL.search(
            "https://github.com/torvalds/linux/commit/abc1234deadbeef0011223344556677889900112",
        )
        assert m is not None
        assert m.group(1) == "torvalds/linux"
        assert m.group(2) == "abc1234deadbeef0011223344556677889900112"

    def test_extracts_slug_and_sha_http_scheme(self):
        # Older OSV records occasionally carry http:// references.
        m = cross_check._GH_COMMIT_URL.search(
            "http://github.com/owner/repo/commit/0123456",
        )
        assert m is not None
        assert m.group(1) == "owner/repo"
        assert m.group(2) == "0123456"

    def test_short_sha_rejected_below_seven_chars(self):
        # The regex requires ``{7,40}`` — six chars must not match.
        m = cross_check._GH_COMMIT_URL.search(
            "https://github.com/owner/repo/commit/abcdef",
        )
        assert m is None

    def test_non_hex_sha_rejected(self):
        m = cross_check._GH_COMMIT_URL.search(
            "https://github.com/owner/repo/commit/zzzzzzzz",
        )
        assert m is None

    def test_url_inside_larger_string_finds_match(self):
        # ``search`` (not ``fullmatch``) — the references-list values
        # often include trailing punctuation or surrounding prose.
        m = cross_check._GH_COMMIT_URL.search(
            "See https://github.com/owner/repo/commit/abcdef0 for details.",
        )
        assert m is not None
        assert m.group(1) == "owner/repo"


class TestLoadPickFromOsvFile:
    """``_load_pick_from_osv_file(summary_dir, cve_id)`` reads
    ``<summary_dir>/<cve_id>.osv.json`` and returns the first
    GitHub-commit-shaped reference's ``(slug, sha)`` — or ``("", "")``.
    """

    def _write_osv(self, tmp_path: Path, cve_id: str, body: dict) -> None:
        (tmp_path / f"{cve_id}.osv.json").write_text(
            json.dumps(body), encoding="utf-8",
        )

    def test_returns_empty_when_file_missing(self, tmp_path):
        slug, sha = cross_check._load_pick_from_osv_file(
            tmp_path, "CVE-9999-99999",
        )
        assert (slug, sha) == ("", "")

    def test_returns_empty_when_file_unparseable(self, tmp_path):
        (tmp_path / "CVE-2024-1234.osv.json").write_text(
            "{not json", encoding="utf-8",
        )
        slug, sha = cross_check._load_pick_from_osv_file(
            tmp_path, "CVE-2024-1234",
        )
        assert (slug, sha) == ("", "")

    def test_extracts_first_github_commit_reference(self, tmp_path):
        self._write_osv(tmp_path, "CVE-2024-1234", {
            "references": [
                {"url": "https://example.com/advisory"},
                {"url": "https://github.com/owner/repo/commit/abc1234deadbeef0011223344556677889900112"},
                {"url": "https://github.com/owner/repo/commit/different0011223344556677889900112"},
            ],
        })
        slug, sha = cross_check._load_pick_from_osv_file(
            tmp_path, "CVE-2024-1234",
        )
        assert slug == "owner/repo"
        # First-match wins.
        assert sha == "abc1234deadbeef0011223344556677889900112"

    def test_strips_dot_git_suffix(self, tmp_path):
        self._write_osv(tmp_path, "CVE-2024-1234", {
            "references": [
                {"url": "https://github.com/owner/repo.git/commit/abc1234"},
            ],
        })
        slug, sha = cross_check._load_pick_from_osv_file(
            tmp_path, "CVE-2024-1234",
        )
        # Regex match stops before ``.git/`` — the slug captured
        # ends at the first ``/``, so the regex sees ``owner/repo``
        # naturally. This test pins the contract: if a future
        # regex change captures ``owner/repo.git`` we drop the
        # suffix.
        assert not slug.endswith(".git")

    def test_handles_non_dict_reference_entries(self, tmp_path):
        # Some malformed OSV records use bare URL strings in the
        # references array rather than ``{"url": "..."}``. The
        # defensive guard inside ``_load_pick_from_osv_file`` skips
        # those silently rather than raising AttributeError. This
        # test exists specifically because the pre-fix shape DID
        # crash the whole oracle path on encountering one of these.
        self._write_osv(tmp_path, "CVE-2024-9999", {
            "references": [
                "https://github.com/owner/repo/commit/abc1234",  # bare string, not dict
                {"url": "https://github.com/owner/repo/commit/abc1234"},
            ],
        })
        slug, sha = cross_check._load_pick_from_osv_file(
            tmp_path, "CVE-2024-9999",
        )
        # The dict entry below the bare string is the one that
        # gets picked.
        assert slug == "owner/repo"

    def test_falls_back_to_affected_ranges_repo(self, tmp_path):
        # When no commit-URL in references, the helper drops to
        # walking ``affected[*].ranges[*].repo`` for a github.com
        # match.
        self._write_osv(tmp_path, "CVE-2024-5555", {
            "references": [{"url": "https://example.com/none"}],
            "affected": [
                {
                    "ranges": [
                        {
                            "repo": "https://github.com/owner/repo",
                            "events": [{"fixed": "feedface"}],
                        },
                    ],
                },
            ],
        })
        slug, sha = cross_check._load_pick_from_osv_file(
            tmp_path, "CVE-2024-5555",
        )
        assert slug == "owner/repo"
        assert sha == "feedface"

    def test_returns_empty_when_references_not_a_list(self, tmp_path):
        # Defensive guard: ``references`` field shape is wrong.
        self._write_osv(tmp_path, "CVE-2024-7777", {"references": "oops"})
        slug, sha = cross_check._load_pick_from_osv_file(
            tmp_path, "CVE-2024-7777",
        )
        assert (slug, sha) == ("", "")


class TestClassifyBenchStatus:
    """``_classify_bench_status(record)`` collapses a bench-summary
    record into one of a small set of status strings.
    """

    def test_pass_when_ok_true(self):
        status = cross_check._classify_bench_status({"ok": True})
        assert status == "PASS"

    def test_unsupported_source(self):
        # The classifier walks ``r["error"]`` (free-form string,
        # not ``error_class``) and looks for specific substrings.
        # ``UnsupportedSource`` → ``UNSUPPORTED``.
        status = cross_check._classify_bench_status({
            "ok": False, "error": "UnsupportedSource: GitHub gist URL",
        })
        assert status == "UNSUPPORTED"

    def test_discovery_error(self):
        status = cross_check._classify_bench_status({
            "ok": False, "error": "DiscoveryError: no matching CVE",
        })
        assert status == "DISCOVERY_ERROR"

    def test_acquisition_error(self):
        status = cross_check._classify_bench_status({
            "ok": False, "error": "AcquisitionError: git clone failed",
        })
        assert status == "ACQUISITION_ERROR"

    def test_analysis_error(self):
        status = cross_check._classify_bench_status({
            "ok": False, "error": "AnalysisError: extractor returned nothing",
        })
        assert status == "ANALYSIS_ERROR"

    def test_other_fail_when_no_classifier_matches(self):
        # Catch-all for unrecognised error shapes — operator-visible
        # signal that the classifier needs a new branch.
        status = cross_check._classify_bench_status({
            "ok": False, "error": "RuntimeError: assert violated",
        })
        assert status == "OTHER_FAIL"

    def test_other_fail_when_ok_field_missing(self):
        # Missing ``ok`` collapses to falsy → goes through the
        # error-class walk; with no ``error`` field that's
        # OTHER_FAIL.
        status = cross_check._classify_bench_status({})
        assert status == "OTHER_FAIL"


# Confirm the regex object is module-level (i.e. compiled once).
def test_gh_commit_url_compiled_once():
    """Sanity check that the regex is module-level — if a future
    refactor moves it into the function body the compile cost
    multiplies by the per-CVE call count."""
    assert hasattr(cross_check._GH_COMMIT_URL, "search")
    # Verify it's the same object across re-imports (module
    # caching, not function-local).
    from cve_diff.oracle import cross_check as cc2
    assert cross_check._GH_COMMIT_URL is cc2._GH_COMMIT_URL


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
