"""OSV Schema 1.6.0 renderer tests."""

from __future__ import annotations

from datetime import UTC, datetime

from cve_diff.core.models import CommitSha, DiffBundle, RepoRef
from cve_diff.report import osv_schema


def _bundle() -> DiffBundle:
    ref = RepoRef(
        repository_url="https://github.com/curl/curl",
        fix_commit=CommitSha("aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"),
        introduced=CommitSha("bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"),
        canonical_score=100,
    )
    return DiffBundle(
        cve_id="CVE-2023-38545",
        repo_ref=ref,
        commit_before=CommitSha("bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"),
        commit_after=CommitSha("aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"),
        diff_text="--- a\n+++ b\n",
        files_changed=2,
        bytes_size=1024,
    )


def test_render_has_required_top_level_fields():
    osv = osv_schema.render(_bundle())
    assert osv["schema_version"] == "1.6.0"
    assert osv["id"] == "CVE-2023-38545"
    assert "modified" in osv
    assert "references" in osv
    assert "affected" in osv


def test_render_modified_is_iso8601_utc():
    osv = osv_schema.render(_bundle(), modified=datetime(2026, 4, 19, 12, 0, 0, tzinfo=UTC))
    assert osv["modified"] == "2026-04-19T12:00:00Z"


def test_render_emits_fix_reference_url():
    osv = osv_schema.render(_bundle())
    refs = osv["references"]
    assert any(r["type"] == "FIX" for r in refs)
    fix = next(r for r in refs if r["type"] == "FIX")
    assert fix["url"] == "https://github.com/curl/curl/commit/aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"


def test_render_strips_dot_git_suffix_from_url():
    ref = RepoRef(
        repository_url="https://github.com/curl/curl.git",
        fix_commit=CommitSha("a" * 40),
        introduced=CommitSha("b" * 40),
        canonical_score=100,
    )
    bundle = DiffBundle(
        cve_id="CVE-X",
        repo_ref=ref,
        commit_before=CommitSha("b" * 40),
        commit_after=CommitSha("a" * 40),
        diff_text="",
        files_changed=0,
        bytes_size=0,
    )
    osv = osv_schema.render(bundle)
    assert osv["references"][0]["url"] == "https://github.com/curl/curl/commit/" + "a" * 40


def test_render_affected_uses_git_range_with_introduced_and_fixed():
    osv = osv_schema.render(_bundle())
    affected = osv["affected"][0]
    assert affected["ranges"][0]["type"] == "GIT"
    assert affected["ranges"][0]["repo"] == "https://github.com/curl/curl"
    events = affected["ranges"][0]["events"]
    assert events == [
        {"introduced": "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"},
        {"fixed": "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"},
    ]


def test_render_database_specific_carries_diff_stats():
    osv = osv_schema.render(_bundle())
    assert osv["database_specific"]["files_changed"] == 2
    assert osv["database_specific"]["diff_bytes"] == 1024
    assert osv["database_specific"]["canonical_score"] == 100
