"""Markdown renderer tests."""

from __future__ import annotations

from cve_diff.core.models import CommitSha, DiffBundle, RepoRef
from cve_diff.report import markdown


def _bundle(diff_text: str = "--- a\n+++ b\n", bytes_size: int = 1024) -> DiffBundle:
    ref = RepoRef(
        repository_url="https://github.com/curl/curl",
        fix_commit=CommitSha("a" * 40),
        introduced=CommitSha("b" * 40),
        canonical_score=100,
    )
    return DiffBundle(
        cve_id="CVE-2023-38545",
        repo_ref=ref,
        commit_before=CommitSha("b" * 40),
        commit_after=CommitSha("a" * 40),
        diff_text=diff_text,
        files_changed=2,
        bytes_size=bytes_size,
    )


def test_renders_header_and_repo():
    md = markdown.render(_bundle())
    assert md.startswith("# CVE-2023-38545")
    assert "https://github.com/curl/curl" in md
    assert "Files changed:** 2" in md


def test_includes_commit_links():
    md = markdown.render(_bundle())
    fix_url = "https://github.com/curl/curl/commit/" + "a" * 40
    intro_url = "https://github.com/curl/curl/commit/" + "b" * 40
    assert fix_url in md
    assert intro_url in md


def test_diff_body_in_fenced_block():
    md = markdown.render(_bundle(diff_text="diff line\n"))
    assert "```diff" in md
    assert "diff line" in md
    assert md.rstrip().endswith("```") or "_…diff truncated" in md


def test_truncates_oversize_diff():
    big = "x" * (markdown.DIFF_BODY_LIMIT_BYTES + 1000)
    md = markdown.render(_bundle(diff_text=big, bytes_size=len(big)))
    assert "diff truncated" in md
    assert big not in md


def test_handles_dot_git_url():
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
    md = markdown.render(bundle)
    assert "curl/curl/commit/" in md
    assert ".git/commit/" not in md


# --- failure markdown (Action a: surrender rationale) ---

def test_render_failure_includes_rationale_after_stripping_prefix() -> None:
    """The surrender prefix is stripped so the rationale reads as headline."""
    err = (
        "DiscoveryError: CVE-X-001: agent surrendered (no_evidence): "
        "WSO2 Carbon products are commercial; OSV's affected.ranges "
        "list only last_affected commits."
    )
    md = markdown.render_failure("CVE-X-001", "no_evidence", err)
    assert "CVE-X-001" in md
    assert "Why no fix was extracted" in md
    assert "WSO2 Carbon products are commercial" in md
    # Prefix must be stripped
    assert "agent surrendered" not in md


def test_render_failure_humanizes_error_class() -> None:
    md = markdown.render_failure("CVE-X-002", "UnsupportedSource",
                                 "UnsupportedSource: CVE-X-002: closed-source vendor.")
    assert "Out of scope" in md
    assert "closed-source" in md.lower()


def test_render_failure_handles_unknown_class() -> None:
    md = markdown.render_failure("CVE-X-003", "weirdo_class",
                                 "weirdo_class: CVE-X-003: rationale here.")
    assert "weirdo_class" in md
    assert "rationale here" in md


def test_render_failure_handles_empty_rationale() -> None:
    md = markdown.render_failure("CVE-X-004", "no_evidence", "")
    assert "CVE-X-004" in md
    assert "no rationale recorded" in md


def test_render_failure_strips_typed_exception_prefix() -> None:
    """`UnsupportedSource: CVE-X: rationale` → just rationale."""
    md = markdown.render_failure(
        "CVE-X-005", "UnsupportedSource",
        "UnsupportedSource: CVE-X-005: F5 BIG-IP appliance is closed-source.",
    )
    # Headline should be the rationale, no "UnsupportedSource:" prefix duplicated
    assert "F5 BIG-IP appliance is closed-source" in md
    assert "UnsupportedSource: CVE-X-005:" not in md
