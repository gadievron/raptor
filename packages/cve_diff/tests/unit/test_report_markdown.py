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


# --- byte-accurate diff truncation ---
# DIFF_BODY_LIMIT_BYTES and the "diff truncated at N bytes" note both
# describe a byte count, so the check and slice must measure the UTF-8
# encoding (dropping any partial trailing character), not the Python
# character count — multi-byte diffs could otherwise run up to ~4x past
# the advertised cap.

def _utf8_bundle(diff_text: str) -> DiffBundle:
    return _bundle(diff_text=diff_text,
                   bytes_size=len(diff_text.encode("utf-8")))


def test_multibyte_diff_truncates_at_byte_limit_not_char_count():
    """Char count under the limit, byte count over: must truncate."""
    # 2 bytes per char in UTF-8; chars < limit < bytes.
    big = "é" * (markdown.DIFF_BODY_LIMIT_BYTES // 2 + 512)
    assert len(big) < markdown.DIFF_BODY_LIMIT_BYTES < len(big.encode("utf-8"))
    md = markdown.render(_utf8_bundle(big))
    assert "diff truncated" in md
    assert big not in md


def test_truncated_body_does_not_exceed_byte_limit():
    big = "é" * markdown.DIFF_BODY_LIMIT_BYTES  # 2x the limit in bytes
    md = markdown.render(_utf8_bundle(big))
    start = md.index("```diff\n") + len("```diff\n")
    end = md.index("\n```", start)
    body = md[start:end]
    # The neutraliser only rewrites backtick runs; none here, so the
    # fenced body is the truncated diff verbatim.
    assert len(body.encode("utf-8")) <= markdown.DIFF_BODY_LIMIT_BYTES


def test_byte_cut_mid_codepoint_drops_partial_char_cleanly():
    """A cut landing inside a multi-byte sequence must not surface a
    replacement char or raise."""
    diff = "a" * (markdown.DIFF_BODY_LIMIT_BYTES - 1) + "é" + "tail"
    md = markdown.render(_utf8_bundle(diff))
    assert "diff truncated" in md
    assert "�" not in md
    assert "tail" not in md


def test_ascii_diff_at_exact_limit_is_not_truncated():
    exact = "x" * markdown.DIFF_BODY_LIMIT_BYTES
    md = markdown.render(_utf8_bundle(exact))
    assert "diff truncated" not in md
    assert exact in md


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


def test_humanize_class_maps_identical_commits_error() -> None:
    label = markdown._humanize_class("IdenticalCommitsError")
    assert not label.startswith("Other (")
    assert "same commit" in label
