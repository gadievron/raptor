"""Tests for agent/prompt.py."""
from __future__ import annotations

from cve_diff.agent.prompt import SYSTEM_PROMPT, build_user_message


def test_system_prompt_has_tool_references() -> None:
    # Sanity — prompt mentions the key tools it promises the agent can call.
    for name in ("osv_raw", "nvd_raw", "submit_result", "gh_commit_detail"):
        assert name in SYSTEM_PROMPT


def test_system_prompt_wraps_untrusted_phrase() -> None:
    assert "<untrusted" in SYSTEM_PROMPT


def test_user_message_minimal() -> None:
    msg = build_user_message("CVE-2023-38545")
    assert "CVE-2023-38545" in msg
    assert "submit_result" in msg


def test_user_message_with_osv_wraps_untrusted() -> None:
    msg = build_user_message("CVE-2023-38545", osv_text='{"id":"X"}')
    assert "<untrusted source=\"osv\">" in msg
    assert "</untrusted>" in msg


def test_user_message_truncates_long_payloads() -> None:
    big = "x" * 100000
    msg = build_user_message("CVE-Y", osv_text=big, nvd_text=big)
    # Two 20K blobs plus framing — should be well under the raw 200K input.
    assert len(msg) < 60_000
