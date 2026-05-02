"""Tests for cve_diff/agent/source_classes.py — source-exhaustion cascade."""
from __future__ import annotations

from cve_diff.agent.source_classes import (
    MIN_CLASSES_FOR_SURRENDER,
    SOURCE_CLASSES,
    SURRENDER_COST_FLOOR_USD,
    VERIFICATION_TOOLS,
    enough_classes_tried,
    has_verified,
    should_surrender_no_evidence,
    tried_classes,
    untried_classes,
)


# ---------- tried_classes ----------

def test_tried_classes_maps_tool_to_class() -> None:
    log = ["osv_raw", "nvd_raw", "gh_search_commits"]
    assert tried_classes(log) == {"osv", "nvd", "github_search"}


def test_tried_classes_dedups_within_class() -> None:
    """Multiple calls to OSV tools count as 1 class."""
    log = ["osv_raw", "osv_expand_aliases", "osv_raw"]
    assert tried_classes(log) == {"osv"}


def test_tried_classes_ignores_unknown_tools() -> None:
    """submit_result and verification-only tools (gh_commit_detail) are
    NOT in any source class (they're terminal / verification, not data
    acquisition)."""
    log = ["submit_result", "gh_commit_detail"]
    assert tried_classes(log) == frozenset()


# ---------- has_verified ----------

def test_has_verified_true_for_gh_commit_detail() -> None:
    assert has_verified(["osv_raw", "gh_commit_detail"]) is True


def test_has_verified_true_for_forge_tools() -> None:
    """gitlab_commit and cgit_fetch double as verification."""
    assert has_verified(["osv_raw", "gitlab_commit"]) is True
    assert has_verified(["osv_raw", "cgit_fetch"]) is True


def test_has_verified_false_for_search_only() -> None:
    log = ["osv_raw", "nvd_raw", "gh_search_commits", "http_fetch"]
    assert has_verified(log) is False


# ---------- should_surrender_no_evidence ----------

def test_surrender_when_threshold_classes_tried_no_verification_above_floor() -> None:
    """≥ MIN_CLASSES_FOR_SURRENDER source classes tried, no verification,
    above cost floor → surrender. Calibrated on v7 walker data."""
    # 5 distinct classes: osv, nvd, github_search, distro_trackers, generic_http
    log = ["osv_raw", "nvd_raw", "gh_search_commits",
           "fetch_distro_advisory", "http_fetch"]
    assert len(set(log)) >= MIN_CLASSES_FOR_SURRENDER
    assert should_surrender_no_evidence(log, SURRENDER_COST_FLOOR_USD) is True
    assert should_surrender_no_evidence(log, 1.50) is True


def test_no_surrender_when_under_cost_floor() -> None:
    """Cheap CVE solved via OSV-only shouldn't trip the rule even
    though only OSV is tried — cost floor protects fast-path PASSes."""
    log = ["osv_raw"]
    assert should_surrender_no_evidence(log, 0.10) is False


def test_no_surrender_when_under_class_threshold() -> None:
    """Under MIN_CLASSES_FOR_SURRENDER classes tried → don't surrender,
    even above cost floor. Gives legitimate cascades a chance to land."""
    # 4 distinct classes — under threshold of 5
    log = ["osv_raw", "nvd_raw", "gh_search_commits", "http_fetch"]
    assert should_surrender_no_evidence(log, 1.00) is False


def test_no_surrender_when_verification_called() -> None:
    """Verified candidate present → never surrender via this rule."""
    log = ["osv_raw", "gh_commit_detail", "http_fetch", "http_fetch"]
    assert should_surrender_no_evidence(log, 2.00) is False


# ---------- untried_classes ----------

def test_untried_classes_lists_remaining() -> None:
    log = ["osv_raw", "nvd_raw"]
    untried = untried_classes(log)
    assert "github_search" in untried
    assert "distro_trackers" in untried
    assert "non_github_forge" in untried
    assert "generic_http" in untried
    assert "deterministic_hints" in untried
    assert "osv" not in untried
    assert "nvd" not in untried


# ---------- catalog hygiene ----------

def test_source_classes_keys_match_documented_set() -> None:
    expected = {
        "osv", "nvd", "deterministic_hints", "github_search",
        "distro_trackers", "non_github_forge", "generic_http",
    }
    assert set(SOURCE_CLASSES.keys()) == expected


def test_verification_tools_includes_all_forge_verifiers() -> None:
    """gh_commit_detail + gitlab_commit + cgit_fetch are the verification trio."""
    assert VERIFICATION_TOOLS == frozenset({
        "gh_commit_detail", "gitlab_commit", "cgit_fetch",
    })


def test_enough_classes_tried_at_threshold() -> None:
    """``enough_classes_tried`` is True at exactly MIN_CLASSES_FOR_SURRENDER
    and above; False below. Calibrated on v7 walker data."""
    # 5 distinct classes
    log_at = ["osv_raw", "nvd_raw", "gh_search_commits",
              "fetch_distro_advisory", "http_fetch"]
    assert enough_classes_tried(log_at) is True

    # 4 distinct classes — under threshold
    log_under = ["osv_raw", "nvd_raw", "gh_search_commits", "http_fetch"]
    assert enough_classes_tried(log_under) is False

    # All 7 classes — well above
    log_all = log_at + ["deterministic_hints", "git_ls_remote"]
    assert enough_classes_tried(log_all) is True
