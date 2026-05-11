"""Tests for ``packages.sca.bump.policy`` — operator
``.raptor-sca-bump.yml`` loading + behaviour."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.bump.policy import (
    BumpPolicy, SkipRule, Thresholds, load_policy,
)


yaml = pytest.importorskip("yaml")


def _write_policy(tmp_path: Path, body: str) -> None:
    (tmp_path / ".raptor-sca-bump.yml").write_text(body)


# ---------------------------------------------------------------------------
# load_policy
# ---------------------------------------------------------------------------

def test_load_no_file_returns_default_policy(tmp_path: Path) -> None:
    """Missing file → default policy (no skips, default
    thresholds). Bumper runs as if no policy file was supplied."""
    policy = load_policy(tmp_path)
    assert policy.skip == []
    assert policy.thresholds.rapid_release_days == 30
    assert policy.thresholds.block_on_major is False


def test_load_skip_by_locator(tmp_path: Path) -> None:
    """``skip:`` rule with a locator matches that locator
    exactly."""
    _write_policy(tmp_path, """
skip:
  - locator: actions/checkout
    reason: vendored fork
""")
    policy = load_policy(tmp_path)
    assert len(policy.skip) == 1
    rule = policy.skip[0]
    assert rule.locator == "actions/checkout"
    assert rule.reason == "vendored fork"


def test_load_skip_by_kind(tmp_path: Path) -> None:
    """``skip:`` rule with a kind matches every candidate of
    that kind."""
    _write_policy(tmp_path, """
skip:
  - kind: from_image
    reason: schema migration coordination required
""")
    policy = load_policy(tmp_path)
    assert policy.skip[0].kind == "from_image"


def test_load_kind_and_locator_both_must_match(tmp_path: Path) -> None:
    """When both ``kind`` and ``locator`` are set, BOTH must
    match for the rule to fire (AND semantics)."""
    rule = SkipRule(kind="arg", locator="SEMGREP_VERSION",
                     reason="test")
    assert rule.matches(candidate_kind="arg",
                         candidate_locator="SEMGREP_VERSION")
    assert not rule.matches(candidate_kind="from_image",
                             candidate_locator="SEMGREP_VERSION")
    assert not rule.matches(candidate_kind="arg",
                             candidate_locator="OTHER_VERSION")


def test_load_skip_wildcard_locator(tmp_path: Path) -> None:
    """``locator: actions/*`` matches any GHA action under the
    ``actions/`` namespace."""
    _write_policy(tmp_path, """
skip:
  - locator: "actions/*"
    reason: pin all official actions manually
""")
    policy = load_policy(tmp_path)
    rule = policy.skip[0]
    assert rule.matches(candidate_kind="gha_uses",
                         candidate_locator="actions/checkout")
    assert rule.matches(candidate_kind="gha_uses",
                         candidate_locator="actions/setup-python")
    assert not rule.matches(candidate_kind="gha_uses",
                             candidate_locator="astral-sh/setup-uv")


def test_load_thresholds(tmp_path: Path) -> None:
    """``thresholds:`` block overrides the defaults."""
    _write_policy(tmp_path, """
thresholds:
  rapid_release_days: 14
  block_on_major: true
""")
    policy = load_policy(tmp_path)
    assert policy.thresholds.rapid_release_days == 14
    assert policy.thresholds.block_on_major is True


def test_load_partial_thresholds_keep_defaults_for_missing(
    tmp_path: Path,
) -> None:
    """Operator sets only ``rapid_release_days``; ``block_on_major``
    stays at its default."""
    _write_policy(tmp_path, """
thresholds:
  rapid_release_days: 7
""")
    policy = load_policy(tmp_path)
    assert policy.thresholds.rapid_release_days == 7
    assert policy.thresholds.block_on_major is False


# ---------------------------------------------------------------------------
# Fail-soft loading
# ---------------------------------------------------------------------------

def test_malformed_yaml_returns_default(tmp_path: Path) -> None:
    """Malformed YAML → default policy + warning log. Bumper
    doesn't crash on a bad policy."""
    _write_policy(tmp_path, ":::: not valid yaml: : :\n")
    policy = load_policy(tmp_path)
    assert policy.skip == []
    assert policy.thresholds.rapid_release_days == 30


def test_non_mapping_top_level_returns_default(tmp_path: Path) -> None:
    """``[a, b, c]`` at top level → default (we expect a dict)."""
    _write_policy(tmp_path, "- just\n- a list\n")
    policy = load_policy(tmp_path)
    assert policy.skip == []


def test_empty_skip_rule_silently_dropped(tmp_path: Path) -> None:
    """``- {}`` in the skip list would match EVERYTHING — refuse
    to load it. Silent drop rather than load + skip-all because
    operators rarely actually want that."""
    _write_policy(tmp_path, """
skip:
  - {}
  - locator: foo
""")
    policy = load_policy(tmp_path)
    assert len(policy.skip) == 1
    assert policy.skip[0].locator == "foo"


def test_negative_rapid_release_days_ignored(tmp_path: Path) -> None:
    """``rapid_release_days: -1`` is nonsensical — ignore and
    keep the default. Operator gets the default + can fix the
    file."""
    _write_policy(tmp_path, """
thresholds:
  rapid_release_days: -1
""")
    policy = load_policy(tmp_path)
    assert policy.thresholds.rapid_release_days == 30


# ---------------------------------------------------------------------------
# is_skipped
# ---------------------------------------------------------------------------

def test_is_skipped_returns_first_matching_rule() -> None:
    """When multiple rules match, the first one wins (so the
    operator can put more specific rules before more general
    ones)."""
    rule_a = SkipRule(locator="actions/*", reason="general")
    rule_b = SkipRule(locator="actions/checkout", reason="specific")
    # rule_b is more specific, but rule_a is listed first — first
    # match wins, so rule_a fires.
    policy = BumpPolicy(skip=[rule_a, rule_b])
    matched = policy.is_skipped(
        kind="gha_uses", locator="actions/checkout",
    )
    assert matched is rule_a


def test_is_skipped_none_when_no_match() -> None:
    policy = BumpPolicy(skip=[SkipRule(locator="actions/*")])
    assert policy.is_skipped(
        kind="gha_uses", locator="astral-sh/setup-uv",
    ) is None


# ---------------------------------------------------------------------------
# Integration with the orchestrator
# ---------------------------------------------------------------------------

def test_orchestrator_honours_policy_skip(tmp_path: Path) -> None:
    """A locator listed in ``skip:`` is moved from candidates
    into skipped with the operator's stated reason."""
    pytest.importorskip("yaml")
    # Set up a target Dockerfile + a policy that skips SEMGREP.
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
        "ARG BLACK_VERSION=20.0\n"
    )
    _write_policy(tmp_path, """
skip:
  - locator: SEMGREP_VERSION
    reason: pinned for compat with old config
""")
    # Stub HTTP / pypi for both upstreams.
    from packages.sca.bump.tests.test_pr_comment import (
        _StubHttp, _StubPyPI,
    )
    from packages.sca.bump.orchestrator import run_bump
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0"},
        "https://api.github.com/repos/psf/black/releases/latest":
            {"tag_name": "25.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "1.119.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
        "black": {"releases": {
            "25.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    report = run_bump(tmp_path, http=http, pypi_client=pypi)
    # SEMGREP_VERSION is skipped; BLACK_VERSION is a candidate.
    arg_cands = [c for c in report.candidates if c.kind == "arg"]
    assert [c.locator for c in arg_cands] == ["BLACK_VERSION"]
    # The skip surfaces in the skipped list with the reason.
    semgrep_skip = [
        s for s in report.skipped
        if s[0] == "SEMGREP_VERSION"
    ]
    assert len(semgrep_skip) == 1
    assert "pinned for compat" in semgrep_skip[0][2]


def test_orchestrator_block_on_major_forces_review_to_block(
    tmp_path: Path,
) -> None:
    """``block_on_major: true`` policy forces major-version
    bumps from Clean/Review to Block-tier, even if no other
    signal escalates."""
    pytest.importorskip("yaml")
    (tmp_path / "Dockerfile").write_text(
        "ARG SEMGREP_VERSION=1.50.0\n"
    )
    _write_policy(tmp_path, """
thresholds:
  block_on_major: true
""")
    from packages.sca.bump.tests.test_pr_comment import (
        _StubHttp, _StubPyPI,
    )
    from packages.sca.bump.orchestrator import (
        _VERDICT_BLOCK, run_bump,
    )
    http = _StubHttp({
        # Major bump 1.x → 2.x.
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v2.0.0"},
    })
    pypi = _StubPyPI({
        "semgrep": {"releases": {
            "2.0.0": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    report = run_bump(tmp_path, http=http, pypi_client=pypi)
    assert report.results[0].verdict == _VERDICT_BLOCK
