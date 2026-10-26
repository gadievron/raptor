"""Tests for resolution-replay validation in _reuse_ineligibility.

Covers:
 - heuristic-derived clean screen (rationale-consistency body prefix)
 - silence-derived resolution replay gated by resolution_tools
 - _reuse_block_class mapping for the new reason strings
"""

from __future__ import annotations

from types import SimpleNamespace

from core.audit.gaps import _reuse_block_class, _reuse_ineligibility


def _entry(**kwargs):
    defaults = dict(
        verdict="clean",
        context_reduced=None,
        provisional=None,
        model=None,
        body="",
        resolution_tools=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class TestHeuristicDerivedCleanScreen:
    def test_rationale_consistency_prefix_refused(self):
        entry = _entry(
            body="[rationale-consistency demotion: the rationale below "
                 "concludes clean while the emitted status was finding]\n\n"
                 "The function is safe.",
        )
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason == "heuristic-derived clean"

    def test_normal_clean_not_refused(self):
        entry = _entry(body="No issue found in this function.")
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason is None

    def test_block_class_heuristic_derived(self):
        assert _reuse_block_class("heuristic-derived clean") == "heuristic_derived"


class TestSilenceDerivedResolutionReplay:
    def test_legacy_resolution_no_tools_refused(self):
        entry = _entry(
            body="[suspicious-resolution: silent sweep, no corroboration]",
            resolution_tools=None,
        )
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason == "legacy silence-derived resolution"

    def test_resolution_with_matching_tools_accepted(self):
        entry = _entry(
            body="[suspicious-resolution: silent sweep]",
            resolution_tools=["joern", "semgrep"],
        )
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
            current_tools=frozenset(["joern", "semgrep"]),
        )
        assert reason is None

    def test_resolution_with_changed_tools_refused(self):
        entry = _entry(
            body="[suspicious-resolution: silent sweep]",
            resolution_tools=["semgrep"],
        )
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
            current_tools=frozenset(["joern", "semgrep"]),
        )
        assert reason == "resolution tool coverage changed"

    def test_resolution_with_fewer_tools_refused(self):
        entry = _entry(
            body="[suspicious-resolution: silent sweep]",
            resolution_tools=["joern", "semgrep"],
        )
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
            current_tools=frozenset(["semgrep"]),
        )
        assert reason == "resolution tool coverage changed"

    def test_resolution_tools_none_current_tools_passes(self):
        """When current_tools is None (unknown), skip the tool check."""
        entry = _entry(
            body="[suspicious-resolution: silent sweep]",
            resolution_tools=["semgrep"],
        )
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
            current_tools=None,
        )
        assert reason is None

    def test_non_resolution_body_unaffected(self):
        entry = _entry(
            body="Normal review body.",
            resolution_tools=None,
        )
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason is None

    def test_block_class_legacy_resolution(self):
        assert _reuse_block_class(
            "legacy silence-derived resolution") == "resolution_stale"

    def test_block_class_tool_coverage_changed(self):
        assert _reuse_block_class(
            "resolution tool coverage changed") == "resolution_stale"
