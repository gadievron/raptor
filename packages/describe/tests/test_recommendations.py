"""Tests for ``packages/describe/recommendations.py``."""

from __future__ import annotations

from pathlib import Path

from packages.describe.deps import DependencyCounts
from packages.describe.recommendations import (
    Recommendation,
    recommend_next,
)
from packages.describe.target_shape import TargetShape


def _shape(**overrides) -> TargetShape:
    base = dict(
        target_path=Path("/tmp"),
        languages={},
        language_breakdown={},
        primary_language=None,
        build_systems={},
        target_type=None,
        total_files=0,
        total_lines=0,
    )
    base.update(overrides)
    return TargetShape(**base)


class TestRecommendNext:
    def test_minimal_shape_recommends_agentic(self):
        # No deps, no build, no CI. /agentic is the only
        # rec — applies to any target as the catch-all.
        recs = recommend_next(_shape())
        assert len(recs) == 1
        assert recs[0].command == "/agentic"
        assert "any target" in recs[0].reason

    def test_deps_present_recommends_sca(self):
        recs = recommend_next(_shape(
            deps=DependencyCounts(by_ecosystem={"npm": 180}),
        ))
        sca = next(r for r in recs if r.command == "/sca")
        assert "180 npm" in sca.reason

    def test_build_present_recommends_codeql(self):
        # /codeql recommended whenever a build system is
        # detected. We deliberately DON'T check CI state — RAPTOR
        # /codeql does different work than a generic CI codeql
        # scan (different queries / suites / IRIS Tier 1
        # dataflow), and "skip because it's in CI" is bad
        # advice for a security framework where defensive
        # scanning should be additive.
        recs = recommend_next(_shape(
            primary_language="cpp",
            build_systems={"cpp": "autotools"},
        ))
        codeql = next(r for r in recs if r.command == "/codeql")
        assert "autotools" in codeql.reason

    def test_no_build_system_omits_codeql(self):
        # Header-only library, script collection, etc. — no
        # build, /codeql doesn't apply.
        recs = recommend_next(_shape(
            primary_language="python",
            build_systems={},  # no build detected
        ))
        assert not any(r.command == "/codeql" for r in recs)

    def test_agentic_dropped_when_other_recs_present(self):
        # /agentic is the catch-all — when signal-driven picks
        # exist, the catalog Pipeline line above already names
        # /agentic, so we don't repeat it. Pre-fix surfaced an
        # always-on row that read like marketing copy.
        recs = recommend_next(_shape(
            deps=DependencyCounts(by_ecosystem={"npm": 10}),
            primary_language="cpp",
            build_systems={"cpp": "cmake"},
        ))
        commands = [r.command for r in recs]
        assert "/agentic" not in commands

    def test_recommendation_is_immutable(self):
        rec = Recommendation(command="/sca", reason="x")
        import pytest
        with pytest.raises(Exception):  # FrozenInstanceError
            rec.command = "/agentic"  # type: ignore[misc]

    def test_full_signal_set_orders_correctly(self):
        # Realistic: a C++ daemon with deps + autotools.
        # /agentic dropped when other recs present (catalog
        # Pipeline line already names it).
        recs = recommend_next(_shape(
            primary_language="cpp",
            build_systems={"cpp": "autotools"},
            deps=DependencyCounts(
                by_ecosystem={"PyPI": 12, "OCI": 3},
            ),
        ))
        commands = [r.command for r in recs]
        assert commands == ["/sca", "/codeql"]
