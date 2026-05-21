"""Tests for LLM maintainer-trust synthesis stage."""

from __future__ import annotations

from pathlib import Path


from packages.sca.llm.maintainer_trust import (
    _format_metadata,
    assess_batch,
)
from packages.sca.models import Confidence, Dependency, PinStyle


def _make_dep(
    name: str = "example-pkg",
    ecosystem: str = "npm",
    version: str = "2.0.0",
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("/fake/package.json"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence(level="high"),
    )


class TestFormatMetadata:
    def test_basic_metadata(self):
        dep = _make_dep()
        meta = {
            "maintainers": [
                {"name": "alice", "email": "alice@example.com", "added": "2024-01"},
                {"name": "bob"},
            ],
            "publish_dates": ["2024-06-01", "2024-07-15"],
            "repository_url": "https://github.com/org/pkg",
            "download_count": 50000,
        }
        text = _format_metadata(dep, meta)
        assert "npm/example-pkg" in text
        assert "alice" in text
        assert "alice@example.com" in text
        assert "2024-06-01" in text
        assert "50000" in text
        assert "github.com/org/pkg" in text

    def test_empty_metadata(self):
        dep = _make_dep()
        text = _format_metadata(dep, {})
        assert "npm/example-pkg" in text
        assert "Version analysed: 2.0.0" in text

    def test_maintainers_capped_at_20(self):
        dep = _make_dep()
        meta = {
            "maintainers": [{"name": f"m{i}"} for i in range(30)],
        }
        text = _format_metadata(dep, meta)
        assert "m19" in text
        assert "m20" not in text

    def test_deprecated_flag(self):
        dep = _make_dep()
        meta = {"deprecated": "Use successor-pkg instead"}
        text = _format_metadata(dep, meta)
        assert "Deprecated:" in text

    def test_extra_fields(self):
        dep = _make_dep()
        meta = {
            "stars": 1234,
            "open_issues": 42,
            "last_commit_date": "2024-12-01",
        }
        text = _format_metadata(dep, meta)
        assert "stars: 1234" in text
        assert "open_issues: 42" in text
        assert "last_commit_date: 2024-12-01" in text


class TestAssessBatch:
    def test_empty_batch(self):
        results = assess_batch(object(), [])
        assert results == {}
