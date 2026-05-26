"""Tests for the sentinel package detector."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.supply_chain.sentinel import scan_deps, _load_sentinels


def _dep(name: str, ecosystem: str = "npm", version: str = "1.0.0") -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("/x/package.json"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def test_loads_sentinel_data():
    sentinels = _load_sentinels()
    assert len(sentinels) > 0
    assert ("npm", "event-stream") in sentinels


def test_matches_known_malicious_npm():
    deps = [_dep("event-stream", ecosystem="npm", version="3.3.6")]
    hits = scan_deps(deps)
    assert len(hits) == 1
    assert hits[0].severity == "critical"
    assert "backdoor" in hits[0].incident.lower()


def test_matches_wildcard_version():
    deps = [_dep("flatmap-stream", ecosystem="npm", version="99.99.99")]
    hits = scan_deps(deps)
    assert len(hits) == 1


def test_no_match_for_clean_package():
    deps = [_dep("express", ecosystem="npm", version="4.18.0")]
    hits = scan_deps(deps)
    assert hits == []


def test_matches_pypi_sentinel():
    deps = [_dep("ctx", ecosystem="PyPI", version="0.1")]
    hits = scan_deps(deps)
    assert len(hits) == 1
    assert "credential stealer" in hits[0].incident.lower()


def test_version_specific_no_match():
    """ua-parser-js sentinel lists specific versions; clean version shouldn't match."""
    deps = [_dep("ua-parser-js", ecosystem="npm", version="1.0.33")]
    hits = scan_deps(deps)
    assert hits == []


def test_version_specific_match():
    deps = [_dep("ua-parser-js", ecosystem="npm", version="0.7.29")]
    hits = scan_deps(deps)
    assert len(hits) == 1


def test_case_insensitive_name():
    deps = [_dep("Event-Stream", ecosystem="npm", version="3.3.6")]
    hits = scan_deps(deps)
    assert len(hits) == 1


def test_dedup_same_dep_multiple_rows():
    deps = [
        _dep("event-stream", ecosystem="npm", version="3.3.6"),
        _dep("event-stream", ecosystem="npm", version="3.3.6"),
    ]
    hits = scan_deps(deps)
    assert len(hits) == 1


def test_wrong_ecosystem_no_match():
    deps = [_dep("event-stream", ecosystem="PyPI", version="3.3.6")]
    hits = scan_deps(deps)
    assert hits == []


def test_confidence_is_high():
    deps = [_dep("flatmap-stream", ecosystem="npm", version="1.0")]
    hits = scan_deps(deps)
    assert hits[0].confidence.level == "high"
