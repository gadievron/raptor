"""Tests for the GHA action sunset / deprecation detector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.supply_chain.gha_sunset import (
    load_sunset_map,
    scan_dependencies,
)


def _action(
    name: str, version: str, *, ecosystem: str = "GitHub Actions",
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path(".github/workflows/ci.yml"),
        scope="build",
        is_lockfile=False,
        pin_style=PinStyle.CARET,
        direct=True,
        purl=f"pkg:githubactions/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
        source_kind="gha_uses",
        source_extra={"ref": version},
    )


def _stub_sunset(records: Dict[str, list]) -> Dict[str, list]:
    return records


# ---------------------------------------------------------------------------
# load_sunset_map
# ---------------------------------------------------------------------------


def test_load_real_sunset_data():
    """The shipped data file loads + the curated entries are
    structured correctly."""
    out = load_sunset_map()
    assert "actions/checkout" in out
    assert "actions/upload-artifact" in out
    # All records have the required shape.
    for action, records in out.items():
        for r in records:
            assert isinstance(r.get("sunset_versions"), list)


def test_load_skips_doc_keys(tmp_path):
    """``_doc`` / ``_schema`` schema-helper keys are filtered."""
    p = tmp_path / "sunset.json"
    p.write_text(json.dumps({
        "_doc": "...",
        "_schema": {},
        "actions/x": [{"sunset_versions": ["v1"]}],
    }))
    out = load_sunset_map(p)
    assert "_doc" not in out
    assert "_schema" not in out
    assert "actions/x" in out


def test_load_drops_malformed_records(tmp_path):
    p = tmp_path / "sunset.json"
    p.write_text(json.dumps({
        "actions/good": [{"sunset_versions": ["v1"]}],
        "actions/bad-list-item": [
            {"sunset_versions": ["v1"]},
            "not-a-dict",
            {"no_sunset_versions": True},
        ],
        "actions/bad-shape": "not-a-list",
    }))
    out = load_sunset_map(p)
    assert "actions/good" in out
    assert "actions/bad-shape" not in out
    # bad-list-item still surfaces with its valid record only.
    assert len(out["actions/bad-list-item"]) == 1


def test_load_returns_empty_on_missing_file(tmp_path):
    out = load_sunset_map(tmp_path / "does-not-exist.json")
    assert out == {}


def test_load_returns_empty_on_malformed_json(tmp_path):
    p = tmp_path / "sunset.json"
    p.write_text("{not json")
    assert load_sunset_map(p) == {}


# ---------------------------------------------------------------------------
# scan_dependencies — match semantics
# ---------------------------------------------------------------------------


def test_exact_version_match_emits_finding():
    deps = [_action("actions/upload-artifact", "v3")]
    sunset = {
        "actions/upload-artifact": [{
            "sunset_versions": ["v1", "v2", "v3"],
            "sunset_date": "2024-11-30",
            "reason": "v3 sunset",
            "replacement": "v4",
            "severity": "high",
        }],
    }
    [finding] = scan_dependencies(deps, sunset_map=sunset)
    assert finding.kind == "gha_action_sunset"
    assert finding.severity == "high"
    assert "v3" in finding.detail
    assert "v4" in finding.detail
    assert finding.evidence["replacement"] == "v4"


def test_unaffected_version_emits_nothing():
    """v4 isn't in the sunset list — no finding."""
    deps = [_action("actions/upload-artifact", "v4")]
    sunset = {
        "actions/upload-artifact": [{
            "sunset_versions": ["v3"],
            "severity": "high",
        }],
    }
    assert scan_dependencies(deps, sunset_map=sunset) == []


def test_case_insensitive_match():
    deps = [_action("actions/checkout", "V1")]
    sunset = {
        "actions/checkout": [{"sunset_versions": ["v1"], "severity": "low"}],
    }
    findings = scan_dependencies(deps, sunset_map=sunset)
    assert len(findings) == 1


def test_sub_action_matches_parent_record():
    """``actions/cache/restore@v2`` matches a record on
    ``actions/cache``."""
    deps = [_action("actions/cache/restore", "v2")]
    sunset = {
        "actions/cache": [{"sunset_versions": ["v2"], "severity": "medium"}],
    }
    findings = scan_dependencies(deps, sunset_map=sunset)
    assert len(findings) == 1
    assert "actions/cache/restore@v2" in findings[0].detail


def test_non_gha_dep_skipped():
    """A PyPI dep with the same shape isn't matched."""
    deps = [_action("requests", "2.31.0", ecosystem="PyPI")]
    sunset = {
        "requests": [{"sunset_versions": ["2.31.0"], "severity": "high"}],
    }
    assert scan_dependencies(deps, sunset_map=sunset) == []


def test_dep_without_version_skipped():
    deps = [_action("actions/checkout", None)]                # type: ignore[arg-type]
    sunset = {
        "actions/checkout": [{"sunset_versions": ["v1"], "severity": "low"}],
    }
    assert scan_dependencies(deps, sunset_map=sunset) == []


def test_severity_default_when_unspecified():
    """Records without explicit severity default to medium."""
    deps = [_action("actions/x", "v1")]
    sunset = {"actions/x": [{"sunset_versions": ["v1"]}]}
    [f] = scan_dependencies(deps, sunset_map=sunset)
    assert f.severity == "medium"


def test_sunset_date_unannounced_in_detail():
    """Records without an explicit sunset_date show
    ``unannounced``."""
    deps = [_action("actions/x", "v1")]
    sunset = {"actions/x": [{"sunset_versions": ["v1"]}]}
    [f] = scan_dependencies(deps, sunset_map=sunset)
    assert "unannounced" in f.detail


def test_empty_sunset_map_produces_no_findings():
    deps = [_action("actions/checkout", "v1")]
    assert scan_dependencies(deps, sunset_map={}) == []


def test_multiple_sunset_records_per_action_match_first():
    """Two records on the same action (different sunset windows).
    Detector emits one finding per matching record — first match
    wins for now (consumers can refine later if needed)."""
    deps = [_action("actions/checkout", "v1")]
    sunset = {
        "actions/checkout": [
            {"sunset_versions": ["v1"], "sunset_date": "2022-04-01",
             "severity": "medium"},
            {"sunset_versions": ["v2"], "sunset_date": "2024-06-30",
             "severity": "medium"},
        ],
    }
    findings = scan_dependencies(deps, sunset_map=sunset)
    assert len(findings) == 1
    assert "2022-04-01" in findings[0].detail
