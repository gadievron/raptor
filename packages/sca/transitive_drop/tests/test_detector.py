"""Tests for the transitive-drop detector.

The canonical case driving this code: instructor 1.14.5 pins
diskcache>=5.6.3 unconditionally; instructor 1.15.1 moves it
behind ``extra == "diskcache"``. The detector spots the
state-change and recommends bumping instructor."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from packages.sca.models import (
    Confidence, Dependency, PinStyle, SupplyChainFinding,
    VulnFinding,
)
from packages.sca.transitive_drop import detect_droppable_transitives


# ---------------------------------------------------------------------------
# Test stubs
# ---------------------------------------------------------------------------

class _StubPyPI:
    """Stub PyPI client with per-version requires_dist support."""

    def __init__(self, versions: Dict[str, Dict[str, Dict[str, Any]]]):
        # versions: {pkg: {version: {"requires_dist": [...], ...}}}
        self._v = versions

    def get_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        canon = name.lower().replace("_", "-")
        if canon not in self._v:
            return None
        releases = {ver: [] for ver in self._v[canon]}
        latest = max(
            self._v[canon].keys(),
            key=lambda v: tuple(int(x) if x.isdigit() else 0
                                 for x in v.split(".")),
        )
        info = dict(self._v[canon][latest])
        info["version"] = latest
        return {"info": info, "releases": releases}

    def get_version_metadata(
        self, name: str, version: str,
    ) -> Optional[Dict[str, Any]]:
        canon = name.lower().replace("_", "-")
        v = self._v.get(canon, {}).get(version)
        if v is None:
            return None
        info = dict(v)
        info["version"] = version
        return {"info": info}

    def list_versions(self, name: str) -> List[str]:
        canon = name.lower().replace("_", "-")
        return list(self._v.get(canon, {}).keys())


def _dep(name: str, version: str, *,
         direct: bool = True,
         source_kind: str = "manifest",
         via: Optional[List[str]] = None) -> Dependency:
    extra = {"via": via} if via else None
    return Dependency(
        ecosystem="PyPI", name=name, version=version,
        declared_in=Path(f"/test/{name}"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=direct,
        purl=f"pkg:pypi/{name}@{version}",
        parser_confidence=Confidence("high", reason="test"),
        source_kind=source_kind,
        source_extra=extra,
    )


def _vuln(dep: Dependency, severity: str = "medium") -> VulnFinding:
    return VulnFinding(
        finding_id=f"sca:vuln:test:{dep.name}",
        dependency=dep,
        advisories=[],
        severity=severity,
        in_kev=False,
        epss=None,
        fixed_version=None,
        reachability=None,
        cvss_score=None,
        cvss_vector=None,
        version_match_confidence=Confidence("high", reason="test"),
        exposure_factor=1.0,
        transitive_depth=1,
    )


# ---------------------------------------------------------------------------
# The canonical case: instructor 1.14.5 → 1.15.1 drops diskcache
# ---------------------------------------------------------------------------

def test_diskcache_optional_in_newer_instructor() -> None:
    """Reproduces raptor's actual scan: ``requirements.txt`` pins
    ``instructor==1.14.5``; cascade resolver pulls in
    ``diskcache==5.6.3``; diskcache has CVE-2025-69872; the
    detector should suggest bumping instructor to 1.15.1 to drop
    the dep."""
    pypi = _StubPyPI({
        "instructor": {
            "1.14.5": {
                "requires_dist": [
                    "openai<3.0.0,>=2.0.0",
                    "diskcache>=5.6.3",   # UNCONDITIONAL
                    "rich<15.0.0,>=13.7.0",
                ],
            },
            "1.15.1": {
                "requires_dist": [
                    "openai<3.0.0,>=2.0.0",
                    'diskcache<6.0.0,>=5.6.3; extra == "diskcache"',  # behind extra
                    "rich<15.0.0,>=13.7.0",
                ],
            },
        },
        "diskcache": {"5.6.3": {}},
    })
    deps = [
        _dep("instructor", "1.14.5", direct=True),
        _dep("diskcache", "5.6.3",
             direct=False, source_kind="cascade_resolver",
             via=["instructor"]),
    ]
    vuln = _vuln(deps[1], severity="medium")
    findings = detect_droppable_transitives(
        deps, vuln_findings=[vuln], pypi_client=pypi,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.transitive_name == "diskcache"
    assert f.parent_name == "instructor"
    assert f.parent_current_version == "1.14.5"
    assert f.parent_latest_version == "1.15.1"
    assert f.transitive_status_in_latest == "extras-gated"
    assert f.extra_name == "diskcache"
    assert f.transitive_finding_severity == "medium"


def test_transitive_removed_entirely_in_newer_parent() -> None:
    """Some parent bumps remove the transitive dep entirely (not
    even behind an extra). Should still emit a finding, with
    status='removed'."""
    pypi = _StubPyPI({
        "parent": {
            "1.0.0": {
                "requires_dist": ["badpkg>=1.0"],
            },
            "2.0.0": {
                "requires_dist": [],   # no longer mentions badpkg
            },
        },
    })
    deps = [
        _dep("parent", "1.0.0", direct=True),
        _dep("badpkg", "1.5.0",
             direct=False, source_kind="cascade_resolver",
             via=["parent"]),
    ]
    findings = detect_droppable_transitives(
        deps, vuln_findings=[_vuln(deps[1])], pypi_client=pypi,
    )
    assert len(findings) == 1
    assert findings[0].transitive_status_in_latest == "removed"
    assert findings[0].extra_name is None


def test_no_finding_when_already_at_latest() -> None:
    """If the parent is already at the latest version, no bump
    available → no finding (even if the dep is troublesome)."""
    pypi = _StubPyPI({
        "instructor": {
            "1.15.1": {
                "requires_dist": [
                    'diskcache; extra == "diskcache"',
                ],
            },
        },
    })
    deps = [
        _dep("instructor", "1.15.1", direct=True),
        _dep("diskcache", "5.6.3",
             direct=False, source_kind="cascade_resolver",
             via=["instructor"]),
    ]
    findings = detect_droppable_transitives(
        deps, vuln_findings=[_vuln(deps[1])], pypi_client=pypi,
    )
    assert findings == []


def test_no_finding_when_transitive_still_required_in_latest() -> None:
    """If the dep is unconditional in BOTH current and latest, no
    suggestion is useful — the bump doesn't help."""
    pypi = _StubPyPI({
        "parent": {
            "1.0.0": {"requires_dist": ["dep>=1"]},
            "2.0.0": {"requires_dist": ["dep>=1"]},
        },
    })
    deps = [
        _dep("parent", "1.0.0", direct=True),
        _dep("dep", "1.0.0",
             direct=False, source_kind="cascade_resolver",
             via=["parent"]),
    ]
    findings = detect_droppable_transitives(
        deps, vuln_findings=[_vuln(deps[1])], pypi_client=pypi,
    )
    assert findings == []


def test_skips_transitives_without_findings() -> None:
    """If the transitive has no associated finding (vuln /
    supply-chain / hygiene), don't spend the PyPI roundtrip —
    the bump suggestion is only useful when there's a problem
    to solve."""
    pypi = _StubPyPI({
        "parent": {
            "1.0.0": {"requires_dist": ["dep>=1"]},
            "2.0.0": {"requires_dist": ['dep; extra == "dep"']},
        },
    })
    deps = [
        _dep("parent", "1.0.0", direct=True),
        _dep("dep", "1.0.0",
             direct=False, source_kind="cascade_resolver",
             via=["parent"]),
    ]
    findings = detect_droppable_transitives(
        deps, vuln_findings=[], pypi_client=pypi,
    )
    # No vuln_findings → no transitive flagged → no work.
    assert findings == []


def test_severity_propagates_from_underlying_vuln() -> None:
    """High-severity vulns on droppable transitives are 'real
    fix' suggestions; their severity carries over."""
    pypi = _StubPyPI({
        "parent": {
            "1.0.0": {"requires_dist": ["dep>=1"]},
            "2.0.0": {"requires_dist": ['dep; extra == "extra"']},
        },
    })
    deps = [
        _dep("parent", "1.0.0", direct=True),
        _dep("dep", "1.0.0",
             direct=False, source_kind="cascade_resolver",
             via=["parent"]),
    ]
    findings = detect_droppable_transitives(
        deps,
        vuln_findings=[_vuln(deps[1], severity="critical")],
        pypi_client=pypi,
    )
    assert findings[0].transitive_finding_severity == "critical"


def test_no_pypi_client_skips() -> None:
    deps = [
        _dep("dep", "1.0.0",
             direct=False, source_kind="cascade_resolver",
             via=["parent"]),
    ]
    findings = detect_droppable_transitives(
        deps, vuln_findings=[_vuln(deps[0])], pypi_client=None,
    )
    assert findings == []


def test_skips_non_pypi_transitives() -> None:
    """The detector is PyPI-specific (other ecosystems have
    different metadata shapes for optional deps)."""
    d = Dependency(
        ecosystem="npm", name="lodash", version="4.17.20",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=False,
        purl="pkg:npm/lodash@4.17.20",
        parser_confidence=Confidence("high", reason="test"),
        source_kind="cascade_resolver",
        source_extra={"via": ["express"]},
    )
    pypi = _StubPyPI({})
    findings = detect_droppable_transitives(
        [d], vuln_findings=[_vuln(d)], pypi_client=pypi,
    )
    assert findings == []
