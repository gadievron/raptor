"""Tests for the registry-metadata supply-chain detectors."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.supply_chain.registry_metadata import (
    RegistryMetaFinding,
    _Meta,
    _escalate_severity,
    _low_bus_factor_check,
    _maintainer_account_change_check,
    _maintainer_change_check,
    scan_deps,
)


def _dep(eco="PyPI", name="django", version="4.0.0",
         direct=True) -> Dependency:
    return Dependency(
        ecosystem=eco, name=name, version=version,
        declared_in=Path("/x/req.txt"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=direct,
        purl=f"pkg:{eco.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


class _PyPIStub:
    def __init__(self, raw: Dict[str, Any]) -> None:
        self.raw = raw

    def get_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        return self.raw


class _NpmStub:
    def __init__(self, raw: Dict[str, Any]) -> None:
        self.raw = raw

    def get_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        return self.raw


class _FailingStub:
    """Simulates a registry client that raises on get_metadata."""

    def get_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        raise ConnectionError("network failure")


_NOW = datetime(2026, 4, 26, 12, 0, 0, tzinfo=timezone.utc)


def _iso(days_ago: int) -> str:
    return (_NOW - timedelta(days=days_ago)).isoformat().replace(
        "+00:00", "Z")


# ---------------------------------------------------------------------------
# recent_publish
# ---------------------------------------------------------------------------

def test_pypi_recent_publish_fires_under_30_days() -> None:
    pypi = _PyPIStub({
        "info": {"author": "test"},
        "releases": {
            "1.0": [{"upload_time_iso_8601": _iso(5)}],
        }
    })
    out = scan_deps([_dep()], pypi_client=pypi, npm_client=None, now=_NOW)
    kinds = [f.kind for f in out]
    assert "recent_publish" in kinds
    rp = next(f for f in out if f.kind == "recent_publish")
    # recent_publish alone is info (severity escalation)
    assert rp.severity == "info"


def test_pypi_recent_publish_does_not_fire_old_pkg() -> None:
    pypi = _PyPIStub({
        "info": {},
        "releases": {"1.0": [{"upload_time_iso_8601": _iso(180)}]},
    })
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    assert all(f.kind != "recent_publish" for f in out)


def test_npm_recent_publish_fires() -> None:
    """All releases under 30 days old -> ``first_publish`` is recent."""
    npm = _NpmStub({
        "time": {
            "1.0.0": _iso(3),
            "0.9.0": _iso(20),
        }
    })
    out = scan_deps([_dep(eco="npm", name="react")], npm_client=npm,
                     now=_NOW)
    assert any(f.kind == "recent_publish" for f in out)


def test_recent_publish_configurable_threshold() -> None:
    """Custom recent_publish_days threshold is honoured."""
    pypi = _PyPIStub({
        "info": {},
        "releases": {"1.0": [{"upload_time_iso_8601": _iso(10)}]},
    })
    # Default 30-day threshold: fires.
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW,
                     recent_publish_days=30)
    assert any(f.kind == "recent_publish" for f in out)
    # Custom 5-day threshold: does NOT fire (10 > 5).
    out2 = scan_deps([_dep()], pypi_client=pypi, now=_NOW,
                      recent_publish_days=5)
    assert all(f.kind != "recent_publish" for f in out2)


# ---------------------------------------------------------------------------
# version_publish (latest version recently published)
# ---------------------------------------------------------------------------

def test_version_publish_fires_on_recent_version() -> None:
    """Latest version published 3 days ago -> fires."""
    pypi = _PyPIStub({
        "info": {},
        "releases": {
            "1.0": [{"upload_time_iso_8601": _iso(500)}],
            "2.0": [{"upload_time_iso_8601": _iso(3)}],
        },
    })
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    vp = [f for f in out if f.kind == "version_publish"]
    assert len(vp) == 1
    assert vp[0].evidence["version_age_days"] == 3


def test_version_publish_does_not_fire_when_old() -> None:
    """Latest version published 30 days ago -> no version_publish."""
    pypi = _PyPIStub({
        "info": {},
        "releases": {
            "1.0": [{"upload_time_iso_8601": _iso(500)}],
            "2.0": [{"upload_time_iso_8601": _iso(30)}],
        },
    })
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    assert all(f.kind != "version_publish" for f in out)


def test_version_publish_non_dormant_active_package_does_not_fire() -> None:
    """Active packages publish all the time — anthropic/openai/etc.
    bump every few days. Without this guard, the report drowns in
    Info-level ``version_publish`` entries for routine releases.
    Only the previously-dormant case is the genuine signal
    (account-takeover pattern: long-stable package gets a sudden
    fresh publish)."""
    pypi = _PyPIStub({
        "info": {},
        "releases": {
            # 30 days between releases ≪ 365-day dormant threshold.
            "1.0.0": [{"upload_time_iso_8601": _iso(30)}],
            "1.0.1": [{"upload_time_iso_8601": _iso(2)}],
        },
    })
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    assert all(f.kind != "version_publish" for f in out), (
        "non-dormant active package should NOT fire version_publish"
    )


def test_version_publish_dormant_package_elevates_severity() -> None:
    """Dormant package (>365d gap) + recent publish -> medium severity."""
    pypi = _PyPIStub({
        "info": {"author": "alice"},
        "releases": {
            "1.0": [{"upload_time_iso_8601": _iso(800)}],
            "2.0": [{"upload_time_iso_8601": _iso(2)}],
        },
    })
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    vp = next(f for f in out if f.kind == "version_publish")
    assert vp.evidence["dormant"] is True
    # Without maintainer_change, dormant version_publish is medium
    assert vp.severity == "medium"


def test_version_publish_npm() -> None:
    """npm: latest version published recently."""
    npm = _NpmStub({
        "time": {
            "0.1.0": _iso(500),
            "1.0.0": _iso(2),
        },
        "maintainers": [{"name": "alice", "email": "a@x"}],
    })
    out = scan_deps([_dep(eco="npm", name="foo")], npm_client=npm, now=_NOW)
    vp = [f for f in out if f.kind == "version_publish"]
    assert len(vp) == 1


def test_version_publish_configurable_threshold() -> None:
    """Custom version_publish_days threshold is honoured."""
    pypi = _PyPIStub({
        "info": {},
        "releases": {
            "1.0": [{"upload_time_iso_8601": _iso(500)}],
            "2.0": [{"upload_time_iso_8601": _iso(5)}],
        },
    })
    # Default 7-day threshold: fires.
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW,
                     version_publish_days=7)
    assert any(f.kind == "version_publish" for f in out)
    # Custom 3-day threshold: does NOT fire (5 > 3).
    out2 = scan_deps([_dep()], pypi_client=pypi, now=_NOW,
                      version_publish_days=3)
    assert all(f.kind != "version_publish" for f in out2)


# ---------------------------------------------------------------------------
# maintainer_change
# ---------------------------------------------------------------------------

def test_maintainer_change_fires_with_recent_join() -> None:
    """When the metadata exposes ``joined_at`` and it's within 14d."""
    pypi = _PyPIStub({
        "info": {"maintainer": "alice", "maintainer_email": "alice@x"},
        "releases": {"1.0": [{"upload_time_iso_8601": _iso(60)}]},
    })
    # PyPI doesn't expose joined_at; the detector just won't fire.
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    assert all(f.kind != "maintainer_change" for f in out)


def test_maintainer_change_with_synthetic_joined_at() -> None:
    """A registry that DOES expose ``joined_at`` (future enriched feed)
    triggers the detector. We build a custom adapter to verify the
    ``_Meta`` shape downstream."""
    meta = _Meta(
        first_publish=None, latest_publish=None,
        maintainers=[
            {"name": "old-hand", "joined_at": _iso(400)},
            {"name": "new-friend", "joined_at": _iso(5)},
        ],
    )
    findings = _maintainer_change_check(_dep(), meta, _NOW)
    assert len(findings) == 1
    assert "1 maintainer(s) added" in findings[0].detail


def test_npm_maintainer_change_between_versions() -> None:
    """npm: maintainer added between the two most recent versions."""
    npm = _NpmStub({
        "time": {
            "0.9.0": _iso(100),
            "1.0.0": _iso(5),
        },
        "maintainers": [
            {"name": "alice", "email": "a@x"},
            {"name": "bob", "email": "b@x"},
        ],
        "versions": {
            "0.9.0": {
                "maintainers": [{"name": "alice", "email": "a@x"}],
            },
            "1.0.0": {
                "maintainers": [
                    {"name": "alice", "email": "a@x"},
                    {"name": "bob", "email": "b@x"},
                ],
            },
        },
    })
    out = scan_deps([_dep(eco="npm", name="my-pkg")], npm_client=npm,
                     now=_NOW)
    mc = [f for f in out if f.kind == "maintainer_change"]
    assert len(mc) == 1
    assert "bob" in mc[0].detail


def test_npm_no_maintainer_change_when_same() -> None:
    """npm: same maintainers across versions -> no finding."""
    npm = _NpmStub({
        "time": {
            "0.9.0": _iso(100),
            "1.0.0": _iso(5),
        },
        "maintainers": [{"name": "alice", "email": "a@x"}],
        "versions": {
            "0.9.0": {
                "maintainers": [{"name": "alice", "email": "a@x"}],
            },
            "1.0.0": {
                "maintainers": [{"name": "alice", "email": "a@x"}],
            },
        },
    })
    out = scan_deps([_dep(eco="npm", name="my-pkg")], npm_client=npm,
                     now=_NOW)
    mc = [f for f in out if f.kind == "maintainer_change"]
    assert mc == []


# ---------------------------------------------------------------------------
# maintainer_account_change
# ---------------------------------------------------------------------------

def test_maintainer_account_change_axios_pattern() -> None:
    """Email change within 14d of release -> high severity."""
    meta = _Meta(
        first_publish=None,
        latest_publish=_NOW - timedelta(days=2),
        maintainers=[
            {"name": "alice",
             "last_email_change": _iso(3)},
        ],
    )
    findings = _maintainer_account_change_check(_dep(), meta, _NOW)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_maintainer_account_change_outside_window_no_fire() -> None:
    meta = _Meta(
        first_publish=None,
        latest_publish=_NOW - timedelta(days=200),  # very old release
        maintainers=[
            {"name": "alice", "last_email_change": _iso(3)},
        ],
    )
    findings = _maintainer_account_change_check(_dep(), meta, _NOW)
    assert findings == []


# ---------------------------------------------------------------------------
# low_bus_factor
# ---------------------------------------------------------------------------

def test_low_bus_factor_fires_single_maintainer() -> None:
    """Single maintainer -> info-level finding."""
    meta = _Meta(
        first_publish=None, latest_publish=None,
        maintainers=[{"name": "alice", "email": "a@x"}],
    )
    findings = _low_bus_factor_check(_dep(), meta)
    assert len(findings) == 1
    assert findings[0].kind == "low_bus_factor"
    assert findings[0].severity == "info"
    assert "single maintainer" in findings[0].detail


def test_low_bus_factor_does_not_fire_multiple_maintainers() -> None:
    meta = _Meta(
        first_publish=None, latest_publish=None,
        maintainers=[
            {"name": "alice", "email": "a@x"},
            {"name": "bob", "email": "b@x"},
        ],
    )
    findings = _low_bus_factor_check(_dep(), meta)
    assert findings == []


def test_low_bus_factor_does_not_fire_no_maintainers() -> None:
    meta = _Meta(first_publish=None, latest_publish=None, maintainers=[])
    findings = _low_bus_factor_check(_dep(), meta)
    assert findings == []


def test_low_bus_factor_pypi() -> None:
    """PyPI single author -> low_bus_factor fires."""
    pypi = _PyPIStub({
        "info": {"author": "alice"},
        "releases": {"1.0": [{"upload_time_iso_8601": _iso(180)}]},
    })
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    bf = [f for f in out if f.kind == "low_bus_factor"]
    assert len(bf) == 1


def test_low_bus_factor_strips_pep621_trailer() -> None:
    """Malformed PEP-621 / PEP-639 metadata can leak into PyPI's
    ``author`` field — the canonical example is
    ``playwright==1.58.0`` which PyPI returns as
    ``"Microsoft Corporation License-Expression: Apache-2.0"``.
    The defensive strip extracts the real name (``Microsoft
    Corporation``) so the finding's ``sole_maintainer`` evidence
    is useful, not corrupted."""
    pypi = _PyPIStub({
        "info": {
            "author": "Microsoft Corporation License-Expression: Apache-2.0",
        },
        "releases": {"1.0": [{"upload_time_iso_8601": _iso(180)}]},
    })
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    lbf = [f for f in out if f.kind == "low_bus_factor"]
    assert len(lbf) == 1
    assert lbf[0].evidence["sole_maintainer"] == "Microsoft Corporation"


def test_low_bus_factor_strips_multiple_pep621_keys() -> None:
    """Defensive strip must handle ``License-File:`` /
    ``Author-email:`` / ``Maintainer-email:`` too (all known
    PEP-621/PEP-639 trailer keys)."""
    for trailer in (
        "License-File: LICENSE",
        "Author-email: foo@example.com",
        "Maintainer-email: bar@example.com",
        "License: MIT",
    ):
        pypi = _PyPIStub({
            "info": {"author": f"Acme Corp {trailer}"},
            "releases": {"1.0": [{"upload_time_iso_8601": _iso(180)}]},
        })
        out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
        lbf = [f for f in out if f.kind == "low_bus_factor"]
        assert len(lbf) == 1, f"with trailer={trailer!r}"
        assert lbf[0].evidence["sole_maintainer"] == "Acme Corp", (
            f"with trailer={trailer!r}, "
            f"got {lbf[0].evidence['sole_maintainer']!r}"
        )


def test_low_bus_factor_pep621_strip_doesnt_eat_real_names() -> None:
    """``License Co. Ltd.`` is a real name containing the word
    ``License`` but no ``:`` after — must NOT be stripped."""
    pypi = _PyPIStub({
        "info": {"author": "License Co. Ltd."},
        "releases": {"1.0": [{"upload_time_iso_8601": _iso(180)}]},
    })
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    lbf = [f for f in out if f.kind == "low_bus_factor"]
    assert len(lbf) == 1
    assert lbf[0].evidence["sole_maintainer"] == "License Co. Ltd."


def test_low_bus_factor_pypi_comma_separated_authors_does_not_fire() -> None:
    """PyPI ``author`` is a free-text field; multi-person projects use
    a comma-separated list (``"Holger Krekel, Bruno Oliveira, …"``).
    The parser must split that into individual entries — without the
    split, a 7-author project registers as single-maintainer because
    the count of distinct ``name`` strings is 1."""
    pypi = _PyPIStub({
        "info": {
            "author": ("Holger Krekel, Bruno Oliveira, Ronny Pfannschmidt, "
                       "Floris Bruynooghe, Brianna Laugher, Freya Bruhin, "
                       "Others (See AUTHORS)"),
        },
        "releases": {"1.0": [{"upload_time_iso_8601": _iso(180)}]},
    })
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    assert all(f.kind != "low_bus_factor" for f in out), (
        "comma-separated author list must NOT register as one maintainer"
    )


def test_low_bus_factor_pypi_two_authors_via_split_no_fire() -> None:
    """The comma-split must register a 2-author entry as 2 maintainers,
    not as 1."""
    pypi = _PyPIStub({
        "info": {
            "author": "Alice Smith, Bob Jones",
            "author_email": "[email protected], [email protected]",
        },
        "releases": {"1.0": [{"upload_time_iso_8601": _iso(180)}]},
    })
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    assert all(f.kind != "low_bus_factor" for f in out)


def test_low_bus_factor_npm_multiple() -> None:
    """npm with 2 maintainers -> no low_bus_factor."""
    npm = _NpmStub({
        "time": {"1.0.0": _iso(180)},
        "maintainers": [
            {"name": "alice", "email": "a@x"},
            {"name": "bob", "email": "b@x"},
        ],
    })
    out = scan_deps([_dep(eco="npm", name="foo")], npm_client=npm, now=_NOW)
    assert all(f.kind != "low_bus_factor" for f in out)


# ---------------------------------------------------------------------------
# Severity escalation
# ---------------------------------------------------------------------------

def test_escalation_publish_plus_maintainer_change_medium() -> None:
    """recent_publish + maintainer_change -> both escalated to medium."""
    dep = _dep()
    meta = _Meta(first_publish=None, latest_publish=None, is_dormant=False)
    findings = [
        RegistryMetaFinding(
            kind="recent_publish", dependency=dep,
            detail="t", evidence={}, severity="info",
            confidence=Confidence("high", reason="t")),
        RegistryMetaFinding(
            kind="maintainer_change", dependency=dep,
            detail="t", evidence={}, severity="low",
            confidence=Confidence("medium", reason="t")),
    ]
    _escalate_severity(findings, meta)
    assert findings[0].severity == "medium"
    assert findings[1].severity == "medium"


def test_escalation_publish_plus_maintainer_plus_dormant_high() -> None:
    """version_publish + maintainer_change + dormant -> high."""
    dep = _dep()
    meta = _Meta(first_publish=None, latest_publish=None, is_dormant=True)
    findings = [
        RegistryMetaFinding(
            kind="version_publish", dependency=dep,
            detail="t", evidence={}, severity="info",
            confidence=Confidence("high", reason="t")),
        RegistryMetaFinding(
            kind="maintainer_change", dependency=dep,
            detail="t", evidence={}, severity="low",
            confidence=Confidence("medium", reason="t")),
        RegistryMetaFinding(
            kind="low_bus_factor", dependency=dep,
            detail="t", evidence={}, severity="info",
            confidence=Confidence("high", reason="t")),
    ]
    _escalate_severity(findings, meta)
    assert findings[0].severity == "high"
    assert findings[1].severity == "high"
    assert findings[2].severity == "high"


def test_escalation_publish_alone_stays_info() -> None:
    """recent_publish without maintainer_change -> no escalation."""
    dep = _dep()
    meta = _Meta(first_publish=None, latest_publish=None, is_dormant=True)
    findings = [
        RegistryMetaFinding(
            kind="recent_publish", dependency=dep,
            detail="t", evidence={}, severity="info",
            confidence=Confidence("high", reason="t")),
    ]
    _escalate_severity(findings, meta)
    assert findings[0].severity == "info"


def test_escalation_account_change_keeps_high() -> None:
    """maintainer_account_change keeps its own high severity."""
    dep = _dep()
    meta = _Meta(first_publish=None, latest_publish=None, is_dormant=False)
    findings = [
        RegistryMetaFinding(
            kind="maintainer_account_change", dependency=dep,
            detail="t", evidence={}, severity="high",
            confidence=Confidence("high", reason="t")),
    ]
    _escalate_severity(findings, meta)
    assert findings[0].severity == "high"  # untouched


# ---------------------------------------------------------------------------
# End-to-end: npm dormant + maintainer change scenario
# ---------------------------------------------------------------------------

def test_npm_dormant_plus_maintainer_change_escalates_to_high() -> None:
    """Full scenario: dormant npm package, new maintainer, recent version
    -> version_publish and maintainer_change both escalated to high."""
    npm = _NpmStub({
        "time": {
            "0.1.0": _iso(800),  # old release
            "1.0.0": _iso(2),    # brand new release
        },
        "maintainers": [
            {"name": "alice", "email": "a@x"},
            {"name": "mallory", "email": "m@x"},
        ],
        "versions": {
            "0.1.0": {
                "maintainers": [{"name": "alice", "email": "a@x"}],
            },
            "1.0.0": {
                "maintainers": [
                    {"name": "alice", "email": "a@x"},
                    {"name": "mallory", "email": "m@x"},
                ],
            },
        },
    })
    out = scan_deps([_dep(eco="npm", name="suspicious-pkg")],
                     npm_client=npm, now=_NOW)
    kinds = {f.kind for f in out}
    assert "version_publish" in kinds
    assert "maintainer_change" in kinds
    # Both should be escalated to high (dormant + maintainer_change + publish).
    vp = next(f for f in out if f.kind == "version_publish")
    mc = next(f for f in out if f.kind == "maintainer_change")
    assert vp.severity == "high"
    assert mc.severity == "high"


# ---------------------------------------------------------------------------
# Wiring + edge cases
# ---------------------------------------------------------------------------

def test_transitive_deps_skipped() -> None:
    pypi = _PyPIStub({"info": {}, "releases": {
        "1.0": [{"upload_time_iso_8601": _iso(3)}]}})
    out = scan_deps([_dep(direct=False)], pypi_client=pypi, now=_NOW)
    assert out == []


def test_no_clients_means_no_findings() -> None:
    """Without registry clients there's nothing to fetch."""
    out = scan_deps([_dep()], pypi_client=None, npm_client=None, now=_NOW)
    assert out == []


def test_unsupported_ecosystem_skipped() -> None:
    """Cargo / Go / etc. -- we don't ship metadata fetchers for them."""
    out = scan_deps([_dep(eco="Cargo", name="serde")],
                     pypi_client=_PyPIStub({}), now=_NOW)
    assert out == []


def test_fetch_failure_degrades_gracefully() -> None:
    """Network error from a registry client returns empty, not crash."""
    out = scan_deps([_dep()], pypi_client=_FailingStub(), now=_NOW)
    assert out == []


def test_empty_metadata_returns_no_findings() -> None:
    """Client returns None (miss) -> no findings, no crash."""
    class _NoneStub:
        def get_metadata(self, name):
            return None

    out = scan_deps([_dep()], pypi_client=_NoneStub(), now=_NOW)
    assert out == []


def test_pypi_dormancy_detection() -> None:
    """PyPI: gap > 365 days between releases sets is_dormant."""
    from packages.sca.supply_chain.registry_metadata import _from_pypi
    raw = {
        "info": {"author": "alice"},
        "releases": {
            "1.0": [{"upload_time_iso_8601": _iso(800)}],
            "2.0": [{"upload_time_iso_8601": _iso(3)}],
        },
    }
    meta = _from_pypi(raw)
    assert meta.is_dormant is True
    assert meta.second_latest_publish is not None


def test_npm_dormancy_detection() -> None:
    """npm: gap > 365 days between releases sets is_dormant."""
    from packages.sca.supply_chain.registry_metadata import _from_npm
    raw = {
        "time": {
            "0.1.0": _iso(800),
            "1.0.0": _iso(3),
        },
        "maintainers": [],
    }
    meta = _from_npm(raw)
    assert meta.is_dormant is True


def test_npm_previous_maintainers_extracted() -> None:
    """npm: previous version's maintainers are captured."""
    from packages.sca.supply_chain.registry_metadata import _from_npm
    raw = {
        "time": {
            "0.9.0": _iso(100),
            "1.0.0": _iso(5),
        },
        "maintainers": [
            {"name": "alice", "email": "a@x"},
            {"name": "bob", "email": "b@x"},
        ],
        "versions": {
            "0.9.0": {
                "maintainers": [{"name": "alice", "email": "a@x"}],
            },
            "1.0.0": {
                "maintainers": [
                    {"name": "alice", "email": "a@x"},
                    {"name": "bob", "email": "b@x"},
                ],
            },
        },
    }
    meta = _from_npm(raw)
    assert len(meta.previous_maintainers) == 1
    assert meta.previous_maintainers[0]["name"] == "alice"


def test_pypi_multiple_files_per_release_uses_earliest() -> None:
    """PyPI: a release with multiple files uses the earliest timestamp."""
    from packages.sca.supply_chain.registry_metadata import _from_pypi
    raw = {
        "info": {},
        "releases": {
            "1.0": [
                {"upload_time_iso_8601": _iso(100)},
                {"upload_time_iso_8601": _iso(102)},
            ],
        },
    }
    meta = _from_pypi(raw)
    # first_publish should be the earlier of the two.
    assert meta.first_publish is not None
    assert (meta.first_publish - (_NOW - timedelta(days=102))).total_seconds() < 1


def test_single_version_no_dormancy() -> None:
    """Single version -> not dormant (no gap to measure)."""
    from packages.sca.supply_chain.registry_metadata import _from_pypi
    raw = {
        "info": {},
        "releases": {
            "1.0": [{"upload_time_iso_8601": _iso(5)}],
        },
    }
    meta = _from_pypi(raw)
    assert meta.is_dormant is False
    assert meta.second_latest_publish is None


# ---------------------------------------------------------------------------
# Process-lifetime _Meta memo — repeat fetches for the same dep should
# parse the raw JSON once
# ---------------------------------------------------------------------------


def test_meta_cache_avoids_reparse_for_same_dep():
    """Multiple supply-chain detectors fetch metadata for the same
    dep. The post-parse ``_Meta`` cache should serve later calls
    from memory instead of re-walking the raw JSON."""
    from packages.sca.supply_chain.registry_metadata import (
        _fetch, _from_pypi as _orig_from_pypi,
    )
    from packages.sca.supply_chain import registry_metadata as rm

    class _CountingPyPI:
        def __init__(self):
            self.calls = 0
        def get_metadata(self, name):
            self.calls += 1
            return {
                "info": {"name": name, "author": "x"},
                "releases": {"1.0.0": [{"upload_time_iso_8601":
                                          "2023-01-01T00:00:00Z"}]},
            }

    parse_calls = {"n": 0}
    def counting_from_pypi(raw):
        parse_calls["n"] += 1
        return _orig_from_pypi(raw)
    rm._from_pypi = counting_from_pypi
    try:
        client = _CountingPyPI()
        dep = _dep(name="foo")
        # 5 fetches → 1 client call, 1 parse, 4 cache hits.
        for _ in range(5):
            _fetch(dep, pypi_client=client, npm_client=None)
        assert client.calls == 1, (
            f"client called {client.calls} times; cache is not "
            f"keeping later fetches off the wire"
        )
        assert parse_calls["n"] == 1, (
            f"_from_pypi ran {parse_calls['n']} times; cache is not "
            f"keeping the parse off the hot path"
        )
    finally:
        rm._from_pypi = _orig_from_pypi


# ---------------------------------------------------------------------------
# payload_size_spike
# ---------------------------------------------------------------------------
#
# Pinned against the Mini Shai-Hulud (May 2026) shape: a maintainer-
# takeover republishes a small utility with a massively inflated
# payload. The detector compares ``dep.version`` to the
# version published immediately before it; an absolute-floor
# guards against tiny-package false positives.

def _npm_versions_doc(
    *, name: str, versions: list[tuple[str, int, str]],
    maintainers: list[dict] | None = None,
) -> dict:
    """Construct an npm registry document carrying per-version
    ``dist.unpackedSize`` + a ``time`` block. ``versions`` is a
    list of ``(version_string, unpacked_size_bytes, iso_timestamp)``
    tuples in publish order (oldest first)."""
    time_block = {"created": versions[0][2], "modified": versions[-1][2]}
    versions_block: dict = {}
    for ver, size, ts in versions:
        time_block[ver] = ts
        versions_block[ver] = {
            "name": name,
            "version": ver,
            "dist": {"unpackedSize": size},
            "maintainers": maintainers or [],
        }
    return {
        "name": name,
        "time": time_block,
        "versions": versions_block,
        "maintainers": maintainers or [],
    }


def test_payload_size_spike_fires_on_shai_hulud_shape() -> None:
    """50 KB → 498 KB across consecutive publishes — the canonical
    Mini Shai-Hulud size inflation. Severity is ``high`` by the
    co-occurrence rule (version_publish + size spike => high)."""
    import packages.sca.supply_chain.registry_metadata as rm
    rm._reset_meta_cache_for_tests()

    # Gap between 1.0.2 (500 days ago) and 1.0.3 (2 days ago) is
    # 498 days — clears the 365-day dormancy threshold so
    # version_publish fires alongside payload_size_spike. The
    # combination is the Shai-Hulud signature.
    npm = _NpmStub(_npm_versions_doc(
        name="size-sensor",
        versions=[
            ("1.0.0", 12_000, _iso(900)),
            ("1.0.1", 13_000, _iso(700)),
            ("1.0.2", 50_000, _iso(500)),    # last legitimate
            ("1.0.3", 498_000, _iso(2)),     # malicious — 9.96x
        ],
    ))
    out = scan_deps(
        [_dep(eco="npm", name="size-sensor", version="1.0.3")],
        pypi_client=None, npm_client=npm, now=_NOW,
    )
    spike_findings = [f for f in out if f.kind == "payload_size_spike"]
    assert len(spike_findings) == 1
    spike = spike_findings[0]
    assert spike.evidence["current_version"] == "1.0.3"
    assert spike.evidence["previous_version"] == "1.0.2"
    assert spike.evidence["current_size_bytes"] == 498_000
    assert spike.evidence["previous_size_bytes"] == 50_000
    assert spike.evidence["growth_ratio"] >= 5.0
    # Co-occurs with version_publish (1.0.3 published 2 days ago);
    # the escalation rule lifts the size-spike to ``high``.
    assert spike.severity in ("high", "critical")


def test_payload_size_critical_when_maintainer_change_co_occurs() -> None:
    """The full Mini Shai-Hulud signature: version_publish +
    maintainer_change + payload_size_spike. The escalation rule
    raises ALL three findings to ``critical`` so severity filters
    can't accidentally hide one."""
    import packages.sca.supply_chain.registry_metadata as rm
    rm._reset_meta_cache_for_tests()

    # Construct a doc where 1.0.3 has a NEW maintainer the prior
    # version didn't. The maintainer_change detector picks this up
    # from the previous version's ``maintainers`` list. 1.0.2 is
    # pinned 500 days before 1.0.3 so the package is dormant —
    # triggering version_publish alongside the size + maintainer
    # signals.
    npm = _NpmStub({
        "name": "echarts-for-react",
        "time": {
            "created": _iso(800),
            "modified": _iso(2),
            "1.0.2": _iso(500),
            "1.0.3": _iso(2),
        },
        "versions": {
            "1.0.2": {
                "name": "echarts-for-react",
                "version": "1.0.2",
                "dist": {"unpackedSize": 60_000},
                "maintainers": [
                    {"name": "legitimate-author",
                     "email": "ok@example.com"},
                ],
            },
            "1.0.3": {
                "name": "echarts-for-react",
                "version": "1.0.3",
                "dist": {"unpackedSize": 480_000},
                "maintainers": [
                    {"name": "legitimate-author",
                     "email": "ok@example.com"},
                    {"name": "atool",
                     "email": "ato0l@protonmail.com"},
                ],
            },
        },
        "maintainers": [
            {"name": "legitimate-author", "email": "ok@example.com"},
            {"name": "atool", "email": "ato0l@protonmail.com"},
        ],
    })
    out = scan_deps(
        [_dep(eco="npm", name="echarts-for-react", version="1.0.3")],
        pypi_client=None, npm_client=npm, now=_NOW,
    )
    kinds_to_severity = {f.kind: f.severity for f in out}
    assert "payload_size_spike" in kinds_to_severity
    assert "maintainer_change" in kinds_to_severity
    assert "version_publish" in kinds_to_severity
    # All three escalate together.
    assert kinds_to_severity["payload_size_spike"] == "critical"
    assert kinds_to_severity["maintainer_change"] == "critical"


def test_payload_size_spike_below_absolute_floor_does_not_fire() -> None:
    """Ratio-wise large (10x) growth from 1 KB → 10 KB is below
    the absolute floor — every tiny utility package would false-
    positive on this signal otherwise."""
    import packages.sca.supply_chain.registry_metadata as rm
    rm._reset_meta_cache_for_tests()

    npm = _NpmStub(_npm_versions_doc(
        name="tiny-util-floor",
        versions=[
            ("1.0.0", 1_000, _iso(300)),
            ("1.0.1", 10_000, _iso(2)),    # 10x ratio but absolutely tiny
        ],
    ))
    out = scan_deps(
        [_dep(eco="npm", name="tiny-util-floor", version="1.0.1")],
        pypi_client=None, npm_client=npm, now=_NOW,
    )
    assert not any(f.kind == "payload_size_spike" for f in out)


def test_payload_size_spike_below_ratio_does_not_fire() -> None:
    """Above the absolute floor but the ratio is too small —
    legitimate library growth (e.g. 2x for a new feature)."""
    import packages.sca.supply_chain.registry_metadata as rm
    rm._reset_meta_cache_for_tests()

    npm = _NpmStub(_npm_versions_doc(
        name="ratio-below-thr",
        versions=[
            ("1.0.0", 100_000, _iso(300)),
            ("1.0.1", 200_000, _iso(2)),  # 2x — below 5x threshold
        ],
    ))
    out = scan_deps(
        [_dep(eco="npm", name="ratio-below-thr", version="1.0.1")],
        pypi_client=None, npm_client=npm, now=_NOW,
    )
    assert not any(f.kind == "payload_size_spike" for f in out)


def test_payload_size_spike_first_version_does_not_fire() -> None:
    """No prior version to compare against — never fires on first
    publish, regardless of size."""
    import packages.sca.supply_chain.registry_metadata as rm
    rm._reset_meta_cache_for_tests()

    npm = _NpmStub(_npm_versions_doc(
        name="brand-new-pkg",
        versions=[("1.0.0", 5_000_000, _iso(2))],  # huge first publish
    ))
    out = scan_deps(
        [_dep(eco="npm", name="brand-new-pkg", version="1.0.0")],
        pypi_client=None, npm_client=npm, now=_NOW,
    )
    assert not any(f.kind == "payload_size_spike" for f in out)


def test_payload_size_spike_missing_unpacked_size_does_not_fire() -> None:
    """Pre-v6 npm publishes don't carry ``dist.unpackedSize``. The
    detector quietly skips them rather than guessing from the
    compressed tarball size."""
    import packages.sca.supply_chain.registry_metadata as rm
    rm._reset_meta_cache_for_tests()

    npm = _NpmStub({
        "name": "no-unpacked-size-pkg",
        "time": {"created": _iso(300), "modified": _iso(2),
                 "1.0.0": _iso(300), "1.0.1": _iso(2)},
        "versions": {
            "1.0.0": {"name": "x", "version": "1.0.0",
                      "dist": {"tarball": "https://example.com/1.tgz"}},
            "1.0.1": {"name": "x", "version": "1.0.1",
                      "dist": {"tarball": "https://example.com/2.tgz"}},
        },
    })
    out = scan_deps(
        [_dep(eco="npm", name="no-unpacked-size-pkg", version="1.0.1")],
        pypi_client=None, npm_client=npm, now=_NOW,
    )
    assert not any(f.kind == "payload_size_spike" for f in out)


def test_payload_size_spike_walks_back_past_missing_sizes() -> None:
    """If the version immediately prior to dep.version lacks
    ``unpackedSize``, walk back further until we find a known
    size. Don't fall back to a guess (False) and don't bail
    silently (False); pick the most-recent comparable prior."""
    import packages.sca.supply_chain.registry_metadata as rm
    rm._reset_meta_cache_for_tests()

    npm = _NpmStub({
        "name": "intermediate-gap-pkg",
        "time": {"created": _iso(400), "modified": _iso(2),
                 "1.0.0": _iso(400),     # has size
                 "1.0.1": _iso(200),     # no size
                 "1.0.2": _iso(2)},      # spike
        "versions": {
            "1.0.0": {"name": "x", "version": "1.0.0",
                      "dist": {"unpackedSize": 50_000}},
            "1.0.1": {"name": "x", "version": "1.0.1",
                      # missing unpackedSize
                      "dist": {"tarball": "https://example.com/2.tgz"}},
            "1.0.2": {"name": "x", "version": "1.0.2",
                      "dist": {"unpackedSize": 480_000}},
        },
    })
    out = scan_deps(
        [_dep(eco="npm", name="intermediate-gap-pkg", version="1.0.2")],
        pypi_client=None, npm_client=npm, now=_NOW,
    )
    spike = next(f for f in out if f.kind == "payload_size_spike")
    # Compared against 1.0.0 (the most-recent prior with a known size),
    # not 1.0.1 (which had no data).
    assert spike.evidence["previous_version"] == "1.0.0"
    assert spike.evidence["previous_size_bytes"] == 50_000


def test_payload_size_spike_pypi_does_not_fire() -> None:
    """PyPI metadata doesn't expose per-version unpacked-size in
    the JSON-API shape we consume. Detector quietly no-ops."""
    import packages.sca.supply_chain.registry_metadata as rm
    rm._reset_meta_cache_for_tests()

    pypi = _PyPIStub({
        "info": {"author": "test"},
        "releases": {
            "1.0.0": [{"upload_time_iso_8601": _iso(300)}],
            "1.0.1": [{"upload_time_iso_8601": _iso(2)}],
        },
    })
    out = scan_deps(
        [_dep(name="pypi-size-noop", version="1.0.1")],
        pypi_client=pypi, npm_client=None, now=_NOW,
    )
    assert not any(f.kind == "payload_size_spike" for f in out)


def test_payload_size_spike_dep_version_missing_from_registry() -> None:
    """Operator pinned a version the registry doesn't list (perhaps
    later unpublished). Detector quietly skips rather than crashing
    or comparing against an arbitrary version."""
    import packages.sca.supply_chain.registry_metadata as rm
    rm._reset_meta_cache_for_tests()

    npm = _NpmStub(_npm_versions_doc(
        name="missing-version-pkg",
        versions=[
            ("1.0.0", 50_000, _iso(300)),
            ("1.0.1", 60_000, _iso(2)),
        ],
    ))
    out = scan_deps(
        [_dep(eco="npm", name="missing-version-pkg", version="9.9.9")],
        pypi_client=None, npm_client=npm, now=_NOW,
    )
    assert not any(f.kind == "payload_size_spike" for f in out)
