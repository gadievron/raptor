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
