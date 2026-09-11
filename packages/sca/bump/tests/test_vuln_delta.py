"""Tests for ``packages.sca.bump.vuln_delta``.

The OSV vuln-delta evaluator queries OSV for both current and
target versions of a dep and returns ``VulnFinding``s for
advisories present on target but not on current — the "this
bump introduces new vulnerability surface" signal."""

from __future__ import annotations

from typing import Dict, List

import pytest

from packages.sca.bump.vuln_delta import (
    VulnDeltaDegraded,
    evaluate_bump_vulns,
)
from packages.sca.models import (
    AffectedRange, Advisory, CVSSScore,
)
from packages.sca.osv import OsvResult


class _StubOsv:
    """OsvClient stub. Replies with operator-supplied advisories
    keyed by (eco, name, version)."""

    def __init__(self, advisories_for: Dict[tuple, List[Advisory]]):
        self._adv = advisories_for

    def query_batch(self, deps):
        return [
            OsvResult(
                dep.key(),
                self._adv.get((dep.ecosystem, dep.name, dep.version), []),
            )
            for dep in deps
        ]


def _adv(osv_id: str, severity: str = "high",
         summary: str = "test advisory") -> Advisory:
    return Advisory(
        osv_id=osv_id,
        aliases=[],
        summary=summary,
        details="",
        affected=[AffectedRange(
            type="ECOSYSTEM",
            events=[{"introduced": "0"}],
        )],
        severity=CVSSScore(score=7.5, vector="CVSS:3.1/AV:N",
                            severity=severity),  # type: ignore[arg-type]
        fixed_versions=[],
        references=[],
    )


# ---------------------------------------------------------------------------
# Delta semantics
# ---------------------------------------------------------------------------

def test_advisory_in_target_only_emitted_as_vuln_finding() -> None:
    """The canonical case: target carries advisory X, current
    doesn't → emit VulnFinding for X. This is the gating signal
    — verdict ladder will escalate based on severity / KEV."""
    osv = _StubOsv({
        ("PyPI", "foo", "1.0"): [],
        ("PyPI", "foo", "2.0"): [_adv("GHSA-new-bad", "critical")],
    })
    findings = evaluate_bump_vulns(
        ecosystem="PyPI", name="foo",
        current_version="1.0", target_version="2.0",
        osv_client=osv,
    )
    assert len(findings) == 1
    assert findings[0].advisories[0].osv_id == "GHSA-new-bad"
    assert findings[0].dependency.version == "2.0"


def test_advisory_in_both_versions_NOT_emitted() -> None:
    """Advisory present on BOTH current and target → silent.
    The bump doesn't change exposure on this axis — it's a
    pre-existing problem, not a bump-introduced one. The current
    scan's job, not the bumper's."""
    shared = _adv("GHSA-shared", "high")
    osv = _StubOsv({
        ("PyPI", "foo", "1.0"): [shared],
        ("PyPI", "foo", "2.0"): [shared],
    })
    findings = evaluate_bump_vulns(
        ecosystem="PyPI", name="foo",
        current_version="1.0", target_version="2.0",
        osv_client=osv,
    )
    assert findings == []


def test_advisory_only_in_current_NOT_emitted() -> None:
    """Advisory only in current (bump CLEARS it) → not in the
    vuln-delta. The bumper proposes the bump; we don't want the
    verdict to escalate on a CVE the bump actually FIXES.

    Future UX work could surface cleared CVEs as a positive
    signal in the PR comment ("this bump fixes N CVEs"); out
    of scope for the verdict-gating path."""
    osv = _StubOsv({
        ("PyPI", "foo", "1.0"): [_adv("GHSA-old", "critical")],
        ("PyPI", "foo", "2.0"): [],
    })
    findings = evaluate_bump_vulns(
        ecosystem="PyPI", name="foo",
        current_version="1.0", target_version="2.0",
        osv_client=osv,
    )
    assert findings == []


def test_mixed_set_emits_only_the_new() -> None:
    """Current has [A]; target has [A, B]. Only B is in the
    delta. A is unchanged exposure."""
    a = _adv("GHSA-shared-A", "medium")
    b = _adv("GHSA-target-B", "high")
    osv = _StubOsv({
        ("PyPI", "foo", "1.0"): [a],
        ("PyPI", "foo", "2.0"): [a, b],
    })
    findings = evaluate_bump_vulns(
        ecosystem="PyPI", name="foo",
        current_version="1.0", target_version="2.0",
        osv_client=osv,
    )
    assert len(findings) == 1
    assert findings[0].advisories[0].osv_id == "GHSA-target-B"


def test_osv_query_failure_raises_degraded() -> None:
    """OSV-side failure (network / 5xx / timeout) raises
    VulnDeltaDegraded rather than returning []. An empty delta is
    indistinguishable from a genuinely-clean bump, so a swallowed
    failure would fail OPEN — the new-CVE gate silently disabled
    while --apply lands the bump as Clean. The orchestrator maps
    the exception to a Review-floored verdict."""
    class _BrokenOsv:
        def query_batch(self, deps):
            raise RuntimeError("OSV unreachable")
    with pytest.raises(VulnDeltaDegraded):
        evaluate_bump_vulns(
            ecosystem="PyPI", name="foo",
            current_version="1.0", target_version="2.0",
            osv_client=_BrokenOsv(),
        )


class _DegradedOsv:
    """Stub with the real client's transient-failure telemetry:
    ``failed_slots`` names which query slots (by version) return no
    advisories AND advance ``failed_lookups`` / ``failed_dep_keys``."""

    def __init__(self, failed_versions, advisories_for=None):
        self._failed_versions = set(failed_versions)
        self._adv = advisories_for or {}
        self.failed_lookups = 0
        self.failed_dep_keys: list = []

    def query_batch(self, deps):
        results = []
        for dep in deps:
            if dep.version in self._failed_versions:
                self.failed_lookups += 1
                self.failed_dep_keys.append(dep.key())
                results.append(OsvResult(dep.key(), []))
                continue
            results.append(OsvResult(
                dep.key(),
                self._adv.get((dep.ecosystem, dep.name, dep.version), []),
            ))
        return results


def test_failed_target_slot_raises_degraded_not_clean() -> None:
    """Transient failure on the TARGET slot: the empty advisories
    list is a failure artifact, not a clean bill — silently
    diffing it would report zero new CVEs (fail-open auto-apply)."""
    osv = _DegradedOsv(
        failed_versions={"2.0"},
        advisories_for={("PyPI", "foo", "1.0"): []},
    )
    with pytest.raises(VulnDeltaDegraded) as exc_info:
        evaluate_bump_vulns(
            ecosystem="PyPI", name="foo",
            current_version="1.0", target_version="2.0",
            osv_client=osv,
        )
    assert "target" in str(exc_info.value)


def test_failed_current_slot_raises_degraded_not_false_findings() -> None:
    """Transient failure on the CURRENT slot: every target advisory
    would look 'newly introduced' (all-false new-CVE findings)."""
    osv = _DegradedOsv(
        failed_versions={"1.0"},
        advisories_for={
            ("PyPI", "foo", "2.0"): [_adv("GHSA-preexisting", "high")],
        },
    )
    with pytest.raises(VulnDeltaDegraded) as exc_info:
        evaluate_bump_vulns(
            ecosystem="PyPI", name="foo",
            current_version="1.0", target_version="2.0",
            osv_client=osv,
        )
    assert "current" in str(exc_info.value)


def test_healthy_lookups_with_telemetry_attributes_still_compute_delta() -> None:
    """Legit path unchanged: a client CARRYING the telemetry
    attributes that doesn't fail computes the delta normally —
    the degradation check only fires when the counters advance."""
    osv = _DegradedOsv(
        failed_versions=set(),
        advisories_for={
            ("PyPI", "foo", "1.0"): [],
            ("PyPI", "foo", "2.0"): [_adv("GHSA-new-bad", "critical")],
        },
    )
    findings = evaluate_bump_vulns(
        ecosystem="PyPI", name="foo",
        current_version="1.0", target_version="2.0",
        osv_client=osv,
    )
    assert len(findings) == 1
    assert findings[0].advisories[0].osv_id == "GHSA-new-bad"


def test_preexisting_failed_lookups_do_not_flag_this_call() -> None:
    """The telemetry is cumulative across the client's lifetime;
    failures from EARLIER calls must not mark this call degraded."""
    osv = _DegradedOsv(
        failed_versions=set(),
        advisories_for={("PyPI", "foo", "1.0"): [],
                        ("PyPI", "foo", "2.0"): []},
    )
    # Simulate earlier-call telemetry.
    osv.failed_lookups = 7
    osv.failed_dep_keys = ["npm:other@1.0"]
    findings = evaluate_bump_vulns(
        ecosystem="PyPI", name="foo",
        current_version="1.0", target_version="2.0",
        osv_client=osv,
    )
    assert findings == []


def test_kev_enrichment_carried_through() -> None:
    """``kev_client`` plumbs through to ``build_vuln_findings``
    so newly-introduced KEV-listed CVEs land with ``in_kev=True``,
    triggering the verdict ladder's Block-on-KEV path."""
    class _KevSays:
        def __init__(self, listed_set):
            self._listed = listed_set

        def is_loaded(self):
            return True

        def contains(self, cve_id):
            return cve_id in self._listed

    new_adv = _adv("GHSA-new", "critical")
    new_adv.aliases = ["CVE-2099-99999"]
    osv = _StubOsv({
        ("PyPI", "foo", "1.0"): [],
        ("PyPI", "foo", "2.0"): [new_adv],
    })
    findings = evaluate_bump_vulns(
        ecosystem="PyPI", name="foo",
        current_version="1.0", target_version="2.0",
        osv_client=osv,
        kev_client=_KevSays({"CVE-2099-99999"}),
    )
    assert len(findings) == 1
    assert findings[0].in_kev is True
