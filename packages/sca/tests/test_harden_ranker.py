"""Unit tests for harden's safety ranker.

Pins the four-key ranking semantics that ``_plan_one`` depends on:
``(any_in_kev, max_severity, max_epss, count)``. Ties broken by newest.

Doesn't go through the OSV client — exercises ``_max_severity``,
``_max_epss``, ``_advisory_in_kev`` and a small ranker stub directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from packages.sca.harden import (
    _RankedCandidate,
    _SEVERITY_ORDINAL,
    _advisory_in_kev,
    _cve_aliases,
    _max_epss,
    _max_severity,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

@dataclass
class _CVSS:
    severity: str


@dataclass
class _Advisory:
    osv_id: str
    aliases: List[str]
    severity: Optional[_CVSS] = None


class _FakeKev:
    def __init__(self, ids: List[str]) -> None:
        self._ids = {i.upper() for i in ids}

    def contains(self, cve_id: str) -> bool:
        return bool(cve_id) and cve_id.upper() in self._ids


# ---------------------------------------------------------------------------
# Severity ordinal
# ---------------------------------------------------------------------------

def test_severity_ordinal_known_keys() -> None:
    assert _SEVERITY_ORDINAL["none"] == 0
    assert _SEVERITY_ORDINAL["critical"] == 4
    # Strict monotone.
    for a, b in zip(["none", "low", "medium", "high", "critical"],
                    ["low", "medium", "high", "critical"]):
        assert _SEVERITY_ORDINAL[a] < _SEVERITY_ORDINAL[b]


def test_max_severity_empty_is_zero() -> None:
    assert _max_severity([]) == 0


def test_max_severity_picks_highest() -> None:
    advs = [
        _Advisory("CVE-1", [], _CVSS("medium")),
        _Advisory("CVE-2", [], _CVSS("critical")),
        _Advisory("CVE-3", [], _CVSS("low")),
    ]
    assert _max_severity(advs) == _SEVERITY_ORDINAL["critical"]


def test_max_severity_missing_treated_as_medium() -> None:
    advs = [_Advisory("CVE-1", [], None)]
    assert _max_severity(advs) == _SEVERITY_ORDINAL["medium"]


# ---------------------------------------------------------------------------
# KEV
# ---------------------------------------------------------------------------

def test_advisory_in_kev_via_osv_id() -> None:
    kev = _FakeKev(["CVE-2021-44228"])
    adv = _Advisory("CVE-2021-44228", [], None)
    assert _advisory_in_kev(adv, kev) is True


def test_advisory_in_kev_via_alias() -> None:
    """KEV stores CVE IDs but the OSV record's primary may be a GHSA;
    the CVE is in ``aliases``."""
    kev = _FakeKev(["CVE-2021-44228"])
    adv = _Advisory("GHSA-jfh8-c2jp-5v3q",
                     ["CVE-2021-44228", "GHSA-7rjr-3q55-vv33"], None)
    assert _advisory_in_kev(adv, kev) is True


def test_advisory_in_kev_no_match() -> None:
    kev = _FakeKev(["CVE-2021-44228"])
    adv = _Advisory("CVE-2099-99999", ["GHSA-zzzz-zzzz-zzzz"], None)
    assert _advisory_in_kev(adv, kev) is False


def test_advisory_in_kev_no_kev_client() -> None:
    """Passing ``kev=None`` (e.g., offline) must not crash."""
    adv = _Advisory("CVE-2021-44228", [], None)
    assert _advisory_in_kev(adv, None) is False


# ---------------------------------------------------------------------------
# CVE alias extraction
# ---------------------------------------------------------------------------

def test_cve_aliases_picks_all_cve_shapes() -> None:
    adv = _Advisory(
        "GHSA-jfh8-c2jp-5v3q",
        ["CVE-2021-44228", "PYSEC-2021-150", "CVE-2021-45046"],
        None,
    )
    assert _cve_aliases(adv) == ["CVE-2021-44228", "CVE-2021-45046"]


def test_cve_aliases_no_matches() -> None:
    adv = _Advisory("GHSA-1", ["GHSA-2", "PYSEC-3"], None)
    assert _cve_aliases(adv) == []


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------

def test_max_epss_picks_highest() -> None:
    advs = [
        _Advisory("CVE-1", [], None),
        _Advisory("CVE-2", [], None),
        _Advisory("CVE-3", [], None),
    ]
    scores = {"CVE-1": 0.05, "CVE-2": 0.92, "CVE-3": 0.10}
    assert _max_epss(advs, scores) == 0.92


def test_max_epss_no_data_is_zero() -> None:
    advs = [_Advisory("CVE-1", [], None)]
    assert _max_epss(advs, {}) == 0.0


def test_max_epss_via_alias() -> None:
    advs = [_Advisory("GHSA-x", ["CVE-2024-1"], None)]
    assert _max_epss(advs, {"CVE-2024-1": 0.5}) == 0.5


# ---------------------------------------------------------------------------
# Ranking semantics
# ---------------------------------------------------------------------------

def _rank(cands: List[_RankedCandidate]) -> List[str]:
    """Apply harden's least-worst sort; return version order."""
    sorted_idx = sorted(
        enumerate(cands),
        key=lambda kv: (int(kv[1].any_in_kev),
                        kv[1].max_severity,
                        kv[1].max_epss,
                        len(kv[1].advisory_ids),
                        kv[0]),
    )
    return [c.version for _, c in sorted_idx]


def test_ranker_kev_outranks_severity() -> None:
    """A medium with KEV should rank WORSE than a critical without KEV."""
    a = _RankedCandidate(version="1.0", advisory_ids=["X"],
                          max_severity=2, any_in_kev=True, max_epss=0.0)
    b = _RankedCandidate(version="2.0", advisory_ids=["Y"],
                          max_severity=4, any_in_kev=False, max_epss=0.0)
    # 2.0 wins (no KEV) despite higher severity.
    assert _rank([a, b])[0] == "2.0"


def test_ranker_severity_outranks_epss() -> None:
    """High severity with low EPSS still ranks worse than medium with high EPSS.

    Severity is the second-priority key; EPSS is third. Two versions
    same KEV-status, severity tier picks first.
    """
    a = _RankedCandidate(version="1.0", advisory_ids=["X"],
                          max_severity=4, any_in_kev=False, max_epss=0.0)
    b = _RankedCandidate(version="2.0", advisory_ids=["Y"],
                          max_severity=2, any_in_kev=False, max_epss=0.95)
    assert _rank([a, b])[0] == "2.0"


def test_ranker_epss_breaks_severity_tie() -> None:
    """Same severity → EPSS picks lower probability."""
    a = _RankedCandidate(version="1.0", advisory_ids=["X"],
                          max_severity=3, any_in_kev=False, max_epss=0.50)
    b = _RankedCandidate(version="2.0", advisory_ids=["Y"],
                          max_severity=3, any_in_kev=False, max_epss=0.10)
    assert _rank([a, b])[0] == "2.0"


def test_ranker_count_breaks_epss_tie() -> None:
    """Same severity + EPSS → fewer advisories wins."""
    a = _RankedCandidate(version="1.0", advisory_ids=["X", "Y", "Z"],
                          max_severity=3, any_in_kev=False, max_epss=0.10)
    b = _RankedCandidate(version="2.0", advisory_ids=["W"],
                          max_severity=3, any_in_kev=False, max_epss=0.10)
    assert _rank([a, b])[0] == "2.0"


def test_ranker_clean_version_wins_overall() -> None:
    """Any clean candidate ranks ahead of every dirty one."""
    a = _RankedCandidate(version="1.0", advisory_ids=[],
                          max_severity=0, any_in_kev=False, max_epss=0.0)
    b = _RankedCandidate(version="2.0", advisory_ids=["X"],
                          max_severity=1, any_in_kev=False, max_epss=0.05)
    assert _rank([a, b])[0] == "1.0"


def test_ranker_idx_breaks_full_tie() -> None:
    """All four primary keys equal → input order (newest-first) wins."""
    a = _RankedCandidate(version="2.0", advisory_ids=["X"],
                          max_severity=2, any_in_kev=False, max_epss=0.1)
    b = _RankedCandidate(version="1.0", advisory_ids=["Y"],
                          max_severity=2, any_in_kev=False, max_epss=0.1)
    # 2.0 was input-first (= newest) so wins on the index tiebreak.
    assert _rank([a, b])[0] == "2.0"
