"""Scan-wide enrichment request bounds for ``build_vuln_findings``.

Container-image scans carry 10^4+ distro CVE findings, and every one of
them now has a CVE-shaped id (the upstream/CVE-primary fold), so
per-finding enrichment fetches turn into a serial HTTPS storm at the
findings-assembly seam: one EPSS request per finding (the client's
100-id batching never engages across findings) plus one
raw.githubusercontent.com GET per unique CVE for Vulnrichment SSVC.
These tests pin the scan-wide contract with a counting transport:

  * EPSS: unique CVEs are collected once across the whole findings set
    and fetched in ceil(unique/100) batched requests — never one
    request per finding.
  * Vulnrichment: at most ``ssvc_fetch_budget`` uncached GETs per
    scan, spent in a deterministic priority order; over-budget CVEs
    degrade to no-signal (``ssvc_exploitation is None``) instead of
    eating the scan budget.
  * Cache reuse: a second pass over the same CVEs costs zero EPSS
    requests, and the SSVC budget is spent only on still-uncached ids
    (repeat scans progressively warm past the budget line).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from core.cve import EpssClient
from core.cve.epss import EPSS_URL
from core.cve.vulnrichment import VulnrichmentClient
from core.http import HttpError
from core.json import JsonCache

from packages.sca.findings import build_vuln_findings
from packages.sca.models import (
    Advisory,
    AffectedRange,
    Confidence,
    CVSSScore,
    Dependency,
    PinStyle,
)
from packages.sca.osv import OsvResult

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_SSVC_ACTIVE_RECORD: dict[str, Any] = {
    "containers": {
        "adp": [{
            "providerMetadata": {"shortName": "CISA-ADP"},
            "metrics": [{
                "other": {
                    "content": {
                        "options": [
                            {"Exploitation": "active"},
                            {"Automatable": "no"},
                            {"Technical Impact": "total"},
                        ],
                    },
                },
            }],
        }],
    },
}


class CountingHttp:
    """Transport stub that answers EPSS batch queries and Vulnrichment
    per-CVE GETs while counting every request per endpoint."""

    def __init__(self, fail_epss_chunks_containing: str | None = None) -> None:
        self.epss_requests: list[str] = []
        self.vuln_requests: list[str] = []
        self.fail_epss_chunks_containing = fail_epss_chunks_containing

    def get_json(self, url: str, timeout: int = 30) -> dict:
        if url.startswith(EPSS_URL):
            self.epss_requests.append(url)
            cves = url.split("cve=", 1)[1].split(",")
            if (self.fail_epss_chunks_containing is not None
                    and self.fail_epss_chunks_containing in cves):
                raise HttpError("simulated EPSS outage", status=503)
            return {"data": [
                {"cve": c, "epss": "0.5", "percentile": "0.9"} for c in cves
            ]}
        if "cisagov/vulnrichment" in url:
            self.vuln_requests.append(url)
            return _SSVC_ACTIVE_RECORD
        raise AssertionError(f"unexpected URL: {url}")

    def post_json(self, *a: Any, **k: Any) -> dict:
        raise NotImplementedError

    def get_bytes(self, *a: Any, **k: Any) -> bytes:
        raise NotImplementedError


class FakeKev:
    def __init__(self, hits: list[str] | None = None) -> None:
        self.hits = {h.upper() for h in (hits or [])}

    def contains(self, cve: str) -> bool:
        return cve.upper() in self.hits


def _dep(name: str) -> Dependency:
    return Dependency(
        ecosystem="PyPI",
        name=name,
        version="1.0.0",
        declared_in=Path("/repo/requirements.txt"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:pypi/{name}@1.0.0",
        parser_confidence=Confidence("high", reason="t"),
    )


def _adv(osv_id: str, cve: str, *, cvss: CVSSScore | None = None) -> Advisory:
    return Advisory(
        osv_id=osv_id,
        aliases=[cve],
        summary="Test advisory",
        details="Details.",
        affected=[AffectedRange(
            type="ECOSYSTEM",
            events=[{"introduced": "0"}, {"fixed": "5.0.0"}],
        )],
        severity=cvss,
        fixed_versions=["5.0.0"],
        references=["https://example.com"],
        published=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


def _distro_scale_inputs(
    n: int,
) -> tuple[list[Dependency], list[OsvResult], list[str]]:
    """``n`` deps, one advisory each, every advisory its own CVE —
    the distro base-image shape (thousands of source packages, each
    with CVE-carrying secdb advisories)."""
    deps: list[Dependency] = []
    results: list[OsvResult] = []
    cves: list[str] = []
    for i in range(n):
        d = _dep(f"pkg-{i:05d}")
        cve = f"CVE-2024-{10000 + i}"
        cves.append(cve)
        deps.append(d)
        results.append(OsvResult(
            dep_key=d.key(), advisories=[_adv(f"DSA-{i:05d}", cve)],
        ))
    return deps, results, cves


def _clients(
    http: CountingHttp, root: Path,
) -> tuple[EpssClient, VulnrichmentClient]:
    cache = JsonCache(root=root)
    return (
        EpssClient(http, cache),                 # type: ignore[arg-type]
        VulnrichmentClient(http, cache),         # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Request-count bounds (the distro-scale regression)
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_distro_scale_scan_bounds_requests(tmp_path: Path) -> None:
    """1200 findings / 1200 unique CVEs must cost ceil(1200/100)=12
    EPSS requests and at most the SSVC fetch budget of Vulnrichment
    GETs — not one request per finding.

    slow (nightly tier): the cost is genuine — 1200 findings built and
    1000 SSVC cache files written is real distro-base-image scale, and
    the file I/O breaches the default-tier per-test budget on contended
    CI runners. The smoke twin below keeps every bound mechanic in the
    default tier at a scale that stays far under the budget."""
    n, budget = 1200, 1000
    deps, results, _ = _distro_scale_inputs(n)
    http = CountingHttp()
    epss, vuln = _clients(http, tmp_path)

    findings = build_vuln_findings(
        deps, results, epss=epss, vulnrichment=vuln,
        ssvc_fetch_budget=budget,
    )

    assert len(findings) == n
    assert len(http.epss_requests) == 12          # ceil(1200 / 100)
    assert len(http.vuln_requests) == budget      # capped, not 1200
    # EPSS enrichment is complete — batching is a cost fix, not a
    # coverage change.
    assert all(f.epss == 0.5 for f in findings)
    # SSVC: exactly budget-many findings enriched; the rest degrade
    # to no-signal (None) rather than eating the scan budget.
    enriched = sum(1 for f in findings if f.ssvc_exploitation == "active")
    degraded = sum(1 for f in findings if f.ssvc_exploitation is None)
    assert enriched == budget
    assert degraded == n - budget


def test_scan_bounds_requests_smoke(tmp_path: Path) -> None:
    """Default-tier twin of the distro-scale bounds test: identical
    mechanics — cross-finding EPSS batching including a partial final
    chunk, the SSVC budget cap engaging, over-budget findings degrading
    to no-signal — at a scale cheap enough for every default-tier run.

    Scale trade-off: n must exceed one EPSS chunk (100) to prove
    batching spans chunks AND exceed the budget to prove the cap +
    degradation, but every finding costs an SSVC cache-file write, so
    growing n re-creates the contended-runner cost the nightly test
    already covers. 150/100 is the smallest shape exercising both."""
    n, budget = 150, 100
    deps, results, _ = _distro_scale_inputs(n)
    http = CountingHttp()
    epss, vuln = _clients(http, tmp_path)

    findings = build_vuln_findings(
        deps, results, epss=epss, vulnrichment=vuln,
        ssvc_fetch_budget=budget,
    )

    assert len(findings) == n
    assert len(http.epss_requests) == 2           # ceil(150 / 100)
    assert len(http.vuln_requests) == budget      # capped, not 150
    # EPSS enrichment is complete — batching is a cost fix, not a
    # coverage change.
    assert all(f.epss == 0.5 for f in findings)
    # SSVC: exactly budget-many findings enriched; the rest degrade
    # to no-signal (None) rather than eating the scan budget.
    enriched = sum(1 for f in findings if f.ssvc_exploitation == "active")
    degraded = sum(1 for f in findings if f.ssvc_exploitation is None)
    assert enriched == budget
    assert degraded == n - budget


def test_second_pass_reuses_cache(tmp_path: Path) -> None:
    """Re-scan against a warm cache: zero EPSS fetches, and the SSVC
    budget is spent only on the CVEs the first pass left uncached —
    repeat scans progressively warm past the budget line."""
    n, budget = 300, 200
    deps, results, _ = _distro_scale_inputs(n)

    http1 = CountingHttp()
    epss1, vuln1 = _clients(http1, tmp_path)
    findings1 = build_vuln_findings(
        deps, results, epss=epss1, vulnrichment=vuln1,
        ssvc_fetch_budget=budget,
    )
    assert len(http1.epss_requests) == 3          # ceil(300 / 100)
    assert len(http1.vuln_requests) == budget

    http2 = CountingHttp()
    epss2, vuln2 = _clients(http2, tmp_path)
    findings2 = build_vuln_findings(
        deps, results, epss=epss2, vulnrichment=vuln2,
        ssvc_fetch_budget=budget,
    )
    assert len(http2.epss_requests) == 0          # fully cached
    # Only the 100 CVEs the first pass skipped need network now.
    assert len(http2.vuln_requests) == n - budget
    assert all(f.epss == 0.5 for f in findings2)
    assert sum(
        1 for f in findings2 if f.ssvc_exploitation == "active"
    ) == n
    assert len(findings1) == len(findings2) == n


def test_shared_cves_fetch_once(tmp_path: Path) -> None:
    """N findings sharing M CVEs cost ceil(M/batch) EPSS requests and
    M Vulnrichment GETs — the unique-CVE set drives the cost, not the
    finding count."""
    shared = [f"CVE-2024-{50000 + i}" for i in range(5)]
    deps: list[Dependency] = []
    results: list[OsvResult] = []
    for i in range(300):
        d = _dep(f"pkg-{i:05d}")
        deps.append(d)
        results.append(OsvResult(
            dep_key=d.key(),
            advisories=[_adv(f"GHSA-x-{i:05d}", shared[i % len(shared)])],
        ))
    http = CountingHttp()
    epss, vuln = _clients(http, tmp_path)
    findings = build_vuln_findings(
        deps, results, epss=epss, vulnrichment=vuln,
    )
    assert len(findings) == 300
    assert len(http.epss_requests) == 1           # 5 CVEs, one batch
    assert len(http.vuln_requests) == len(shared)
    assert all(f.epss == 0.5 for f in findings)
    assert all(f.ssvc_exploitation == "active" for f in findings)


# ---------------------------------------------------------------------------
# Budget priority + degrade semantics
# ---------------------------------------------------------------------------

def test_budget_priority_non_kev_high_severity_first(tmp_path: Path) -> None:
    """The SSVC budget is spent where the signal changes the risk
    verdict: KEV-listed findings already carry the top exploitation
    tier (the risk formula applies SSVC only when ``not in_kev``), so
    non-KEV CVEs come first, highest group severity first."""
    critical = CVSSScore(
        score=9.8,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="critical",
    )
    low = CVSSScore(
        score=3.1,
        vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
        severity="low",
    )
    cve_kev = "CVE-2024-70001"       # KEV-listed, critical
    cve_crit = "CVE-2024-70002"      # non-KEV, critical
    cve_low = "CVE-2024-70003"       # non-KEV, low
    deps = [_dep("a"), _dep("b"), _dep("c")]
    results = [
        OsvResult(dep_key=deps[0].key(),
                  advisories=[_adv("GHSA-kev", cve_kev, cvss=critical)]),
        OsvResult(dep_key=deps[1].key(),
                  advisories=[_adv("GHSA-crit", cve_crit, cvss=critical)]),
        OsvResult(dep_key=deps[2].key(),
                  advisories=[_adv("GHSA-low", cve_low, cvss=low)]),
    ]
    http = CountingHttp()
    epss, vuln = _clients(http, tmp_path)
    findings = build_vuln_findings(
        deps, results, kev=FakeKev([cve_kev]),  # type: ignore[arg-type]
        epss=epss, vulnrichment=vuln, ssvc_fetch_budget=2,
    )
    by_name = {f.dependency.name: f for f in findings}
    # Both non-KEV findings got the budget, critical before low.
    assert by_name["b"].ssvc_exploitation == "active"
    assert by_name["c"].ssvc_exploitation == "active"
    fetched = [u.rsplit("/", 1)[1] for u in http.vuln_requests]
    assert fetched == [f"{cve_crit}.json", f"{cve_low}.json"]
    # The KEV finding degrades SSVC to no-signal but keeps its KEV
    # verdict — the budget can never hide KEV enrichment, which is
    # computed from the (budget-independent) KEV catalog.
    assert by_name["a"].ssvc_exploitation is None
    assert by_name["a"].in_kev is True


def test_epss_chunk_failure_degrades_only_that_chunk(tmp_path: Path) -> None:
    """A failed EPSS batch leaves its own CVEs unresolved and nothing
    else — one lost chunk must not nuke the whole scan's enrichment."""
    n = 150                                       # 2 chunks: 100 + 50
    deps, results, cves = _distro_scale_inputs(n)
    # Fail whichever chunk carries the last CVE (the second chunk —
    # the client sorts ids, and ours are generated in sorted order).
    http = CountingHttp(fail_epss_chunks_containing=cves[-1])
    epss, vuln = _clients(http, tmp_path)
    findings = build_vuln_findings(
        deps, results, epss=epss, vulnrichment=vuln,
    )
    assert len(findings) == n
    assert len(http.epss_requests) == 2
    scored = [f for f in findings if f.epss == 0.5]
    unscored = [f for f in findings if f.epss is None]
    assert len(scored) == 100
    assert len(unscored) == 50
    # SSVC enrichment is unaffected by the EPSS outage.
    assert all(f.ssvc_exploitation == "active" for f in findings)
