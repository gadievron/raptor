"""Tests for ``packages.sca.review`` (the ``raptor-sca check`` subcommand)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from packages.sca import review
from core.json import JsonCache
from packages.sca.osv import OSV_VULN_URL_TEMPLATE


_LODASH_VULN_RECORD = {
    "id": "GHSA-jf85-cpcp-j695",
    "modified": "2024-01-01T00:00:00Z",
    "aliases": ["CVE-2019-10744"],
    "summary": "Prototype pollution in lodash",
    "details": "",
    "affected": [{
        "package": {"ecosystem": "npm", "name": "lodash"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"},
                               {"fixed": "4.17.12"}]}],
    }],
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "references": [],
    "fixed_versions": ["4.17.12"],
}

_LOG4SHELL_RECORD = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "modified": "2024-01-01T00:00:00Z",
    "aliases": ["CVE-2021-44228"],
    "summary": "Log4Shell",
    "details": "",
    "affected": [{
        "package": {"ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "2.0-beta9"},
                               {"fixed": "2.15.0"}]}],
    }],
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "references": [],
}


class StubHttp:
    def __init__(self, posts: Dict[Any, Any] | None = None,
                 gets: Dict[str, Any] | None = None) -> None:
        self.posts: List[tuple] = []
        self.gets: List[str] = []
        self._post_response = posts or {"results": [{"vulns": []}]}
        self._get_responses = gets or {}

    def post_json(self, url, body, timeout=30, **kwargs):
        self.posts.append((url, body))
        return self._post_response

    def get_json(self, url, timeout=30, **kwargs):
        self.gets.append(url)
        if url in self._get_responses:
            return self._get_responses[url]
        if "cisa.gov" in url:
            return {"vulnerabilities": []}
        if "first.org" in url:
            return {"data": []}
        raise RuntimeError(f"unexpected GET {url}")

    def get_bytes(self, *a, **k):
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------

def test_clean_dep_returns_zero(tmp_path: Path, capsys) -> None:
    """A safe version with no advisories and no typosquat → exit 0.

    Uses ``--no-transitive`` to skip the registry-metadata walk; the
    StubHttp doesn't model registry responses, and an unknown registry
    URL would otherwise trigger the seed-metadata-unverifiable warning.
    """
    http = StubHttp()
    cache = JsonCache(root=tmp_path)
    rc = review.main(
        ["npm", "@types/node", "20.10.5",
         "--no-transitive",
         "--out", str(tmp_path / "r.md")],
        http=http, cache=cache,
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "**Verdict:** Clean" in out
    assert "No advisories found" in out


def test_unknown_ecosystem_returns_2(tmp_path: Path, capsys) -> None:
    """Unrecognised ecosystem rejected before any OSV call."""
    http = StubHttp()
    cache = JsonCache(root=tmp_path)
    rc = review.main(["Bogus", "requests", "0.1.0"], http=http, cache=cache)
    assert rc == 2
    err = capsys.readouterr().err
    assert "unknown ecosystem" in err


def test_lowercase_ecosystem_canonicalised(tmp_path: Path, capsys) -> None:
    """Lowercase ecosystem is canonicalised to the OSV-accepted form
    so the OSV query actually returns advisories.
    """
    http = StubHttp()
    cache = JsonCache(root=tmp_path)
    rc = review.main(
        ["pypi", "requests", "2.31.0", "--no-transitive"],
        http=http, cache=cache,
    )
    # OSV would have been called with PyPI (canonical); StubHttp returns
    # no advisories, so verdict is Clean.
    assert rc == 0
    # Verify we sent PyPI (not pypi) to OSV.
    posts = http.posts
    assert any(
        any(q.get("package", {}).get("ecosystem") == "PyPI"
            for q in body.get("queries", []))
        for _url, body in posts
    )


def test_seed_metadata_unverifiable_escalates_to_review(
    tmp_path: Path, capsys,
) -> None:
    """When the registry can't confirm the package exists, escalate
    an otherwise-clean verdict to Review.
    """
    # StubHttp with no advisories AND no registry responses → seed
    # walk fails → seed_metadata_unverifiable=True.
    http = StubHttp()
    cache = JsonCache(root=tmp_path)
    rc = review.main(
        ["npm", "nonexistent-package-xyz123", "1.0.0"],
        http=http, cache=cache,
    )
    # Verdict escalated from Clean to Review (exit 1).
    assert rc == 1
    out = capsys.readouterr().out
    assert "**Verdict:** Review" in out
    assert "could not confirm" in out


def test_existence_probe_runs_under_no_transitive(
    tmp_path: Path, capsys, monkeypatch,
) -> None:
    """The existence probe runs even when --no-transitive is set, so
    nonexistent packages are still escalated to Review.
    """
    http = StubHttp()
    cache = JsonCache(root=tmp_path)

    # Stub package_version_exists to return False (404), simulating a
    # nonexistent package without needing real network.
    from packages.sca import registry_metadata_walk
    monkeypatch.setattr(
        registry_metadata_walk, "package_version_exists",
        lambda *a, **kw: False,
    )
    rc = review.main(
        ["PyPI", "nonexistent-pkg-xyz", "1.0.0", "--no-transitive"],
        http=http, cache=cache,
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "**Verdict:** Review" in out
    assert "## Existence" in out
    assert "could not confirm" in out


def test_existence_probe_skipped_under_offline(
    tmp_path: Path, capsys, monkeypatch,
) -> None:
    """--offline skips the existence probe (no network available).
    Operators get Clean for nonexistent packages in offline mode;
    that's the documented trade-off.
    """
    http = StubHttp()
    cache = JsonCache(root=tmp_path)

    # The probe shouldn't be called under --offline; assert that.
    from packages.sca import registry_metadata_walk
    called = []
    def _record(*a, **kw):
        called.append(True)
        return False
    monkeypatch.setattr(
        registry_metadata_walk, "package_version_exists", _record,
    )
    rc = review.main(
        ["PyPI", "anything-x-y-z", "1.0.0", "--no-transitive", "--offline"],
        http=http, cache=cache,
    )
    assert rc == 0
    assert called == [], "probe should not run under --offline"


def test_kev_listed_dep_returns_block(tmp_path: Path, capsys) -> None:
    http = StubHttp(
        posts={"results": [{"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q"}]}]},
        gets={
            OSV_VULN_URL_TEMPLATE.format("GHSA-jfh8-c2jp-5v3q"):
                _LOG4SHELL_RECORD,
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json":
                {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]},
        },
    )
    cache = JsonCache(root=tmp_path)
    rc = review.main(
        ["Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"],
        http=http, cache=cache,
    )
    assert rc == 2
    out = capsys.readouterr().out
    assert "**Verdict:** Block" in out
    assert "**KEV**" in out


def test_unfixable_critical_returns_block(tmp_path: Path, capsys) -> None:
    """A critical CVE without a fixed_versions entry blocks even
    without KEV listing."""
    record = dict(_LODASH_VULN_RECORD)
    record["affected"] = [{
        "package": {"ecosystem": "npm", "name": "lodash"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}]}],   # no fixed event
    }]
    http = StubHttp(
        posts={"results": [{"vulns": [{"id": "GHSA-jf85-cpcp-j695"}]}]},
        gets={OSV_VULN_URL_TEMPLATE.format("GHSA-jf85-cpcp-j695"): record},
    )
    cache = JsonCache(root=tmp_path)
    rc = review.main(["npm", "lodash", "4.17.4"],
                     http=http, cache=cache)
    assert rc == 2
    assert "**Verdict:** Block" in capsys.readouterr().out


def test_typosquat_distance_one_blocks(tmp_path: Path, capsys) -> None:
    http = StubHttp()
    cache = JsonCache(root=tmp_path)
    rc = review.main(["npm", "loadash", "1.0.0"],
                     http=http, cache=cache)
    assert rc == 2
    out = capsys.readouterr().out
    assert "Typosquat candidate" in out
    assert "**Verdict:** Block" in out


def test_typosquat_distance_two_returns_review(tmp_path: Path, capsys) -> None:
    http = StubHttp()
    cache = JsonCache(root=tmp_path)
    rc = review.main(["npm", "lodaasch", "1.0.0"],
                     http=http, cache=cache)
    assert rc == 1
    assert "**Verdict:** Review" in capsys.readouterr().out


def test_slopsquat_high_severity_blocks(tmp_path: Path, capsys) -> None:
    """Lookalike-collapse heuristic match is severity=high → Block.
    The LLM-paste developer typing
    ``raptor-sca check npm 1odash 1.0.0`` sees a Block verdict
    on the visual-confusable name."""
    http = StubHttp()
    cache = JsonCache(root=tmp_path)
    rc = review.main(["npm", "1odash", "1.0.0"],
                     http=http, cache=cache)
    assert rc == 2  # Block
    out = capsys.readouterr().out
    assert "Slopsquat candidate" in out
    assert "**Verdict:** Block" in out


def test_slopsquat_medium_severity_returns_review(
    tmp_path: Path, capsys,
) -> None:
    """Generic-suffix heuristic alone is severity=medium →
    Review. ``lodash-pro`` is the canonical LLM hallucination
    shape; pre-install check surfaces it as Review so the
    operator sees the warning before running ``npm install``."""
    http = StubHttp()
    cache = JsonCache(root=tmp_path)
    rc = review.main(["npm", "lodash-pro", "1.0.0"],
                     http=http, cache=cache)
    assert rc == 1  # Review
    out = capsys.readouterr().out
    assert "Slopsquat candidate" in out
    assert "**Verdict:** Review" in out
    assert "popular_prefix_generic_suffix" in out


def test_slopsquat_check_dep_public_api(tmp_path: Path) -> None:
    """``check_dep`` is the canonical single-dep predicate. Smoke-
    test it directly (not via the CLI) to pin the public API
    shape — keeps external callers (bumper, harden, future
    consumers) from drifting onto the private ``_check_one``."""
    from packages.sca.supply_chain.slopsquat import check_dep
    from packages.sca.models import (
        Confidence, Dependency, PinStyle,
    )
    dep = Dependency(
        ecosystem="npm", name="lodash-pro", version="1.0",
        declared_in=Path("/x"), scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:npm/lodash-pro@1.0",
        parser_confidence=Confidence("high", reason="t"),
    )
    f = check_dep(dep)
    assert f is not None
    assert f.severity == "medium"
    assert "popular_prefix_generic_suffix" in f.reasons


def test_advisory_with_fix_returns_review(tmp_path: Path, capsys) -> None:
    """A high-sev CVE with an upgrade path is a review, not a block."""
    http = StubHttp(
        posts={"results": [{"vulns": [{"id": "GHSA-jf85-cpcp-j695"}]}]},
        gets={OSV_VULN_URL_TEMPLATE.format("GHSA-jf85-cpcp-j695"):
              _LODASH_VULN_RECORD},
    )
    cache = JsonCache(root=tmp_path)
    rc = review.main(["npm", "lodash", "4.17.4"],
                     http=http, cache=cache)
    assert rc == 1
    out = capsys.readouterr().out
    assert "**Verdict:** Review" in out
    assert "Fix available: **4.17.12**" in out


# ---------------------------------------------------------------------------
# Output handling
# ---------------------------------------------------------------------------

def test_writes_report_to_out_when_supplied(tmp_path: Path, capsys) -> None:
    out_path = tmp_path / "review.md"
    http = StubHttp()
    cache = JsonCache(root=tmp_path / "cache")
    review.main(["npm", "@types/node", "20.10.5", "--out", str(out_path)],
                http=http, cache=cache)
    assert out_path.exists()
    contents = out_path.read_text()
    assert "**Verdict:**" in contents
    # stdout still received the same body.
    assert capsys.readouterr().out == contents


def test_offline_mode_skips_network(tmp_path: Path, capsys) -> None:
    http = StubHttp()
    cache = JsonCache(root=tmp_path)
    rc = review.main(["npm", "@types/node", "20.10.5", "--offline"],
                     http=http, cache=cache)
    assert rc == 0
    assert http.posts == []
    assert http.gets == []


def test_purl_includes_ecosystem_lowercase(tmp_path: Path, capsys) -> None:
    """The header line shows a canonical purl so operators can paste
    it into other tools."""
    review.main(["PyPI", "django", "2.0.0"],
                http=StubHttp(), cache=JsonCache(root=tmp_path))
    out = capsys.readouterr().out
    assert "pkg:pypi/django@2.0.0" in out


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

def test_missing_args_returns_2(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        review.main(["npm"], http=StubHttp(), cache=JsonCache(root=tmp_path))
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# Transitive surface (registry-metadata walk)
# ---------------------------------------------------------------------------

def test_transitive_walk_runs_by_default(tmp_path: Path, capsys) -> None:
    """Default: review walks one level of declared deps so the
    operator sees the full install surface, not just the named pkg."""
    http = StubHttp(gets={
        "https://pypi.org/pypi/django/2.0.0/json": {
            "info": {"requires_dist": ["pytz>=2017.2"]},
        },
        "https://pypi.org/pypi/pytz/2017.2/json": {
            "info": {"requires_dist": []},
        },
    })
    review.main(["PyPI", "django", "2.0.0"],
                 http=http, cache=JsonCache(root=tmp_path))
    out = capsys.readouterr().out
    assert "Transitive surface" in out
    assert "pytz" in out
    assert "1 declared dependency" in out


def test_transitive_walk_skipped_via_flag(tmp_path: Path, capsys) -> None:
    """--no-transitive disables the walk; no Transitive surface
    section appears."""
    review.main(["PyPI", "django", "2.0.0", "--no-transitive"],
                 http=StubHttp(), cache=JsonCache(root=tmp_path))
    out = capsys.readouterr().out
    assert "Transitive surface" not in out


def test_transitive_walk_skipped_when_offline(tmp_path: Path, capsys) -> None:
    """--offline implies no walk (the metadata fetch needs network)."""
    review.main(["PyPI", "django", "2.0.0", "--offline"],
                 http=StubHttp(), cache=JsonCache(root=tmp_path))
    out = capsys.readouterr().out
    assert "Transitive surface" not in out


def test_unsupported_ecosystem_emits_honest_section(
    tmp_path: Path, capsys,
) -> None:
    """Maven / RubyGems / etc. don't have a metadata walker yet —
    the section must say so explicitly so silence isn't mistaken
    for safety."""
    review.main(
        ["Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"],
        http=StubHttp(), cache=JsonCache(root=tmp_path),
    )
    out = capsys.readouterr().out
    assert "Transitive surface" in out
    assert "not yet supported" in out


def test_kev_in_transitive_escalates_verdict_to_block(
    tmp_path: Path, capsys,
) -> None:
    """Block-class signal in a TRANSITIVE dep should still mean
    'don't install the named package' — the named package's clean
    bill is meaningless if installing it pulls in a KEV CVE."""

    transitive_advisory = {
        "id": "GHSA-fake-trans",
        "modified": "2024-01-01T00:00:00Z",
        "aliases": ["CVE-2024-FAKE-T"],
        "summary": "Hostile transitive",
        "details": "",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "vulnerable-pkg"},
            "ranges": [{"type": "ECOSYSTEM",
                         "events": [{"introduced": "0"},
                                     {"fixed": "2.0"}]}],
        }],
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "references": [],
    }

    class _SeqHttp(StubHttp):
        def __init__(self):
            super().__init__()
            self._batch_count = 0

        def post_json(self, url, body, timeout=30, **kwargs):
            self.posts.append((url, body))
            self._batch_count += 1
            # First OSV batch = direct dep (clean).
            # Second OSV batch = transitives (one hit).
            if self._batch_count == 1:
                return {"results": [{"vulns": []}]}
            return {"results": [{"vulns": [{"id": "GHSA-fake-trans"}]}]}

        def get_json(self, url, timeout=30, **kwargs):
            self.gets.append(url)
            if "pypi.org/pypi/safe-pkg/1.0/json" in url:
                return {"info": {
                    "requires_dist": ["vulnerable-pkg==1.0"],
                }}
            if "pypi.org/pypi/vulnerable-pkg/1.0/json" in url:
                return {"info": {"requires_dist": []}}
            if "GHSA-fake-trans" in url:
                return transitive_advisory
            if "cisa.gov" in url:
                return {"vulnerabilities": [{"cveID": "CVE-2024-FAKE-T"}]}
            if "first.org" in url:
                return {"data": []}
            raise RuntimeError(f"unexpected GET {url}")

    rc = review.main(
        ["PyPI", "safe-pkg", "1.0"],
        http=_SeqHttp(), cache=JsonCache(root=tmp_path),
    )
    out = capsys.readouterr().out
    assert rc == 2
    assert "**Verdict:** Block" in out
    assert "Transitive surface" in out
    assert "vulnerable-pkg" in out
    assert "KEV" in out


# ---------------------------------------------------------------------------
# _compute_verdict — unit-level guards for the multi-critical and
# high-EPSS threshold additions.
# ---------------------------------------------------------------------------

from packages.sca.models import (                       # noqa: E402
    Confidence, Dependency, PinStyle, Reachability,
    VulnFinding,
)


def _vuln(severity: str = "critical", *, fixed: str | None = "9.0.0",
           in_kev: bool = False, epss: float | None = None) -> VulnFinding:
    dep = Dependency(
        ecosystem="PyPI", name="x", version="1.0",
        declared_in=Path("/r/req.txt"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:pypi/x@1.0",
        parser_confidence=Confidence("high", reason="t"),
    )
    return VulnFinding(
        finding_id=f"sca:vuln:PyPI:x@1.0:{severity}-{epss}-{in_kev}",
        dependency=dep,
        advisories=[],
        in_kev=in_kev,
        epss=epss,
        fixed_version=fixed,
        reachability=Reachability(
            verdict="not_evaluated",
            confidence=Confidence("low", reason="t"),
        ),
        version_match_confidence=Confidence("high", reason="t"),
        cvss_score=9.0,
        cvss_vector="CVSS:3.1/...",
        severity=severity,         # type: ignore[arg-type]
        exposure_factor=1.0,
        transitive_depth=0,
    )


def test_two_criticals_with_fix_now_block() -> None:
    """django 4.2.10 had 3 critical SQL-injection CVEs, each with
    a fix available; pre-fix the verdict was Review because no
    single finding tripped a threshold. Multiple criticals at
    install time are blocker-tier."""
    from packages.sca.review import (
        _VERDICT_BLOCK, _compute_verdict,
    )
    findings = [_vuln(severity="critical"),
                _vuln(severity="critical")]
    assert _compute_verdict(findings, []) == _VERDICT_BLOCK


def test_single_critical_with_fix_stays_review() -> None:
    """Threshold for the new block path is ≥2 criticals — one is
    still a Review (operator may have a reason to accept a single
    fixable critical for a release-train window)."""
    from packages.sca.review import (
        _VERDICT_REVIEW, _compute_verdict,
    )
    assert _compute_verdict([_vuln(severity="critical")], []) == _VERDICT_REVIEW


def test_single_critical_with_high_epss_blocks() -> None:
    """Single critical with EPSS ≥ 0.5 (FIRST.org: "likely
    exploited in next 30 days") is operator-actionable even with
    a fix available — telling someone "I'll upgrade next sprint"
    isn't defensible when the EPSS is that high."""
    from packages.sca.review import (
        _VERDICT_BLOCK, _compute_verdict,
    )
    f = _vuln(severity="critical", epss=0.65)
    assert _compute_verdict([f], []) == _VERDICT_BLOCK


def test_single_critical_with_low_epss_does_not_block() -> None:
    """Below-threshold EPSS doesn't fire the high-EPSS escalation;
    falls back to Review."""
    from packages.sca.review import (
        _VERDICT_REVIEW, _compute_verdict,
    )
    f = _vuln(severity="critical", epss=0.10)
    assert _compute_verdict([f], []) == _VERDICT_REVIEW


def test_single_critical_no_epss_does_not_block() -> None:
    """``epss=None`` (FIRST.org has no score for this CVE yet) is
    not an escalation signal; falls back to Review."""
    from packages.sca.review import (
        _VERDICT_REVIEW, _compute_verdict,
    )
    f = _vuln(severity="critical", epss=None)
    assert _compute_verdict([f], []) == _VERDICT_REVIEW


# ---------------------------------------------------------------------------
# _compute_verdict — bump-tier supply-chain findings
#
# These tests exercise the ``bump_supply_chain_findings=`` parameter
# added for the dependabot++ bumper loop. Bump-time supply-chain
# signals are evaluated by the bumper evaluator (separate module,
# tested separately); this verdict pass just consumes pre-computed
# findings and maps them onto Clean / Review / Block.
# ---------------------------------------------------------------------------

from packages.sca.models import SupplyChainFinding         # noqa: E402


def _supply(kind: str = "recent_publish",
             severity: str = "medium",
             detail: str = "") -> SupplyChainFinding:
    dep = Dependency(
        ecosystem="PyPI", name="x", version="2.0",
        declared_in=Path("/r/req.txt"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:pypi/x@2.0",
        parser_confidence=Confidence("high", reason="t"),
    )
    return SupplyChainFinding(
        finding_id=f"sca:supply:{kind}:PyPI:x@2.0",
        kind=kind,                # type: ignore[arg-type]
        dependency=dep,
        detail=detail or f"{kind} fired on bump",
        evidence={},
        severity=severity,        # type: ignore[arg-type]
        confidence=Confidence("high", reason="bump-tier"),
    )


def test_bump_unused_when_param_omitted() -> None:
    """Default ``check`` flow doesn't pass bump findings; verdict
    is computed exactly as before. Pin against accidental
    behavioural drift."""
    from packages.sca.review import (
        _VERDICT_CLEAN, _compute_verdict,
    )
    assert _compute_verdict([], []) == _VERDICT_CLEAN


def test_bump_single_high_severity_blocks() -> None:
    """A ``high``-severity bump-tier finding alone is enough to
    Block: e.g. maintainer account ownership flipped between
    current and target (account-takeover shape) — the operator
    should not auto-merge that bump."""
    from packages.sca.review import (
        _VERDICT_BLOCK, _compute_verdict,
    )
    sf = _supply(kind="maintainer_account_change", severity="high")
    assert _compute_verdict([], [], bump_supply_chain_findings=[sf]) == _VERDICT_BLOCK


def test_bump_single_medium_escalates_to_review() -> None:
    """A single ``medium``-severity bump-tier finding escalates
    Clean → Review. Example: target version published 5 days ago
    (rapid-release window) — operator should pause and look."""
    from packages.sca.review import (
        _VERDICT_REVIEW, _compute_verdict,
    )
    sf = _supply(kind="recent_publish", severity="medium")
    assert _compute_verdict([], [], bump_supply_chain_findings=[sf]) == _VERDICT_REVIEW


def test_bump_two_mediums_compound_block() -> None:
    """Two ``medium`` bump-tier findings on the same bump compound
    into a Block. Three Review-tier signals stacked aren't "three
    Review-tier signals" — they're a supply-chain-attack shape:
    e.g. recently published AND from a changed maintainer AND
    added an install hook."""
    from packages.sca.review import (
        _VERDICT_BLOCK, _compute_verdict,
    )
    sfs = [
        _supply(kind="recent_publish", severity="medium"),
        _supply(kind="maintainer_change", severity="medium"),
    ]
    assert _compute_verdict([], [], bump_supply_chain_findings=sfs) == _VERDICT_BLOCK


def test_bump_low_info_does_not_change_verdict() -> None:
    """``low`` / ``info`` bump-tier findings annotate but don't
    move the verdict ladder. Example: a low-severity
    ``maintainer_email_change`` is operator-visible context, not
    a gate signal."""
    from packages.sca.review import (
        _VERDICT_CLEAN, _compute_verdict,
    )
    sfs = [
        _supply(kind="maintainer_email_change", severity="low"),
        _supply(kind="recent_publish", severity="info"),
    ]
    assert _compute_verdict([], [], bump_supply_chain_findings=sfs) == _VERDICT_CLEAN


def test_bump_high_severity_dominates_typo_distance_two() -> None:
    """When both a typosquat-distance-two AND a high-severity
    bump-tier signal fire, the higher-tier signal wins. (Typo
    distance two alone would be Review; a high-severity bump
    finding alone is Block.)"""
    from packages.sca.review import (
        _VERDICT_BLOCK, _compute_verdict,
    )
    from packages.sca.supply_chain.typosquat import TyposquatFinding
    typo_dep = Dependency(
        ecosystem="npm", name="loadash", version="1.0",
        declared_in=Path("/r/package.json"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:npm/loadash@1.0",
        parser_confidence=Confidence("high", reason="t"),
    )
    typo = TyposquatFinding(
        dependency=typo_dep, nearest_popular="lodash",
        distance=2, severity="medium",
        confidence=Confidence("high", reason="t"),
    )
    sf = _supply(severity="high")
    assert _compute_verdict([], [typo],
                              bump_supply_chain_findings=[sf]) == _VERDICT_BLOCK


def test_bump_clean_when_only_clean_signals() -> None:
    """No bump-tier findings + no vuln/typo findings → Clean.
    Pinpoints the Clean-tier passthrough for the bumper's
    auto-merge eligibility check."""
    from packages.sca.review import (
        _VERDICT_CLEAN, _compute_verdict,
    )
    assert _compute_verdict([], [],
                              bump_supply_chain_findings=[]) == _VERDICT_CLEAN
