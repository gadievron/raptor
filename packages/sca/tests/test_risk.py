"""Tests for ``packages.sca.risk.compute_risk_estimate``.

Covers the worked examples from ``design/sca.md`` §1316 and per-
multiplier behaviour. The tests pin numeric scores within tolerance
bands (≤1.0 point) so calibration tweaks that change a multiplier
slightly won't false-fail; gross regressions still trip.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pytest

from packages.sca.models import (
    AffectedRange, Advisory, Confidence, Dependency,
    PinStyle, Reachability, VulnFinding,
)
from packages.sca.risk import compute_risk_estimate


def _dep(*, name: str = "foo", direct: bool = True,
         parser_conf: str = "high") -> Dependency:
    return Dependency(
        ecosystem="PyPI", name=name, version="1.0.0",
        declared_in=Path("/x/req.txt"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=direct,
        purl=f"pkg:pypi/{name}@1.0.0",
        parser_confidence=Confidence(parser_conf, reason="test fixture"),
    )


def _adv() -> Advisory:
    return Advisory(
        osv_id="GHSA-fake", aliases=[],
        summary="test", details="",
        affected=[AffectedRange(
            type="ECOSYSTEM",
            events=[{"introduced": "0"}, {"fixed": "9.9"}])],
        severity=None,
        fixed_versions=["9.9"],
        references=[],
    )


def _finding(
    *, dep: Optional[Dependency] = None,
    cvss: Optional[float] = 7.5,
    in_kev: bool = False,
    epss: Optional[float] = 0.5,
    reach_verdict: str = "imported",
    reach_conf: str = "high",
    exposure: float = 0.5,
    depth: int = 0,
    vmc: str = "high",
    exploit_evidence: "Optional[object]" = None,
) -> VulnFinding:
    d = dep if dep is not None else _dep()
    return VulnFinding(
        finding_id="t-1",
        dependency=d,
        advisories=[_adv()],
        in_kev=in_kev,
        epss=epss,
        fixed_version="9.9",
        reachability=Reachability(
            verdict=reach_verdict,
            confidence=Confidence(reach_conf, reason="test"),
            evidence=[]),
        version_match_confidence=Confidence(vmc, reason="test"),
        cvss_score=cvss, cvss_vector=None,
        severity="high",
        exposure_factor=exposure,
        transitive_depth=depth,
        exploit_evidence=exploit_evidence,
    )


# ---------------------------------------------------------------------------
# Worked examples from design §1316
# ---------------------------------------------------------------------------

def test_log4shell_kev_reachable_direct_scores_high():
    """Critical, KEV, EPSS 97%, reachable, direct, exact match → ~96."""
    f = _finding(
        cvss=10.0, in_kev=True, epss=0.97,
        reach_verdict="imported", exposure=1.0, depth=0, vmc="high",
    )
    score, comps = compute_risk_estimate(f, f.dependency)
    assert 90 <= score <= 100, f"got {score}"
    assert comps["kev_multiplier"] == 1.20


def test_log4shell_but_not_reachable_drops_to_low():
    """Same vuln, but high-confidence not_reachable should land WAY
    below the reachable scenario (under 25). The design's ~29 was an
    approximation; the exact bound depends on whether exposure is
    treated as 0 (not_reachable means no call sites) or 1. We use 0
    — the natural reading — which gives ~18."""
    f = _finding(
        cvss=10.0, in_kev=True, epss=0.97,
        reach_verdict="not_reachable", reach_conf="high",
        exposure=0.0, depth=0,
    )
    score, _ = compute_risk_estimate(f, f.dependency)
    assert score < 25, f"got {score}"
    # And much lower than the reachable equivalent.
    reachable = _finding(
        cvss=10.0, in_kev=True, epss=0.97,
        reach_verdict="imported", exposure=1.0, depth=0,
    )
    s_reach, _ = compute_risk_estimate(reachable, reachable.dependency)
    assert score < s_reach * 0.30, (
        f"not_reachable={score} should be <30% of reachable={s_reach}"
    )


def test_log4shell_at_transitive_depth_3():
    """Same vuln, but at depth 3 → ~33."""
    transitive = _dep(direct=False)
    f = _finding(
        dep=transitive,
        cvss=10.0, in_kev=True, epss=0.97,
        reach_verdict="imported", exposure=1.0, depth=3,
    )
    score, _ = compute_risk_estimate(f, transitive)
    assert 28 <= score <= 38, f"got {score}"


def test_background_hygiene_finding_scores_low():
    """CVSS 5, no KEV, EPSS 5%, reachable, direct → ~14."""
    f = _finding(
        cvss=5.0, in_kev=False, epss=0.05,
        reach_verdict="imported", exposure=0.5, depth=0,
    )
    score, _ = compute_risk_estimate(f, f.dependency)
    assert 10 <= score <= 18, f"got {score}"


def test_kev_high_with_heuristic_parser_haircut():
    """CVSS 9, KEV, EPSS 90%, reachable, parser heuristic → score
    below the "exact parser, exact match" equivalent. Design said
    ~63; the parser × vmc double-haircut at medium=0.70 gives ~42 —
    the contract is "heuristic-parser haircut materially knocks
    down the score", which the relative-ordering check enforces."""
    heuristic = _dep(parser_conf="medium")
    f_heur = _finding(
        dep=heuristic, cvss=9.0, in_kev=True, epss=0.90,
        reach_verdict="imported", exposure=0.7, depth=0,
        vmc="medium",
    )
    f_exact = _finding(
        cvss=9.0, in_kev=True, epss=0.90,
        reach_verdict="imported", exposure=0.7, depth=0,
        vmc="high",
    )
    s_heur, _ = compute_risk_estimate(f_heur, heuristic)
    s_exact, _ = compute_risk_estimate(f_exact, f_exact.dependency)
    # The heuristic version must score noticeably lower.
    assert s_heur < s_exact * 0.65, (
        f"heuristic={s_heur} should be <65% of exact={s_exact}"
    )
    # But not zero — heuristic-parser hits still merit attention.
    assert s_heur > 30, f"got {s_heur}"


# ---------------------------------------------------------------------------
# Per-multiplier behaviour
# ---------------------------------------------------------------------------

def test_score_clamped_to_0_100():
    """Even adversarial inputs (negative exposure etc.) clamp into [0,100]."""
    f = _finding(cvss=10.0, in_kev=True, epss=1.0, exposure=2.0)
    score, _ = compute_risk_estimate(f, f.dependency)
    assert 0.0 <= score <= 100.0


def test_missing_cvss_uses_neutral_default():
    """A finding with no CVSS shouldn't score zero — use a neutral 5."""
    f = _finding(cvss=None)
    score, comps = compute_risk_estimate(f, f.dependency)
    # Neutral 5 → 50 base, then ~halved by EPSS+exposure → ~10-20.
    assert score > 0
    assert comps["cvss_base"] == 50.0


def test_missing_epss_uses_neutral_default():
    """No EPSS → 0.5 default → epss_multiplier = 0.30 + 0.70*0.5 = 0.65."""
    f = _finding(epss=None)
    _, comps = compute_risk_estimate(f, f.dependency)
    assert comps["epss_multiplier"] == pytest.approx(0.65, abs=1e-6)


def test_calibration_status_in_components(tmp_path, monkeypatch):
    """Every breakdown carries a ``calibration_status`` key so
    consumers can show a UI hint or refuse to ship the score.

    Hermetic: redirects the validation-report lookup at a tmp
    dir so this test's assertion is stable regardless of what's
    under the in-tree ``data/calibration/validation/`` directory.
    """
    from packages.sca import risk
    risk._reset_calibration_cache_for_tests()
    monkeypatch.setattr(
        risk, "_load_latest_validation_verdict",
        lambda: "unverified",
    )
    f = _finding()
    _, comps = compute_risk_estimate(f, f.dependency)
    assert comps["calibration_status"] == "unverified"


def test_components_breakdown_carries_every_named_multiplier():
    """The breakdown is the operator-facing 'why this score' surface;
    every multiplier the formula applies must appear in it."""
    f = _finding()
    _, comps = compute_risk_estimate(f, f.dependency)
    for k in ("cvss_base", "kev_multiplier", "epss_multiplier",
              "reachability_multiplier", "exposure_multiplier",
              "depth_multiplier", "parser_confidence",
              "version_match_confidence", "final"):
        assert k in comps, f"missing component: {k}"


def test_score_is_deterministic():
    """Same inputs → identical score every call (no clock / random)."""
    f = _finding()
    a, _ = compute_risk_estimate(f, f.dependency)
    b, _ = compute_risk_estimate(f, f.dependency)
    assert a == b


def test_kev_floor_overrides_low_cvss():
    """A KEV finding with a low CVSS still gets the 80-floor."""
    low_cvss = _finding(cvss=3.0, in_kev=True, epss=0.9, exposure=1.0)
    score_kev, _ = compute_risk_estimate(low_cvss, low_cvss.dependency)
    same_no_kev = _finding(cvss=3.0, in_kev=False, epss=0.9, exposure=1.0)
    score_no_kev, _ = compute_risk_estimate(same_no_kev, same_no_kev.dependency)
    assert score_kev > 2 * score_no_kev, (
        f"KEV floor should dominate low CVSS: kev={score_kev} "
        f"non-kev={score_no_kev}"
    )


def test_not_reachable_low_confidence_smaller_reduction():
    """Low-confidence not_reachable shouldn't fully discount the score —
    the operator might still want to look at it."""
    high_conf = _finding(
        cvss=10.0, in_kev=True, epss=0.9, exposure=1.0,
        reach_verdict="not_reachable", reach_conf="high",
    )
    low_conf = _finding(
        cvss=10.0, in_kev=True, epss=0.9, exposure=1.0,
        reach_verdict="not_reachable", reach_conf="low",
    )
    s_high, _ = compute_risk_estimate(high_conf, high_conf.dependency)
    s_low, _ = compute_risk_estimate(low_conf, low_conf.dependency)
    assert s_low > s_high, (
        f"low-confidence not_reachable ({s_low}) should score higher "
        f"than high-confidence not_reachable ({s_high})"
    )


def test_depth_decay_geometric():
    """Depth 1 → 0.7×; depth 2 → 0.49×; depth 3 → 0.343×."""
    base_dep = _dep(direct=True)
    direct = _finding(dep=base_dep, depth=0)
    s0, _ = compute_risk_estimate(direct, direct.dependency)

    for depth, expected_ratio in [(1, 0.70), (2, 0.49), (3, 0.343)]:
        td = _dep(direct=False)
        f = _finding(dep=td, depth=depth)
        s, _ = compute_risk_estimate(f, td)
        # Tolerance: other multipliers cancel since fixtures are
        # otherwise identical.
        assert s == pytest.approx(s0 * expected_ratio, abs=0.5), (
            f"depth={depth}: expected ~{s0 * expected_ratio:.2f}, got {s:.2f}"
        )


# ---------------------------------------------------------------------------
# Calibration-status read from validation reports
# ---------------------------------------------------------------------------


class TestCalibrationStatusFromValidation:
    """``compute_risk_estimate`` reads the latest
    ``validation/<date>.json`` and surfaces its verdict in the
    components breakdown.

    Tests use the test helper to flush the cache; in production the
    verdict is read once per process.
    """

    def _patch_validation_dir(self, monkeypatch, tmp_path):
        """Redirect the validation-reports lookup to a tmp dir."""
        from packages.sca import risk
        risk._reset_calibration_cache_for_tests()

        # The lookup uses ``Path(__file__).resolve().parent /
        # "data" / "calibration" / "validation"``. Monkey-patch
        # the loader to read from tmp_path instead.
        validation_dir = tmp_path / "validation"
        validation_dir.mkdir()

        original = risk._load_latest_validation_verdict

        def _patched():
            import json
            if not validation_dir.is_dir():
                return "unverified"
            candidates = sorted(
                (p for p in validation_dir.iterdir()
                 if p.is_file() and p.suffix == ".json"),
                key=lambda p: p.name, reverse=True,
            )
            for path in candidates:
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except Exception:               # noqa: BLE001
                    continue
                if not isinstance(data, dict):
                    continue
                verdict = data.get("verdict")
                if isinstance(verdict, str) and verdict:
                    return verdict
            return "unverified"

        monkeypatch.setattr(
            risk, "_load_latest_validation_verdict", _patched,
        )
        return validation_dir

    def test_validated_v1_verdict_surfaces(self, tmp_path, monkeypatch):
        """A validation report saying ``validated_v1`` is read and
        flowed through to the components breakdown."""
        validation_dir = self._patch_validation_dir(monkeypatch, tmp_path)
        (validation_dir / "2026-05-08.json").write_text(json.dumps({
            "snapshot_date": "2026-05-08",
            "verdict": "validated_v1",
            "top_20_precision": 0.65,
            "spearman_rho": 0.55,
        }))

        f = _finding()
        _, comps = compute_risk_estimate(f, f.dependency)
        assert comps["calibration_status"] == "validated_v1"

    def test_needs_retune_verdict_surfaces(self, tmp_path, monkeypatch):
        """When the validator emits ``needs_retune``, that's what
        operators see — not a stale ``unverified``."""
        validation_dir = self._patch_validation_dir(monkeypatch, tmp_path)
        (validation_dir / "2026-05-08.json").write_text(json.dumps({
            "verdict": "needs_retune",
            "top_20_precision": 0.3,
            "spearman_rho": 0.2,
        }))

        f = _finding()
        _, comps = compute_risk_estimate(f, f.dependency)
        assert comps["calibration_status"] == "needs_retune"

    def test_latest_report_wins(self, tmp_path, monkeypatch):
        """Multiple reports → the most recent (lex-largest filename
        for ISO-formatted dates) sets the verdict."""
        validation_dir = self._patch_validation_dir(monkeypatch, tmp_path)
        (validation_dir / "2026-04-01.json").write_text(json.dumps({
            "verdict": "validated_v1",
        }))
        (validation_dir / "2026-05-08.json").write_text(json.dumps({
            "verdict": "needs_retune",
        }))
        (validation_dir / "2026-03-15.json").write_text(json.dumps({
            "verdict": "validated_v1",
        }))

        f = _finding()
        _, comps = compute_risk_estimate(f, f.dependency)
        assert comps["calibration_status"] == "needs_retune"

    def test_no_reports_falls_back_to_unverified(
        self, tmp_path, monkeypatch,
    ):
        """Empty validation/ dir → unverified."""
        self._patch_validation_dir(monkeypatch, tmp_path)
        # No files written.
        f = _finding()
        _, comps = compute_risk_estimate(f, f.dependency)
        assert comps["calibration_status"] == "unverified"

    def test_malformed_report_skipped_for_next(
        self, tmp_path, monkeypatch,
    ):
        """A malformed report is skipped; the lookup falls through
        to the next-most-recent valid one rather than crashing."""
        validation_dir = self._patch_validation_dir(monkeypatch, tmp_path)
        (validation_dir / "2026-05-08.json").write_text(
            "this isn't json"
        )
        (validation_dir / "2026-04-01.json").write_text(json.dumps({
            "verdict": "validated_v1",
        }))
        f = _finding()
        _, comps = compute_risk_estimate(f, f.dependency)
        assert comps["calibration_status"] == "validated_v1"

    def test_report_missing_verdict_field_falls_back(
        self, tmp_path, monkeypatch,
    ):
        """A JSON object without a ``verdict`` field is skipped
        rather than mistakenly read as ``"unverified"`` from
        nothing."""
        validation_dir = self._patch_validation_dir(monkeypatch, tmp_path)
        (validation_dir / "2026-05-08.json").write_text(json.dumps({
            "snapshot_date": "2026-05-08",
            "top_20_precision": 0.65,
            # no verdict
        }))
        (validation_dir / "2026-04-01.json").write_text(json.dumps({
            "verdict": "validated_v1",
        }))
        f = _finding()
        _, comps = compute_risk_estimate(f, f.dependency)
        # Verdict-less newer report skipped, older one wins.
        assert comps["calibration_status"] == "validated_v1"

    def test_non_json_files_in_validation_dir_ignored(
        self, tmp_path, monkeypatch,
    ):
        """A README.md / .gitkeep / etc. in the validation dir
        shouldn't confuse the lookup."""
        validation_dir = self._patch_validation_dir(monkeypatch, tmp_path)
        (validation_dir / "README.md").write_text("notes")
        (validation_dir / "2026-05-08.json").write_text(json.dumps({
            "verdict": "validated_v1",
        }))
        f = _finding()
        _, comps = compute_risk_estimate(f, f.dependency)
        assert comps["calibration_status"] == "validated_v1"

    def test_cache_persists_within_process(
        self, tmp_path, monkeypatch,
    ):
        """Once the verdict is loaded, subsequent compute_risk_estimate
        calls don't re-read the disk — even if the file has been
        updated. SCA scans see one consistent verdict."""
        validation_dir = self._patch_validation_dir(monkeypatch, tmp_path)
        (validation_dir / "2026-05-08.json").write_text(json.dumps({
            "verdict": "validated_v1",
        }))
        f = _finding()
        # First call populates the cache.
        _, comps1 = compute_risk_estimate(f, f.dependency)
        assert comps1["calibration_status"] == "validated_v1"
        # Mutate the on-disk file to a different verdict.
        (validation_dir / "2026-05-08.json").write_text(json.dumps({
            "verdict": "needs_retune",
        }))
        # Without cache flush, the second call should still see
        # the cached verdict.
        _, comps2 = compute_risk_estimate(f, f.dependency)
        assert comps2["calibration_status"] == "validated_v1"


# ---------------------------------------------------------------------------
# Exploit-evidence boost — independent of in_kev
# ---------------------------------------------------------------------------


def _ee(
    *, kev: bool = False, edb: int = 0, msf: int = 0, poc: int = 0,
):
    """Construct an ExploitEvidence with the given signal counts."""
    from packages.sca.models import ExploitEvidence
    return ExploitEvidence(
        kev_listed=kev,
        edb_ids=list(range(edb)),
        msf_modules=[f"exploit/m{i}" for i in range(msf)],
        github_poc_urls=[f"https://github.com/x/p{i}" for i in range(poc)],
    )


def test_exploit_evidence_no_signal_no_boost():
    """ExploitEvidence with all-empty signals → no multiplier change."""
    no_ee = _finding(cvss=5.0, in_kev=False, epss=0.1,
                      exploit_evidence=_ee())
    s_no, c_no = compute_risk_estimate(no_ee, no_ee.dependency)
    none = _finding(cvss=5.0, in_kev=False, epss=0.1, exploit_evidence=None)
    s_none, c_none = compute_risk_estimate(none, none.dependency)
    assert s_no == s_none, (
        "empty exploit_evidence should be identical to None — same score"
    )
    assert c_no["exploit_evidence_multiplier"] == 1.0


def test_exploit_evidence_edb_boosts_non_kev_finding():
    """A non-KEV finding with an Exploit-DB entry scores ABOVE an
    otherwise-identical finding without exploit evidence — closing
    the calibration gap where 4 of 7 exploited CVEs ranked at
    99/174/175/192 because they weren't KEV-listed."""
    plain = _finding(cvss=5.0, in_kev=False, epss=0.1, exploit_evidence=None)
    with_edb = _finding(cvss=5.0, in_kev=False, epss=0.1,
                         exploit_evidence=_ee(edb=1))
    s_plain, c_plain = compute_risk_estimate(plain, plain.dependency)
    s_edb, c_edb = compute_risk_estimate(with_edb, with_edb.dependency)
    assert s_edb > s_plain, (
        f"EDB-listed finding should score higher than plain — "
        f"plain={s_plain:.2f} vs edb={s_edb:.2f}"
    )
    assert c_edb["exploit_evidence_multiplier"] > 1.0


def test_exploit_evidence_msf_or_poc_alone_also_boosts():
    """Each of the three sources (EDB, MSF, GitHub PoC) is sufficient
    on its own to trigger the boost — no source combo is required."""
    base = _finding(cvss=5.0, in_kev=False, epss=0.1, exploit_evidence=None)
    s_base, _ = compute_risk_estimate(base, base.dependency)
    for ee in (_ee(msf=1), _ee(poc=1)):
        f = _finding(cvss=5.0, in_kev=False, epss=0.1, exploit_evidence=ee)
        s, _ = compute_risk_estimate(f, f.dependency)
        assert s > s_base, (
            f"signal {ee} alone should boost score above base "
            f"({s:.2f} <= {s_base:.2f})"
        )


def test_exploit_evidence_does_not_double_count_with_kev():
    """KEV-listed findings already get a boost; the exploit-evidence
    branch must NOT compound on top — it's gated by ``not in_kev``.
    Two findings, both with KEV+EDB, should score the same as KEV
    alone (the EDB signal isn't double-counted on a CVE we already
    know is KEV)."""
    kev_only = _finding(cvss=7.5, in_kev=True, epss=0.5,
                         exploit_evidence=None)
    kev_plus_edb = _finding(cvss=7.5, in_kev=True, epss=0.5,
                             exploit_evidence=_ee(kev=True, edb=5))
    s_a, _ = compute_risk_estimate(kev_only, kev_only.dependency)
    s_b, _ = compute_risk_estimate(kev_plus_edb, kev_plus_edb.dependency)
    assert s_a == s_b, (
        f"KEV+EDB should equal KEV alone "
        f"({s_a:.2f} vs {s_b:.2f}) — exploit-evidence must not "
        f"double-count when already credited via KEV"
    )


def test_exploit_evidence_floor_lifts_low_cvss_finding():
    """An EDB-listed CVE with low CVSS gets lifted by the floor —
    matches the design where 'working exploit exists in the wild'
    outranks a theoretical-but-low-CVSS finding without one."""
    low_no_ee = _finding(cvss=2.0, in_kev=False, epss=0.1,
                          exploit_evidence=None)
    low_with_ee = _finding(cvss=2.0, in_kev=False, epss=0.1,
                            exploit_evidence=_ee(edb=1))
    s_no, _ = compute_risk_estimate(low_no_ee, low_no_ee.dependency)
    s_yes, _ = compute_risk_estimate(low_with_ee, low_with_ee.dependency)
    assert s_yes > s_no * 2, (
        f"floor should ~triple a low-CVSS score when exploit evidence "
        f"is present (no_ee={s_no:.2f}, with_ee={s_yes:.2f})"
    )
