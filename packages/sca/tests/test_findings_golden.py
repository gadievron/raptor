"""Byte-level golden pins for findings.json and its derived emitters.

``findings.json`` is the canonical schema — every other emitter
re-derives from it (see the package README) and downstream consumers
(thresholds gate, diff, update planner, external CI) parse it
structurally. These tests serialise a representative row set — one row
per finding kind, fields fully populated — and compare the EXACT bytes
against committed golden fixtures, so a refactor of the row builders or
the read side cannot silently change the on-disk contract:

  * ``findings.json``       — the canonical row list
  * ``findings.sarif``      — SARIF 2.1.0 projection
  * ``report.md``           — markdown report (render path)
  * ``diff-delta.json`` / ``diff-report.md`` / ``pr-comment.md``
                            — cross-run delta projections
  * ``thresholds.txt``      — CI-gate failure messages

A failing golden means one of two things: the change accidentally
altered the output (fix the change), or the schema deliberately moved —
in which case regenerate the fixtures IN THE SAME COMMIT and call the
schema change out in the commit message:

    RAPTOR_SCA_REGEN_GOLDEN=1 pytest packages/sca/tests/test_findings_golden.py
"""

from __future__ import annotations

import copy
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast


from core.cve import EpssClient, KevClient

from packages.sca.diff import (
    compute_delta,
    render_pr_comment,
)
from packages.sca.diff import _render_markdown as _render_diff_markdown
from packages.sca.findings import build_vuln_findings, write_findings_json
from packages.sca.models import (
    Advisory,
    AffectedRange,
    Confidence,
    CVSSScore,
    Dependency,
    ExploitEvidence,
    HygieneFinding,
    LicenseFinding,
    PinStyle,
    Reachability,
    SupplyChainFinding,
)
from packages.sca.osv import OsvResult
from packages.sca.render import _render_markdown as _render_report_markdown
from packages.sca.sarif import build_sarif
from packages.sca.thresholds import ThresholdConfig, evaluate

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "golden"

# Fixed timestamps so every golden byte is reproducible.
_PUBLISHED = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
_MODIFIED = datetime(2024, 2, 1, 8, 30, 0, tzinfo=timezone.utc)
_GENERATED = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Fixture builders — deterministic, fully-populated rows
# ---------------------------------------------------------------------------

def _dep(
    *,
    ecosystem: str,
    name: str,
    version: str | None,
    declared_in: str,
    pin_style: PinStyle = PinStyle.EXACT,
    direct: bool = True,
    alias_name: str | None = None,
    commented_out: bool = False,
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path(declared_in),
        scope="main",
        is_lockfile=False,
        pin_style=pin_style,
        direct=direct,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version or ''}",
        parser_confidence=Confidence("high", reason="exact manifest pin"),
        alias_name=alias_name,
        commented_out=commented_out,
    )


def _advisory(
    *,
    osv_id: str,
    aliases: list[str],
    summary: str,
    fixed: list[str],
    score: float,
    severity: str,
    cwe_ids: list[str] | None = None,
) -> Advisory:
    return Advisory(
        osv_id=osv_id,
        aliases=aliases,
        summary=summary,
        details="Full advisory details (markdown).",
        affected=[AffectedRange(
            type="ECOSYSTEM",
            events=[{"introduced": "0"}, {"fixed": fixed[0]}],
        )],
        severity=CVSSScore(
            score=score,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity=severity,  # type: ignore[arg-type]
        ),
        fixed_versions=list(fixed),
        references=["https://example.invalid/advisory"],
        published=_PUBLISHED,
        modified=_MODIFIED,
        cwe_ids=list(cwe_ids or []),
    )


class _FixedKev:
    def __init__(self, hits: set[str]) -> None:
        self._hits = {h.upper() for h in hits}

    def contains(self, cve: str) -> bool:
        return cve.upper() in self._hits


class _FixedEpss:
    def __init__(self, scores: dict[str, float]) -> None:
        self._scores = {k.upper(): v for k, v in scores.items()}

    def scores(self, cves: list[str]) -> dict[str, float]:
        return {c: self._scores[c.upper()] for c in cves
                if c.upper() in self._scores}


def _build_rows(tmp_path: Path) -> tuple[Path, list[dict[str, Any]]]:
    """One row per finding kind, every field populated, all deterministic."""
    dep_lodash = _dep(
        ecosystem="npm", name="lodash", version="4.17.20",
        declared_in="/repo/package.json", alias_name="my-lodash",
    )
    dep_requests = _dep(
        ecosystem="PyPI", name="requests", version="2.19.0",
        declared_in="/repo/requirements.txt",
    )

    # Alias pair (GHSA + PYSEC sharing one CVE) so the golden pins the
    # merged-group shape: representative-first advisory list, alias
    # union, group-max severity.
    adv_ghsa = _advisory(
        osv_id="GHSA-aaaa-bbbb-cccc",
        aliases=["CVE-2021-23337"],
        summary="Command injection in template",
        fixed=["4.17.21"], score=9.8, severity="critical",
        cwe_ids=["CWE-94"],
    )
    adv_alias = _advisory(
        osv_id="PYSEC-2021-0001",
        aliases=["CVE-2021-23337"],
        summary="Duplicate record for the same CVE",
        fixed=["4.17.21"], score=7.2, severity="high",
    )
    adv_requests = _advisory(
        osv_id="GHSA-dddd-eeee-ffff",
        aliases=["CVE-2018-18074"],
        summary="Credentials leak on redirect",
        fixed=["2.20.0"], score=5.0, severity="medium",
    )

    reachability = {
        dep_lodash.key(): Reachability(
            verdict="likely_called",
            confidence=Confidence("high", reason="call site found"),
            evidence=["src/app.js:42"],
        ),
        # dep_requests deliberately absent → default not_evaluated.
    }

    # Pin the calibration-status axis. risk_components carries
    # calibration_status, which compute_risk_estimate reads from the
    # newest in-tree data/calibration/validation/<date>.json and then
    # caches per process — an environment-coupled input on two axes:
    # the weekly calibration refresh commits a new verdict (breaking
    # any golden that embedded the old one), and under pytest-xdist
    # the per-process cache can carry whatever an earlier test in the
    # same worker loaded. Pin the loader to the documented cold-start
    # value and flush the cache on BOTH sides so the goldens neither
    # inherit worker state nor leak any.
    from packages.sca import risk
    risk._reset_calibration_cache_for_tests()
    real_loader = risk._load_latest_validation_verdict
    risk._load_latest_validation_verdict = lambda: "unverified"
    try:
        vulns = build_vuln_findings(
            deps=[dep_lodash, dep_requests],
            osv_results=[
                OsvResult(dep_key=dep_lodash.key(),
                          advisories=[adv_ghsa, adv_alias]),
                OsvResult(dep_key=dep_requests.key(),
                          advisories=[adv_requests]),
            ],
            kev=cast("KevClient", _FixedKev({"CVE-2021-23337"})),
            epss=cast("EpssClient", _FixedEpss({"CVE-2021-23337": 0.97,
                                                "CVE-2018-18074": 0.12})),
            reachability=reachability,
        )
    finally:
        risk._load_latest_validation_verdict = real_loader
        risk._reset_calibration_cache_for_tests()
    assert len(vulns) == 2
    by_name = {f.dependency.name: f for f in vulns}
    by_name["lodash"].exploit_evidence = ExploitEvidence(
        kev_listed=True,
        edb_ids=[50001],
        msf_modules=["exploit/multi/http/lodash_template"],
        github_poc_urls=["https://example.invalid/poc"],
    )
    by_name["requests"].suppressed = True
    by_name["requests"].suppression_reason = "accepted: internal-only service"

    hygiene = [HygieneFinding(
        finding_id="sca:hygiene:loose_pin:npm:express",
        kind="loose_pin",
        dependency=_dep(
            ecosystem="npm", name="express", version="4.0.0",
            declared_in="/repo/package.json", pin_style=PinStyle.CARET,
        ),
        detail="express uses a caret range; patch releases land silently",
        severity="low",
        confidence=Confidence("high", reason="manifest says ^4.0.0"),
    )]

    supply = [
        SupplyChainFinding(
            finding_id="sca:supplychain:typosquat_candidate:PyPI:reqeusts",
            kind="typosquat_candidate",
            dependency=_dep(
                ecosystem="PyPI", name="reqeusts", version="1.0.0",
                declared_in="/repo/requirements.txt",
            ),
            detail="reqeusts is 1 edit from requests (top-1k package)",
            evidence={"target": "requests", "edit_distance": 1},
            severity="high",
            confidence=Confidence("medium", reason="edit-distance heuristic"),
        ),
        SupplyChainFinding(
            finding_id="sca:supplychain:image_capability_drift:sha256-abc",
            kind="image_capability_drift",
            dependency=_dep(
                ecosystem="OCI", name="alpine", version="3.19",
                declared_in="/repo/Dockerfile",
            ),
            detail="rebuilt image gained network capability",
            evidence={"added_buckets": ["network"], "removed_buckets": []},
            severity="medium",
            confidence=Confidence("high", reason="capability diff"),
        ),
    ]

    licenses = [LicenseFinding(
        finding_id="sca:license_denied:npm:left-pad@1.3.0",
        kind="license_denied",
        dependency=_dep(
            ecosystem="npm", name="left-pad", version="1.3.0",
            declared_in="/repo/package.json",
        ),
        spdx="AGPL-3.0-only",
        detail="left-pad is AGPL-3.0-only; policy denies AGPL",
        severity="high",
        confidence=Confidence("high", reason="registry-declared license"),
    )]

    scan_health = [{
        "kind": "osv_lookup_failed",
        "detail": "OSV lookups failed transiently for 1 ecosystem",
        "evidence": {"failed_ecosystems": ["Cargo"]},
    }]

    out = tmp_path / "findings.json"
    n = write_findings_json(
        out,
        vuln_findings=vulns,
        hygiene_findings=hygiene,
        supply_chain_findings=supply,
        license_findings=licenses,
        scan_health=scan_health,
    )
    assert n == 7
    rows = json.loads(out.read_text(encoding="utf-8"))
    return out, rows


# ---------------------------------------------------------------------------
# Golden comparison plumbing
# ---------------------------------------------------------------------------

def _check_golden(name: str, actual: str) -> None:
    """Compare ``actual`` byte-for-byte against the committed golden.

    ``RAPTOR_SCA_REGEN_GOLDEN=1`` rewrites the fixture instead —
    a deliberate act for intentional schema moves only.
    """
    golden = GOLDEN_DIR / name
    if os.environ.get("RAPTOR_SCA_REGEN_GOLDEN") == "1":
        # Regeneration is a deliberate local act; under CI it would
        # silently compare each golden against the bytes just written
        # and mask any drift — refuse loudly instead.
        assert not os.environ.get("CI"), (
            "RAPTOR_SCA_REGEN_GOLDEN=1 must never be set in CI — it "
            "would rewrite the fixtures and vacuously pass"
        )
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(actual, encoding="utf-8")
        # Fall through to the comparison (now trivially green) so a
        # regen run still exercises every golden in the test.
    assert golden.exists(), (
        f"missing golden fixture {golden}; generate with "
        "RAPTOR_SCA_REGEN_GOLDEN=1"
    )
    expected = golden.read_text(encoding="utf-8")
    assert actual == expected, (
        f"{name} drifted from the golden fixture. If the schema change "
        "is intentional, regenerate with RAPTOR_SCA_REGEN_GOLDEN=1 and "
        "commit the fixture update alongside the change."
    )


# ---------------------------------------------------------------------------
# The pins
# ---------------------------------------------------------------------------

def test_findings_json_golden(tmp_path: Path) -> None:
    out, _rows = _build_rows(tmp_path)
    _check_golden("findings.json", out.read_text(encoding="utf-8"))


def test_sarif_golden(tmp_path: Path) -> None:
    _out, rows = _build_rows(tmp_path)
    doc = build_sarif(target=Path("/repo"), rows=rows,
                      generated_at=_GENERATED)
    _check_golden(
        "findings.sarif",
        json.dumps(doc, indent=2, sort_keys=False) + "\n",
    )


def test_report_markdown_golden(tmp_path: Path) -> None:
    _out, rows = _build_rows(tmp_path)
    # Row-only regeneration has no captured execution timestamp; it must
    # report that absence rather than invent a fresh scan date.
    md = _render_report_markdown(rows, target=Path("/repo"))
    _check_golden("report.md", md)


def _delta_rows(rows: list[dict[str, Any]]) -> tuple[
    list[dict[str, Any]], list[dict[str, Any]],
]:
    """Mutate a copy of the golden rows into a "current run" so every
    delta bucket (new / resolved / suppression_added / persistent) is
    populated."""
    rows_a = copy.deepcopy(rows)
    rows_b = copy.deepcopy(rows)
    # Resolved: license finding present in A only.
    rows_b = [r for r in rows_b
              if not str(r.get("vuln_type", "")).startswith("sca:license:")]
    # Suppression added: typosquat row becomes suppressed in B.
    # Suppression lifted: the suppressed requests vuln is unsuppressed.
    for r in rows_b:
        if r.get("vuln_type") == "sca:supply_chain:typosquat_candidate":
            r["suppressed"] = True
            r["suppression_reason"] = "vendored fork, reviewed"
        if r.get("suppressed") and (
            r.get("vuln_type") == "sca:vulnerable_dependency"
        ):
            r["suppressed"] = False
            r["suppression_reason"] = None
    # New: a fresh vuln row in B only.
    new_row = copy.deepcopy(
        next(r for r in rows_b
             if r.get("vuln_type") == "sca:vulnerable_dependency"
             and not r.get("suppressed")),
    )
    new_row["id"] = new_row["finding_id"] = (
        "sca:vuln:npm:minimist:1.2.0:GHSA-gggg-hhhh-iiii"
    )
    new_row["sca"]["name"] = "minimist"
    new_row["sca"]["advisory"]["id"] = "GHSA-gggg-hhhh-iiii"
    new_row["sca"]["advisory"]["aliases"] = ["CVE-2020-7598"]
    rows_b.append(new_row)
    return rows_a, rows_b


def test_diff_goldens(tmp_path: Path) -> None:
    _out, rows = _build_rows(tmp_path)
    rows_a, rows_b = _delta_rows(rows)
    delta = compute_delta(rows_a, rows_b)

    from core.json import dumps_artifact

    from packages.sca.diff import _delta_to_dict
    _check_golden("diff-delta.json", dumps_artifact(_delta_to_dict(delta)))
    _check_golden(
        "diff-report.md",
        _render_diff_markdown("baseline.json", "current.json", delta,
                              show_persistent=True),
    )
    _check_golden("pr-comment.md", render_pr_comment(delta))


def test_thresholds_golden(tmp_path: Path) -> None:
    _out, rows = _build_rows(tmp_path)
    cfg = ThresholdConfig(
        fail_on_severity="low",
        fail_on_kev=True,
        fail_on_supply_chain="low",
        fail_on_hygiene="low",
        fail_on_license="low",
        fail_on_capability_drift=True,
        max_added_capability_buckets=0,
    )
    passed, fails = evaluate(rows, cfg)
    assert passed is False
    _check_golden("thresholds.txt", "\n".join(fails) + "\n")
