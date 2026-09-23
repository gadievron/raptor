"""Closure over the findings-kind universe.

``write_findings_json`` is the single writer: five row builders, one
``vuln_type`` family each. Both read-side consumers — the diff layer's
``_canonical_key`` and the thresholds branch ladder — hand-enumerate
that universe, and the mechanism has already fired three times (a
whole family fell through to "no key / no gate branch" silently:
license rows, then scan_health keys, then the license gate branch).
This test derives one representative row per family FROM THE WRITER
and asserts each maps to a non-None canonical key AND to a thresholds
branch — or sits in the explicit, justified exclusion set — so the
fourth member of the class fails CI instead of waiting for the next
audit.
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca import diff as diff_mod
from packages.sca.findings import build_vuln_findings, write_findings_json
from packages.sca.kinds import SCAN_HEALTH_PREFIX
from packages.sca.models import (
    Advisory,
    AffectedRange,
    Confidence,
    CVSSScore,
    Dependency,
    HygieneFinding,
    LicenseFinding,
    PinStyle,
    SupplyChainFinding,
)
from packages.sca.osv import OsvResult
from packages.sca.rows import FindingRow
from packages.sca.thresholds import ThresholdConfig, evaluate

# Families deliberately OUTSIDE the thresholds ladder. Each entry
# needs the documented rationale next to it — an addition here is an
# operator-visible design decision, not a fall-through.
_THRESHOLD_EXCLUDED_PREFIXES: dict[str, str] = {
    SCAN_HEALTH_PREFIX: (
        "scan_health rows record scan-level degradation at info "
        "severity; the writer documents they never trip --fail-on-* "
        "gates (pipelines gate on the row explicitly instead)"
    ),
}


def _dep() -> Dependency:
    return Dependency(
        ecosystem="npm", name="lodash", version="4.17.20",
        declared_in=Path("/repo/package.json"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:npm/lodash@4.17.20",
        parser_confidence=Confidence("high", reason="t"),
    )


def _adv() -> Advisory:
    return Advisory(
        osv_id="GHSA-x", aliases=["CVE-2099-9999"], summary="s",
        details="d",
        affected=[AffectedRange(
            type="ECOSYSTEM",
            events=[{"introduced": "0"}, {"fixed": "5.0.0"}],
        )],
        severity=CVSSScore(
            score=9.8,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="critical",        # type: ignore[arg-type]
        ),
        fixed_versions=["5.0.0"],
        references=[],
    )


def _writer_rows(tmp_path: Path) -> list[dict]:
    """One representative row per writer row-builder — the universe
    comes from ``write_findings_json`` itself, so a new builder joins
    this closure automatically the moment a representative is added
    (and the count assertion below flags the moment one is needed)."""
    d = _dep()
    out = tmp_path / "findings.json"
    write_findings_json(
        out,
        vuln_findings=build_vuln_findings(
            [d], [OsvResult(dep_key=d.key(), advisories=[_adv()])],
        ),
        hygiene_findings=[HygieneFinding(
            finding_id="sca:hygiene:loose_pin:npm:lodash:/x",
            kind="loose_pin", dependency=d, detail="t",
            severity="high", confidence=Confidence("high", reason="t"),
        )],
        supply_chain_findings=[SupplyChainFinding(
            finding_id="sca:supply_chain:recent_publish:npm:lodash",
            kind="recent_publish", dependency=d, detail="t",
            evidence={}, severity="high",
            confidence=Confidence("high", reason="t"),
        )],
        license_findings=[LicenseFinding(
            finding_id="sca:license:license_denied:npm:lodash",
            kind="license_denied", dependency=d, spdx="AGPL-3.0",
            detail="t", severity="high",
            confidence=Confidence("high", reason="t"),
        )],
        scan_health=[{"kind": "osv_lookup_degraded", "detail": "t"}],
    )
    return json.loads(out.read_text(encoding="utf-8"))


def test_every_writer_kind_has_a_canonical_key(tmp_path: Path) -> None:
    rows = _writer_rows(tmp_path)
    assert len(rows) == 5, (
        "writer row-builder count changed — add a representative "
        "above so the new family joins the closure"
    )
    for row in rows:
        fr = FindingRow.from_row(row)
        assert fr is not None
        key = diff_mod._canonical_key(fr)
        assert key is not None, (
            f"{row['vuln_type']}: no canonical key — the family is "
            f"invisible to every diff bucket (new/resolved/persistent)"
        )


def test_every_writer_kind_reaches_a_thresholds_branch(
    tmp_path: Path,
) -> None:
    cfg = ThresholdConfig(
        fail_on_severity="info",
        fail_on_supply_chain="info",
        fail_on_hygiene="info",
        fail_on_license="info",
    )
    for row in _writer_rows(tmp_path):
        vuln_type = row["vuln_type"]
        excluded = next(
            (why for prefix, why in _THRESHOLD_EXCLUDED_PREFIXES.items()
             if vuln_type.startswith(prefix)),
            None,
        )
        passed, fails = evaluate([row], cfg)
        if excluded is not None:
            assert passed, (
                f"{vuln_type} is documented as gate-excluded "
                f"({excluded}) but tripped a branch"
            )
        else:
            assert not passed, (
                f"{vuln_type}: no thresholds branch fired with every "
                f"floor at 'info' — the family can never fail a build"
            )
