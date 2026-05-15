"""Convert ``DropOnBumpFinding`` records into the wider
``SupplyChainFinding`` shape so the existing report / SARIF /
SBOM / PR-comment renderers pick them up automatically."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from packages.sca.models import (
    Confidence, Dependency, PinStyle, SupplyChainFinding,
)
from packages.sca.transitive_drop.detector import DropOnBumpFinding


def to_supply_chain_findings(
    drops: Iterable[DropOnBumpFinding],
) -> List[SupplyChainFinding]:
    """One ``SupplyChainFinding`` per droppable transitive.

    Severity matches the underlying issue's severity: an HIGH/
    CRITICAL vuln on the transitive yields an HIGH finding (this
    IS a real remediation path), while LOW/INFO yields INFO.
    """
    out: List[SupplyChainFinding] = []
    for d in drops:
        out.append(_make_finding(d))
    return out


def _make_finding(d: DropOnBumpFinding) -> SupplyChainFinding:
    # Synthetic dep coordinate for the transitive being dropped.
    placeholder_dep = Dependency(
        ecosystem="PyPI",
        name=d.transitive_name,
        version=d.transitive_version,
        declared_in=Path("/<transitive_drop>"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=False,
        purl=f"pkg:pypi/{d.transitive_name}@{d.transitive_version}",
        parser_confidence=Confidence(
            "high", reason="transitive_drop detector",
        ),
    )

    # Severity escalation: an underlying critical/high vuln on the
    # transitive means the bump is a real fix path, not just
    # hygiene. Otherwise informational.
    sev_in = d.transitive_finding_severity
    if sev_in in ("critical", "high"):
        severity = "high"
    elif sev_in == "medium":
        severity = "medium"
    else:
        severity = "info"

    if d.transitive_status_in_latest == "extras-gated":
        suffix = (
            f" (now optional behind extra "
            f"``[{d.extra_name}]`` — operator must opt in to "
            f"install it)"
        )
    else:
        suffix = " (no longer required at all)"
    detail = (
        f"{d.transitive_name}=={d.transitive_version} is required by "
        f"{d.parent_name}=={d.parent_current_version} but moved out "
        f"of the unconditional dep set in "
        f"{d.parent_name}=={d.parent_latest_version}{suffix}. "
        f"Bumping {d.parent_name} drops {d.transitive_name} from "
        f"the install set — resolves the underlying "
        f"{sev_in}-severity finding without an upstream patch."
    )

    return SupplyChainFinding(
        finding_id=(
            f"sca:supply_chain:transitive_now_optional:PyPI:"
            f"{d.transitive_name}:{d.parent_name}"
        ),
        kind="transitive_now_optional",
        dependency=placeholder_dep,
        detail=detail,
        evidence={
            "transitive_name": d.transitive_name,
            "transitive_version": d.transitive_version,
            "parent_name": d.parent_name,
            "parent_current_version": d.parent_current_version,
            "parent_latest_version": d.parent_latest_version,
            "transitive_status_in_latest":
                d.transitive_status_in_latest,
            "extra_name": d.extra_name,
            "underlying_severity": d.transitive_finding_severity,
        },
        severity=severity,
        confidence=Confidence(
            "high",
            reason="PyPI requires_dist diff across parent versions",
        ),
    )
