"""Bounded findings projection and SBOM-coordinate matching for upgrade plans."""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path

from core.json.projection import project_array
from core.source.gated import open_regular_gated
from ..kinds import MAX_FINDINGS_BYTES
from ..rows import FindingRow
from ..sbom_import import _component_to_dep


@dataclass
class PackagePlan:
    occurrences: list[str]
    name: str
    installed_version: str
    purl: str
    ecosystem: str | None = None
    query: dict | None = None
    target_scope: str = "package_release"
    status: str = "no_reported_vulnerabilities"
    advisories: list[dict] = field(default_factory=list)
    suppressed_findings: int = 0
    proposed_version: str | None = None
    candidates: list[dict] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


def _advisory(row):
    if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
        raise ValueError("vulnerability finding has an invalid advisory identity")
    for key in ("aliases", "fixed_versions"):
        values = row.get(key, [])
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ValueError("vulnerability finding has invalid advisory metadata")
    return {key: row.get(key, []) if key != "id" else row[key] for key in ("id", "aliases", "fixed_versions")}


def _finding(raw):
    row = FindingRow.from_row(raw)
    if row is None:
        raise ValueError("findings must contain object rows")
    if row.is_scan_health:
        return {"kind": "scan_gap", "id": row.finding_id, "reason": (row.description or row.title)[:2000]}
    if not row.is_vulnerable_dependency:
        return None
    if "suppressed" in raw and type(raw["suppressed"]) is not bool:
        raise ValueError("finding suppression status must be a boolean")
    sca = row.sca
    advisories = sca.get("all_advisories") or [row.advisory]
    if not isinstance(advisories, list) or len(advisories) > 1000:
        raise ValueError("invalid vulnerability advisory group")
    result = {key: sca.get(key) for key in ("ecosystem", "name", "version", "purl", "fixed_version", "advisory_package", "advisory_match_scope")}
    result.update(kind="vulnerability", finding_id=row.finding_id, suppressed=row.suppressed,
                  advisories=[_advisory(value) for value in advisories])
    return result


def read_findings(path):
    """Retain coordinates and advisory/fix metadata, not descriptions or source text."""
    retained = 0
    def compact(raw):
        nonlocal retained
        value = _finding(raw)
        retained += value is not None
        if retained > 100_000:
            raise ValueError("upgrade-plan findings exceed the record budget")
        return value
    with open_regular_gated(path) as stream:
        if os.fstat(stream.fileno()).st_size > MAX_FINDINGS_BYTES:
            raise ValueError("findings exceed the operator-input byte budget")
        rows, digest = project_array(stream, max_bytes=MAX_FINDINGS_BYTES, project=compact, max_depth=64)
    if len(rows) > 100_000:
        raise ValueError("upgrade-plan findings exceed the record budget")
    return rows, digest


def inventory_plans(inventory):
    plans, dependencies, groups = [], {}, {}
    for record in inventory.records:
        if record.scope != "packages":
            continue
        dep = _component_to_dep({"name": record.name, "version": record.version, "purl": record.purl},
                                sbom_path=Path("<sbom-plan>"))
        key = (record.purl, dep.ecosystem if dep else None, dep.name if dep else record.name,
               dep.version if dep else record.version)
        if key in groups:
            plans[groups[key]].occurrences.append(record.id)
            continue
        index = len(plans)
        groups[key] = index
        plan = PackagePlan([record.id], dep.name if dep else record.name,
                           dep.version or "" if dep else record.version, record.purl,
                           ecosystem=dep.ecosystem if dep else None)
        if dep is None or not dep.version:
            plan.status = "inventory_coordinates_unavailable"
            plan.gaps.append("supported package URL and resolved version required for advisory comparison")
        else:
            dependencies[index] = dep
        plans.append(plan)
    return plans, dependencies


def match_findings(plans, dependencies, findings):
    from collections import defaultdict
    purls, coordinates = defaultdict(list), defaultdict(list)
    for index, dep in dependencies.items():
        purls[plans[index].purl].append(index)
        coordinates[(dep.ecosystem, dep.name, dep.version)].append(index)
    matched, unmatched, gaps = defaultdict(list), [], []
    for row in findings:
        if row["kind"] == "scan_gap":
            gaps.append(row)
            continue
        key = tuple(row.get(field) for field in ("ecosystem", "name", "version"))
        if not all(isinstance(value, str) and value for value in key):
            matches = []
        elif row.get("purl"):
            matches = [index for index in purls.get(row["purl"], [])
                       if (dependencies[index].ecosystem, dependencies[index].name, dependencies[index].version) == key]
        else:
            matches = coordinates.get(key, [])
        if len(matches) != 1:
            unmatched.append({"finding_id": row["finding_id"], "coordinates": list(key),
                              "reason": "no unique matching SBOM package identity"})
        else:
            matched[matches[0]].append(row)
    return matched, unmatched, gaps
