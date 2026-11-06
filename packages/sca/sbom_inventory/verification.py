"""Verify observed package targets and advisory outcomes against a saved plan."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, fields, replace

from ..diff import compute_delta
from ..distro import advisory_dependency, has_source_coordinates
from ..findings import _is_parseable_version
from ..kinds import VULNERABLE_DEPENDENCY
from ..versions import compare, VersionError
from .advisory_coverage import query_key
from .model import Record
from .plan_inputs import PackagePlan, inventory_plans, match_findings
from .source import Source, SHA256


@dataclass
class Verification:
    sources: dict
    status: str
    summary: dict
    packages: list
    ambiguous_groups: list
    advisories: dict
    coverage: dict
    unmatched_findings: list
    limitations: list
    exit_code: int
    format: str = "raptor-sbom-plan-verification"
    schema_version: int = 1


def _plan_package(raw):
    if not isinstance(raw, dict):
        raise ValueError("invalid upgrade-plan package")
    # Candidate matrices are unnecessary for observing a recorded proposal.
    allowed = {item.name for item in fields(PackagePlan)} - {"candidates"}
    return {key: value for key, value in raw.items() if key in allowed}


def read_plan(path):
    with Source(path) as source:
        data, digest = source.read_json(projectors={"packages": _plan_package})
    if (data.get("format") != "raptor-sbom-upgrade-plan" or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1):
        raise ValueError("unsupported upgrade-plan format")
    sources = data.get("sources")
    if not isinstance(sources, dict) or any(not isinstance(sources.get(key), str) or not SHA256.fullmatch(sources[key])
                                          for key in ("sbom_sha256", "findings_sha256")):
        raise ValueError("invalid upgrade-plan source fingerprints")
    raw = data.get("packages")
    if not isinstance(raw, list) or len(raw) > 100_000:
        raise ValueError("invalid upgrade-plan package inventory")
    packages, occurrences = [], set()
    for value in raw:
        package = PackagePlan(**value)
        if (not all(isinstance(getattr(package, key), str) for key in ("name", "installed_version", "purl", "status"))
                or not package.name or not isinstance(package.occurrences, list) or not package.occurrences
                or any(not isinstance(ref, str) or not ref for ref in package.occurrences)
                or len(set(package.occurrences)) != len(package.occurrences)
                or occurrences.intersection(package.occurrences)
                or package.ecosystem is not None and not isinstance(package.ecosystem, str)
                or package.proposed_version is not None and (not isinstance(package.proposed_version, str) or not package.proposed_version)
                or package.target_scope not in {"package_release", "source_package"}):
            raise ValueError("invalid or duplicate upgrade-plan package identity")
        if package.query is not None and (not isinstance(package.query, dict) or any(
                not isinstance(package.query.get(key), str) or not package.query[key] for key in ("ecosystem", "name", "version"))):
            raise ValueError("invalid upgrade-plan query coordinates")
        if not isinstance(package.advisories, list) or len(package.advisories) > 100_000:
            raise ValueError("invalid upgrade-plan advisories")
        for advisory in package.advisories:
            if (not isinstance(advisory, dict) or not isinstance(advisory.get("id"), str) or not advisory["id"]
                    or not isinstance(advisory.get("aliases", []), list)
                    or any(not isinstance(alias, str) for alias in advisory.get("aliases", []))
                    or type(advisory.get("suppressed")) is not bool):
                raise ValueError("invalid upgrade-plan advisory")
        occurrences.update(package.occurrences)
        packages.append(package)
    gaps = data.get("scan_gaps", [])
    if not isinstance(gaps, list) or any(not isinstance(row, dict) for row in gaps):
        raise ValueError("invalid upgrade-plan coverage gaps")
    unmatched = data.get("unmatched_findings", [])
    if not isinstance(unmatched, list) or any(not isinstance(row, dict) or not isinstance(row.get("reason"), str) for row in unmatched):
        raise ValueError("invalid upgrade-plan unmatched findings")
    data["packages"] = packages
    return data, digest


def _identity(package):
    return Record("identity", package.name, package.installed_version, "library", purl=package.purl).identity


def _rows(package, advisories):
    for advisory in advisories:
        yield {"vuln_type": VULNERABLE_DEPENDENCY, "finding_id": advisory["id"],
               "suppressed": advisory["suppressed"], "severity": "info",
               "sca": {"ecosystem": package.ecosystem or "", "name": package.name,
                       "advisory": {"id": advisory["id"].upper(),
                                    "aliases": sorted(alias.upper() for alias in advisory.get("aliases", []))}}}


def _event(row, reason=""):
    advisory = row["sca"]["advisory"]
    return {"ecosystem": row["sca"]["ecosystem"], "name": row["sca"]["name"], "id": advisory["id"],
            "aliases": advisory["aliases"], "suppressed": row["suppressed"], "reason": reason}


def _query_coverage(index, package, dep):
    if dep is None:
        return "supported package URL and resolved version required"
    if dep.ecosystem.split(":", 1)[0] in {"Debian", "Ubuntu", "Alpine"} and not has_source_coordinates(dep.purl):
        return "explicit distro source coordinates are required; a binary version is not source-fix evidence"
    row = index.get(query_key(dict(ecosystem=dep.ecosystem, name=dep.name, version=dep.version, purl=dep.purl or "")))
    if row is None:
        return "no matching positive advisory-query receipt"
    if row["status"] != "checked":
        return row["reason"] or "advisory query unavailable"
    try:
        query = advisory_dependency(dep)
    except ValueError as error:
        return str(error)
    if any((row.get("query") or {}).get(key) != value for key, value in
           dict(ecosystem=query.ecosystem, name=query.name, version=query.version).items()):
        return "coverage receipt query coordinates differ from the current package"
    return None


def _target(before, current, dependencies, *, ambiguous):
    observed, values, notes = [], [], []
    # Ambiguous groups are described once at report level. Expanding their
    # complete current inventory for every baseline version is quadratic.
    examine = [] if ambiguous else current
    for index, package in examine:
        dep = dependencies.get(index)
        query = None
        if dep is not None:
            try:
                query_dep = advisory_dependency(dep)
                query = dict(ecosystem=query_dep.ecosystem, name=query_dep.name, version=query_dep.version)
            except ValueError as error:
                notes.append(str(error))
        observed.append({"occurrences": package.occurrences, "version": package.installed_version, "query": query})
        if before.target_scope == "source_package":
            expected = before.query or {}
            if dep is not None and not has_source_coordinates(dep.purl):
                notes.append("explicit source coordinates are missing; binary versions cannot verify source targets")
            if query is None or any(query.get(key) != expected.get(key) for key in ("ecosystem", "name")):
                notes.append("source/release query identity is unavailable or changed")
            else:
                values.append(query["version"])
        elif dep is None or dep.ecosystem != before.ecosystem:
            notes.append("package advisory ecosystem is unavailable or changed")
        else:
            values.append(package.installed_version)
    proposed = before.proposed_version
    status = "not_planned" if not proposed else "target_not_met"
    if not current:
        status = "not_observed"
    elif ambiguous:
        status = "ambiguous" if proposed else "not_planned"
        notes.append("multiple baseline versions cannot be uniquely associated; see ambiguous_groups for observed versions")
    elif proposed:
        ecosystem = (before.query or {}).get("ecosystem") if before.target_scope == "source_package" else before.ecosystem
        if notes or not ecosystem or not _is_parseable_version(ecosystem, proposed) or any(
                not _is_parseable_version(ecosystem, value) for value in values):
            status = "unavailable"
            notes.append("planned/observed versions cannot be compared with confidence")
        else:
            try:
                comparisons = [compare(ecosystem, value, proposed) for value in values]
                status = "target_met" if all(value >= 0 for value in comparisons) else "partially_met" if any(
                    value >= 0 for value in comparisons) else "target_not_met"
            except VersionError as error:
                status = "unavailable"
                notes.append(str(error))
    return {"name": before.name, "baseline_occurrences": before.occurrences, "installed_version": before.installed_version,
            "proposed_version": proposed, "target_scope": before.target_scope, "current": observed,
            "status": status, "notes": notes}


def verify_plan(plan, plan_sha, inventory, findings, findings_sha, *, coverage, coverage_sha=None, coverage_errors=()):
    baseline_unmatched = plan.get("unmatched_findings", [])
    current, dependencies = inventory_plans(inventory)
    matched, unmatched, health = match_findings(current, dependencies, findings)
    old_groups, new_groups = defaultdict(list), defaultdict(list)
    for package in plan["packages"]:
        old_groups[_identity(package)].append(package)
    for index, package in enumerate(current):
        for row in matched.get(index, []):
            package.advisories.extend(dict(advisory, suppressed=row["suppressed"]) for advisory in row["advisories"])
        new_groups[_identity(package)].append((index, package))
    missing_coverage = {}
    for index, package in enumerate(current):
        reason = _query_coverage(coverage, package, dependencies.get(index))
        if reason:
            missing_coverage[index] = {"occurrences": package.occurrences, "name": package.name, "reason": reason}
    results, ambiguous_groups = [], []
    events = {key: [] for key in ("newly_reported", "remaining", "resolved", "not_reported", "suppression_added", "suppression_lifted", "not_observed")}
    for identity in sorted(old_groups.keys() | new_groups.keys(), key=str):
        before, after = old_groups.get(identity, []), new_groups.get(identity, [])
        by_occurrence = {ref: (index, package) for index, package in after for ref in package.occurrences}
        group_ambiguous = False
        for package in before:
            direct = [by_occurrence.get(ref) for ref in package.occurrences]
            pinned = bool(direct) and all(row is not None for row in direct)
            selected = after
            if pinned:
                members, refs = {}, defaultdict(list)
                for ref, (index, member) in zip(package.occurrences, direct):
                    members[index] = member
                    refs[index].append(ref)
                # A coalesced current group can contain many older occurrences.
                # Retain only this target's matches, not the entire group N times.
                selected = [(index, replace(members[index], occurrences=ids)) for index, ids in refs.items()]
            ambiguous = len(before) > 1 and not pinned
            group_ambiguous |= bool(ambiguous and after)
            results.append(_target(package, selected, dependencies, ambiguous=ambiguous))
        if group_ambiguous:
            observed = _target(replace(before[0], proposed_version=None), after, dependencies, ambiguous=False)["current"]
            ambiguous_groups.append({"identity": list(identity),
                                     "baseline_occurrences": [ref for package in before for ref in package.occurrences],
                                     "current": observed})
        a = [row for package in before for row in _rows(package, package.advisories)]
        b = [row for _, package in after for row in _rows(package, package.advisories)]
        delta = compute_delta(a, b, include_suppressed=True)
        events["newly_reported"].extend(_event(row) for row in delta.new)
        events["remaining"].extend(_event(row) for row in delta.persistent)
        events["suppression_added"].extend(_event(row) for row in delta.suppression_added)
        events["suppression_lifted"].extend(_event(row) for row in delta.suppression_lifted)
        for row in delta.resolved:
            if not after:
                events["not_observed"].append(_event(row, "package identity is not listed in the current inventory; file removal is not established"))
            elif coverage_errors or unmatched or baseline_unmatched or any(index in missing_coverage for index, _ in after):
                events["not_reported"].append(_event(row, "absence from findings is not backed by matching positive query coverage"))
            else:
                events["resolved"].append(_event(row))
    current_active = sum(not advisory["suppressed"] for package in current for advisory in package.advisories)
    target_unknown = sum(row["status"] in {"ambiguous", "unavailable"} for row in results)
    target_missed = sum(row["proposed_version"] is not None and row["status"] in
                        {"target_not_met", "partially_met", "not_observed"} for row in results)
    unknown = bool(coverage_errors or missing_coverage or unmatched or baseline_unmatched or health or target_unknown)
    attention = bool(target_missed or current_active or events["newly_reported"] or events["suppression_added"]
                     or any(not row["suppressed"] for row in events["not_observed"]))
    code = 2 if unknown else 1 if attention else 0
    old_gaps = plan.get("scan_gaps", [])
    gap_id = lambda row: str(row.get("id") or row.get("kind") or "unknown")
    current_gaps = [*health, *({"kind": "sbom_coverage", "reason": value} for value in inventory.diagnostics)]
    previous_ids, current_ids = {gap_id(row) for row in old_gaps}, {gap_id(row) for row in current_gaps}
    return asdict(Verification(
        sources={"plan_sha256": plan_sha, "baseline": plan["sources"], "current_sbom_sha256": inventory.source_sha256,
                 "current_findings_sha256": findings_sha, "coverage_sha256": coverage_sha},
        status="unavailable" if code == 2 else "attention_required" if code == 1 else "verified", exit_code=code,
        summary={"planned_targets": sum(row.proposed_version is not None for row in plan["packages"]),
                 "targets_met": sum(row["status"] == "target_met" for row in results), "targets_not_met": target_missed,
                 "targets_unavailable": target_unknown, "newly_reported_advisories": len(events["newly_reported"]),
                 "current_active_advisories": current_active, "resolved_advisories": len(events["resolved"]),
                 "uncovered_package_groups": len(missing_coverage), "unmatched_findings": len(unmatched) + len(baseline_unmatched)},
        packages=results, ambiguous_groups=ambiguous_groups, advisories=events, unmatched_findings=unmatched,
        coverage={"errors": list(coverage_errors), "uncovered_packages": list(missing_coverage.values()),
                  "current_scan_gaps": health, "inventory_notes": inventory.diagnostics,
                  "baseline_unmatched_findings": baseline_unmatched,
                  "new_gap_kinds": sorted(current_ids - previous_ids), "persistent_gap_kinds": sorted(current_ids & previous_ids),
                  "no_longer_reported_gap_kinds": sorted(previous_ids - current_ids)},
        limitations=["Compares local artifact consistency, not signatures, build provenance or completeness of advisory databases.",
                     "Newly reported advisories can result from feed changes; the rebuild is not established as their cause.",
                     "Unlisted packages are not proof of file removal; suppressed findings are not resolutions.",
                     "Meeting a source-package target does not establish which distributor binary build contains its fix."],
    ))
