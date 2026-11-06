"""Read-only upgrade proposals from an inventory and its recorded SCA findings."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from functools import cmp_to_key

from ..distro import advisory_dependency
from ..findings import _is_parseable_version
from ..versions import compare, VersionError
from .plan_inputs import inventory_plans, match_findings


@dataclass
class UpgradePlan:
    sources: dict
    mode: str
    summary: dict
    packages: list
    unmatched_findings: list
    scan_gaps: list
    limitations: list
    exit_code: int = 0
    format: str = "raptor-sbom-upgrade-plan"
    schema_version: int = 1


def _coordinates(dep):
    return {"ecosystem": dep.ecosystem, "name": dep.name, "version": dep.version}


def _versions(ecosystem, installed, values):
    valid, invalid = set(), []
    for value in values:
        if not isinstance(value, str) or not _is_parseable_version(ecosystem, value):
            invalid.append(value)
            continue
        try:
            if compare(ecosystem, value, installed) > 0:
                valid.add(value)
            else:
                invalid.append(value)
        except VersionError:
            invalid.append(value)
    return sorted(valid, key=cmp_to_key(lambda a, b: compare(ecosystem, a, b))), invalid


def _prepare(plan, dep, rows, max_candidates):
    active = [row for row in rows if not row["suppressed"]]
    plan.suppressed_findings = len(rows) - len(active)
    for row in rows:
        plan.advisories.extend({"id": adv["id"], "aliases": adv["aliases"], "suppressed": row["suppressed"]}
                               for adv in row["advisories"])
    if not active:
        if rows:
            plan.status = "suppressed_findings_only"
        return
    try:
        query = advisory_dependency(dep, require_context=False)
    except ValueError as error:
        plan.status = "query_coordinates_unavailable"
        plan.gaps.append(str(error))
        return
    if not query.version or not _is_parseable_version(query.ecosystem, query.version):
        plan.status = "query_coordinates_unavailable"
        plan.gaps.append("installed advisory version cannot be compared")
        return
    plan.query = _coordinates(query)
    if query.ecosystem.split(":", 1)[0] in {"Debian", "Ubuntu", "Alpine"}:
        plan.target_scope = "source_package"
        plan.gaps.append("source fix versions are not installable binary-package recommendations")
    fixes, alternatives = [], []
    for row in active:
        declared = row.get("advisory_package")
        if declared is not None and (not isinstance(declared, dict) or any(declared.get(key) != value for key, value in plan.query.items())):
            plan.gaps.append("finding advisory coordinates differ from the SBOM query identity")
            plan.status = "query_coordinates_unavailable"
            return
        valid, invalid = _versions(query.ecosystem, query.version, [row.get("fixed_version")])
        fixes.extend(valid)
        if invalid:
            plan.gaps.append("finding " + row["finding_id"] + " has no usable forward fix version")
        for advisory in row["advisories"]:
            alternatives.extend(advisory["fixed_versions"])
    ordered, _ = _versions(query.ecosystem, query.version, [*fixes, *alternatives])
    chosen, _ = _versions(query.ecosystem, query.version, fixes)
    plan.proposed_version = chosen[-1] if chosen else None
    if len(ordered) > max_candidates:
        # Preserve the combined recorded proposal even when alternative branches
        # exceed the candidate budget. No truncated option is silently queried.
        keep = ordered[:max_candidates]
        if plan.proposed_version and plan.proposed_version not in keep:
            keep[-1] = plan.proposed_version
        ordered = keep
        plan.gaps.append("additional advisory fix candidates omitted by --max-candidates")
    plan.candidates = [{"version": value, "status": "not_checked", "resolved": [], "remaining": [],
                        "introduced": [], "gaps": []} for value in ordered]
    plan.status = "fix_candidates_available" if ordered else "no_applicable_fix"


def _advisories(deps, results):
    # Use the same version matching, alias grouping and canonical IDs as upgrade.
    from ..findings import build_vuln_findings
    from ..whatif import _canonical_id
    grouped = {dep.key(): {} for dep in deps}
    for finding in build_vuln_findings(deps, results):
        aliases = {value for advisory in finding.advisories for value in (advisory.osv_id, *advisory.aliases)}
        grouped[finding.dependency.key()][_canonical_id(finding)] = aliases
    return grouped


def _delta(before, after):
    resolved = [key for key, aliases in before.items() if not any(aliases & other for other in after.values())]
    introduced = [key for key, aliases in after.items() if not any(aliases & other for other in before.values())]
    return sorted(resolved), sorted(after), sorted(introduced)


def _check(plans, dependencies, osv, max_queries):
    from ..osv import primary_query_supported
    requests, bindings, problems = {}, {}, {}
    for index, plan in enumerate(plans):
        if not plan.candidates:
            continue
        try:
            # Validate distro context before clearing the original binary PURL.
            # Candidate versions belong to the resulting source coordinate.
            query = advisory_dependency(dependencies[index])
            if not primary_query_supported(query.ecosystem):
                raise ValueError("ecosystem requires a dedicated advisory mapping; primary candidate comparison unavailable")
            query = replace(query, purl="")
        except ValueError as error:
            problems[index] = str(error)
            continue
        deps = [query, *(replace(query, version=row["version"]) for row in plan.candidates)]
        additional = {dep.key(): dep for dep in deps if dep.key() not in requests}
        if len(requests) + len(additional) > max_queries:
            problems[index] = "candidate query budget exhausted"
            continue
        requests.update(additional)
        bindings[index] = deps
    # A missing result, empty degraded slot or missing offline cache is unknown.
    deps = list(requests.values())
    results = osv.query_batch(deps) if deps else []
    available = {row.dep_key for row in results}
    lookup_gaps = dict(osv.coverage_gaps)
    failed = {dep.key() for dep in deps if osv.lookup_failed(dep.key())}
    assessed = _advisories(deps, results)
    for index, plan in enumerate(plans):
        if not plan.candidates:
            continue
        plan_deps = bindings.get(index, [])
        unavailable = problems.get(index)
        if plan_deps and (plan_deps[0].key() not in available or plan_deps[0].key() in failed or plan_deps[0].key() in lookup_gaps):
            unavailable = lookup_gaps.get(plan_deps[0].key(), "installed-version lookup unavailable")
        for candidate, dep in zip(plan.candidates, plan_deps[1:] if plan_deps else [None] * len(plan.candidates)):
            reason = unavailable
            if dep and (dep.key() not in available or dep.key() in failed or dep.key() in lookup_gaps):
                reason = lookup_gaps.get(dep.key(), "candidate lookup unavailable")
            if reason:
                candidate.update(status="lookup_unavailable", gaps=[reason])
                continue
            before, after = assessed[plan_deps[0].key()], assessed[dep.key()]
            resolved, remaining, introduced = _delta(before, after)
            candidate.update(status="no_known_advisories" if not remaining else "advisories_remain",
                             resolved=resolved, remaining=remaining, introduced=introduced)
        clean = [row["version"] for row in plan.candidates if row["status"] == "no_known_advisories"]
        plan.proposed_version = None
        if clean:
            plan.proposed_version = clean[0]
            plan.status = "candidate_available_for_review"
        elif any(row["status"] == "lookup_unavailable" for row in plan.candidates):
            plan.status = "candidate_verdict_unavailable"
        else:
            plan.status = "no_candidate_clears_known_advisories"


def build_plan(inventory, findings, findings_sha, *, osv=None, max_candidates=5, max_queries=1000):
    """Create proposals only; never mutate manifests, lockfiles or SBOM input."""
    if not 1 <= max_candidates <= 20 or not 1 <= max_queries <= 10_000:
        raise ValueError("candidate/query budgets are outside supported ranges")
    plans, dependencies = inventory_plans(inventory)
    matched, unmatched, gaps = match_findings(plans, dependencies, findings)
    for index, rows in matched.items():
        _prepare(plans[index], dependencies[index], rows, max_candidates)
    if osv is not None:
        _check(plans, dependencies, osv, max_queries)
    unavailable = sum(row.status in {"candidate_verdict_unavailable", "query_coordinates_unavailable", "inventory_coordinates_unavailable"}
                      or any(c["status"] == "lookup_unavailable" for c in row.candidates) for row in plans)
    unresolved = sum(row.status in {"no_applicable_fix", "no_candidate_clears_known_advisories"} for row in plans)
    code = 0 if osv is None else 2 if unavailable or unmatched or gaps else 1 if unresolved else 0
    return asdict(UpgradePlan(
        sources={"sbom_sha256": inventory.source_sha256, "findings_sha256": findings_sha},
        mode="candidate_recheck" if osv else "saved_findings", exit_code=code,
        summary={"package_groups": len(plans), "package_occurrences": sum(len(p.occurrences) for p in plans),
                 "with_reported_advisories": sum(bool(p.advisories) for p in plans),
                 "with_proposals": sum(p.proposed_version is not None for p in plans),
                 "unavailable": unavailable, "without_applicable_fix": unresolved,
                 "unmatched_findings": len(unmatched), "scan_health_gaps": len(gaps)},
        packages=[asdict(row) for row in plans], unmatched_findings=unmatched,
        scan_gaps=[*gaps, *({"kind": "sbom_coverage", "reason": value} for value in inventory.diagnostics)],
        limitations=["Saved findings are a snapshot; absence of findings does not establish complete advisory coverage.",
                     "Findings are matched by package identity, not an attestation that they came from this exact scan.",
                     "Candidate checks use existing advisory matching, not build, API, registry availability or dependency-resolution validation.",
                     "Source-package fixes require mapping to a distributor's available binary build.",
                     "Plans do not change source manifests, lockfiles, SBOMs or images."],
    ))
