"""Portable pre-add review capture without additional lookups."""
from __future__ import annotations

from pathlib import Path
import sys

from core.reporting.document import Block, StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.log_sanitisation import sanitise_for_terminal
from .findings import _confidence_summary, _vuln_finding_to_row

DETAIL_LIMIT = 100


def check_result(*, dep, vuln_findings, typo_findings, slop_findings, verdict, exit_code,
                 transitive_deps, transitive_findings, transitive_walk_attempted,
                 transitive_walk_supported, seed_metadata_unverifiable, osv_degraded, failed_lookups,
                 failed_dep_keys=(), offline=False, kev_enabled=True, epss_enabled=True):
    from .review import _VERDICT_BLOCK, _VERDICT_CLEAN, _VERDICT_REVIEW, _recommendation
    label = {_VERDICT_CLEAN: "Clean", _VERDICT_REVIEW: "Review", _VERDICT_BLOCK: "Block"}[verdict]
    if osv_degraded and verdict != _VERDICT_BLOCK:
        label = "Degraded"
    notes = ["Recorded pre-add evaluation; advisory and name-heuristic signals do not establish exploitability or package safety."]
    if osv_degraded:
        notes.append(f"{failed_lookups} advisory lookup(s) unavailable; verdict unavailable. Re-run with available online or cached advisory data.")
    if seed_metadata_unverifiable:
        notes.append("Registry could not confirm the requested package version exists; verify the package coordinates before installing.")
    if not transitive_walk_attempted:
        notes.append("Transitive metadata walk was not attempted; dependencies pulled in by installation are outside this check.")
    elif not transitive_walk_supported:
        notes.append("Transitive metadata walk is unsupported for this ecosystem; only the named package was checked.")
    else:
        notes.append("Transitive surface is approximate registry metadata, not resolver-resolved install coverage.")
        if not transitive_deps:
            notes.append("No transitive dependencies were recorded; this may mean no declared dependencies or unavailable registry metadata.")
    groups = {"direct advisories": vuln_findings, "transitive advisories": transitive_findings,
              "typosquat candidates": typo_findings, "slopsquat candidates": slop_findings,
              "transitive dependencies": transitive_deps}
    for name, values in groups.items():
        if len(values) > DETAIL_LIMIT:
            notes.append(f"{name}: report captures {DETAIL_LIMIT} of {len(values)} records; native console/--out output retains the complete review.")
    counts = {name: len(values) for name, values in groups.items()}
    def coordinates(dependency):
        return {"ecosystem": dependency.ecosystem, "name": dependency.name, "version": dependency.version,
                "purl": dependency.purl}
    payload = {
        "package": coordinates(dep), "verdict": label, "exit_code": exit_code,
        "recommendation": _recommendation(verdict, osv_degraded),
        "coverage": {"offline": offline, "KEV enabled": kev_enabled, "EPSS enabled": epss_enabled,
                     "OSV degraded": osv_degraded, "failed advisory lookups": failed_lookups,
                     "failed package sample": list(failed_dep_keys[:5]),
                     "registry existence unverified": seed_metadata_unverifiable,
                     "transitive walk attempted": transitive_walk_attempted,
                     "transitive walk supported": transitive_walk_supported},
        "direct advisories": [_vuln_finding_to_row(f) for f in vuln_findings[:DETAIL_LIMIT]],
        "transitive advisories": [_vuln_finding_to_row(f) for f in transitive_findings[:DETAIL_LIMIT]],
        "typosquat candidates": [{"package": coordinates(f.dependency), "nearest popular": f.nearest_popular,
                                  "distance": f.distance, "severity": f.severity,
                                  "confidence": _confidence_summary(f.confidence)} for f in typo_findings[:DETAIL_LIMIT]],
        "slopsquat candidates": [{"package": coordinates(f.dependency), "score": f.score, "reasons": list(f.reasons),
                                  "suspected root": f.suspected_root, "severity": f.severity,
                                  "confidence": _confidence_summary(f.confidence)} for f in slop_findings[:DETAIL_LIMIT]],
        "transitive dependencies": [coordinates(d) for d in transitive_deps[:DETAIL_LIMIT]],
    }
    return NativeResult("sca-check", dep.purl, "sca-check", payload, state="partial" if osv_degraded else "completed",
                        diagnostics=notes, metrics={"Recorded verdict": label, **counts},
                        stages=[StageEnvelope("pre-add check", "partial" if osv_degraded else "completed", producer="sca")],
                        blocks=[Block("paragraph", text="Recorded verdict: " + label),
                                Block("table", title="Recorded observations", columns=["Category", "Records"],
                                      rows=[[name, count] for name, count in counts.items()])])


def complete_check_report(args, **observations):
    try:
        result = check_result(**observations, offline=args.offline,
                              kev_enabled=not args.no_kev, epss_enabled=not args.no_epss)
        if args.out:
            result.artifacts = [{"path": str(Path(args.out).resolve())}]
        output = args._report_options.output
        root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
        return complete_native_result(result, root, stem="sca-check", options=args._report_options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print(sanitise_for_terminal("Optional pre-add report unavailable (" + type(error).__name__ + "); native review and exit status retained"), file=sys.stderr)
        return None
