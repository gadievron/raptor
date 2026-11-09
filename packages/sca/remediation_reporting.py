"""Portable remediation receipts over domain-owned plans and concrete changes."""
from __future__ import annotations

import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.log_sanitisation import sanitise_for_terminal
from .update import _change_to_dict

DETAIL_LIMIT = 100


def fix_result(args, *, target, out_dir, scan_result, mode, vuln_plans, hygiene_plans, major_blocked,
               changes, exit_code, llm_approved, llm_verdicts, hash_pin_receipt):
    groups = {"CVE plans": vuln_plans, "pin plans": hygiene_plans, "major-version blocked": major_blocked}
    notes = ["Recorded remediation workflow. Plans and proposed files are not changes applied to the target; a rewritten version is not proof that all vulnerabilities are resolved."]
    if mode == "no actionable changes":
        notes.append("No actionable remediation was planned; this is not a claim that the scan found no findings or had complete coverage.")
    if mode in {"plan only", "proposed export"}:
        notes.append("Target manifests were not changed by this remediation mode; the existing scan prepass may have written analysis artifacts.")
    payload = {"mode": mode, "exit_code": exit_code, "scan summary": scan_result.scan_summary,
               "hash-pin receipt": hash_pin_receipt, "write exclusions": list(args.exclude or []),
               "policy": {"allow major": args.allow_major, "LLM approval opted in": args.llm_approve_major,
                          "LLM disabled": args.no_llm, "hash pin disabled": args.no_hash_pin},
               "planned counts": {name: len(plans) for name, plans in groups.items()}}
    for name, plans in groups.items():
        captured = []
        for key, plan in plans.items():
            if len(captured) == DETAIL_LIMIT:
                break
            entry = {"ecosystem": plan.ecosystem, "name": plan.name, "installed": plan.installed,
                     "target": plan.target, "manifest": str(plan.manifest), "advisories": list(plan.advisory_ids),
                     "floor raise": plan.floor_raise, "alias": plan.alias_name, "LLM approved": key in llm_approved}
            verdict = llm_verdicts.get(key)
            if verdict is not None:
                entry["impact review"] = {"verdict": verdict.verdict, "confidence": verdict.confidence,
                                           "summary": verdict.summary,
                                           "breaking changes": [{"site": change.site, "what breaks": change.what_breaks,
                                                                 "suggested fix": change.suggested_fix}
                                                                 for change in verdict.breaking_changes[:3]]}
                if len(verdict.breaking_changes) > 3:
                    notes.append(f"Impact review captures 3 of {len(verdict.breaking_changes)} breaking-change details; omitted detail is unavailable in this report.")
            captured.append(entry)
        payload[name] = captured
        if len(plans) > len(captured):
            notes.append(f"{name}: report captures {len(captured)} of {len(plans)} plans; omitted plan detail is unavailable in this report. Prepass findings retain the source evidence.")
    payload["changes"] = [_change_to_dict(change) for change in changes[:DETAIL_LIMIT]]
    skipped = sum(change.skipped_reason is not None for change in changes)
    payload["recorded changes"] = len(changes)
    payload["skipped changes"] = skipped
    if len(changes) > DETAIL_LIMIT:
        notes.append(f"Report captures {DETAIL_LIMIT} of {len(changes)} change records; changes.json retains the full list.")
    parse_failures = scan_result.parse_failures
    payload["parser failures"] = [{"path": str(failure.path), "reason": failure.reason}
                                  for failure in parse_failures[:DETAIL_LIMIT]]
    if parse_failures:
        notes.append(f"Prepass reported {len(parse_failures)} manifest parser failures; native scan artifacts retain the coverage limits.")
    if len(parse_failures) > DETAIL_LIMIT:
        notes.append(f"Report captures {DETAIL_LIMIT} of {len(parse_failures)} parser failure details.")
    state = "partial" if major_blocked or skipped or parse_failures else "completed"
    artifacts = [scan_result.findings_path, scan_result.report_path, scan_result.sbom_path, scan_result.sarif_path,
                 out_dir / "changes.md", out_dir / "changes.json"]
    artifacts.extend(plan.manifest for plans in groups.values() for plan in plans.values())
    return NativeResult("sca-fix", str(target), out_dir.name, payload, state=state, diagnostics=notes,
                        stages=[StageEnvelope("remediation workflow", state, producer="sca")],
                        metrics={"Mode": mode, **{name: len(plans) for name, plans in groups.items()},
                                 "Materialised changes": len(changes) - skipped, "Skipped changes": skipped,
                                 "Prepass dependencies": scan_result.deps_analysed, "Fix exit code": exit_code},
                        artifacts=[{"path": str(path)} for path in artifacts])


def complete_fix_report(args, **observations):
    try:
        result = fix_result(args, **observations)
        output = args._report_options.output
        root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
        return complete_native_result(result, root, stem="sca-fix", options=args._report_options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print(sanitise_for_terminal("Optional fix report unavailable (" + type(error).__name__ + "); native workflow and exit status retained"), file=sys.stderr)
        return None
