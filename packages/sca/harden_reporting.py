"""Portable hardening plans and phase receipts; no candidate re-evaluation."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict
import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.log_sanitisation import sanitise_for_terminal
from .update import _change_to_dict

DETAIL_LIMIT = 100


def harden_result(args, *, target, out_dir, candidates, changes, mode, exit_code, patch_path, osv,
                  target_kind, target_kind_reason, library_mode, excluded_surfaces, ecosystem_allowlist,
                  self_test_exit, apply_exit):
    from .harden import _count_actionable
    actionable = _count_actionable(candidates, allow_major_without_review=args.allow_major_without_review,
                                   allow_degraded=args.allow_degraded, allow_major=args.allow_major,
                                   ecosystem_allowlist=ecosystem_allowlist)
    notes = ["Candidate statuses are planner decisions. Promoted candidates and proposed files do not by themselves establish in-place application or complete remediation.",
             "Status totals cover all recorded candidates; actionability applies the selected ecosystem and consent policies."]
    if osv.degraded:
        notes.append(f"Advisory lookups degraded ({osv.failed_lookups} failed); affected safety answers remain unknown, not clean.")
        notes.append("Observed actionable candidates are incomplete; a complete actionability verdict is unavailable.")
    if len(candidates) > DETAIL_LIMIT or len(changes) > DETAIL_LIMIT:
        notes.append(f"Report captures up to {DETAIL_LIMIT} candidate/change details; native candidates.json retains the full plan.")
    if len(excluded_surfaces) > DETAIL_LIMIT:
        notes.append(f"Report lists {DETAIL_LIMIT} of {len(excluded_surfaces)} excluded surfaces.")
    stages = [StageEnvelope("hardening plan", "partial" if osv.degraded else "completed", producer="sca")]
    for name, requested, status in [("self-test", args.self_test, self_test_exit), ("apply", args.apply, apply_exit)]:
        if requested:
            stages.append(StageEnvelope(name, "skipped" if status is None else ("failed" if status else "completed"),
                                        producer="sca", reason="not reached in this mode" if status is None else f"Domain exit code {status}"))
    failed = any(status is not None and status != 0 for status in (self_test_exit, apply_exit))
    state = "failed" if failed else ("partial" if osv.degraded else "completed")
    payload = {"mode": mode, "exit_code": exit_code,
               "status counts": dict(Counter(candidate.status for candidate in candidates)),
               "recorded candidates": len(candidates), "policy-filtered actionable": None if osv.degraded else actionable,
               "observed actionable": actionable,
               "recorded changes": len(changes), "candidates": [asdict(candidate) for candidate in candidates[:DETAIL_LIMIT]],
               "changes": [_change_to_dict(change) for change in changes[:DETAIL_LIMIT]],
               "scope": {"target kind": target_kind, "target kind reason": target_kind_reason,
                         "library mode": library_mode, "excluded surfaces": list(excluded_surfaces[:DETAIL_LIMIT]),
                         "recorded excluded surfaces": len(excluded_surfaces),
                         "exclude patterns": list(args.exclude or []),
                         "ecosystem allowlist": sorted(ecosystem_allowlist) if ecosystem_allowlist is not None else None},
               "policy": {"allow major": args.allow_major, "allow major without review": args.allow_major_without_review,
                          "allow degraded": args.allow_degraded},
               "advisory coverage": {"degraded": osv.degraded, "failed query slots": osv.failed_lookups,
                                     "failed package sample": list(osv.failed_dep_keys[:5])},
               "phases": {"self-test exit": self_test_exit, "apply exit": apply_exit,
                          "patch supplied": patch_path is not None}}
    artifacts = [out_dir / "candidates.json"]
    if mode not in {"self-test failed", "apply failed"}:
        artifacts.append(out_dir / "report.md")
    if patch_path is not None:
        artifacts.append(patch_path)
    if self_test_exit is not None:
        notes.append("Captured candidates are the recorded planner snapshot; native self-test results are a separate operation and are not inferred from this plan.")
    artifacts.extend(candidate.manifest for candidate in candidates)
    artifacts.extend(candidate.resolved_in for candidate in candidates if candidate.resolved_in)
    return NativeResult("sca-harden", str(target), out_dir.name, payload, state=state, diagnostics=notes,
                        stages=stages, metrics={"Mode": mode, "Recorded candidates": len(candidates),
                                               "Policy-filtered actionable": "unavailable" if osv.degraded else actionable, "Recorded changes": len(changes),
                                               "Harden exit code": exit_code},
                        artifacts=[{"path": str(path)} for path in artifacts])


def complete_harden_report(args, **observations):
    try:
        result = harden_result(args, **observations)
        output = args._report_options.output
        root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
        return complete_native_result(result, root, stem="sca-harden", options=args._report_options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print(sanitise_for_terminal("Optional hardening report unavailable (" + type(error).__name__ + "); native workflow and exit status retained"), file=sys.stderr)
        return None
