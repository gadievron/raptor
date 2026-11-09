"""Bounded bump views over the native report and recorded advisory evidence."""
from __future__ import annotations

from collections import Counter
from dataclasses import replace
import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.log_sanitisation import sanitise_for_terminal
from ..findings import _vuln_finding_to_row

DETAIL_LIMIT = 100


def bump_result(report, *, apply_requested, trust_repo, excludes=()):
    from .cli import _report_to_dict
    notes = ["Verdicts and rewrite outcomes are separate observations. Clean does not itself establish that a change was applied, and advisory matches do not establish exploitability."]
    rows = [replace(row, bump_supply_chain_findings=row.bump_supply_chain_findings[:DETAIL_LIMIT],
                    bump_vuln_findings=row.bump_vuln_findings[:DETAIL_LIMIT]) for row in report.results[:DETAIL_LIMIT]]
    captured = replace(report, candidates=report.candidates[:DETAIL_LIMIT], results=rows,
                       skipped=report.skipped[:DETAIL_LIMIT], excluded_by_pattern=report.excluded_by_pattern[:DETAIL_LIMIT])
    payload = _report_to_dict(captured)
    for data, row, original in zip(payload["results"], rows, report.results):
        data["new_advisories"] = [_vuln_finding_to_row(finding) for finding in row.bump_vuln_findings]
        data["recorded_new_advisories"] = len(original.bump_vuln_findings)
        data["recorded_supply_chain_findings"] = len(original.bump_supply_chain_findings)
    counts = {"candidates": len(report.candidates), "results": len(report.results),
              "skipped": len(report.skipped), "excluded files": len(report.excluded_by_pattern)}
    if any(count > DETAIL_LIMIT for count in counts.values()):
        notes.append(f"Report captures up to {DETAIL_LIMIT} entries per category; native --json/console output retains the full native report.")
    if any(len(row.bump_supply_chain_findings) > DETAIL_LIMIT or len(row.bump_vuln_findings) > DETAIL_LIMIT for row in report.results):
        notes.append(f"Per-result report evidence is bounded to {DETAIL_LIMIT} supply-chain and new-advisory records.")
    verdicts = dict(Counter(row.verdict_label.lower() for row in report.results))
    applied = sum(row.rewrite_result is not None and row.rewrite_result.applied for row in report.results)
    errors = sum(row.error is not None for row in report.results)
    evidence = {"New-advisory occurrences": sum(len(row.bump_vuln_findings) for row in report.results),
                "Supply-chain observations": sum(len(row.bump_supply_chain_findings) for row in report.results)}
    payload.update({"requested mode": "apply" if apply_requested else "dry run", "recorded counts": counts,
                    "recorded verdicts": verdicts, "recorded applied results": applied,
                    "recorded result errors": errors, "recorded evidence": evidence,
                    "policy": {"repo trust resolved": trust_repo,
                                                                  "write exclusions": list(excludes or [])}})
    state = "partial" if errors else "completed"
    if errors:
        notes.append(f"{errors} candidate result(s) record errors; their safety answers must not be inferred from overall command completion.")
    artifacts = [report.target, *(candidate.file for candidate in report.candidates),
                 *(row.candidate.file for row in report.results), *(path for _, path, _ in report.skipped),
                 *report.excluded_by_pattern]
    return NativeResult("sca-bump", str(report.target), "sca-bump", payload, state=state, diagnostics=notes,
                        stages=[StageEnvelope("bump evaluation", state, producer="sca")],
                        metrics={"Requested mode": "apply" if apply_requested else "dry run", **counts,
                                 **{label + " results": count for label, count in verdicts.items()},
                                 **evidence,
                                 "Recorded applied results": applied, "Recorded result errors": errors},
                        artifacts=[{"path": str(path)} for path in artifacts])


def _complete(args, result):
    output = args._report_options.output
    root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
    return complete_native_result(result, root, stem="sca-bump", options=args._report_options, stream=sys.stderr)


def complete_bump_report(args, report, *, trust_repo):
    try:
        return _complete(args, bump_result(report, apply_requested=args.apply, trust_repo=trust_repo, excludes=args.exclude))
    except (OSError, ValueError, TypeError) as error:
        print(sanitise_for_terminal("Optional bump report unavailable (" + type(error).__name__ + "); native outputs and exit status retained"), file=sys.stderr)
        return None


def complete_bump_failure(args, target, error):
    # Persist the failure category, not a traceback, credentials or raw CLI args.
    result = NativeResult("sca-bump", str(target), "sca-bump",
                          {"error type": type(error).__name__, "apply requested": args.apply}, state="failed",
                          diagnostics=["Bump evaluation did not complete; native stderr retains the diagnostic."],
                          stages=[StageEnvelope("bump evaluation", "failed", producer="sca")],
                          artifacts=[{"path": str(target)}])
    try:
        return _complete(args, result)
    except (OSError, ValueError, TypeError):
        print("Optional bump failure report unavailable; native error retained", file=sys.stderr)
        return None
