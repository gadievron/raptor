"""Portable harness plan receipts; declared checks are never executed results."""
from __future__ import annotations

from pathlib import Path
import sys

from core.reporting.results import NativeResult, complete_native_result
from core.reporting.service import unrefreshed_report_notice

from .reporting import _safe


_PLAN_FIELDS = ("id", "target", "ingress", "family", "status", "reason", "operator_inputs", "unknowns",
                "verification_contract", "next_step", "evidence_policy")


def complete_harness_report(args, spec: dict, run_dir: Path):
    options = getattr(args, "_report_options", None)
    if options is None:
        return None  # direct native handler callers retain their old contract
    if not options.enabled or not (args.report_format or args.report_output):
        notice = unrefreshed_report_notice(run_dir)
        if notice:
            print("Warning: " + notice, file=sys.stderr)
        return None
    if not (args.report_format or args.report_output):
        return None
    try:
        data = {key: spec.get(key) for key in _PLAN_FIELDS}
        data["linked_evidence_counts"] = {key: len(value) for key, value in (spec.get("linked_evidence") or {}).items() if isinstance(value, list)}
        artifacts = [{"path": value} for value in (spec.get("artifacts") or {}).values() if isinstance(value, str)]
        binary = (spec.get("target") or {}).get("path")
        if isinstance(binary, str) and binary:
            artifacts.append({"path": binary})
        artifacts.extend({"path": str(run_dir / name)} for name in (
            "binary-manifest.json", "binary-context-map.json", "context-map.json", "binary-evidence.json",
            "binary-investigation.json", "binary-checklist.json", "re-database.json", "graph/binary-graph.sqlite"))
        root = run_dir
        if options.output is not None:
            root = options.output if options.output.is_dir() or not options.output.suffix else options.output.parent / ("." + options.output.stem + "-report")
        result = NativeResult("binary-harness-plan", str(binary or run_dir), "unknown", _safe(data), state="completed",
                              artifacts=artifacts,
                              metrics={"Native plan status": spec.get("status"), "Unknown prerequisites": len(spec.get("unknowns") or []),
                                       "Verification requirements": len(spec.get("verification_contract") or [])},
                              diagnostics=["Native plan completion does not mean the harness is built, replayed, deterministic, coverage-validated or trusted. Verification entries are requirements, not executed checks.",
                                           "Generated source and build scripts are referenced, never read or run by reporting. Linked evidence is counted without copying runtime payloads.",
                                           "Details are bounded to 100 entries and 2000 characters per string; use the native plan for full prerequisites and evidence. Existing run identity is not adopted as a new planning execution."])
        return complete_native_result(result, root, stem="harness-plan-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("Optional harness plan report unavailable (" + type(exc).__name__ + "); native plan retained", file=sys.stderr)
        return None
