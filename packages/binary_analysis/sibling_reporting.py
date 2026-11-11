"""Portable view of current sibling review leads, without another analysis pass."""
from __future__ import annotations

from pathlib import Path
import sys

from core.reporting.results import NativeResult, complete_native_result
from core.reporting.service import unrefreshed_report_notice

from .reporting import _safe


def complete_sibling_report(args, payload: dict, run_dir: Path):
    options = args._report_options
    if not options.enabled or not (args.report_format or args.report_output):
        notice = unrefreshed_report_notice(run_dir)
        if notice:
            print("Warning: " + notice, file=sys.stderr)
        return None
    if not (args.report_format or args.report_output):
        return None
    try:
        clusters = payload.get("clusters") or []
        leads = payload.get("asymmetries") or []
        data = {key: payload.get(key) for key in ("query", "substrate", "substrate_notes", "honesty", "notes", "claim",
                                                "export_contract_asymmetries", "hypothesis_seeds_emitted")}
        data["clusters"] = clusters[:100]
        data["asymmetries"] = leads[:100]
        data["report_omissions"] = {"clusters": max(0, len(clusters) - 100), "asymmetries": max(0, len(leads) - 100)}
        metrics = {"Clusters analysed": len(clusters), "Asymmetry review leads": len(leads),
                   "Hypothesis seeds emitted": payload.get("hypothesis_seeds_emitted", 0)}
        artifacts = [{"path": path} for path in (payload.get("artifacts") or {}).values() if isinstance(path, str)]
        binary = payload.get("binary")
        if isinstance(binary, str) and binary:
            artifacts.append({"path": binary})
        # These are inputs of the native pass, not report output destinations.
        artifacts.extend({"path": str(run_dir / name)} for name in (
            "binary-manifest.json", "binary-context-map.json", "binary-evidence.json", "binary-checklist.json",
            "binary-decompilations.json", "graph/binary-graph.sqlite", "re-database.json"))
        root = run_dir
        if options.output is not None:
            if options.output.name.startswith("binary-hunt-") and options.output.suffix == ".json":
                raise ValueError("Report destination uses a native hunt artifact name")
            root = options.output if options.output.is_dir() or not options.output.suffix else options.output.parent / ("." + options.output.stem + "-report")
        result = NativeResult("binary-siblings", str(payload.get("binary") or run_dir), "unknown", _safe(data),
                              state="completed", metrics=metrics, artifacts=artifacts,
                              diagnostics=["Sibling asymmetries are structural review leads, never confirmed findings. Consistent clusters are unexamined, not safe; syntactic checks do not establish reachable enforcement.",
                                           "This pass uses an existing binary run without starting a new lifecycle execution; prior run identity is not adopted.",
                                           "Detail lists/maps are capped at 100 entries and strings at 2000 characters; full counts and native artifact references are retained. Nested detail may be omitted; use native JSON for full matrices and disproof recipes."])
        return complete_native_result(result, root, stem="binary-siblings-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("Optional sibling report unavailable (" + type(exc).__name__ + "); native result retained", file=sys.stderr)
        return None
