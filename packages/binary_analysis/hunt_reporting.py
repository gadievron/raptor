"""Portable projections of captured anchor/caller views, without new hunts."""
from __future__ import annotations

from pathlib import Path
import sys

from core.reporting.results import NativeResult, complete_native_result
from core.reporting.service import unrefreshed_report_notice

from .reporting import _safe


def complete_hunt_report(args, results: list[dict], run_dir: Path):
    options = args._report_options
    if not options.enabled:
        notice = unrefreshed_report_notice(run_dir)
        if notice:
            print("Warning: " + notice, file=sys.stderr)
        return None
    if not (args.report_format or args.report_output):
        return None
    try:
        views = []
        metrics: dict[str, int | None] = {}
        artifacts = [{"path": str(run_dir / name)} for name in (
            "binary-manifest.json", "binary-context-map.json", "binary-evidence.json", "binary-checklist.json",
            "binary-decompilations.json", "graph/binary-graph.sqlite", "re-database.json", "map-result.json")]
        degraded = False
        for payload in results:
            mode = payload["mode"]
            # Each query view keeps its own population; overlapping anchor,
            # callers and residual sets are never summed into a finding count.
            data = {key: value for key, value in payload.items() if key not in {"artifacts", "evidence"}}
            data["report_list_omissions"] = {key: max(0, len(value) - 100) for key, value in data.items() if isinstance(value, list)}
            views.append(_safe(data))
            if mode == "anchor":
                metrics["Anchor families recorded"] = len(payload.get("families") or [])
                degraded |= bool((payload.get("scan") or {}).get("degraded"))
            if mode == "calls":
                metrics["Callers recorded"] = payload.get("caller_count")
                residual = payload.get("residual")
                if isinstance(residual, dict):
                    metrics["Chokepoint residual observations"] = residual.get("count")
            binary = payload.get("binary")
            if isinstance(binary, str) and binary:
                artifacts.append({"path": binary})
            artifacts.extend({"path": value} for value in (payload.get("artifacts") or {}).values() if isinstance(value, str))
        root = run_dir
        if options.output is not None:
            if options.output.name.startswith("binary-hunt-") and options.output.suffix == ".json":
                raise ValueError("Portable report filename belongs to the native hunt input namespace")
            root = options.output if options.output.is_dir() or not options.output.suffix else options.output.parent / ("." + options.output.stem + "-report")
        result = NativeResult("binary-hunt", str(args.target), "unknown", {"query_views": views},
                              state="partial" if degraded else "completed", artifacts=artifacts, metrics=metrics,
                              diagnostics=["Hunt populations describe separate query views, not confirmed findings. Overlap is not deduplicated or summed; absence from a bounded graph is not proof of absence.",
                                           "Lists/maps are limited to 100 entries and text to 2000 characters; top-level omissions are recorded, nested detail may be omitted. Native JSON retains complete captured detail and evidence records.",
                                           "Native scan degradation, substrate notes, truncation warnings and residual hypothesis labels remain attached to each view."],
                              lifecycle_dir=getattr(args, "_report_lifecycle_dir", None), lifecycle_producer="understand",
                              lifecycle_metadata=getattr(args, "_report_lifecycle_metadata", None))
        return complete_native_result(result, root, stem="hunt-review-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("Optional hunt report unavailable (" + type(exc).__name__ + "); native result retained", file=sys.stderr)
        return None
