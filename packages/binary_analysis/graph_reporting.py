"""Portable graph-query metadata; no second query or raw evidence properties."""
from __future__ import annotations

from pathlib import Path
import sys

from core.reporting.results import NativeResult, complete_native_result
from core.reporting.service import unrefreshed_report_notice

from .reporting import _safe


def complete_graph_report(args, payload: dict | None, db_path: Path, status: int):
    options = args._report_options
    default_root = Path(args.run_dir) if args.run_dir else db_path.parent
    if not options.enabled:
        notice = unrefreshed_report_notice(default_root)
        if notice:
            print("Warning: " + notice, file=sys.stderr)
        return None
    if not (args.report_format or args.report_output):
        return None
    try:
        mode = "edges" if args.edges else "evidence" if args.evidence else "summary"
        data = {"selection": {"mode": mode, "kind": args.kind, "tier": args.tier}, "native_exit_status": status}
        metrics = {"Native exit status": status}
        artifacts = [{"path": str(db_path.expanduser().resolve())}]
        if payload is None:
            data["result"] = None
        elif mode == "summary":
            latest = payload.get("latest_snapshot") or {}
            data["result"] = {key: payload.get(key) for key in ("exists", "nodes", "edges", "evidence")}
            data["latest_graph_snapshot"] = {key: latest.get(key) for key in ("id", "binary_path", "binary_sha256", "created_at", "producer_run")}
            binary = latest.get("binary_path")
            if isinstance(binary, str) and binary:
                artifacts.append({"path": binary})
        else:
            rows = payload[mode]
            fields = ("id", "kind", "source", "target", "confidence") if mode == "edges" else ("id", "kind", "tier", "confidence", "reproducible", "source", "tool")
            data["records"] = [{key: row.get(key) for key in fields} for row in rows[:100]]
            data["records_omitted"] = max(0, len(rows) - 100)
            metrics["Records returned by native query"] = len(rows)
        root = default_root
        if options.output is not None:
            root = options.output if options.output.is_dir() or not options.output.suffix else options.output.parent / ("." + options.output.stem + "-report")
        result = NativeResult("binary-graph-query", str(db_path), "unknown", _safe(data), artifacts=artifacts,
                              state="failed" if status else "completed", metrics=metrics,
                              diagnostics=["This is a captured query view, not a new analysis or validation. Counts describe returned records under the selected filter, not whole-program coverage.",
                                           "Evidence properties and free-form summaries are omitted; native JSON retains them. Recorded confidence and tier labels do not establish a finding verdict.",
                                           "Report records are capped at 100, maps at 100 fields and strings at 2000 characters; omitted record counts are explicit. Existing graph snapshot IDs are recorded claims, not adopted run identities."])
        return complete_native_result(result, root, stem="graph-query-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("Optional graph query report unavailable (" + type(exc).__name__ + "); native result retained", file=sys.stderr)
        return None
