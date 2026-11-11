"""Bounded receipts over an already captured native understand result."""
from __future__ import annotations

from itertools import islice
import math
from pathlib import Path
import sys

from core.reporting.options import options_from_args
from core.reporting.results import NativeResult, complete_native_result
from core.reporting.service import unrefreshed_report_notice
from core.security.prompt_output_sanitise import sanitise_string
from core.security.redaction import redact_secrets

_LIMIT = 100


def _scalar(value):
    if isinstance(value, str):
        return sanitise_string(redact_secrets(value), max_chars=2000)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    return "Structured detail retained in native JSON"


def _mapping(value):
    if not isinstance(value, dict):
        return {"recorded": False}
    return {"entries": [[_scalar(str(key)), _scalar(item)]
                        for key, item in islice(value.items(), _LIMIT)],
            "entries_omitted": max(0, len(value) - _LIMIT)}


def _models(value):
    if not isinstance(value, list):
        return {"recorded": False}
    return {"total": len(value), "names": [_scalar(item) for item in value[:_LIMIT]],
            "names_omitted": max(0, len(value) - _LIMIT)}


def prepare_understand_report(args, out_dir: Path, target: Path) -> None:
    """Refuse source-tree destinations before native work or resume transitions."""
    options = getattr(args, "_report_options", None) or options_from_args(args)
    args._report_options = options
    if not options.enabled or not (getattr(args, "report_format", None) or getattr(args, "report_output", None)):
        return
    destination = options.output or out_dir / "portable-reports"
    root = destination if destination.is_dir() or not destination.suffix else destination.parent
    native_root = out_dir.resolve()
    if root.resolve().is_relative_to(native_root) and not root.resolve().is_relative_to(native_root / "portable-reports"):
        raise ValueError("Portable reports within a run must use its portable-reports directory; native files and checkpoints are reserved")
    if target.is_dir() and root.resolve().is_relative_to(target.resolve()):
        raise ValueError("Portable reports must be outside the analysed source tree; use --report-output with an external directory")
    if root.resolve() == target.resolve() or destination.resolve() == target.resolve():
        raise ValueError("Portable reports cannot replace the analysed target")
    for name in ("runtime_dir", "fuzz_dir"):
        value = getattr(args, name, None)
        if value and root.resolve().is_relative_to(Path(value).resolve()):
            raise ValueError("Portable reports must be outside native input directories")


def complete_understand_report(args, payload: dict, native_path: Path):
    options = getattr(args, "_report_options", None) or options_from_args(args)
    if not options.enabled or not (getattr(args, "report_format", None) or getattr(args, "report_output", None)):
        notice = unrefreshed_report_notice(native_path.parent / "portable-reports")
        if notice:
            print("Warning: " + notice, file=sys.stderr)
        return None
    if not (getattr(args, "report_format", None) or getattr(args, "report_output", None)):
        return None
    try:
        failed = payload.get("failed_models")
        items = payload.get("items")
        correlation = payload.get("correlation")
        data = {
            "mode": _scalar(payload.get("mode")),
            "backend": _scalar(payload.get("backend")),
            "items_recorded": len(items) if isinstance(items, list) else None,
            "models": _models(payload.get("models")),
            "failed_models": _models(failed),
            "model_errors": _mapping(payload.get("model_errors")),
            "model_costs_usd": _mapping(payload.get("model_costs_usd")),
            "total_cost_usd": _scalar(payload.get("total_cost_usd")),
            "correlation_summary": _mapping(correlation.get("summary") if isinstance(correlation, dict) else None),
            "resumed_segment": _scalar(payload.get("resumed_segment")),
            "carried_models": _models(payload.get("carried_models")),
            "resumed_with_drift": _scalar(payload.get("resumed_with_drift")),
        }
        artifacts = [{"path": str(native_path.resolve())}, {"path": str(Path(args.target).resolve())}]
        for name in ("trace", "compare", "constraint_file"):
            path = getattr(args, name, None)
            if path:
                artifacts.append({"path": str(Path(path).resolve())})
        # Pin/checkpoint files are never imported as current evidence or overwritten.
        from .checkpoint import RUN_CONFIG_FILENAME, TRACES_PIN_FILENAME
        for name in (RUN_CONFIG_FILENAME, TRACES_PIN_FILENAME):
            artifacts.append({"path": str((native_path.parent / name).resolve())})
        result = NativeResult(
            "understand", str(_scalar(str(args.target))), "unknown", data,
            state="partial" if failed else "completed", artifacts=artifacts,
            metrics={"Items recorded": data["items_recorded"],
                     "Failed models": len(failed) if isinstance(failed, list) else None},
            diagnostics=[
                "This receipt summarises the captured native result without another analysis, model call or graph query. Item details remain in native JSON.",
                "Analysis observations, model agreement and reachability labels are not validation verdicts. Use /validate for finding assessment.",
                "Lists and maps are capped at 100 entries with explicit omission counts; strings are redacted and capped at 2000 characters. Nested details remain in native JSON.",
                "Recorded costs already include carried checkpoints; do not add prior segment totals. Missing or zero cost is not proof of free execution; some backend work is unmetered.",
                "Lifecycle identity and complete input inventory were not captured by this reporting hook; previous directory metadata is not adopted.",
            ],
        )
        root = native_path.parent / "portable-reports"
        if options.output is not None:
            root = options.output if options.output.is_dir() or not options.output.suffix else options.output.parent / ("." + options.output.stem + "-report")
        return complete_native_result(result, root, stem="understand-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as exc:
        print("Optional understand report unavailable (" + type(exc).__name__ + "); native result retained", file=sys.stderr)
        return None
