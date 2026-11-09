"""Portable final-map projections over native binary results and phase receipts."""
from __future__ import annotations

from collections import Counter
from itertools import islice
from pathlib import Path
import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.prompt_output_sanitise import sanitise_string
from core.security.redaction import redact_secrets

DETAIL_LIMIT = 100
_FIELD_LIMIT = 100
_STATIC_CATEGORIES = ("entry_points", "sink_details", "surface_details", "candidate_flows", "framework_callback_candidates")
_MANIFEST_FIELDS = ("binary_path", "binary_sha256", "binary_format", "arch", "bits", "identity_kind", "build_id", "image_base")


def _safe(value, depth=0, remaining=None):
    if remaining is None:
        remaining = [20_000]
    remaining[0] -= 1
    if remaining[0] < 0:
        raise ValueError("Report detail node budget exceeded")
    if depth > 12:
        return "Report detail depth limit reached"
    if isinstance(value, str):
        return sanitise_string(redact_secrets(value), max_chars=2000)
    if isinstance(value, dict):
        data = {key: _safe(item, depth + 1, remaining) for key, item in islice(value.items(), _FIELD_LIMIT)}
        if len(value) > _FIELD_LIMIT:
            data["raptor.report_fields_omitted"] = len(value) - _FIELD_LIMIT
        return data
    if isinstance(value, (list, tuple)):
        return [_safe(item, depth + 1, remaining) for item in value[:DETAIL_LIMIT]]
    return value


def map_report_result(args, payload, result, out_dir, status, *, active_phases=()):
    mode = args.command
    notes = ["Binary map candidates and evidence tiers are observations, not confirmed vulnerabilities. Command completion does not establish complete analysis coverage.",
             "This receipt describes the final completed map only; intermediate map populations are not added together. No prior investigation summary is adopted from disk.",
             "Detail lists/maps are bounded to 100 entries and text to 2000 characters. Full native artifacts remain available; raw runtime arguments and fuzz payloads are not copied."]
    if getattr(args, "_report_lifecycle_dir", None) is None:
        notes.append("No current native execution was started; lifecycle lineage is unavailable.")
    phases = [{key: phase.get(key) for key in ("kind", "status", "returncode", "output_dir", "reason")} for phase in active_phases]
    stages = []
    for phase in phases:
        native_state = phase["status"]
        stages.append(StageEnvelope(str(phase["kind"]), native_state if native_state in {"completed", "failed", "skipped"} else "unknown",
                                    producer="binary", reason=_safe(phase.get("reason") or "")))
    metrics = {"Native exit status": status}
    artifacts = [{"path": str(Path(args.target).expanduser().resolve())}]
    if result is None or payload is None:
        state = "failed" if status else "unknown"
        data = {"native exit status": status, "final map": None, "active phases": phases}
        notes.append("No current final map was captured; candidate/evidence populations are unavailable, not zero. Native stderr retains the diagnostic.")
    else:
        context = result.context_map
        counts = {key: len(context.get(key) or []) for key in _STATIC_CATEGORIES}
        tiers = dict(Counter(getattr(entry.tier, "value", str(entry.tier)) for entry in result.evidence))
        summary = payload.get("correlation", {}).get("summary", {})
        data = {"native exit status": status, "mode": mode,
                "manifest": {key: getattr(result.manifest, key, None) for key in _MANIFEST_FIELDS},
                "map summary": summary, "recorded category counts": counts, "evidence tier counts": tiers,
                "analysis scope": context.get("analysis_scope"),
                "decompilation coverage": result.decompilations.get("coverage"),
                "static evidence excerpts": {key: (context.get(key) or [])[:DETAIL_LIMIT] for key in _STATIC_CATEGORIES},
                "active phases": phases}
        metrics.update(summary)
        metrics.update({"Evidence tier " + key: count for key, count in tiers.items()})
        state = "failed" if status else "partial" if any(stage.state in {"failed", "unknown"} for stage in stages) else "completed"
        # map_result_payload also advertises a possibly old investigation path.
        for label, path in payload.get("artifacts", {}).items():
            if isinstance(path, str):
                reference = {"path": path}
                if mode == "map" and label.startswith("binary_investigation"):
                    reference["role"] = "protected legacy artifact; current content not captured"
                artifacts.append(reference)
    for name in ("compare", "constraint_file"):
        path = getattr(args, name, None)
        if path:
            artifacts.append({"path": str(Path(path).expanduser().resolve())})
    if out_dir is not None:
        artifacts.append({"path": str(Path(out_dir) / "map-result.json")})
        artifacts.append({"path": str(Path(out_dir) / "binary-analysis-report.md")})
        if mode == "investigate":
            artifacts.append({"path": str(Path(out_dir) / "binary-investigation-report.md")})
    if any(stage.state in {"failed", "unknown"} for stage in stages):
        notes.append("Some active phases did not complete; map data comes from the latest completed mechanical pass, not evidence from a failed phase.")
    map_state = "completed" if payload is not None and result is not None and not status else "failed" if status else "unknown"
    stages.append(StageEnvelope("final binary map", map_state, producer="binary"))
    return NativeResult("binary-map", str(args.target), "unknown", _safe(data),
                        state=state, diagnostics=notes, stages=stages, metrics=metrics, artifacts=artifacts,
                        lifecycle_dir=getattr(args, "_report_lifecycle_dir", None), lifecycle_producer="understand",
                        lifecycle_metadata=getattr(args, "_report_lifecycle_metadata", None))


def complete_map_report(args, payload, result, out_dir, status, *, active_phases=()):
    options = args._report_options
    output = options.output
    root = out_dir
    if output is not None:
        root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
    try:
        if root is None:
            raise ValueError("No output directory was allocated; select an explicit report destination")
        destinations = [Path(root)] + ([output] if output is not None else [])
        sources = [getattr(args, name, None) for name in ("runtime_dir", "fuzz_dir")]
        sources.extend(phase.get("output_dir") for phase in active_phases)
        for source in sources:
            if source and any(path.resolve().is_relative_to(Path(source).expanduser().resolve()) for path in destinations):
                raise ValueError("Report destination belongs to an imported evidence directory")
        return complete_native_result(map_report_result(args, payload, result, out_dir, status, active_phases=active_phases),
                                      root, stem="binary-map-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print("Optional binary map report unavailable (" + type(error).__name__ + "); native result retained", file=sys.stderr)
        return None
