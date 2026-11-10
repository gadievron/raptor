"""Presentation of captured analysis counters and claims; no analysis dispatch."""
from __future__ import annotations

from itertools import islice
import math
from pathlib import Path
import sys

from core.reporting.document import Block, ReportContext, ReportDocument, StageEnvelope, digest
from core.reporting.lifecycle import apply_lifecycle
from core.reporting.options import ReportOptions
from core.reporting.renderers import get_renderer
from core.reporting.results import result_blocks
from core.reporting.service import complete_reporting, unrefreshed_report_notice
from core.reporting.summary import build_operator_summary, render_operator_summary
from core.security.redaction import redact_secrets


_COUNTERS = ("processed", "prepped", "analyzed", "exploitable", "exploits_generated", "patches_generated",
             "dataflow_validated", "false_positives_caught", "journal_entries_emitted", "variant_matches", "execution_time")
_SECTIONS = ("dataflow_validation", "variant_reviews", "verification_tiers", "llm_stats", "fixture_detection_metrics",
             "reachability_suppression", "sage_fp_suppression", "guard_dominance", "fail_open_channel",
             "context_expansion", "context_toolloop", "orchestration")


def build_document(report: dict, *, orchestration_skipped: bool = False) -> ReportDocument:
    """A bounded metadata projection; native reports retain bodies and evidence."""
    remaining = 200_000
    nodes = 5000
    limited = False
    excluded = 0
    collection_entries_omitted = 0

    def text(value: object) -> str:
        nonlocal remaining, limited
        value = redact_secrets(str(value))
        allowed = min(2000, remaining)
        limited |= len(value) > allowed
        result = value[:allowed]
        remaining -= len(result)
        return result

    def project(value: object, depth: int = 0):
        nonlocal nodes, limited, excluded, collection_entries_omitted
        if nodes <= 0 or depth > 8:
            limited = True
            excluded += 1
            return None
        nodes -= 1
        if isinstance(value, (dict, list)):
            captured = []
            entries = value.items() if isinstance(value, dict) else enumerate(value)
            for index, (key, item) in enumerate(islice(entries, 1000), 1):
                if nodes <= 0:
                    break
                projected = project(item, depth + 1)
                captured.append({"row": index, "field": text(key), "value": projected} if isinstance(value, dict) else projected)
            omitted_entries = len(value) - len(captured)
            collection_entries_omitted += omitted_entries
            limited |= omitted_entries > 0
            return captured
        if isinstance(value, str):
            return text(value)
        if value is None or type(value) in (bool, int) or (isinstance(value, float) and math.isfinite(value)):
            return value
        limited = True
        excluded += 1
        return None

    mode = text(report.get("mode", "not supplied"))
    summary: dict[str, int | float | None] = {}
    for key in _COUNTERS:
        value = report.get(key)
        if value is None or type(value) is int or type(value) is float and math.isfinite(value):
            summary[key] = value
        else:
            summary[key] = None
            excluded += 1
            limited = True
    raw_results = report.get("results")
    results = raw_results if isinstance(raw_results, list) else []
    summary["Returned result rows"] = len(results) if isinstance(raw_results, list) else None
    stats = {key: project(report[key]) for key in _SECTIONS if key in report}
    rows = []
    invalid = 0
    for index, result in enumerate(islice(results, 1000), 1):
        if not isinstance(result, dict):
            invalid += 1
            continue
        raw_analysis = result.get("analysis")
        analysis = raw_analysis if isinstance(raw_analysis, dict) else {}
        raw_claim = analysis.get("is_exploitable", result.get("is_exploitable"))
        if isinstance(raw_claim, (dict, list)):
            excluded += 1
            limited = True
            claim = None
        else:
            claim = project(raw_claim)
        # Only existing claims, never inferred verification from code generation.
        rows.append([index, text(result.get("finding_id", result.get("id", "not supplied"))),
                     text(result.get("file", result.get("file_path", "not supplied"))),
                     text(result.get("status", "not supplied")),
                     claim,
                     "error" in result])
    omitted = max(0, len(results) - 1000)
    limited |= omitted > 0 or invalid > 0
    blocks = [Block("table", title="Retained result claims (not new validation)",
                    columns=["Row", "Recorded identity", "File", "Recorded status", "Recorded exploitable claim", "Error field present"], rows=rows),
              *result_blocks(stats, title="Captured telemetry", limit=20_000)]
    notes = ["This is a captured summary of existing analysis output. Generated exploit/patch bodies, prompts, source excerpts and reasoning remain in native evidence and are not included here. Code generation is not proof of compilation, execution or exploitability.",
             "Preparation-only counters and orchestrated telemetry describe different stages and populations; they are not added together. Missing counters remain unavailable. A returned snapshot does not establish whole-target coverage or complete analysis.",
             "Recorded statuses and exploitable claims are reproduced as claims, without new validation or confidence promotion. Per-row identifiers and table positions are not inferred stable finding identities. No model, target execution, analysis or evidence read is triggered by rendering."]
    if orchestration_skipped:
        notes.append("Orchestration was skipped by the existing CLI path; only the preparation snapshot is available.")
    if mode == "prep_only":
        notes.append("Preparation only: findings were prepared for review; this snapshot is not a completed analysis verdict population.")
    if limited:
        notes.append("Portable capture limited: 1000 retained result rows, 1000 entries per telemetry collection, depth 8, 5000 telemetry nodes, 2000 characters per string and 200000 text characters. Unavailable/omitted subtrees and rejected retained rows are disclosed separately; scalars inside an omitted subtree are unknown.")
    document = ReportDocument("Captured analysis summary", "analysis", "", metadata={"Native mode": mode, "Orchestration skipped": orchestration_skipped},
                              summary=summary, blocks=blocks, diagnostics=notes,
                              extensions={"raptor.capture_limited": limited, "raptor.result_rows_omitted": omitted,
                                          "raptor.retained_result_rows_rejected": invalid,
                                          "raptor.telemetry_values_or_subtrees_unavailable": excluded,
                                          "raptor.telemetry_collection_entries_omitted": collection_entries_omitted})
    document.snapshot_id = digest(document.to_dict())
    return document


def prepare(options: ReportOptions, output: Path, inputs: list[Path], target: Path) -> Path:
    root = output / "portable-reports" / "analysis"
    if not options.enabled:
        return root
    options = options.validate()
    chosen = options.output or root
    is_file = options.output_is_file or (bool(chosen.suffix) and not chosen.is_dir())
    protected = {path.resolve() for path in inputs}
    protected.update((output / name).resolve() for name in ("autonomous_analysis_report.json", "orchestrated_report.json", "correlation.json", "aggregation.json"))
    for format in options.formats:
        destination = chosen if is_file else chosen / ("analysis" + get_renderer(format).extension)
        if destination.resolve() in protected:
            raise ValueError("Portable analysis output cannot replace native evidence or input")
        if destination.exists() and destination.is_file() and destination.resolve().is_relative_to(target.resolve()):
            raise ValueError("Portable analysis output cannot replace an existing target file")
    return chosen.parent / ("." + chosen.stem + "-report") if is_file else chosen


def emit(report: dict, output: Path, inputs: list[Path], target: Path, options: ReportOptions, *, orchestration_skipped: bool = False) -> None:
    try:
        root = prepare(options, output, inputs, target)
        document = build_document(report, orchestration_skipped=orchestration_skipped)
        state = "partial" if orchestration_skipped or report.get("mode") == "prep_only" or document.extensions["raptor.capture_limited"] else "unknown"
        context = ReportContext("analysis", "unknown", target=redact_secrets(str(target))[:2000], state=state,
                                stages=[StageEnvelope("analysis-snapshot", "completed", producer="analysis result adapter", reason="Returned result captured; analysis coverage and whole-job completion not inferred")],
                                expected_stages=["analysis-snapshot"], diagnostics=list(document.diagnostics),
                                artifacts=[{"path": str(path.resolve()), "role": "input/native evidence; preserved"} for path in inputs] +
                                          [{"path": str((output / name).resolve()), "role": "native evidence; preserved"} for name in ("autonomous_analysis_report.json", "orchestrated_report.json", "correlation.json", "aggregation.json")],
                                extensions={"raptor.findings_available": False, "raptor.metrics": dict(document.summary), "raptor.analysis_capture": document.to_dict()})
        apply_lifecycle(context, output, producer_command="analyze")
        if not options.enabled:
            quick = build_operator_summary(context)
            quick.diagnostics.append("Full exports disabled; previous custom destinations are not refreshed.")
            notice = unrefreshed_report_notice(root)
            if notice:
                quick.diagnostics.append(notice)
            print(render_operator_summary(quick), file=sys.stderr, end="")
            return
        document.snapshot_id = context.snapshot_id
        complete_reporting(context, root, document=document, stem="analysis", options=options, stream=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — presentation cannot alter native analysis or orchestration status
        print("Optional analysis report unavailable (" + type(exc).__name__ + "); native result retained", file=sys.stderr)
