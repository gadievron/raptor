"""Bounded triage exports over one already executed CVE-diff attempt."""
from __future__ import annotations

from itertools import islice
import math
from pathlib import Path
import sys

from core.reporting.document import ReportContext, StageEnvelope
from core.reporting.options import ReportOptions
from core.reporting.results import NativeResult, complete_native_result
from core.reporting.service import unrefreshed_report_notice
from core.reporting.summary import build_operator_summary, render_operator_summary
from core.run import RUN_METADATA_FILE
from core.security.prompt_output_sanitise import sanitise_string
from core.security.redaction import redact_secrets

from cve_diff.security.exceptions import ValidationError
from cve_diff.security.validators import validate_cve_id


class _Projection:
    """One shared text budget; scalar views never recurse into native blobs."""

    def __init__(self):
        self.remaining = 200_000
        self.limited = False

    def scalar(self, value):
        if isinstance(value, str):
            text = redact_secrets(value)
            if not text:
                return ""
            limit = min(2000, self.remaining)
            self.limited |= len(text) > limit
            if not limit:
                return "Text capture limit reached"
            escaped = sanitise_string(text[:limit], max_chars=2000)
            self.limited |= len(escaped) > limit
            captured = escaped[:limit]
            self.remaining -= len(captured)
            return captured
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float) and math.isfinite(value):
            return value
        self.limited = True
        return "Non-scalar or non-finite value not projected"

    def mapping(self, value, *, exclude=()):
        if not isinstance(value, dict):
            self.limited |= value is not None
            return {"recorded": False}
        rows = []
        nested = 0
        for key, item in islice(value.items(), 20 + len(exclude)):
            if key in exclude:
                continue
            if len(rows) == 20:
                break
            if isinstance(item, (dict, list, tuple)):
                nested += 1
            rows.append([self.scalar(str(key)), self.scalar(item)])
        omitted = max(0, len(value) - sum(key in value for key in exclude) - len(rows))
        self.limited |= bool(omitted or nested)
        return {"entries": rows, "fields_omitted": omitted, "nested_fields_not_projected": nested}

    def sequence(self, value, *, records=False):
        if not isinstance(value, (list, tuple)):
            self.limited |= value is not None
            return {"recorded": False}
        convert = self.mapping if records else self.scalar
        omitted = max(0, len(value) - 100)
        self.limited |= bool(omitted)
        return {"total": len(value), "entries": [convert(item) for item in value[:100]], "entries_omitted": omitted}

    def pairs(self, value):
        if not isinstance(value, dict):
            return {"recorded": False}
        omitted = max(0, len(value) - 100)
        self.limited |= bool(omitted)
        return {"total": len(value), "entries": [{"pair": self.scalar(str(key)),
                                                   "recorded_value": self.mapping(item) if isinstance(item, dict) else self.scalar(item)}
                                                  for key, item in islice(value.items(), 100)], "entries_omitted": omitted}


def _metrics(view, status, bundle, root_cause, telemetry):
    metrics = {"Native exit status": status}
    if bundle is not None:
        metrics.update({"Files changed": view.scalar(bundle.files_changed), "Recorded diff bytes": view.scalar(bundle.bytes_size)})
    if root_cause is not None:
        metrics.update({"Root-cause input tokens": view.scalar(root_cause.input_tokens),
                        "Root-cause output tokens": view.scalar(root_cause.output_tokens)})
    if isinstance(telemetry, dict) and "cost_usd" in telemetry:
        metrics["Discovery cost USD"] = view.scalar(telemetry["cost_usd"])
    return metrics


def _stages(view, stage_status):
    stages = []
    if isinstance(stage_status, dict):
        for name, record in islice(stage_status.items(), 100):
            raw_status = record.get("status") if isinstance(record, dict) else None
            reason = record.get("reason") if isinstance(record, dict) else None
            state = {"ok": "completed", "fail": "failed"}.get(raw_status, "unknown") if isinstance(raw_status, str) else "unknown"
            stages.append(StageEnvelope(str(view.scalar(str(name))), state, producer="cve-diff", reason=str(view.scalar(reason or ""))))
    return stages


def _quick_summary(cve_id, status, *, bundle, root_cause, root_cause_requested, root_cause_error,
                   error_class, telemetry, stage_status):
    """Display results without building a document or persisting any files."""
    view = _Projection()
    metrics = _metrics(view, status, bundle, root_cause, telemetry)
    stages = _stages(view, stage_status)
    if root_cause_requested or root_cause is not None:
        stages.append(StageEnvelope("root-cause analysis", "completed" if root_cause is not None else "failed" if root_cause_error else "unknown",
                                    producer="cve-diff", reason=str(view.scalar(root_cause_error))))
    notes = ["Recorded agreement and analysis confidence are not validation verdicts."]
    if error_class:
        notes.append("Native failure class: " + str(view.scalar(error_class)))
    if bundle is None:
        notes.append("Current diff file and byte counts are unavailable, not zero.")
    if isinstance(telemetry, dict) and "cost_usd" in telemetry:
        notes.append("Recorded discovery cost may exclude other attempts and root-cause work; no full run-cost total is inferred.")
    if view.limited:
        notes.append("Some recorded summary metadata could not be represented completely.")
    state = "failed" if status else "partial" if view.limited or any(stage.state in {"failed", "unknown"} for stage in stages) else "completed"
    context = ReportContext("cve-diff", "unknown", target=str(view.scalar(cve_id)), state=state, stages=stages,
                            diagnostics=notes, extensions={"raptor.findings_available": False, "raptor.metrics": metrics})
    print(render_operator_summary(build_operator_summary(context)), file=sys.stderr, end="")


def _native_paths(output_dir: Path, cve_id: str) -> list[Path]:
    suffixes = (".osv.json", ".md", ".flow.jsonl", ".flow.md", ".clone.patch", ".github_api.patch", ".patch_url.patch")
    return [*(output_dir / (cve_id + suffix) for suffix in suffixes),
            output_dir / RUN_METADATA_FILE, output_dir / "llm-telemetry.jsonl"]


def prepare_cve_report(options: ReportOptions | None, output_dir: Path, cve_id: str, *, input_root: Path | None = None):
    """Preflight known destinations without doing pipeline work."""
    if options is None or not options.enabled:
        return
    options.validate()
    cve_id = validate_cve_id(cve_id)
    destination = options.output or output_dir / "portable-reports" / cve_id
    root = destination if destination.is_dir() or not destination.suffix else destination.parent
    if options.output is not None and options.output.resolve() in {path.resolve() for path in _native_paths(output_dir, cve_id)}:
        raise ValueError("Portable CVE reports cannot replace native pipeline artifacts")
    if input_root is not None and root.resolve().is_relative_to(input_root.resolve()):
        raise ValueError("Portable CVE reports must be outside the clone input directory")


def complete_cve_report(options: ReportOptions | None, output_dir: Path, cve_id: str, status: int, *,
                        bundle=None, root_cause=None, root_cause_requested=False, root_cause_error="",
                        error_class="", error_detail="", telemetry=None, stage_status=None, input_root=None):
    """Never rerun discovery, extraction, consensus, root cause or validation."""
    if options is None:
        _quick_summary(cve_id, status, bundle=bundle, root_cause=root_cause, root_cause_requested=root_cause_requested,
                       root_cause_error=root_cause_error, error_class=error_class, telemetry=telemetry, stage_status=stage_status)
        return None
    try:
        cve_id = validate_cve_id(cve_id)
        root = output_dir / "portable-reports" / cve_id
        if not options.enabled:
            _quick_summary(cve_id, status, bundle=bundle, root_cause=root_cause, root_cause_requested=root_cause_requested,
                           root_cause_error=root_cause_error, error_class=error_class, telemetry=telemetry, stage_status=stage_status)
            notice = unrefreshed_report_notice(root)
            if notice:
                print("Warning: " + notice, file=sys.stderr)
            return None
        prepare_cve_report(options, output_dir, cve_id, input_root=input_root)
        view = _Projection()
        data = {"native_exit_status": status, "recorded_error_class": view.scalar(error_class),
                "recorded_error_detail": view.scalar(error_detail), "bundle": None, "root_cause": None}
        metrics = _metrics(view, status, bundle, root_cause, telemetry)
        stages = _stages(view, stage_status)
        if isinstance(stage_status, dict):
            data["observed_stages"] = []
            for name, record in islice(stage_status.items(), 100):
                stage_name = str(view.scalar(str(name)))
                data["observed_stages"].append({"name": stage_name, "details": view.mapping(record)})
            data["stages_omitted"] = max(0, len(stage_status) - 100)
            view.limited |= bool(data["stages_omitted"])
        if bundle is not None:
            data["bundle"] = {"repository_url": view.scalar(bundle.repo_ref.repository_url),
                              "parent_commit": view.scalar(bundle.commit_before), "fix_commit": view.scalar(bundle.commit_after),
                              "shape": view.scalar(bundle.shape), "canonical_score": view.scalar(bundle.repo_ref.canonical_score),
                              "files_changed": bundle.files_changed, "recorded_diff_bytes": bundle.bytes_size,
                              "files_captured": [{"path": view.scalar(file.path), "is_test": file.is_test, "hunks": file.hunks_count}
                                                 for file in bundle.files[:100]],
                              "file_records_omitted": max(0, len(bundle.files) - 100)}
            view.limited |= bool(data["bundle"]["file_records_omitted"])
            consensus = bundle.consensus
            if isinstance(consensus, dict):
                data["pointer_consensus"] = {"fields": view.mapping(consensus, exclude=("methods",)),
                                             "methods": view.sequence(consensus.get("methods"), records=True)}
            agreement = bundle.extraction_agreement
            if isinstance(agreement, dict):
                data["extraction_agreement"] = {"recorded_verdict": view.scalar(agreement.get("verdict")),
                                                "sources": view.sequence(agreement.get("sources"), records=True),
                                                "outliers": view.sequence(agreement.get("outliers")),
                                                "pairwise": view.pairs(agreement.get("pairwise"))}
        if root_cause is not None:
            data["root_cause"] = {name: view.scalar(getattr(root_cause, name)) for name in
                                  ("cwe_id", "vulnerability_type", "summary", "confidence", "model_id", "input_tokens", "output_tokens")}
            data["root_cause"].update({"why_chain": view.sequence(root_cause.why_chain),
                                        "affected_functions": view.sequence(root_cause.affected_functions)})
        if root_cause_requested or root_cause is not None:
            stages.append(StageEnvelope("root-cause analysis", "completed" if root_cause is not None else "failed" if root_cause_error else "unknown",
                                        producer="cve-diff", reason=str(view.scalar(root_cause_error))))
        if isinstance(telemetry, dict):
            public_fields = ("cost_usd", "tokens", "elapsed_s", "iterations", "llm_retries")
            data["discovery_telemetry"] = {"fields": {key: view.scalar(telemetry[key]) for key in public_fields if key in telemetry},
                                            "tool_names": view.sequence(telemetry.get("tool_calls")),
                                            "fields_not_projected": len(telemetry) - sum(key in telemetry for key in (*public_fields, "tool_calls"))}
        else:
            data["discovery_telemetry"] = {"recorded": False}
        data["capture_limited"] = view.limited
        notes = ["This is one captured CVE-diff attempt; no discovery, extraction, consensus or model call was repeated for reporting.",
                 "Root-cause confidence and agreement are recorded observations, not vulnerability validation verdicts. Failure to produce a diff is not proof of absence of a fix.",
                 "Raw diff/source bodies and tool-call argument/prompt collections are not copied. Native artifacts retain the command's original output when emitted; reserved paths are not evidence of a successful write.",
                 "Discovery telemetry is a recorded agent observation; other attempts and separately requested root-cause work may incur additional cost. No complete monetary total is inferred.",
                 "Lists are capped at 100, scalar maps at 20 fields, strings at 2000 characters and total captured input text at 200000 characters. Nested values are omitted from scalar rows; omission counts are explicit.",
                 "Lifecycle identity was not captured by this hook; historical directory metadata is not adopted."]
        notes.append("Only observed pipeline stage statuses are captured; missing stages are not implicitly passed.")
        if view.limited:
            notes.append("Portable capture is limited; omitted fields and rows are not zero-valued observations.")
        if bundle is None:
            notes.append("No current diff bundle was captured; file and diff-byte populations are unavailable, not zero.")
        state = "failed" if status else "partial" if view.limited or any(stage.state in {"failed", "unknown"} for stage in stages) else "completed"
        result = NativeResult("cve-diff", cve_id, "unknown", data, state=state, stages=stages, metrics=metrics,
                              diagnostics=notes, artifacts=[{"path": str(path.resolve()), "role": "reserved native artifact path; contents not imported"}
                                                           for path in _native_paths(output_dir, cve_id)])
        if options.output is not None:
            root = options.output if options.output.is_dir() or not options.output.suffix else options.output.parent / ("." + options.output.stem + "-report")
        return complete_native_result(result, root, stem="cve-diff-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError, ValidationError) as exc:
        print("Optional CVE-diff report unavailable (" + type(exc).__name__ + "); native result retained", file=sys.stderr)
        return None
