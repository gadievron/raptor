"""Explicit input contracts for SARIF triage and native workflow results."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from core.sarif.parser import (
    get_result_rule, get_tool_name, load_sarif, parse_sarif_document,
)
from .document import MAX_FINDINGS, ReportContext, StageEnvelope, digest, json_value
from core.run.finding_status import read_verdict
from .formatting import get_display_status

MAX_INPUT_BYTES = 128 * 1024 * 1024


def read_json_artifact(root: Path, path: Path):
    """Capture implicit run-owned JSON without following planted symlinks.

    Operator-selected files and authenticated checklist accessors keep their
    own policies. This reader is for report enrichment from child-writable runs.
    """
    import logging
    import os
    from core.json.bounded import loads_bounded
    from core.source.beneath import open_regular_beneath
    from .document import MAX_JSON_BYTES
    stream = open_regular_beneath(root, path.relative_to(root), mode="rb")
    if stream is None:
        return None
    try:
        with stream:
            if os.fstat(stream.fileno()).st_size > MAX_JSON_BYTES:
                raise ValueError("Reporting artifact exceeds capture limit")
            raw = stream.read(MAX_JSON_BYTES + 1)
        return loads_bounded(raw, max_bytes=MAX_JSON_BYTES)
    except (OSError, ValueError, RecursionError) as exc:
        logging.getLogger(__name__).warning("Reporting artifact refused (%s)", type(exc).__name__)
        return None


def apply_scan_metrics(context: ReportContext, metrics: dict) -> None:
    """Capture invocation-local accounting without treating zero findings as success.

    Accept both older producers and main's execution/coverage additions. Never
    rediscover coverage files: an explicitly empty snapshot remains empty.
    """
    captured = json_value(metrics)
    context.extensions["raptor.scan_metrics"] = captured
    failures = (
        "semgrep_failed_packs", "dropped_registry_packs", "sarif_merge_failed",
        "analysis_gaps", "semgrep_dropped_files", "codeql_no_output",
        "tool_execution_failures", "tool_coverage_limitations", "sarif_input_errors",
        "semgrep_metadata_errors", "semgrep_partial_files",
    )
    recorded = captured.get("execution_status")
    limited = any(captured.get(key) for key in failures)
    if "execution_status" in captured or limited:
        status = "error" if recorded == "error" else "partial" if limited or recorded != "ok" else "ok"
        context.extensions.setdefault("raptor.metrics", {})["Scan execution"] = status
        if status != "ok":
            context.diagnostics.append(f"Scan execution: {status}; findings do not establish complete scanner coverage")
            if context.state not in {"failed", "cancelled"}:
                context.state = "partial"
    for key in failures:
        value = captured.get(key)
        if value:
            context.diagnostics.append(f"Recorded scan limitation: {key}; details retained in scan metrics")


def stages_from_phases(phases: dict, *, producer: str, run_id: str = "") -> list[StageEnvelope]:
    """Adapt explicit execution claims, preserving unknown/contradictory states."""
    result = []
    for name, raw in phases.items():
        phase = raw if isinstance(raw, dict) else {}
        original = phase.get("status") or phase.get("state")
        state = original if original in ("pending", "running", "completed", "partial", "failed", "cancelled", "skipped", "unknown") else "unknown"
        error = phase.get("error")
        has_error = bool(error) if isinstance(error, (str, dict, list)) else False
        notes = []
        if phase.get("completed") is True:
            state = "partial" if has_error or phase.get("enabled") is False else "completed"
            if state == "partial":
                notes.append("Phase completion conflicts with a recorded error or disabled state")
        elif has_error:
            state = "failed"
        elif phase.get("skipped") is True or phase.get("enabled") is False or phase.get("skipped_reason"):
            state = "skipped"
        duration = phase.get("duration_seconds")
        if not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration < 0:
            duration = None
        result.append(StageEnvelope(str(name), state, producer=producer, run_id=run_id,
                                    original_state=original if isinstance(original, str) else "",
                                    reason=error if isinstance(error, str) else str(phase.get("skipped_reason") or ""),
                                    duration_seconds=duration, diagnostics=notes, extensions={"raptor.phase": json_value(raw)}))
    return result


def native_findings(findings: list[dict], *, run_id: str, producer: str, triage: bool = False,
                    pass_id: str = "", attempt_id: str = "") -> list[dict]:
    """Keep original evidence, map display fields, and never infer verdicts."""
    if len(findings) > MAX_FINDINGS:
        raise ValueError("Too many native findings to capture a complete report")
    source_digest = digest(findings)
    result = []
    seen: set[str] = set()
    for i, raw in enumerate(findings):
        if not isinstance(raw, dict):
            raise ValueError(f"findings[{i}]: expected an object")
        f = json_value(raw, f"$.findings[{i}]")
        local_id = f.get("finding_id") or f.get("id")
        ref = f"native:{producer}:{run_id}:{pass_id}:{attempt_id}:{source_digest}:{i}"
        notes = []
        if local_id is not None and (isinstance(local_id, bool) or not isinstance(local_id, (str, int))):
            local_id = None
            notes.append("Unsupported source finding ID shape retained in native evidence")
        if isinstance(local_id, str):
            if local_id in seen:
                notes.append("Duplicate producer-local finding ID; retained as a distinct occurrence")
            seen.add(local_id)
        line = f.get("line") or f.get("start_line") or f.get("startLine")
        line = line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None
        file = f.get("file") or f.get("file_path") or ""
        severity = f.get("severity") or f.get("severity_assessment")
        if severity is not None and not isinstance(severity, str):
            severity = None
            notes.append("Unsupported security severity shape retained in native evidence")
        normalized = {
            "occurrence_ref": ref, "source_id": local_id,
            "tool": str(f.get("tool") or producer),
            "rule_id": str(f.get("rule_id") or f.get("vuln_type") or "unknown"),
            "message": str(f.get("message") or f.get("description") or f.get("vuln_type") or ""),
            "file": file if isinstance(file, str) else "", "line": line,
            "scanner_level": f.get("level") if isinstance(f.get("level"), str) else None, "severity": severity,
            "status": "Unconfirmed" if triage else get_display_status(f),
            "verdict_origin": "none" if triage else producer,
            "suppressed": read_verdict(f, "suppressed") is True,
            "diagnostics": notes, "native": f,
        }
        result.append(normalized)
    return result


def context_from_sarif(paths: list[Path], *, kind: str = "scan", target: str = "", run_id: str = "",
                       stages: list[StageEnvelope] | None = None, max_findings: int = MAX_FINDINGS,
                       pass_id: str = "", attempt_id: str = "", parents: list[str] | None = None) -> ReportContext:
    """Capture raw scanner claims as Unconfirmed, with typed input failures.

    Caller supplies authoritative artifacts (combined OR components). No globbing,
    source reads, URI fetching, or acceptance of imported verdict-shaped fields.
    """
    if not 1 <= max_findings <= MAX_FINDINGS:
        raise ValueError("Invalid reporting finding limit")
    context = ReportContext(kind=kind, run_id=run_id, target=target, stages=list(stages or []),
                            pass_id=pass_id, attempt_id=attempt_id, parents=list(parents or []))
    budget = 0
    observed = 0
    skipped = 0
    capped = False
    seen_digests: set[str] = set()
    for path in paths:
        path = Path(path)
        try:
            size = path.stat().st_size
            budget += size
            if budget > MAX_INPUT_BYTES:
                raise ValueError("Aggregate SARIF input limit exceeded")
            metadata: dict[str, Any] = {}
            data = load_sarif(path, metadata=metadata)
            if data is None or data.get("version") != "2.1.0" or not isinstance(data.get("runs"), list):
                raise ValueError("Invalid SARIF 2.1.0 document")
            budget += metadata["size_bytes"] - size
            if budget > MAX_INPUT_BYTES:
                raise ValueError("Aggregate SARIF input limit exceeded during read")
            # Same guarded read supplies bytes provenance and parsed content.
            identity = metadata["sha256"]
            if identity in seen_digests:
                context.diagnostics.append(f"Duplicate SARIF input omitted: {path.name}")
                continue
            seen_digests.add(identity)
            from .lifecycle import input_digest
            context.artifacts.append({"path": str(path), "digest": identity, "digest_kind": "sha256-bytes", "media_type": "application/sarif+json",
                                      "canonical_digest": input_digest(data)})
            runs = data["runs"]
            prepared: list[dict[str, Any]] = []
            remaining = max_findings - len(context.findings)
            for ri, run in enumerate(runs):
                if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
                    context.diagnostics.append(f"{path.name}: invalid run {ri}")
                    skipped += 1
                    prepared.append({"results": []})
                    continue
                clean: list[dict[str, Any] | None] = []
                observed += len(run.get("results", []))
                for result in run.get("results", []):
                    if remaining <= 0:
                        capped = True
                        break
                    if not isinstance(result, dict):
                        skipped += 1
                        clean.append(None)
                        continue
                    remaining -= 1
                    item = deepcopy(result)
                    rule = get_result_rule(run, result)
                    item.setdefault("ruleId", rule.get("id", "unknown"))
                    msg = item.get("message")
                    if isinstance(msg, dict) and not isinstance(msg.get("text"), str) and isinstance(msg.get("markdown"), str):
                        item["message"] = {"text": msg["markdown"]}
                    # Resolve artifact indices without opening referenced files.
                    locations = item.get("locations")
                    for loc in locations if isinstance(locations, list) else []:
                        if not isinstance(loc, dict):
                            continue
                        physical = loc.get("physicalLocation")
                        artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
                        artifacts = run.get("artifacts", [])
                        if isinstance(artifact, dict) and "uri" not in artifact and isinstance(artifact.get("index"), int):
                            index = artifact["index"]
                            if isinstance(artifacts, list) and 0 <= index < len(artifacts) and isinstance(artifacts[index], dict):
                                location = artifacts[index].get("location")
                                if isinstance(location, dict):
                                    artifact.update(location)
                    clean.append(item)
                prepared.append({**run, "results": clean})
                invocations = run.get("invocations", [])
                for inv in invocations if isinstance(invocations, list) else []:
                    if isinstance(inv, dict) and inv.get("executionSuccessful") is False:
                        context.diagnostics.append(f"{get_tool_name(run)}: scanner invocation failed")
                # Keep source arrays aligned so exact occurrence references survive.
            normalized = parse_sarif_document({**data, "runs": prepared}, include_occurrences=True)
            for f in normalized:
                ri, ix = f["sarif_run_index"], f["sarif_result_index"]
                original = runs[ri]["results"][ix]
                rule = get_result_rule(runs[ri], original)
                properties = rule.get("properties") or {}
                severity = properties.get("security-severity") if isinstance(properties, dict) else None
                try:
                    severity = json_value(severity)
                except ValueError:
                    severity = None
                    context.diagnostics.append("Invalid scanner security score omitted")
                # Scores stay scores. SARIF warning/error is not a CVSS band.
                result_properties = original.get("properties")
                nosemgrep = result_properties.get("nosemgrep") if isinstance(result_properties, dict) else None
                suppressions = original.get("suppressions")
                suppressed = (isinstance(nosemgrep, dict) and nosemgrep.get("suppressed") is True) or (
                    isinstance(suppressions, list) and any(isinstance(s, dict) and (s.get("status") is None or s.get("status") == "accepted") for s in suppressions)
                )
                context.findings.append({
                    "occurrence_ref": f"sarif:{identity}:{ri}:{ix}",
                    "source_id": f["finding_id"], "tool": f["tool"], "rule_id": f["rule_id"],
                    "message": f["message"] or "", "file": f["file"] or "", "line": f["startLine"] if f["startLine"] and f["startLine"] > 0 else None,
                    "scanner_level": f["level"], "severity": None, "security_score": severity,
                    "status": "Unconfirmed", "verdict_origin": "none",
                    "suppressed": suppressed,
                    "cwe_id": f.get("cwe_id"), "dataflow_path": f.get("dataflow_path"),
                    "snippet": f.get("snippet", ""),
                    "function": f.get("function"), "rule_scope": f.get("rule_scope"),
                    "end_line": f.get("endLine"), "start_column": f.get("startColumn"),
                    "end_column": f.get("endColumn"),
                })
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            context.diagnostics.append(f"{path.name}: could not capture SARIF ({type(exc).__name__})")
            skipped += 1
    if not paths:
        context.diagnostics.append("No SARIF artifacts available; scanner coverage is unknown")
    if skipped:
        context.diagnostics.append(f"{skipped} invalid input/run/result(s) omitted")
    if capped:
        context.diagnostics.append(f"Report truncated: captured {len(context.findings)} of {observed} observed results")
    context.extensions["raptor.accounting"] = {"observed_results": observed, "captured_results": len(context.findings)}
    failed = any(s.state in {"failed", "partial", "unknown", "cancelled"} for s in context.stages)
    context.state = "partial" if context.diagnostics or failed else ("completed" if context.stages else "unknown")
    return context
