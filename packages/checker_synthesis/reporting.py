"""Bounded portable receipts from the bridge's existing native JSON result."""
from __future__ import annotations

from pathlib import Path
import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.prompt_output_sanitise import sanitise_string
from core.security.redaction import redact_secrets

DETAIL_LIMIT = 50


def _safe(value):
    if isinstance(value, str):
        return sanitise_string(redact_secrets(value), max_chars=2000)
    if isinstance(value, dict):
        return {key: _safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe(item) for item in value[:DETAIL_LIMIT]]
    return value


def bridge_result(args, native, status, *, error=None):
    notes = ["Proposed rules, mechanical controls, matches and LLM triage are separate observations. Matches are not confirmed vulnerabilities; promotion is recorded only from native promoted_rule_ids.",
             "Receipt captures up to 50 entries per detail list and 2000 characters per text field, excludes executable rule bodies, and retains full recorded totals."]
    if native is None:
        payload = {"native exit status": status, "unavailable reason": error}
        metrics = {"Native exit status": status, "Derived seeds": None}
        results = []
        state = "failed"
        notes.append("No checker result was produced; synthesis/control/promotion outcomes are unavailable, not successful or empty.")
    else:
        notes.append("Native JSON/rule files remain the full native output.")
        results = native["results"]
        rows = []
        for result in results[:DETAIL_LIMIT]:
            row = dict(result)
            if result.get("rule") is not None:
                row["rule"] = {key: value for key, value in result["rule"].items() if key != "body"}
            row["recorded detail counts"] = {key: len(result.get(key, [])) for key in ("matches", "triage", "errors")}
            rows.append(row)
        metrics = {"Native exit status": status, "Derived seeds": native["seeds_derived"],
                   "Recorded seed results": len(results), "Proposed rules": sum(row.get("rule") is not None for row in results),
                   "Recorded promoted rule IDs": len(native["promoted_rule_ids"]),
                   "Recorded matches": sum(len(row.get("matches", [])) for row in results),
                   "Results with native match caps": sum(bool(row.get("capped")) for row in results),
                   "Recorded errors": len(native["errors"]) + sum(len(row.get("errors", [])) for row in results)}
        payload = {**native, "results": rows, "native exit status": status, "recorded counts": metrics}
        state = "partial" if metrics["Recorded errors"] or any(row.get("rule") is None for row in results) else "completed"
    payload["requested synthesis policy"] = {"CWE override": args.cwe, "maximum seeds": args.max_seeds,
                                               "maximum refinement iterations": args.max_iterations,
                                               "promotion requested": not args.no_promote}
    artifacts = [{"path": str(path.resolve())} for path in Path(args.output_dir).glob("*.osv.json")]
    for result in results:
        if result.get("rule_path"):
            artifacts.append({"path": str(result["rule_path"])})
        seed = result.get("seed") or {}
        if seed.get("file"):
            artifacts.append({"path": str((Path(args.repo) / seed["file"]).resolve())})
    return NativeResult("cve-checker", str(Path(args.repo).resolve()), "cve-checker", _safe(payload), state=state,
                        diagnostics=notes, metrics=metrics, artifacts=artifacts,
                        stages=[StageEnvelope("CVE checker bridge", state, producer="checker-synthesis")])


def complete_bridge_report(args, native, out_dir, status, *, error=None):
    options = args._report_options
    output = options.output
    root = out_dir
    if output is not None:
        root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
    try:
        from .library import _default_library_dir
        library = (Path(args.library_dir) if args.library_dir else _default_library_dir()).resolve()
        destinations = [Path(root)] + ([output] if output is not None else [])
        if any(path.resolve().is_relative_to(library) for path in destinations):
            raise ValueError("Report output belongs to the persistent rule library")
        return complete_native_result(bridge_result(args, native, status, error=error), root,
                                      stem="cve-checker-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as failure:
        print("Optional checker report unavailable (" + type(failure).__name__ + "); native result retained", file=sys.stderr)
        return None
