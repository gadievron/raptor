"""Portable receipts over already-computed fingerprints and drift models."""
from __future__ import annotations

from dataclasses import asdict
import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.redaction import redact_secrets

DETAIL_LIMIT = 100


def _fingerprint_view(fingerprint):
    if fingerprint is None:
        return None
    data = fingerprint.to_dict()
    buckets = data["capability_buckets"]
    data["recorded import counts"] = {name: len(values) for name, values in buckets.items()}
    data["capability_buckets"] = {name: values[:DETAIL_LIMIT] for name, values in buckets.items()}
    data["binary_path"] = redact_secrets(data["binary_path"])
    return data


def fingerprint_result(args, fp_input, store_dir, status):
    from core.binary.fingerprint_store import _ref_filename
    capture = args._report_capture
    mode = "check" if args.check else "save" if args.save else "compute"
    ref = args.ref or str(fp_input[1])
    drift = capture.get("drift")
    delta = asdict(drift) if drift is not None else None
    if delta is not None:
        for key in ("new_buckets", "removed_buckets"):
            entries = delta[key]
            delta[key + " recorded import counts"] = {name: len(values) for name, values in entries.items()}
            delta[key] = {name: values[:DETAIL_LIMIT] for name, values in entries.items()}
    state = "failed" if status == 3 else "partial" if status == 2 else "completed"
    notes = ["Fingerprint and drift observations describe binary capabilities, not exploitability or malicious intent.",
             "Import details are bounded to 100 entries per bucket; recorded counts retain full totals."]
    if status == 2:
        notes.append("No usable baseline was loaded. Drift is unavailable, not absent.")
    if status == 3:
        notes.append("Fingerprinting, baseline persistence or native output did not complete; retain the native infrastructure-failure status.")
    payload = {"mode": mode, "ref": redact_secrets(ref), "native exit status": status,
               "current fingerprint": _fingerprint_view(capture.get("fingerprint")),
               "baseline used": _fingerprint_view(capture.get("baseline")),
               "baseline written": capture.get("baseline_written"), "drift": delta}
    metrics = {"Mode": mode, "Native exit status": status,
               "Drift available": drift is not None,
               "Drift detected": not drift.is_empty() if drift is not None else "unavailable"}
    artifacts = []
    if fp_input[0] == "path":
        artifacts.append({"path": str(fp_input[1])})
    if args.out:
        artifacts.append({"path": args.out})
    if args.check or args.save:
        artifacts.append({"path": str(store_dir / _ref_filename(ref))})
    return NativeResult("sca-fingerprint", redact_secrets(args.target), "sca-fingerprint", payload,
                        state=state, diagnostics=notes, metrics=metrics, artifacts=artifacts,
                        stages=[StageEnvelope("fingerprint " + mode, state, producer="sca")])


def complete_fingerprint_report(args, fp_input, store_dir, status):
    output = args._report_options.output
    root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
    try:
        return complete_native_result(fingerprint_result(args, fp_input, store_dir, status), root,
                                      stem="sca-fingerprint", options=args._report_options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print("Optional fingerprint report unavailable (" + type(error).__name__ + "); native status retained", file=sys.stderr)
        return None
