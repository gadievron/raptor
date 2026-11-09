"""Portable registry reachability evidence; no additional network activity."""
from __future__ import annotations

import sys
from dataclasses import asdict

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.prompt_output_sanitise import sanitise_string
from core.security.redaction import redact_secrets


def health_result(results, *, offline=False):
    rows = []
    for result in results:
        row = asdict(result)
        if row["error"]:
            row["error"] = sanitise_string(redact_secrets(row["error"]), max_chars=500)
        rows.append(row)
    passed = sum(result.ok for result in results)
    failed = len(results) - passed
    state = "failed" if offline else "partial" if failed else "completed"
    notes = ["Registry reachability is a point-in-time observation, not a vulnerability or package-safety verdict."]
    if offline:
        notes.append("Offline mode was refused. No live registry probes ran; reachability is unavailable.")
    return NativeResult("sca-health", "configured package registries", "sca-health",
                        {"probes": rows, "offline refused": offline}, state=state,
                        diagnostics=notes, stages=[StageEnvelope("registry reachability", state, producer="sca")],
                        metrics={"Probes completed": len(results), "Reachable registries": passed,
                                 "Failed registry probes": failed})


def complete_health_report(options, results, *, offline=False):
    output = options.output
    root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
    try:
        return complete_native_result(health_result(results, offline=offline), root,
                                      stem="sca-health", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print("Optional health report unavailable (" + type(error).__name__ + "); native result retained", file=sys.stderr)
        return None
