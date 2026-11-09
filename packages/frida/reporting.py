"""Portable capture receipts without copying sensitive instrumentation payloads."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.log_sanitisation import sanitise_for_terminal
from core.security.redaction import redact_secrets


def _safe(value):
    if isinstance(value, str):
        return sanitise_for_terminal(redact_secrets(value), max_len=1000)
    if isinstance(value, dict):
        return {key: _safe(item) for key, item in value.items()}
    return value


def frida_result(args, cfg, result, status):
    # RunConfig contains executed JavaScript; never serialize it wholesale.
    metadata = asdict(result) if result is not None else None
    payload = {"native exit status": status, "target": asdict(cfg.target),
               "script origin": cfg.script_origin, "requested duration seconds": cfg.duration_sec,
               "requested module": args.module, "effective spawn": cfg.spawn or bool(cfg.target.binary),
               "unsafe attach requested": cfg.unsafe_attach, "follow children": cfg.follow_children,
               "device selection": {"remote host": cfg.host, "USB requested": cfg.use_usb},
               "capture result": metadata}
    state = "completed" if status == 0 else "failed"
    metrics = {"Native exit status": status, "Events captured": result.events_captured if result else None,
               "Elapsed seconds": result.duration_actual_sec if result else None,
               "Setup seconds": result.setup_sec if result else None,
               "Children observed": result.children_observed if result else None,
               "Flushes completed": result.flushes_completed if result else None}
    notes = ["Event counts are observations from this instrumentation session, not vulnerability verdicts. Zero captured events do not establish that a sink is unreachable or safe.",
             "Receipt excludes raw event arguments, executed JavaScript and seed bytes. Post-run seed/IO assessments remain in their native artifacts; reporting does not repeat them."]
    if result is None:
        notes.append("Frida was unavailable; capture results and counts are unavailable, not zero.")
    root = Path(args.out).resolve()
    artifacts = [{"path": str(root / name)} for name in ("metadata.json", "frida-report.md", "events.jsonl", "script.js",
                                                          "seeds-manifest.json", "coverage.drcov", "io-correlation.json")]
    for path in (cfg.target.binary, args.script, args.sink_watch, args.stdin_file):
        if path:
            artifacts.append({"path": str(Path(path).resolve())})
    return NativeResult("frida", _safe(cfg.target.raw), "frida", _safe(payload), state=state,
                        diagnostics=notes, metrics=metrics, artifacts=artifacts,
                        stages=[StageEnvelope("dynamic capture", state, producer="frida")])


def complete_frida_report(args, cfg, result, status):
    options = args._report_options
    output = options.output
    root = Path(args.out)
    if output is not None:
        root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
    try:
        return complete_native_result(frida_result(args, cfg, result, status), root,
                                      stem="frida-capture-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print("Optional Frida report unavailable (" + type(error).__name__ + "); native result retained", file=sys.stderr)
        return None
