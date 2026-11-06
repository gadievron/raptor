"""Offline reporting: python -m core.reporting {sarif,render,delta}."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from core.json import load_json
from core.security.log_sanitisation import sanitise_for_terminal
from .adapters import context_from_sarif, native_findings
from .delta import build_delta
from .document import MAX_JSON_BYTES, ReportContext
from .options import add_report_arguments, options_from_args
from .service import complete_reporting
from .writer import load_context, regenerate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic offline RAPTOR reporting; no analysis or LLM calls")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capabilities", help="List exact integrated command boundaries and available formats as JSON; no analysis or file writes")
    sarif = sub.add_parser("sarif", help="Create an Unconfirmed triage report from explicit SARIF inputs")
    sarif.add_argument("inputs", nargs="+", type=Path)
    sarif.add_argument("--target", default="")
    sarif.add_argument("--out", required=True, type=Path)
    add_report_arguments(sarif)
    native = sub.add_parser("native", help="Adapt an existing workflow JSON finding array without rerunning analysis")
    native.add_argument("input", type=Path)
    native.add_argument("--findings-key", default="findings", help="Top-level findings array field; '.' means root array; '-' means a result without a finding population")
    native.add_argument("--kind", default="imported")
    native.add_argument("--target", default="")
    native.add_argument("--out", required=True, type=Path)
    native.add_argument("--recorded-verdicts", action="store_true", help="Display recorded claims with imported provenance, not evidence of validation by this run")
    add_report_arguments(native)
    for capture in (sarif, native):
        capture.add_argument("--run-id", default="", help="Explicit originating run identity; defaults to output directory name")
        capture.add_argument("--pass-id", default="", help="Explicit logical pass identity; never inferred from timestamps")
        capture.add_argument("--attempt-id", default="", help="Explicit execution attempt identity")
        capture.add_argument("--parent", action="append", default=[], help="Parent snapshot identity (repeatable; recorded claim, not inferred supersession)")
    render = sub.add_parser("render", help="Rerender a captured document without live workflow state")
    render.add_argument("document", type=Path)
    render.add_argument("--format", default="markdown")
    render.add_argument("--output", required=True, type=Path)
    delta = sub.add_parser("delta", help="Compare two explicit report-context snapshots")
    delta.add_argument("baseline", type=Path)
    delta.add_argument("candidate", type=Path)
    delta.add_argument("--out", required=True, type=Path)
    delta.add_argument("--lineage", type=Path, help="Explicit JSON mapping of candidate occurrence refs to baseline refs")
    add_report_arguments(delta)
    args = parser.parse_args(argv)
    try:
        if args.command == "capabilities":
            from .capabilities import command_capabilities
            print(json.dumps(command_capabilities(), sort_keys=True, ensure_ascii=True))
            return 0
        if args.command == "render":
            for note in regenerate(args.document, args.output, format=args.format):
                print(sanitise_for_terminal(note, max_len=1000), file=sys.stderr)
            return 0
        options = options_from_args(args, parser)
        document = None
        if args.command == "sarif":
            context = context_from_sarif(args.inputs, target=args.target, run_id=args.run_id or args.out.name,
                                         pass_id=args.pass_id, attempt_id=args.attempt_id, parents=args.parent)
        elif args.command == "native":
            payload = load_json(args.input, max_bytes=MAX_JSON_BYTES)
            findings = payload if args.findings_key == "." else payload.get(args.findings_key) if isinstance(payload, dict) else None
            if args.findings_key == "-":
                findings = None
            if args.findings_key != "-" and not isinstance(findings, list):
                raise ValueError("Selected workflow findings field is not an array")
            if payload is None:
                raise ValueError("Workflow data could not be loaded")
            context = ReportContext(args.kind, args.run_id or args.out.name, target=args.target, state="unknown",
                                    pass_id=args.pass_id, attempt_id=args.attempt_id, parents=args.parent,
                                    findings=native_findings(findings or [], run_id=args.run_id or args.out.name, producer="imported", triage=not args.recorded_verdicts,
                                                             pass_id=args.pass_id, attempt_id=args.attempt_id),
                                    artifacts=[{"path": str(args.input)}],
                                    extensions={"raptor.imported": payload, "raptor.findings_available": args.findings_key != "-"},
                                    diagnostics=["Imported workflow data; recorded verdicts, when requested, are source claims, not local validation."])
            from .builders import build_document
            from .results import result_blocks
            document = build_document(context, blocks=result_blocks(payload, title="Recorded workflow data"))
        else:
            before = load_context(args.baseline)
            after = load_context(args.candidate)
            lineage = load_json(args.lineage, max_bytes=1024 * 1024) if args.lineage else None
            if args.lineage and lineage is None:
                raise ValueError("Requested lineage mapping could not be loaded")
            if lineage is not None and (not isinstance(lineage, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in lineage.items())):
                raise ValueError("Lineage must map candidate occurrence strings to baseline occurrence strings")
            context, document = build_delta(before, after, lineage=lineage)
        result = complete_reporting(context, args.out, document=document, options=options, stream=sys.stdout)
        return 1 if result.errors or (args.command == "sarif" and not context.artifacts) else 0
    except (OSError, ValueError, TypeError) as exc:
        print("Reporting failed: " + sanitise_for_terminal(str(exc), max_len=1000), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
