"""Typed, offline SBOM presentations; domain inventories and verdicts stay owned here."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
from pathlib import Path
import sys

from core.json import dumps_canonical
from core.security.log_sanitisation import sanitise_for_terminal
from core.reporting.builders import build_document
from core.reporting.document import Block, ReportContext, ReportDocument, StageEnvelope
from core.reporting.options import options_from_args
from core.reporting.renderers import render_document
from core.reporting.results import result_blocks
from core.reporting.service import complete_reporting
from core.reporting.summary import build_operator_summary, render_operator_summary

FORMATS = ("markdown", "json", "xml")
MAX_CAPTURE_RECORDS = 1000
MAX_CAPTURE_BYTES = 4 * 1024 * 1024


def add_arguments(parser):
    parser.add_argument("--report-format", action="append", choices=FORMATS,
                        help="Additional human report format; repeat for multiple outputs (default: markdown)")
    parser.add_argument("--report-output", type=Path,
                        help="Report file or directory; required for saved reports without --out")
    parser.add_argument("--no-report", action="store_true",
                        help="Disable additional full reports; retain native exports and operator summaries")


def report_options(args):
    options = options_from_args(args)
    if any(format not in FORMATS for format in options.formats):
        raise ValueError("SBOM reports support markdown, json and xml")
    if args.report_format and not (args.report_output or args.out):
        raise ValueError("--report-format requires --report-output or --out")
    return options


def _display(value):
    return value[:4096] + " [truncated; native exports retain the full value]" if isinstance(value, str) and len(value) > 4096 else value


def _table(title, values):
    return Block("table", title=title, columns=["Check", "Count"],
                 rows=[[_display(key.replace("_", " ")), _display("not assessed" if value is None else value)] for key, value in values.items()])


def _notes(title, values):
    return Block("list", title=title, items=[_display(value) for value in values])


def inventory_capture(inventory, records):
    """Bound optional report data; native streamed inventories remain authoritative."""
    captured, size, selection = [], 0, hashlib.sha256()
    for row in records:
        selection.update(dumps_canonical([row.scope, row.id]).encode("utf-8"))
        if len(captured) >= MAX_CAPTURE_RECORDS:
            continue
        value = asdict(row)
        encoded = dumps_canonical(value).encode("utf-8")
        if size + len(encoded) > MAX_CAPTURE_BYTES:
            continue
        captured.append(value)
        size += len(encoded)
    coverage = inventory.coverage
    # An aggregate may carry a large file catalogue. Preserve its fingerprint
    # instead of silently dropping the authoritative receipt or copying it all.
    if coverage is not None and len(dumps_canonical(coverage).encode("utf-8")) > MAX_CAPTURE_BYTES:
        coverage = {"capture": "omitted", "sha256": hashlib.sha256(dumps_canonical(coverage).encode("utf-8")).hexdigest()}
    return {"source_format": inventory.source_format, "source_sha256": inventory.source_sha256,
            "subject": inventory.subject, "summary": inventory.summary(),
            "notice_verification": inventory.notice_verification, "coverage": coverage,
            "selection_sha256": selection.hexdigest(), "selected_records": len(records),
            "captured_records": len(captured), "records": captured}


def inventory_blocks(inventory, records, *, limit=50, offset=0):
    summary = {("package declarations unresolved" if key == "unresolved_declarations" else key):
               "not assessed" if value is None else value for key, value in inventory.summary().items()}
    blocks = [_table("Inventory totals (all supplied records)", summary),
              Block("paragraph", text="Counts describe the supplied package/source/subject records and file totals; the table below contains the selection. Source candidates are not confirmed installed components. Notice text is not legal review."),
              Block("paragraph", text="Notice verification: " + inventory.notice_verification)]
    if inventory.coverage:
        metrics = inventory.coverage.get("metrics") or {}
        blocks.extend([Block("paragraph", text="Executable ownership checks outstanding: " + str(metrics.get("unidentified_executables", "not assessed")) + "."),
                       Block("paragraph", text="Source/build assessments with warnings: " + str(metrics.get("source_gap_packages", "not assessed")) + ".")])
    shown = records[offset:] if limit is None else records[offset:offset + limit]
    blocks.append(Block("table", title="Selected inventory", columns=["Scope", "Package", "Version", "Licence declarations", "Notice evidence"],
                        rows=[[_display(value) for value in (row.scope, row.name, row.version, "; ".join(row.declarations) or "not declared", row.notice_status)] for row in shown]))
    if len(shown) < len(records):
        blocks.append(Block("paragraph", text=f"Showing rows {min(offset + 1, len(records))}–{min(offset + len(shown), len(records))} of {len(records)} selected records; native CSV/JSONL and selected-record JSON contain the full selection. Inventory JSON retains all records plus selection references."))
    blocks.append(_notes("Coverage notes", inventory.diagnostics[:50]))
    return blocks


def plan_blocks(report, *, limit=50):
    rows = [row for row in report["packages"] if row["advisories"] or row["gaps"]]
    shown = rows if limit is None else rows[:limit]
    blocks = [Block("paragraph", text="Mode: " + report["mode"]),
              Block("paragraph", text="Proposals require review. A missing finding is not proof of complete advisory coverage."),
              _table("Summary", report["summary"]),
              Block("table", title="Proposed targets", columns=["Package", "Installed", "Proposed", "Target scope", "Status"],
                    rows=[[row["name"], row["installed_version"], row["proposed_version"] or "unavailable", row["target_scope"], row["status"]] for row in shown])]
    for row in shown:
        children = [_notes("Gaps", row["gaps"])]
        for candidate in row["candidates"]:
            empty = "none recorded" if candidate["status"] not in {"not_checked", "lookup_unavailable"} else "not assessed"
            children.append(Block("paragraph", text=candidate["version"] + ": " + candidate["status"] +
                                  "; resolved: " + (", ".join(candidate["resolved"]) or empty) +
                                  "; remaining: " + (", ".join(candidate["remaining"]) or empty) +
                                  "; introduced: " + (", ".join(candidate["introduced"]) or empty)))
            children.append(_notes("Candidate gaps", candidate["gaps"]))
        blocks.append(Block("section", title=row["name"] + " " + row["installed_version"], children=children))
    if len(shown) < len(rows):
        blocks.append(Block("paragraph", text=f"Showing {len(shown)} of {len(rows)} actionable/uncertain groups; saved native JSON and Markdown contain the full plan."))
    blocks.extend([_notes("Coverage gaps", [row["reason"] for row in [*report["unmatched_findings"], *report["scan_gaps"]]]),
                   _notes("Scope", report["limitations"])])
    return blocks


def verification_blocks(report, *, limit=50):
    rows = [row for row in report["packages"] if limit is None or row["proposed_version"] is not None
            or row["status"] in {"not_observed", "unavailable", "ambiguous"}]
    shown = rows if limit is None else rows[:limit]
    targets = []
    for row in shown:
        versions = [current["version"] + (" / source " + str((current["query"] or {}).get("version") or "unavailable")
                    if row["target_scope"] == "source_package" else "") for current in row["current"]]
        targets.append([row["name"], row["target_scope"].replace("_", " "), row["proposed_version"] or "not proposed",
                        ", ".join(versions) or "not listed", row["status"].replace("_", " ")])
    blocks = [Block("paragraph", text="Outcome: " + report["status"].replace("_", " ")),
              _table("Summary", report["summary"]),
              Block("table", title="Planned targets", columns=["Package", "Target scope", "Planned", "Observed", "Outcome"], rows=targets)]
    for row in shown:
        blocks.append(_notes(row["name"], row["notes"]))
    if len(shown) < len(rows):
        blocks.append(Block("paragraph", text="Additional package outcomes are retained in the saved reports."))
    # These observations are domain results, not newly inferred report verdicts.
    blocks.extend(result_blocks(report.get("ambiguous_groups", []), title="Ambiguous package groups"))
    for key, events in report["advisories"].items():
        values = events if limit is None else events[:limit]
        blocks.append(_notes(key.replace("_", " ").capitalize() + " advisories",
                             [event["name"] + ": " + event["id"] + (" (suppressed)" if event["suppressed"] else "") +
                              (" — " + event["reason"] if event["reason"] else "") for event in values]))
        if len(values) < len(events):
            blocks.append(Block("paragraph", text="Additional advisory events are retained in the saved reports."))
    gaps = [*report["coverage"]["uncovered_packages"], *report["coverage"]["current_scan_gaps"],
            *report["unmatched_findings"], *report["coverage"]["baseline_unmatched_findings"]]
    blocks.append(_notes("Unavailable coverage", [*report["coverage"]["errors"],
                         *((row.get("name") or row.get("finding_id") or "scan") + ": " + row["reason"] for row in (gaps if limit is None else gaps[:limit]))]))
    blocks.append(_notes("Scope", report["limitations"]))
    return blocks


def _result_blocks(command, payload, limit):
    if command == "plan":
        return plan_blocks(payload, limit=limit)
    if command == "verify-plan":
        return verification_blocks(payload, limit=limit)
    if command == "stats":
        blocks = [_table("Inventory totals (all supplied records)", payload["summary"])]
        for scope, values in payload["selection_scopes"].items():
            children = [_table("Selected records", {"records": values["records"], "unresolved declarations": values["unresolved_declarations"]})]
            for key in ("license_expressions", "license_operands", "ecosystems", "notice_status"):
                children.append(_table(key.replace("_", " ").capitalize(), values[key]))
            blocks.append(Block("section", title=scope, children=children))
        blocks.append(_notes("Scope", payload["limitations"]))
        return blocks
    if command == "diff":
        return [_table("Inventory changes", payload["counts"]),
                Block("paragraph", text="These are differences in supplied inventories. Removal is not proof of remediation; ambiguous identities remain unpaired."),
                *result_blocks({key: payload[key] for key in ("changes", "ambiguous", "dependencies", "ownership")}, title="Recorded changes"),
                _notes("Scope", payload["limitations"])]
    return result_blocks(payload, title="Recorded dependency paths" if command == "why" else "Export receipt")


def build_sbom_report(command, *, inventory=None, records=None, payload=None, limit=50, offset=0, artifacts=(), target="", selection=None):
    records = inventory.records if records is None and inventory is not None else (records or [])
    notes = []
    if command == "inspect":
        payload = inventory_capture(inventory, records)
        notes.extend(_display(note) for note in inventory.diagnostics[:50])
        if len(inventory.diagnostics) > 50:
            notes.append(f"{len(inventory.diagnostics) - 50} additional diagnostics remain in the native inventory")
        if payload["captured_records"] != len(records):
            notes.append(f"Optional report capture contains {payload['captured_records']} of {len(records)} selected records; use the native inventory export for the full evidence. Selection fingerprint covers every selected occurrence.")
        blocks = inventory_blocks(inventory, records, limit=limit, offset=offset)
        metrics = {**{key.replace("_", " "): "not assessed" if value is None else value for key, value in inventory.summary().items()}, "selected records": len(records), "notice verification": inventory.notice_verification}
        title = "SBOM inventory and evidence"
    else:
        notes.extend(payload.get("limitations", []))
        blocks = _result_blocks(command, payload, limit)
        metrics = {key.replace("_", " "): "not assessed" if value is None else value for key, value in (payload.get("summary") or payload.get("counts") or {}).items()}
        if command == "stats":
            metrics["selected records"] = sum(scope["records"] for scope in payload["selection_scopes"].values())
        if "status" in payload:
            metrics["recorded outcome"] = payload["status"]
        title = {"plan": "SBOM upgrade plan", "verify-plan": "SBOM upgrade verification", "stats": "SBOM inventory statistics",
                 "diff": "SBOM inventory comparison", "why": "SBOM dependency explanation", "collect": "SBOM evidence collection", "notices": "SBOM notice export"}[command]
    state = "partial" if command == "inspect" and payload["captured_records"] != len(records) else "completed"
    if payload.get("exit_code"):
        state = "partial"
    context = ReportContext("sbom-" + command, "sbom-" + command, target=target or (inventory.subject if inventory else ""), state=state,
                            diagnostics=list(dict.fromkeys(notes)), artifacts=list(artifacts),
                            stages=[StageEnvelope("SBOM " + command, state, reason="Recorded inventory/evidence operation; no exploitability or legal verdict is inferred")],
                            extensions={"raptor.findings_available": False, "raptor.result": payload, "raptor.metrics": metrics,
                                        "raptor.scope": {"population": "supplied SBOM evidence", "command": command, "filters": selection or {}},
                                        "raptor.sbom": {"source_sha256": inventory.source_sha256 if inventory else payload.get("source_sha256", ""),
                                                        "notice_verification": inventory.notice_verification if inventory else "not_recorded"}})
    document = build_document(context, title=title, blocks=blocks)
    document.summary.update(metrics)
    return context, document


def render_sbom_markdown(command, **kwargs):
    # Compatibility Markdown is a native view, not a second full capture. In
    # particular, publishing a streamed inventory must not require serialising
    # all its metadata into an optional reporting context first.
    if command == "inspect":
        blocks = inventory_blocks(kwargs["inventory"], kwargs["records"], limit=kwargs.get("limit", 50), offset=kwargs.get("offset", 0))
        title = "SBOM inventory and evidence"
    else:
        blocks = _result_blocks(command, kwargs["payload"], kwargs.get("limit", 50))
        title = "SBOM upgrade plan" if command == "plan" else "SBOM upgrade verification"
    return render_document(ReportDocument(title, "sbom-" + command, "", blocks=blocks), "markdown").content.decode("utf-8")


def _print_summary(context):
    for line in render_operator_summary(build_operator_summary(context)).splitlines():
        print(sanitise_for_terminal(line, max_len=2000), file=sys.stderr)


def _complete_sbom_report(args, *, options, inventory=None, records=None, payload=None):
    """Human quick view goes to stderr; stdout remains the native machine contract."""
    artifacts = [{"path": str(value)} for name in ("input", "current", "baseline", "plan", "findings", "coverage", "syft", "oci_layout", "out")
                 if isinstance((value := getattr(args, name, None)), Path) and (name != "out" or value.is_file())]
    if args.command == "verify-plan":
        artifacts.append({"path": str(args.coverage or args.findings.parent / "advisory-coverage.json")})
    if getattr(args, "oci_layout", None):
        artifacts.extend({"path": str(args.oci_layout / name)} for name in ("index.json", "oci-layout"))
    for name in ("input", "current", "baseline"):
        directory = getattr(args, name, None)
        if isinstance(directory, Path) and directory.is_dir():
            artifacts.extend({"path": str(directory / member)} for member in ("inventory.json", "notice-index.json", "syft.json", "image-digest.txt", "prepared/sbom.cdx.json", "prepared/provenance.json", "capture/evidence.json"))
    if args.out and args.out.is_dir():
        artifacts.extend({"path": str(args.out / filename)} for filename in ("inventory.json", "inventory.csv", "summary.md", "upgrade-plan.json", "upgrade-plan.md", "upgrade-verification.json", "upgrade-verification.md", "notice-index.json", "syft.json"))
    context, document = build_sbom_report(args.command, inventory=inventory, records=records, payload=payload,
                                          selection={name: getattr(args, name) for name in ("license_id", "package", "scope", "ecosystem", "unresolved", "notice_status", "root") if getattr(args, name, None) is not None},
                                          artifacts=artifacts, target=str(getattr(args, "input", None) or getattr(args, "current", None) or ""))
    if args.out and args.out.is_dir():
        root = args.out / "report"
    elif options.output:
        root = options.output if not options.output.suffix or options.output.is_dir() else options.output.parent / (".sbom-" + args.command + "-report")
    else:
        _print_summary(context)
        return None
    # Native formats/files keep their names. Additional portable report files
    # live beside them under report/ and can be regenerated without domain IO.
    return complete_reporting(context, root, document=document, stem="sbom-" + args.command,
                              options=options, stream=sys.stderr)


def complete_sbom_report(args, *, options, inventory=None, records=None, payload=None):
    # Optional persistence must not change the domain command's exit status or
    # corrupt its machine stream, including for valid but oversized inventories.
    try:
        return _complete_sbom_report(args, options=options, inventory=inventory, records=records, payload=payload)
    except (OSError, ValueError, TypeError, RecursionError) as error:
        context = ReportContext("sbom-" + args.command, "sbom-" + args.command, state="partial",
                                diagnostics=["Optional report unavailable (" + type(error).__name__ + "); native outputs and domain status are retained"],
                                extensions={"raptor.findings_available": False})
        _print_summary(context)
        return None


def attach_sca_inventory(context, document, sbom_path):
    """Freeze emitted inventory metadata in the SCA report, without notice IO."""
    from .inventory import read_inventory
    from .source import Source
    with Source(sbom_path) as source:
        inventory, _ = read_inventory(source, verify_notices=False)
    capture = inventory_capture(inventory, inventory.records)
    context.extensions["raptor.sbom"] = capture
    context.artifacts.append({"path": str(sbom_path), "digest": inventory.source_sha256})
    context.extensions["raptor.metrics"].update({"SBOM packages": capture["summary"]["packages"],
                                                "SBOM declarations unresolved": capture["summary"]["unresolved_declarations"],
                                                "SBOM notice verification": capture["notice_verification"]})
    notes = list(inventory.diagnostics[:50])
    if capture["captured_records"] != capture["selected_records"]:
        notes.append(f"SBOM report captures {capture['captured_records']} of {capture['selected_records']} inventory records; the native SBOM retains the full inventory")
    context.diagnostics.extend(notes)
    document.blocks.append(Block("section", title="SBOM inventory and evidence",
                                 children=inventory_blocks(inventory, inventory.records)))
    document.snapshot_id = context.snapshot_id
    document.summary.update({"SBOM packages": capture["summary"]["packages"]})
    document.diagnostics.extend(notes)
    document.extensions["raptor.summary"] = build_operator_summary(context).to_dict()
    document.extensions["raptor.artifacts"] = context.artifacts
