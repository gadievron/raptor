"""Portable hint-only views over one already captured gadget-oracle result."""
from __future__ import annotations

from itertools import islice
import math
from pathlib import Path
import sys

from core.reporting.document import Block, ReportContext, ReportDocument, StageEnvelope, digest
from core.reporting.options import ReportOptions
from core.reporting.renderers import get_renderer
from core.reporting.service import complete_reporting, unrefreshed_report_notice
from core.reporting.summary import build_operator_summary, render_operator_summary
from core.security.redaction import redact_secrets


def build_document(report: dict) -> ReportDocument:
    """Capture census and witness metadata, never recompute an absence tier."""
    remaining = 200_000
    limited = False
    omissions: dict[str, int] = {}

    def text(value: object) -> str:
        nonlocal remaining, limited
        value = redact_secrets(str(value))
        allowance = min(2000, remaining)
        limited |= len(value) > allowance
        result = value[:allowance]
        remaining -= len(result)
        return result

    raw_census, raw_chains, raw_sites = report.get("census"), report.get("chains"), report.get("unserialize_sites")
    census = raw_census if isinstance(raw_census, dict) else {}
    chains = raw_chains if isinstance(raw_chains, list) else []
    sites = raw_sites if isinstance(raw_sites, list) else []
    target = text(report.get("target_path", "not supplied"))
    tier = text(report.get("tier", "not supplied"))
    absence = text(report.get("absence_tier", "not supplied"))
    blocks = []
    subtrees_omitted: dict[str, int] = {}
    values_unavailable: dict[str, int] = {}
    # Metadata carries counts, analysis depth and coverage limits. Native source
    # evidence and census path samples stay in gadget-chains.json.
    for key in ("producer", "capability", "analysis_depth", "census", "magic_method_census", "pop_surface"):
        rows: list[list] = []
        dropped = 0
        subtree_count = 0
        invalid_values = 0
        def visit(value: object, path: str, depth: int = 0) -> None:
            nonlocal dropped, limited, subtree_count, invalid_values
            if depth > 8:
                limited = True
                subtree_count += 1
                return
            if isinstance(value, dict):
                for name, child in value.items():
                    visit(child, path + "." + str(name), depth + 1)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, path + f"[{index}]", depth + 1)
            elif len(rows) >= 1000:
                dropped += 1
            else:
                scalar = text(value) if isinstance(value, str) else value
                if scalar is not None and not isinstance(scalar, (str, bool, int)) and not (isinstance(scalar, float) and math.isfinite(scalar)):
                    scalar = None
                    limited = True
                    invalid_values += 1
                rows.append([len(rows) + 1, text(path), scalar])
        if key in report:
            visit(report[key], key)
        omissions[key] = dropped
        subtrees_omitted[key] = subtree_count
        values_unavailable[key] = invalid_values
        blocks.append(Block("table", title=key, columns=["Row", "Field", "Captured value"], rows=rows))
    rows = []
    rejected = 0
    for index, chain in enumerate(islice(chains, 100), 1):
        if not isinstance(chain, dict):
            rejected += 1
            continue
        raw_sink = chain.get("sink")
        sink = raw_sink if isinstance(raw_sink, dict) else {}
        rows.append([index, *[text(chain.get(name, "not supplied")) for name in ("file", "class", "magic_method", "property_path", "availability")],
                     text(sink.get("category", "not supplied")), text(sink.get("callee", "not supplied")), text(sink.get("line", "not supplied"))])
    omissions["witness rows"] = max(0, len(chains) - 100)
    limited |= any(omissions.values()) or rejected > 0
    blocks.append(Block("table", title="Retained hint witnesses (metadata only)", columns=["Row", "File", "Class", "Method", "Property", "Availability", "Sink category", "Sink", "Line"], rows=rows))
    raw_autoload = report.get("autoload")
    autoload = raw_autoload if isinstance(raw_autoload, dict) else {}
    raw_autoload_sites = autoload.get("sites")
    summary = {"Autoload registered": autoload.get("registered") if type(autoload.get("registered")) is bool else None,
               "Retained autoload sites": len(raw_autoload_sites) if isinstance(raw_autoload_sites, list) else None,
               "PHP files": census.get("php_files"), "Parsed clean": census.get("parsed_clean"),
               "Census complete": census.get("complete") if type(census.get("complete")) is bool else None,
               "Retained chains": len(chains), "Retained unserialize sites": len(sites),
               "Native unserialize sites total": report.get("unserialize_sites_total"),
               "Native chain truncation": report.get("chains_truncated", False),
               "Native site truncation": report.get("unserialize_sites_truncated", False)}
    notes = ["Hint witnesses and the native absence tier are descriptive oracle output, not exploitability verdicts. No scan, target execution or absence-tier recomputation occurs during reporting.",
             "Completeness applies only to the captured census. Analysis depth, unresolved structures, skipped files and native truncation remain relevant even when no chains are retained. Generated artifacts or a completed invocation do not prove absence.",
             "Source evidence, unserialize-site bodies and census path samples remain in the native gadget-chains.json artifact when requested. This portable projection contains census counters and retained witness metadata; row numbers are local, not stable finding identities.",
             "Source-read rejection accounting and whole-run lineage were not independently supplied to this presentation API."]
    if limited:
        notes.append("Portable projection limited: 1000 metadata scalars per section, depth 8, 100 witness rows, 2000 characters per string and 200000 total text characters. Omitted/rejected rows, depth-limited subtrees and unavailable scalar values are counted separately; the number of scalars inside omitted subtrees is unknown.")
    document = ReportDocument("PHP gadget oracle snapshot", "gadget-oracle", "",
                              metadata={"Target": target, "Witness tier": tier, "Native absence tier": absence},
                              summary=summary, blocks=blocks, diagnostics=notes,
                              extensions={"raptor.capture_limited": limited, "raptor.rows_omitted": omissions,
                                          "raptor.witness_rows_rejected": rejected, "raptor.metadata_subtrees_omitted": subtrees_omitted,
                                          "raptor.metadata_values_unavailable": values_unavailable})
    document.snapshot_id = digest(document.to_dict())
    return document


def prepare(options: ReportOptions, target: Path, native_root: Path | None) -> Path:
    root = native_root / "portable-reports" if native_root is not None else target.parent / "portable-reports" / "gadget-oracle"
    if not options.enabled:
        return root
    options = options.validate()
    if options.output is None and native_root is None:
        raise ValueError("Gadget report exports require --report-output or native --out")
    chosen = options.output or root
    is_file = options.output_is_file or (bool(chosen.suffix) and not chosen.is_dir())
    for format in options.formats:
        destination = chosen if is_file else chosen / ("gadget-oracle" + get_renderer(format).extension)
        if native_root is not None and destination.resolve() == (native_root / "gadget-chains.json").resolve():
            raise ValueError("Portable output cannot replace native gadget-chains.json")
        if (destination.exists() and destination.is_file()
                and destination.resolve().is_relative_to(target.resolve())):
            raise ValueError("Portable output cannot replace an existing target file")
        if destination.resolve() == target.resolve():
            raise ValueError("Portable output cannot replace target")
    return chosen.parent / ("." + chosen.stem + "-report") if is_file else chosen


def emit(report: dict, target: Path, native_root: Path | None, options: ReportOptions) -> None:
    try:
        root = prepare(options, target, native_root)
        document = build_document(report)
        complete = document.summary["Census complete"]
        state = "completed" if complete is True and not document.extensions["raptor.capture_limited"] else "partial"
        context = ReportContext("gadget-oracle", "unknown", target=str(document.metadata["Target"]), state=state,
                                stages=[StageEnvelope("gadget-scan", state, producer="PHP gadget oracle", reason="Captured census; hint witnesses only")],
                                expected_stages=["gadget-scan"], diagnostics=list(document.diagnostics),
                                artifacts=[{"path": str((native_root / "gadget-chains.json").resolve()), "role": "native evidence; preserved"}] if native_root is not None else [],
                                extensions={"raptor.findings_available": False, "raptor.metrics": dict(document.summary), "raptor.gadget_capture": document.to_dict()})
        if not options.enabled:
            quick = build_operator_summary(context)
            quick.diagnostics.append("Full exports disabled; previous custom destinations are not refreshed.")
            notice = unrefreshed_report_notice(root)
            if notice:
                quick.diagnostics.append(notice)
            print(render_operator_summary(quick), file=sys.stderr, end="")
            return
        document.snapshot_id = context.snapshot_id
        complete_reporting(context, root, document=document, stem="gadget-oracle", options=options, stream=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — preserve native result and scan exit
        print("Optional gadget report unavailable (" + type(exc).__name__ + "); native result retained", file=sys.stderr)
