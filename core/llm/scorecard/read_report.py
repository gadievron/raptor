"""Bounded exports over already computed scorecard dashboard/compare payloads."""
from __future__ import annotations

import argparse
from itertools import islice
import math
from pathlib import Path
import sys

from core.reporting.document import Block, ReportContext, ReportDocument
from core.reporting.options import ReportOptions
from core.reporting.renderers import get_renderer
from core.reporting.service import complete_reporting, unrefreshed_report_notice
from core.reporting.summary import build_operator_summary, render_operator_summary
from core.security.redaction import redact_secrets

from .scorecard import DecisionClassStats


def prepare(options: ReportOptions, source: Path, kind: str) -> Path:
    if kind not in {"summary", "compare", "list", "recommend", "chain-closure"}:
        raise ValueError("Unsupported scorecard report view")
    root = source.parent / "portable-reports" / ("scorecard-" + kind)
    if not options.enabled:
        return root
    if options.output is None:
        raise ValueError("Read-only scorecard exports require --report-output")
    options = options.validate()
    chosen = options.output or root
    is_file = options.output_is_file or (bool(chosen.suffix) and not chosen.is_dir())
    for format in options.formats:
        filename = dict(options.filenames).get(format, "scorecard-" + kind + get_renderer(format).extension)
        path = chosen if is_file else chosen / filename
        if path.resolve() == source.resolve():
            raise ValueError("Portable reports cannot replace the source scorecard")
    return chosen.parent / ("." + chosen.stem + "-report") if is_file else chosen


class _View:
    def __init__(self):
        self.remaining = 200_000
        self.limited = False

    def scalar(self, value: object) -> str | bool | int | float | None:
        if isinstance(value, str):
            text = redact_secrets(value)
            allowed = min(2000, self.remaining)
            self.limited |= len(text) > allowed
            text = text[:allowed]
            self.remaining -= len(text)
            return text
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float) and math.isfinite(value):
            return value
        self.limited = True
        return None

    def record(self, value: object):
        if not isinstance(value, dict):
            self.limited |= value is not None
            return []
        self.limited |= len(value) > 50
        # These keys come from the CLI's closed scalar payload schema. Rows
        # preserve identity even if future/redacted labels become identical.
        return [[self.scalar(str(key)), self.scalar(item)] for key, item in islice(value.items(), 50)]


def emit(args: argparse.Namespace, kind: str, payload: dict, stats: list[DecisionClassStats]) -> None:
    options = getattr(args, "_report_options", None)
    if options is None:
        return
    try:
        source = Path(args.path)
        root = prepare(options, source, kind)
        view = _View()
        data: dict = {}
        blocks: list[Block] = []
        metrics: dict[str, str | bool | int | float | None] = {"Read cells": len(stats), "Unverified read cells": sum(not stat.trusted for stat in stats)}
        if kind == "summary":
            totals = {key: view.scalar(payload.get(key)) for key in ("cells_total", "models_total", "total_spend_usd", "recent_cells_7d")}
            metrics.update(totals)
            data.update(totals)
            data["policy_breakdown"] = view.record(payload.get("policy_breakdown"))
            blocks.append(Block("table", title="Recorded policy breakdown", columns=["Policy", "Cells"], rows=data["policy_breakdown"]))
            spend = payload.get("spend_by_model", {})
            calls = payload.get("calls_by_model", {})
            if not isinstance(spend, dict) or not isinstance(calls, dict):
                raise ValueError("Invalid captured dashboard maps")
            models = sorted(spend.keys() | calls.keys())
            data["model_rows"] = [[view.scalar(str(model)), view.scalar(spend.get(model)), view.scalar(calls.get(model))] for model in models[:1000]]
            data["models_omitted"] = max(0, len(models) - 1000)
            view.limited |= bool(data["models_omitted"])
            blocks.append(Block("table", title="Recorded model usage", columns=["Row", "Model", "Spend USD", "Calls"],
                                rows=[[index, *row] for index, row in enumerate(data["model_rows"], 1)]))
            for key, title in (("most_used", "Most-used recorded model"), ("cheapest_short_circuit", "Recorded cheapest short-circuit model")):
                data[key] = view.record(payload.get(key))
                blocks.append(Block("table", title=title, columns=["Field", "Value"], rows=data[key]))
        elif kind == "compare":
            data["model_a"] = view.scalar(payload.get("model_a"))
            data["model_b"] = view.scalar(payload.get("model_b"))
            shared = payload.get("shared", [])
            if not isinstance(shared, list):
                raise ValueError("Invalid captured comparison rows")
            metrics["Shared decision classes"] = len(shared)
            data["shared"] = []
            for record in shared[:1000]:
                if not isinstance(record, dict):
                    raise ValueError("Invalid captured comparison record")
                row = {"decision_class": view.scalar(record.get("decision_class")),
                       "model_a": view.record(record.get("model_a")), "model_b": view.record(record.get("model_b"))}
                data["shared"].append(row)
                blocks.append(Block("section", title=str(row["decision_class"]), children=[
                    Block("table", title="Model A", columns=["Field", "Value"], rows=row["model_a"]),
                    Block("table", title="Model B", columns=["Field", "Value"], rows=row["model_b"])]))
            data["shared_classes_omitted"] = max(0, len(shared) - 1000)
            view.limited |= bool(data["shared_classes_omitted"])
        elif kind == "list":
            cells = payload.get("cells", [])
            selected = payload.get("selected_event_rows", [])
            if not isinstance(cells, list) or not isinstance(selected, list) or len(cells) != len(selected):
                raise ValueError("Invalid captured selected event rows")
            metrics["Selected cells"] = len(cells)
            data["selected_event_type"] = view.scalar(payload.get("selected_event_type"))
            metrics["Selected event type"] = data["selected_event_type"]
            data["selection"] = view.record(payload.get("selection"))
            data["freshness_impact"] = view.record(payload.get("freshness_impact"))
            data["cells"] = []
            blocks.extend([Block("table", title="Selection", columns=["Field", "Value"], rows=data["selection"]),
                           Block("table", title="Recorded whole-scorecard freshness impact", columns=["Field", "Value"], rows=data["freshness_impact"])])
            for index, (cell, event) in enumerate(zip(cells[:1000], selected[:1000], strict=True), 1):
                if not isinstance(cell, dict):
                    raise ValueError("Invalid captured list cell")
                record = {"fields": view.record({key: value for key, value in cell.items() if key != "freshness_drift"}),
                          "freshness_drift": view.record(cell.get("freshness_drift")), "selected_event": view.record(event)}
                data["cells"].append(record)
                blocks.append(Block("section", title=f"Selected cell {index}", children=[
                    Block("table", title="Native cheap-policy fields", columns=["Field", "Value"], rows=record["fields"]),
                    Block("table", title="Selected event observations", columns=["Field", "Value"], rows=record["selected_event"]),
                    Block("table", title="Recorded freshness drift", columns=["Field", "Value"], rows=record["freshness_drift"])]))
            data["cells_omitted"] = max(0, len(cells) - 1000)
            view.limited |= bool(data["cells_omitted"])
        else:
            data["decision_class"] = view.scalar(payload.get("decision_class"))
            data["recommendation_recorded"] = "recommendation" in payload
            recommendation = payload.get("recommendation")
            data["recommendation"] = view.record(recommendation) if isinstance(recommendation, dict) else view.scalar(recommendation)
            blocks.append(Block("table", title="Recorded recommendation", columns=["Field", "Value"], rows=data["recommendation"])
                          if isinstance(recommendation, dict) else Block("paragraph", title="Recorded recommendation",
                          text=str(data["recommendation"]) if recommendation is not None else "No recommendation recorded in this view."))
            groups = (("short_circuit", "Recorded short-circuit candidates"), ("fall_through", "Recorded fall-through candidates")) if kind == "recommend" else (("candidates", "Recorded chain-closure candidates"),)
            data["candidate_rows_omitted"] = 0
            for key, title in groups:
                records = payload.get(key, [])
                if not isinstance(records, list):
                    raise ValueError("Invalid captured ranking records")
                metrics[title] = len(records)
                data[key] = [view.record(record) for record in records[:1000]]
                data["candidate_rows_omitted"] += max(0, len(records) - 1000)
                blocks.append(Block("section", title=title, children=[Block("table", title=f"Candidate {index}",
                                    columns=["Field", "Value"], rows=record) for index, record in enumerate(data[key], 1)]))
            if kind == "recommend":
                learning = payload.get("learning", [])
                if not isinstance(learning, list):
                    raise ValueError("Invalid captured learning models")
                metrics["Recorded learning models"] = len(learning)
                data["learning"] = [view.scalar(value) for value in learning[:1000]]
                data["candidate_rows_omitted"] += max(0, len(learning) - 1000)
                blocks.append(Block("table", title="Recorded learning models", columns=["Row", "Model"],
                                    rows=[[index, value] for index, value in enumerate(data["learning"], 1)]))
                if "least_bad" in payload:
                    data["least_bad"] = view.record(payload["least_bad"])
                    blocks.append(Block("table", title="Recorded least-bad option", columns=["Field", "Value"], rows=data["least_bad"]))
            data["recorded_no_candidates"] = bool(payload.get("recorded_no_candidates"))
            if "message" in payload:
                data["message"] = view.scalar(payload["message"])
                blocks.append(Block("paragraph", title="Recorded availability", text=str(data["message"])))
            view.limited |= bool(data["candidate_rows_omitted"])
        target = str(view.scalar(str(source)))
        freshness = view.scalar(getattr(args, "freshness_half_life_days", None))
        notes = ["Recorded scorecard introspection only; exports neither change routing policy nor validate findings. No scorecard reread or model call was made for reporting.",
                 "The CLI's recorded policy lens is retained. Run-specific gate settings or freshness weighting can produce a different routing decision. Counts and spend describe retained scorecard data, not guaranteed complete call history.",
                 "Lifecycle and target execution coverage are not inferred from this read.",
                 "The stats API supplies per-cell read integrity but no read-completeness or rejected-row accounting. Returned cells are not proof of complete source coverage."]
        if not stats:
            notes.append("No recorded cells were available. Historical calls and spend are unavailable, not established as zero.")
        if kind == "summary":
            notes.append("Usage row numbers distinguish captured rows when redacted or shortened labels look identical. Row numbers are local to this view, not persistent model identities.")
        if kind == "list":
            notes.append("Selected event counts and Wilson bounds describe the requested event slot. Native policy fields always describe the cheap-tier policy axis; they are not recomputed from the selected event. Cell numbers are local to this view.")
            notes.append("Freshness impact is the native whole-scorecard measurement, ignores operator pins, and may include cells outside this selection. Read-cell counts here describe selected rows.")
        if kind in {"recommend", "chain-closure"}:
            notes.append("Rank order and any recommendation were copied from the native calculation, not recomputed. Missing rates or costs remain unavailable; an observed zero rate is distinct from missing data.")
            if data["recorded_no_candidates"]:
                notes.append("No candidate cells matched this decision class; this is not proof that a model has no historical calls or successes.")
        if any(not stat.trusted for stat in stats):
            notes.append("The read includes unverified cells; displayed policy labels grant no routing authority.")
        if view.limited:
            notes.append("Portable capture is limited: up to 1000 model, cell or candidate/shared-class rows per group, 50 fields per scalar record, 2000 characters per string and 200000 text characters. Non-scalar/non-finite values are unavailable; original scorecard data is unchanged.")
        context = ReportContext("scorecard-" + kind, "unknown", target=target,
                                state="partial" if view.limited or any(not stat.trusted for stat in stats) else "completed",
                                diagnostics=notes, artifacts=[{"path": str(source.resolve()), "role": "source scorecard; preserved"}],
                                extensions={"raptor.findings_available": False, "raptor.metrics": metrics,
                                            "raptor.scorecard_read": data, "raptor.capture_limited": view.limited,
                                            "raptor.read_quality": {"completeness": "unknown", "rejected_rows": None,
                                                                    "reason": "not supplied by scorecard stats API"},
                                            "raptor.freshness_half_life_days": freshness})
        if not options.enabled:
            summary = build_operator_summary(context)
            notice = unrefreshed_report_notice(root)
            if notice:
                summary.diagnostics.append(notice)
            print(render_operator_summary(summary), file=sys.stderr, end="")
            return
        metadata = {"Freshness half-life days": freshness if freshness is not None else "unweighted CLI view"}
        if kind == "compare":
            metadata.update({"Model A": data["model_a"], "Model B": data["model_b"]})
        if kind == "list":
            metadata["Selected event type"] = data["selected_event_type"]
        if kind in {"recommend", "chain-closure"}:
            metadata["Decision class"] = data["decision_class"]
        document = ReportDocument("Scorecard " + kind, context.kind, context.snapshot_id, metadata=metadata,
                                  summary=metrics, blocks=blocks, diagnostics=notes)
        complete_reporting(context, root, document=document, stem="scorecard-" + kind, options=options, stream=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — optional capture cannot alter native introspection
        print("Optional scorecard report unavailable (" + type(exc).__name__ + "); native view retained", file=sys.stderr)
