"""Typed presentation of a captured scorecard data-sufficiency audit."""
from __future__ import annotations

import math
from typing import TYPE_CHECKING

from core.reporting.document import Block, ReportDocument, digest
from core.security.redaction import redact_secrets

if TYPE_CHECKING:
    from .audit import AuditReport


def build_audit_document(report: AuditReport) -> ReportDocument:
    """Preserve native readiness and integrity decisions without rereading data."""
    from .audit import THRESHOLDS
    limited: set[str] = set()
    remaining = 200_000

    def capture(value: object, field: str, limit: int = 64):
        nonlocal remaining
        if isinstance(value, str):
            text = redact_secrets(value)
            allowed = min(limit, remaining)
            if len(text) > allowed:
                limited.add(field)
            text = text[:allowed]
            remaining -= len(text)
            return text
        if value is None or isinstance(value, (bool, int)) or isinstance(value, float) and math.isfinite(value):
            return value
        limited.add(field)
        return None

    metadata = {"Scorecard": capture(report.scorecard_path, "Scorecard path", 2000),
                "Schema version": capture(report.schema_version, "Schema version"),
                "Primary event type": capture(report.primary_event_type, "Primary event type"),
                "Sidecar demoted": report.sidecar_demoted, "Integrity key unusable": report.key_unusable}
    verdict = str(capture(report.verdict, "Readiness verdict"))
    reason = str(capture(report.verdict_reason, "Readiness reason", 4000))
    event_rows = [[capture(summary.event_type, "Event type"), summary.total_cells, summary.cells_with_any_data,
                   *[summary.cells_at_thresholds.get(threshold, 0) for threshold in THRESHOLDS], summary.total_observations]
                  for summary in report.event_type_summaries[:1000]]
    class_rows = [[capture(summary.decision_class, "Decision class"), summary.distinct_models,
                   f"{summary.median_obs_primary:.1f}", summary.total_obs_primary]
                  for summary in report.decision_class_summaries[:1000]]
    omitted_events = max(0, len(report.event_type_summaries) - len(event_rows))
    omitted_classes = max(0, len(report.decision_class_summaries) - len(class_rows))
    blocks = [Block("paragraph", title="Verdict — " + verdict.title(), text=reason),
              Block("table", title="Per-event-type coverage", columns=["event_type", "cells", "cells w/ data",
                    *[f"≥N={threshold}" for threshold in THRESHOLDS], "total obs"], rows=event_rows)]
    if class_rows:
        blocks.append(Block("table", title="Per-decision-class coverage (" + str(metadata["Primary event type"]) + ")",
                            columns=["decision_class", "distinct models", "median obs/cell", "total obs"], rows=class_rows))
    else:
        blocks.append(Block("paragraph", title="Per-decision-class coverage", text="No decision classes carry any data."))
    notes = ["This verdict describes recorded data sufficiency for calibration, not finding validity or target security. Rendering does not rerun the audit, verify the source again, or change any gate.",
             "Threshold columns use the audit's declared native thresholds; unknown event types already present in the audit result are retained."]
    if report.sidecar_demoted:
        notes.append("Sidecar content failed integrity verification and was excluded from every native count above.")
    if report.key_unusable:
        notes.append("Integrity key unusable: verification could not run; every native count above includes unverified sidecar content.")
    if limited or omitted_events or omitted_classes:
        notes.append("Portable capture is limited: up to 1000 event and 1000 decision-class rows, 64 characters per label, 4000 characters for the reason, 2000 for the path and 200000 captured text characters. Omitted text is not retained in this document; native audit JSON is unchanged.")
    document = ReportDocument("Scorecard audit", "scorecard-audit", "", metadata=metadata,
                              summary={"Distinct models": report.total_models, "Distinct decision classes": report.total_decision_classes,
                                       "Total cells": report.total_cells}, blocks=blocks, diagnostics=notes,
                              extensions={"raptor.readiness_verdict": verdict, "raptor.truncated_fields": sorted(limited),
                                          "raptor.event_rows_omitted": omitted_events, "raptor.class_rows_omitted": omitted_classes})
    document.snapshot_id = digest(document.to_dict())
    return document
