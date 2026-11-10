"""Portable presentation of captured parity measurements; no fixture execution."""
from __future__ import annotations

from itertools import islice
from typing import TYPE_CHECKING

from core.reporting.document import Block, Inline, ReportDocument, digest
from core.security.redaction import redact_secrets

if TYPE_CHECKING:
    from .sanitizer_cut_parity import ParitySummary


def build_parity_document(
    summary: ParitySummary, *, title: str = "Sanitizer-cut parity report",
    synthetic_baseline: bool = False,
) -> ReportDocument:
    """Preserve native criteria while distinguishing missing rate populations."""
    from .sanitizer_cut_parity import parity_criterion_met

    remaining = 200_000
    limited = False

    def text(value: str) -> str:
        nonlocal remaining, limited
        source = redact_secrets(value)
        allowance = min(2000, remaining)
        limited |= len(source) > allowance
        source = source[:allowance]
        remaining -= len(source)
        return source

    safe_title = text(title)
    rate_rows = []
    native_rates = []
    for label, method in (("Lexical", summary.lexical), ("Value-bound", summary.value_bound)):
        for axis, rate in (("Noise-suppression", method.noise_suppression), ("Bug-hiding", method.bug_hiding)):
            available = rate.total > 0
            rate_rows.append([label, axis, rate.successes, rate.total,
                              rate.rate if available else None,
                              rate.low if available else None, rate.high if available else None])
            native_rates.append({"method": label, "axis": axis, "available": available,
                                 "successes": rate.successes, "total": rate.total,
                                 "rate": rate.rate, "low": rate.low, "high": rate.high})
    rows = [[index, text(kind), counts["both_suppress"], counts["lexical_only"],
             counts["value_bound_only"], counts["neither"]]
            for index, (kind, counts) in enumerate(islice(summary.by_kind.items(), 1000), 1)]
    omitted = max(0, len(summary.by_kind) - len(rows))
    limited |= omitted > 0
    gate = parity_criterion_met(summary)
    blocks = [
        Block("paragraph", inline=[Inline("text", "Records in window: "), Inline("strong", str(summary.total))]),
        Block("paragraph", inline=[Inline("strong", f"Safe to remove lexical (Phase 16 gate): {'YES' if gate else 'NO'}")]),
        Block("table", title="Suppression rates (Wilson 95% CI)",
              columns=["Method", "Axis", "Successes", "Population", "Rate", "CI low", "CI high"], rows=rate_rows),
        Block("paragraph", text="Noise-suppression is the fraction of labelled safe findings suppressed (higher is better). Bug-hiding is the fraction of labelled real findings suppressed (lower is better). Rates and intervals are fractions; zero populations are unavailable."),
        Block("table", title="Agreement matrix (all records)",
              columns=["Decision", "Value-bound suppress", "Value-bound keep"],
              rows=[["Lexical suppress", summary.both_suppress, summary.lexical_only],
                    ["Lexical keep", summary.value_bound_only, summary.neither]]),
        Block("table", title="By proposal kind", columns=["Row", "Kind", "Both", "Lexical only", "Value-bound only", "Neither"], rows=rows),
    ]
    notes = ["These are captured labelled-parity measurements, not new target finding verdicts or authorisation to change a gate. No analysis, fixture execution or shadow-log read is repeated for rendering.",
             "Window identity, source-read quality, rejected rows and whole-run completeness were not supplied by this aggregate API. Native rate/CI values are retained separately, including zero-population placeholders; unavailable displayed rates are not observed zeros."]
    if synthetic_baseline:
        blocks.insert(0, Block("paragraph", inline=[Inline("strong", "Baseline, not the gating window."), Inline("text", " This small synthetic fixture set demonstrates telemetry and coverage only. The Phase 16 gate requires the real horizon window from /agentic shadow logs.")]))
    if limited:
        notes.append("Portable capture limited: 1000 proposal-kind rows, 2000 characters per string and 200000 text characters. Omitted rows are counted; omitted text is not retained here.")
    document = ReportDocument(safe_title, "sanitizer-cut-parity", "",
                              metadata={"Measurement scope": "synthetic-baseline" if synthetic_baseline else "supplied aggregate; window identity not supplied"},
                              summary={"Records": summary.total, "Labelled records": summary.labelled_total,
                                       "should_suppress": summary.should_suppress_total,
                                       "should_not_suppress": summary.should_not_suppress_total,
                                       "Rate criterion met": summary.rate_criterion_met,
                                       "No lexical regression": summary.no_lexical_regression,
                                       "Native Phase 16 gate": gate}, blocks=blocks, diagnostics=notes,
                              extensions={"raptor.native_rates": native_rates, "raptor.capture_limited": limited,
                                          "raptor.proposal_kind_rows_omitted": omitted})
    document.snapshot_id = digest(document.to_dict())
    return document
