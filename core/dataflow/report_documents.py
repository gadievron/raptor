"""Portable views of captured trust measurements, without corpus execution."""
from __future__ import annotations

from itertools import islice
from typing import TYPE_CHECKING

from core.reporting.document import Block, ReportDocument, digest
from core.security.redaction import redact_secrets

if TYPE_CHECKING:
    from .trust_report import TrustReport
    from .trust_corpus_report import CorpusReport


def build_trust_document(report: TrustReport) -> ReportDocument:
    """Keep native numerators, denominators and vacuous-control semantics."""
    document = ReportDocument("Trust FP-suppressor measurement", "trust-measurement", "",
                              summary={"Recorded findings": report.total, "True-positive controls": report.tp,
                                       "Trust-addressable false positives": report.trust_fp, "Native corpus sound": report.is_sound},
                              blocks=[Block("table", title="Recorded rates", columns=["Metric", "Numerator", "Denominator", "Rate"], rows=[
                                  ["coverage", report.coverage_n, report.trust_fp, report.coverage],
                                  ["false-suppression", report.false_suppression_n, report.tp, report.false_suppression_rate],
                                  ["suppression precision", report.suppressed_on_fp, report.suppressed_total, report.suppression_precision],
                                  ["defer (uncertain)", report.defer_n, report.total, report.defer_n / report.total if report.total else None]]),
                                  Block("paragraph", title="Native control outcome", text="No TPs — vacuous" if not report.tp else
                                        "No true-positive control was suppressed" if report.is_sound else "NONZERO false suppression — UNSOUND on this corpus")],
                              diagnostics=["These are labelled-corpus measurements, not new finding verdicts or proof of soundness on arbitrary targets. No validator, model or CSV read is repeated for rendering.",
                                           "Rates with a zero denominator are unavailable, not zero. Source-read quality and lifecycle identity were not supplied by this aggregate API."])
    document.snapshot_id = digest(document.to_dict())
    return document


def build_corpus_document(report: CorpusReport) -> ReportDocument:
    """Preserve outcome/error axes, all observed backends and sample limits."""
    remaining = 200_000
    limited = False
    omissions: dict[str, int] = {}

    def text(value: object) -> str:
        nonlocal remaining, limited
        source = "not recorded" if value is None else redact_secrets(str(value))
        allowed = min(2000, remaining)
        limited |= len(source) > allowed
        source = source[:allowed]
        remaining -= len(source)
        return source

    def counter_rows(counter, name):
        omissions[name] = max(0, len(counter) - 1000)
        return [[index, text(key if key != "" else "<unknown>"), count]
                for index, (key, count) in enumerate(islice(counter.items(), 1000), 1)]

    metadata = {"Source read state": text(report.read_state), "Source read reason": text(report.read_reason),
                "Captured source rows": report.read_rows}
    summary = {"Processed outcomes": report.processed, "sound": report.sound, "not_sound": report.not_sound,
               "no_barrier": report.no_barrier, "Pipeline-error rows (separate)": sum(report.pipeline_errors.values()),
               "Suppression rate": report.suppression_rate, "Tier 0 share of sound": report.tier0_share_of_sound,
               "Estimated Tier 0 attempts saved": report.tier0_attempts_saved(), "Retained not_sound samples": len(report.not_sound_samples)}
    blocks = [Block("table", title=title, columns=["Row", label, "Count"], rows=counter_rows(counter, title))
              for title, label, counter in (("Pipeline errors", "Status", report.pipeline_errors),
                                           ("Backend split among SOUND verdicts", "Backend", report.sound_by_backend),
                                           ("not_sound failure modes", "Mode", report.not_sound_modes))]
    for title, groups in (("By CWE", report.by_cwe), ("By language", report.by_language)):
        total = sum(len(backends) for statuses in groups.values() for backends in statuses.values())
        entries = ((group, status, backend, count) for group, statuses in groups.items()
                   for status, backends in statuses.items() for backend, count in backends.items())
        rows = [[index, text(group), text(status), text(backend if backend != "" else "<unknown>"), count]
                for index, (group, status, backend, count) in enumerate(islice(entries, 1000), 1)]
        omissions[title] = max(0, total - len(rows))
        blocks.append(Block("table", title=title, columns=["Row", "Group", "Status", "Backend", "Count"], rows=rows))
    omissions["not_sound samples"] = max(0, len(report.not_sound_samples) - 100)
    blocks.append(Block("table", title="not_sound samples (retained subset)", columns=["Row", "CVE", "CWE", "Language", "Detail"],
                        rows=[[index, *[text(value) for value in sample]] for index, sample in enumerate(report.not_sound_samples[:100], 1)]))
    notes = ["This is a snapshot of returned corpus aggregates, not a target vulnerability report. Pipeline errors are separate from processed sound/not_sound/no_barrier outcomes.",
             "No database query, synthesis, model or CodeQL adjudication is repeated for rendering. The source may still be changing; rejected-row accounting and whole-run completion were not supplied. Read state and source-row counts describe only the captured query snapshot.",
             "Missing denominators remain unavailable. A zero-count aggregate does not distinguish an empty or in-flight table from an unavailable database/query.",
             "Tier 0 savings use the native rough default attempt assumption: avoided proposer attempts plus matched adjudications, not measured tokens, currency or completed work. Library backend rows are not counted as free SMT short-circuits.",
             "Sample rows are only the retained diagnostic subset; row numbers are local to this snapshot. All observed backend/status labels in captured rows are retained, including unknown labels."]
    if not report.sound and not report.not_sound:
        blocks.append(Block("paragraph", text="No verdicts yet in returned aggregates; no rows yet is not proof of source completeness."))
    limited |= any(omissions.values())
    if limited:
        notes.append("Portable capture limited: 1000 rows per counter/breakdown, 100 retained samples, 2000 characters per string and 200000 text characters. Omission counts are structured; omitted text is not retained here.")
    document = ReportDocument("Trust-witness corpus report", "trust-corpus", "", summary=summary, blocks=blocks, diagnostics=notes,
                              metadata=metadata,
                              extensions={"raptor.capture_limited": limited, "raptor.rows_omitted": omissions})
    document.snapshot_id = digest(document.to_dict())
    return document
