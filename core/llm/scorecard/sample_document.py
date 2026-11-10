"""Portable presentation of one already-read scorecard sample cell."""
from __future__ import annotations

from itertools import islice
from typing import TYPE_CHECKING

from core.reporting.document import Block, ReportDocument, digest
from core.security.redaction import redact_secrets

if TYPE_CHECKING:
    from .scorecard import DecisionClassStats


def build_sample_document(stat: DecisionClassStats) -> ReportDocument:
    """Capture sample observations without reading or changing scorecard policy."""
    limited: set[str] = set()
    remaining = 200_000

    def capture(value: str, field: str, limit: int = 4000) -> str:
        nonlocal remaining
        text = redact_secrets(value)
        allowed = min(remaining, limit)
        if len(text) > allowed:
            limited.add(field)
        text = text[:allowed]
        remaining -= len(text)
        return text

    title = capture(stat.decision_class, "Decision class", 64) + " on " + capture(stat.model, "Model", 64)
    blocks: list[Block] = []
    omitted_samples = max(0, len(stat.disagreement_samples) - 100)
    omitted_fields = 0
    for index, sample in enumerate(stat.disagreement_samples[:100], 1):
        heading = (f"Sample {index} — " + capture(sample.get("ts", "?"), "Timestamp", 128)
                   + " (" + capture(sample.get("event_type", "?"), "Event type", 128) + ")")
        children = []
        for key, label in (("this_reasoning", "Cheap (clear_fp)"), ("other_reasoning", "Full (overruled)"), ("note", "Operator note")):
            if sample.get(key):
                children.append(Block("paragraph", title=label, text=capture(sample[key], label)))
        handled = {"ts", "event_type", "this_reasoning", "other_reasoning", "note"}
        extras = ((key, value) for key, value in sample.items() if key not in handled and isinstance(value, str) and value)
        extra_count = 0
        for key, value in islice(extras, 20):
            extra_count += 1
            children.append(Block("paragraph", title=capture(key, "Field name", 128), text=capture(value, "Producer-specific field")))
        omitted_fields += max(0, sum(key not in handled and isinstance(value, str) and bool(value) for key, value in sample.items()) - extra_count)
        blocks.append(Block("section", title=heading, children=children))
    if not stat.disagreement_samples:
        blocks.append(Block("paragraph", text="No disagreement samples recorded for this cell."))
    notes = ["Recorded disagreement reasoning is diagnostic data, not new evidence or a finding validation verdict. Rendering neither reads the scorecard again nor updates its policy.",
             "Only retained samples from this read are shown; sample counts are not a complete model-call history."]
    if not stat.trusted:
        notes.append("The sidecar read was unverified; these samples do not grant routing or validation authority.")
    if limited or omitted_samples or omitted_fields:
        notes.append("Portable capture is limited: up to 100 samples, 20 additional fields per sample, 4000 characters per body and 200000 captured text characters. Omitted text is not retained in this document; the scorecard's recorded data is unchanged.")
    document = ReportDocument(title, "scorecard-samples", "", metadata={"Recorded read integrity": "verified" if stat.trusted else "unverified"},
                              summary={"Recorded samples": len(stat.disagreement_samples), "Samples omitted": omitted_samples,
                                       "Additional fields omitted": omitted_fields}, blocks=blocks, diagnostics=notes,
                              extensions={"raptor.truncated_fields": sorted(limited)})
    document.snapshot_id = digest(document.to_dict())
    return document
