"""Portable per-CVE failure view; no discovery or pipeline status changes."""
from __future__ import annotations

from core.reporting.document import Block, ReportDocument, digest
from core.security.redaction import redact_secrets

from .markdown import _ERROR_LABELS, _strip_surrender_prefix


def build_failure_document(cve_id: str, error_class: str, error_text: str) -> ReportDocument:
    """Capture recorded failure metadata within the existing presentation caps."""
    limited: list[str] = []

    def capture(value: str, field: str, limit: int) -> str:
        text = redact_secrets(value)
        if len(text) > limit:
            limited.append(field)
        return text[:limit]

    title = capture(cve_id, "CVE identifier", 300)
    classification = capture(_ERROR_LABELS.get(error_class, f"Other ({error_class})"), "Outcome label", 300)
    recorded_class = capture(error_class, "Failure class", 300)
    rationale = capture(_strip_surrender_prefix(error_text), "Rationale", 4000)
    diagnostics = ["No fix artifact was produced in this attempt. This does not establish that the CVE has no fix, that a target is safe, or that any finding has been validated."]
    if limited:
        diagnostics.append("Presentation truncated recorded fields: " + ", ".join(limited) + ". Additional input text is not retained in this portable document.")
    document = ReportDocument(title, "cve-diff-failure", "", metadata={"Outcome": classification, "Class": recorded_class},
                              blocks=[Block("paragraph", title="Why no fix was extracted", text=rationale)],
                              diagnostics=diagnostics, extensions={"raptor.truncated_fields": limited})
    document.snapshot_id = digest(document.to_dict())
    return document
