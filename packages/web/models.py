"""Web scan data models.

WebFinding maps to RAPTOR's core finding schema so results are renderable
by the existing reporting layer. CheckResult is the internal intermediate
type that individual checks produce.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class WebFinding:
    """A confirmed security finding from the web scanner.

    Field names align with core/reporting/findings.py expectations.
    The `file` alias for `url` is injected in to_dict() so the shared
    findings table renders correctly.
    """

    id: str
    title: str
    severity: str           # critical | high | medium | low | informational
    confidence: str         # high | medium | low
    status: str             # confirmed | needs_review | ruled_out
    url: str
    evidence: str
    description: str
    recommendation: str
    vuln_type: str
    asvs_category: str      # e.g. "V14.4"
    check_id: str           # e.g. "V14.4.3"
    auth_context: str = "unauthenticated"
    asvs_ref: str | None = None  # precise ASVS 5.0 reference from the check
    cwe_id: str | None = None
    cvss_score_estimate: float | None = None
    confirmed: bool | None = None
    target_url: str | None = None
    confirmation_payload: str | None = None
    response_evidence: str | None = None
    baseline_evidence: str | None = None
    attack_evidence: str | None = None
    diff_summary: str | None = None
    attack_vector: str | None = None
    method: str | None = None
    affected_parameters: list[str] = field(default_factory=list)
    oracle_signal: str | None = None
    oracle: str = "web"
    reproducible: bool = False
    # Phase 6v replay verdict folded onto the finding:
    # "verified" / "refuted" / "inconclusive" / None (not replayed).
    # A control-refuted finding keeps its detection-time record but
    # must never be projected as an oracle-verified outcome.
    verification_status: str | None = None

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if v is not None}
        d["file"] = self.url
        d["finding_id"] = self.id
        d["target_url"] = self.target_url or self.url
        if self.confirmed is None:
            d["confirmed"] = self.status == "confirmed"
        return d


