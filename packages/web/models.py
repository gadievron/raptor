"""Web scan data models.

WebFinding maps to RAPTOR's core finding schema so results are renderable
by the existing reporting layer. CheckResult is the internal intermediate
type that individual checks produce.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


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
    cwe_id: Optional[str] = None
    cvss_score_estimate: Optional[float] = None

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if v is not None}
        d["file"] = self.url
        d["finding_id"] = self.id
        return d


@dataclass
class ScanTarget:
    """Resolved target for a web scan."""

    base_url: str
    auth_mode: str = "none"   # none | form | bearer | cookie | basic
    max_depth: int = 3
    max_pages: int = 100
    verify_ssl: bool = True
    reveal_secrets: bool = False
