"""Machine-readable context guard reports.

The guard is intentionally declarative here: scanner phases still own the
actual scope checks, redaction and prompt envelopes, while this report records
what context was allowed into the run and what was kept out.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping


def build_web_context_guard_report(
    *,
    target: str,
    artifacts: Mapping[str, str],
    llm_enabled: bool,
    auth_context: str,
    reveal_secrets: bool = False,
) -> dict[str, Any]:
    """Return the context contract for one web scan."""

    return {
        "target": target,
        "phase": "web",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "llm_enabled": llm_enabled,
        "auth_context": auth_context,
        "allowed_context_classes": [
            "operator_supplied_target_scope",
            "target_http_responses_untrusted",
            "crawl_and_discovery_metadata",
            "web_session_context",
            "web_oracle_verified_outcomes",
            "research_landscape",
            "scope_receipt",
            "web_tool_adapter_metadata",
            "web_evidence_ledger",
        ],
        "blocked_context_classes": [
            "off_scope_urls",
            "raw_cookie_or_token_values",
            "target_supplied_instructions",
            "cross_project_memory_without_target_match",
            "live_web_evidence_as_replayable_witness",
            "unapproved_intrusive_web_tools",
        ],
        "enforcement": {
            "same_origin_http_scope": True,
            "scope_receipt_required": True,
            "tool_risk_approval_levels": True,
            "target_content_is_untrusted": True,
            "prompt_envelope_for_llm_payload_generation": True,
            "secret_values_redacted": not reveal_secrets,
            "live_web_findings_reproducible": False,
        },
        "artifacts": dict(artifacts),
    }
