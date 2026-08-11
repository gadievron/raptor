"""Phase 2: security impact classification for bug-first mode.

After Phase 1 finds all defects (mode-agnostic), Phase 2 classifies
which defects have security impact.  Each finding/suspicious outcome
is evaluated against the domain model's security context — privilege
level, attack surface, trust boundaries, isolation.

The classifier adds ``security_impact`` to the outcome's review_result.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


CLASSIFICATION_SCHEMA = {
    "type": "object",
    "properties": {
        "rationale": {
            "type": "string",
            "description": "Why this is or is not security-impacting.",
        },
        "primitive": {
            "type": "string",
            "enum": [
                "read", "write", "execute", "auth_bypass",
                "dos", "info_leak", "none",
            ],
            "description": (
                "The attacker primitive this defect provides, if "
                "security-impacting.  'none' for quality findings."
            ),
        },
        "classification": {
            "type": "string",
            "enum": ["security_finding", "quality_finding"],
            "description": (
                "security_finding = the defect is security-impacting. "
                "quality_finding = the defect is a correctness issue "
                "without security implications."
            ),
        },
        "is_security": {
            "type": "boolean",
            "description": (
                "true if this defect has security implications — it "
                "crosses a trust boundary, is reachable by an "
                "unprivileged user, or affects confidentiality, "
                "integrity, or availability."
            ),
        },
    },
    "required": ["rationale", "classification", "is_security"],
}


def _load_security_context(out_dir: Path) -> str:
    """Load security context from the domain model for classification."""
    try:
        from core.concepts.audit_bridge import domain_security_context
        ctx = domain_security_context(out_dir)
        return ctx or ""
    except Exception:
        logger.debug("security context load failed", exc_info=True)
        return ""


def _build_classification_prompt(
    outcome: Any,
    security_context: str,
) -> str:
    """Build the prompt for security impact classification."""
    review = outcome.review_result or {}
    bug_class = review.get("bug_class", "unknown")
    cwe = review.get("cwe", "")

    parts = [
        "Given this verified defect:\n",
        f"  File: {outcome.file}:{outcome.function}",
        f"  Bug: {outcome.hypothesis}",
        f"  Class: {bug_class}",
    ]
    if cwe:
        parts.append(f"  CWE: {cwe}")
    parts.append(f"\n  Description: {outcome.body}")

    if security_context:
        parts.append(f"\nSecurity context from domain model:\n{security_context}")

    parts.append(
        "\nIs this defect security-impacting?  Consider:\n"
        "- Can an unprivileged user reach this code path?\n"
        "- Does the defect cross a trust boundary?\n"
        "- Does the defect affect confidentiality, integrity, "
        "or availability?\n"
        "- Could an attacker exploit this to gain unauthorized "
        "access, escalate privileges, or cause denial of service?\n\n"
        "A defect that only affects correctness (wrong output, "
        "resource leak with no security consequence, cosmetic error) "
        "is a quality_finding.  A defect that an attacker can use "
        "to violate a security property is a security_finding."
    )
    return "\n".join(parts)


def classify_security_impact(
    outcomes: List[Any],
    out_dir: Path,
    llm_client: Any,
    *,
    model_name: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    """Classify findings/suspicious outcomes for security impact.

    Returns a dict mapping ``file:function`` to the classification result.
    Only processes outcomes with status in (finding, suspicious).
    """
    candidates = [
        o for o in outcomes
        if o.status in ("finding", "suspicious")
    ]
    if not candidates:
        return {}

    security_context = _load_security_context(out_dir)

    results: Dict[str, Dict[str, Any]] = {}
    kwargs: Dict[str, Any] = {"task_type": "audit"}
    if model_name:
        try:
            mc = llm_client.config.config_for_model(model_name)
            kwargs = {"model_config": mc}
        except (ValueError, AttributeError):
            pass

    total_cost = 0.0
    for outcome in candidates:
        key = f"{outcome.file}:{outcome.function}"
        prompt = _build_classification_prompt(outcome, security_context)

        try:
            response = llm_client.generate_structured(
                prompt,
                CLASSIFICATION_SCHEMA,
                system_prompt=(
                    "You are a security impact classifier.  Given a "
                    "verified code defect, decide whether it has security "
                    "implications or is purely a quality issue."
                ),
                **kwargs,
            )
            result = response.result if hasattr(response, "result") else response[0]
            cost = response.cost if hasattr(response, "cost") else 0.0
            total_cost += cost
        except Exception:
            logger.warning(
                "security classification failed for %s — defaulting to quality",
                key, exc_info=True,
            )
            result = {
                "is_security": False,
                "classification": "quality_finding",
                "rationale": "classification failed — defaulted to quality",
            }

        results[key] = result

        if outcome.review_result is not None:
            outcome.review_result["security_impact"] = result

        logger.info(
            "Phase 2: %s → %s (%s)",
            key,
            result.get("classification", "?"),
            result.get("primitive", "none"),
        )

    logger.info(
        "Phase 2 complete: %d classified (%.2f USD), %d security, %d quality",
        len(results),
        total_cost,
        sum(1 for r in results.values() if r.get("is_security")),
        sum(1 for r in results.values() if not r.get("is_security")),
    )
    return results
