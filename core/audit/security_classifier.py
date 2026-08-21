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
from typing import Any

from core.llm.coerce import structured_result
from core.security.prompt_framing import with_audit_framing

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


# Shared calibration rules — every phase-2 style security-impact
# classification (the in-run classifier below AND the corpus runner's
# merged-row pass) must carry these, or the two deciders drift: the
# CWE-362 stream-race rule exists because unsynchronized writes to a
# parsed stream or a check-then-create map are the mechanism behind
# real CVEs (moby CVE-2024-36623 and CVE-2024-36621), and an
# uncalibrated prompt reliably rules them
# "quality".
CALIBRATION_RULES = (
    "Two calibration rules:\n"
    "- Data races and unsynchronized concurrent writes that can "
    "interleave or corrupt shared state another component relies on "
    "— a stream another component parses (wire protocols, "
    "API/progress streams, structured logs) or a shared registry/"
    "refcount map mutated by a check-then-create sequence — are "
    "integrity/availability defects for that state's consumers "
    "— security_finding, not cosmetic output error. The trigger "
    "is ordinary concurrent operation, not a contrived input.\n"
    "- Do not infer impact from the bug class or CWE alone. A "
    "security_finding needs a concrete mechanism connecting a "
    "reachable trigger to the violated property. A hypothesis of "
    "the form 'could mishandle X' or 'might produce invalid "
    "output', with no stated path from attacker-influenced or "
    "concurrent execution to that failure, is a quality_finding."
)

_CLASSIFICATION_SYSTEM = with_audit_framing(
    "You are a security impact classifier.  Given a "
    "verified code defect, decide whether it has security "
    "implications or is purely a quality issue.\n\n"
    "The defect's hypothesis, description, and any domain-model "
    "security context arrive as untrusted blocks; the file, "
    "function, bug class, and CWE are in the slots.\n\n"
    "Is this defect security-impacting?  Consider:\n"
    "- Can an unprivileged user reach this code path?\n"
    "- Does the defect cross a trust boundary?\n"
    "- Does the defect affect confidentiality, integrity, "
    "or availability?\n"
    "- Could an attacker exploit this to gain unauthorized "
    "access, escalate privileges, or cause denial of service?\n\n"
    "A defect that only affects correctness (wrong output, "
    "resource leak with no security consequence, cosmetic error) "
    "is a quality_finding.  A defect that an attacker can use "
    "to violate a security property is a security_finding.\n\n"
    + CALIBRATION_RULES,
)


def _build_classification_prompt(
    outcome: Any,
    security_context: str,
    *,
    model_id: str = "",
) -> tuple[str, str]:
    """Build the enveloped prompt for security impact classification.
    Returns ``(user, system)``."""
    from core.security.prompt_envelope import TaintedString, UntrustedBlock

    from ._util import envelope_prompt

    review = outcome.review_result or {}
    bug_class = review.get("bug_class", "unknown")
    cwe = review.get("cwe", "")
    key = f"{outcome.file}:{outcome.function}"

    blocks = [
        UntrustedBlock(
            content=outcome.hypothesis or "",
            kind="defect-hypothesis",
            origin=key,
        ),
        UntrustedBlock(
            content=outcome.body or "",
            kind="defect-description",
            origin=key,
        ),
    ]
    if security_context:
        blocks.append(UntrustedBlock(
            content=security_context,
            kind="domain-security-context",
            origin="domain-model",
        ))

    slots = {
        "file": TaintedString(value=outcome.file or "", trust="untrusted"),
        "function": TaintedString(value=outcome.function or "", trust="untrusted"),
        "bug_class": TaintedString(value=str(bug_class), trust="untrusted"),
    }
    if cwe:
        slots["cwe"] = TaintedString(value=str(cwe), trust="untrusted")

    # transparent_payload: measured live (calibration corpus, kernel
    # target), this classification ask over an ENCODED payload of
    # kernel-audit content (defect hypothesis + description +
    # domain-security context) is hard-refused by Claude models
    # (stop_reason=refusal) while the identical class over a smaller
    # plaintext-adjacent payload succeeds on the same route — the
    # fourth call class to hit the encoded-payload refusal conjunction
    # (see envelope_prompt's docstring; summary / spec_inference /
    # checker_synthesis landed first). Compensating defences for the
    # plaintext rendering, per the sibling pattern: pre-call injection
    # preflight and envelope-echo discard in classify_security_impact.
    # Both fail toward the existing quality_finding default — a
    # skipped or discarded call can never promote a finding to
    # security.
    return envelope_prompt(
        _CLASSIFICATION_SYSTEM, blocks, slots, model_id=model_id,
        transparent_payload=True,
    )


def _echoes_envelope(result: dict[str, Any]) -> bool:
    """True when any string field parrots envelope structure.

    A response that echoes ``<untrusted-`` tags is replaying
    attacker-adjacent structure rather than answering — same
    contamination floor as the summary and spec-inference classes.
    """
    return any(
        isinstance(v, str) and "<untrusted-" in v
        for v in result.values()
    )


def classify_security_impact(
    outcomes: list[Any],
    out_dir: Path,
    llm_client: Any,
    *,
    model_name: str | None = None,
) -> dict[str, dict[str, Any]]:
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

    results: dict[str, dict[str, Any]] = {}
    kwargs: dict[str, Any] = {"task_type": "audit"}
    if model_name:
        try:
            mc = llm_client.config.config_for_model(model_name)
            kwargs = {"model_config": mc}
        except (ValueError, AttributeError):
            pass

    from core.security.prompt_input_preflight import preflight

    total_cost = 0.0
    for outcome in candidates:
        key = f"{outcome.file}:{outcome.function}"
        # Injection preflight over the untrusted inputs BEFORE the
        # call: this class renders its payload plaintext (see
        # _build_classification_prompt), so inputs carrying known
        # injection phrasing get no LLM pass at all — the outcome
        # keeps the fail-safe quality default instead.
        pf = preflight(
            "\n".join((
                outcome.hypothesis or "",
                outcome.body or "",
                security_context or "",
            )),
        )
        if pf.has_injection_indicators:
            logger.warning(
                "security classification: injection indicators (%s) in "
                "%s inputs — skipping LLM classification (quality "
                "default)",
                ",".join(pf.indicators), key,
            )
            results[key] = {
                "is_security": False,
                "classification": "quality_finding",
                "rationale": (
                    "classification skipped — injection preflight "
                    "indicators in inputs"
                ),
            }
            if outcome.review_result is not None:
                outcome.review_result["security_impact"] = results[key]
            continue

        prompt, system_prompt = _build_classification_prompt(
            outcome, security_context,
            model_id=model_name or getattr(llm_client, "model_name", "") or "",
        )

        try:
            response = llm_client.generate_structured(
                prompt,
                CLASSIFICATION_SCHEMA,
                system_prompt=system_prompt,
                **kwargs,
            )
            result = structured_result(response)
            cost = response.cost if hasattr(response, "cost") else 0.0
            total_cost += cost
            if _echoes_envelope(result):
                logger.warning(
                    "security classification for %s discarded — envelope "
                    "structure echoed in output (possible injection "
                    "contamination)",
                    key,
                )
                result = {
                    "is_security": False,
                    "classification": "quality_finding",
                    "rationale": (
                        "classification discarded — envelope structure "
                        "echoed in output"
                    ),
                }
        except Exception:
            logger.warning(
                "security classification failed for %s — recording error",
                key, exc_info=True,
            )
            # FAIL CLOSED: a transport/auth failure is an error cell,
            # not a quality ruling. Downstream consumers that demote
            # on ``classification == "quality_finding"`` must never
            # act on a call that did not happen. (The preflight and
            # envelope-echo defaults above are different: those are
            # deliberate fail-safe RULINGS on suspect inputs, and can
            # only prevent promotion, so they keep the quality
            # default.)
            result = {
                "is_security": False,
                "classification": "error",
                "rationale": "classification call failed — not a ruling",
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
