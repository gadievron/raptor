"""LLM-assisted analysis stages for ``raptor-sca``.

Shared infrastructure that every LLM stage uses:

1. ``get_llm_client()`` — obtain a configured :class:`LLMClient`.
2. ``run_stage()`` — the canonical call pattern: build prompt →
   preflight → generate_structured → validate → sanitise → telemetry.
3. Defence primitives re-exported for convenience.

All stages degrade gracefully: when no LLM is reachable the caller
gets ``None`` and the pipeline continues with mechanical-only results.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Type

from pydantic import BaseModel

from core.security.prompt_envelope import (
    UntrustedBlock,
    TaintedString,
    build_prompt,
)
from core.security.prompt_defense_profiles import get_profile_for
from core.security.prompt_input_preflight import preflight, PreflightResult
from core.security.prompt_output_sanitise import sanitise_string
from core.security.llm_response_schema import validate_response
from core.security.prompt_telemetry import defense_telemetry

logger = logging.getLogger(__name__)

_TASK_TYPE = "sca_review"


# ------------------------------------------------------------------
# Client factory
# ------------------------------------------------------------------

def get_llm_client():
    """Return a configured :class:`LLMClient`, or ``None`` if unavailable."""
    try:
        from core.llm.client import LLMClient
        from core.llm.config import LLMConfig
        config = LLMConfig()
        if not config.primary_model or not config.primary_model.enabled:
            logger.info("sca.llm: no enabled LLM model — LLM stages disabled")
            return None
        return LLMClient(config)
    except Exception:  # noqa: BLE001
        logger.info("sca.llm: LLM client unavailable — LLM stages disabled",
                     exc_info=True)
        return None


# ------------------------------------------------------------------
# Stage result
# ------------------------------------------------------------------

@dataclass
class StageResult:
    """Outcome of a single LLM stage invocation."""
    model: Optional[BaseModel]
    raw: Optional[str]
    preflight_hit: bool
    confidence_haircut: float
    cost: float
    error: Optional[str] = None


# ------------------------------------------------------------------
# Canonical run helper
# ------------------------------------------------------------------

def run_stage(
    *,
    client,
    system: str,
    untrusted_blocks: tuple[UntrustedBlock, ...],
    slots: Dict[str, TaintedString],
    schema_cls: Type[BaseModel],
    model_id: Optional[str] = None,
    task_type: str = _TASK_TYPE,
) -> StageResult:
    """Execute the full defence-in-depth LLM call pattern.

    1. ``preflight()`` on every untrusted block.
    2. ``build_prompt()`` with per-model defence profile.
    3. ``generate_structured()`` via the LLM client.
    4. ``validate_response()`` with single re-prompt on schema mismatch.
    5. ``sanitise_string()`` on every string field.
    6. Record telemetry.

    Returns a :class:`StageResult`; ``model`` is ``None`` when the call
    fails or the response doesn't validate after re-prompt.
    """
    # 1. Preflight — aggregate across all untrusted blocks.
    pf_results: List[PreflightResult] = []
    for block in untrusted_blocks:
        pf_results.append(preflight(block.content))
    any_hit = any(pf.has_injection_indicators for pf in pf_results)
    haircut = 0.5 if any_hit else 1.0

    for pf in pf_results:
        defense_telemetry.record_preflight(hit=pf.has_injection_indicators)

    # 2. Build prompt with defence envelope.
    if model_id is None:
        model_id = _resolve_model_id(client)
    profile = get_profile_for(model_id)
    bundle = build_prompt(
        system=system,
        profile=profile,
        untrusted_blocks=untrusted_blocks,
        slots=slots,
    )

    system_prompt = next(
        (m.content for m in bundle.messages if m.role == "system"), system)
    user_prompt = next(
        (m.content for m in bundle.messages if m.role == "user"), "")

    # 3. generate_structured
    json_schema = schema_cls.model_json_schema()
    try:
        resp = client.generate_structured(
            prompt=user_prompt,
            schema=json_schema,
            system_prompt=system_prompt,
            task_type=task_type,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("sca.llm: generate_structured failed: %s", exc)
        return StageResult(
            model=None, raw=None, preflight_hit=any_hit,
            confidence_haircut=haircut, cost=0.0,
            error=str(exc),
        )

    raw_text = resp.raw if resp.raw else ""
    cost = resp.cost if resp.cost else 0.0

    # 4. Validate response against Pydantic schema.
    import json as _json
    raw_for_validate = (
        _json.dumps(resp.result) if isinstance(resp.result, dict) else raw_text
    )

    def _retry():
        r2 = client.generate_structured(
            prompt=user_prompt + "\n\nYour previous response did not match "
                   "the required JSON schema. Please try again, returning "
                   "ONLY valid JSON matching the schema.",
            schema=json_schema,
            system_prompt=system_prompt,
            task_type=task_type,
        )
        return _json.dumps(r2.result) if isinstance(r2.result, dict) else (r2.raw or "")

    validated = validate_response(raw_for_validate, schema_cls, llm_call=_retry)

    # 5. Sanitise string fields.
    if validated is not None:
        validated = _sanitise_model(validated)

    # 6. Telemetry.
    defense_telemetry.record_response(
        model_id=model_id,
        profile_name=profile.name,
        nonce=getattr(bundle, "nonce", ""),
        raw_response=raw_text,
        schema_accepted=validated is not None,
        schema_retried=False,
    )

    return StageResult(
        model=validated,
        raw=raw_text,
        preflight_hit=any_hit,
        confidence_haircut=haircut,
        cost=cost,
    )


# ------------------------------------------------------------------
# Cross-family verification
# ------------------------------------------------------------------

def cross_family_check(
    *,
    client,
    system: str,
    untrusted_blocks: tuple[UntrustedBlock, ...],
    slots: Dict[str, TaintedString],
    schema_cls: Type[BaseModel],
    primary_result: StageResult,
    verdict_field: str = "verdict",
    high_severity_values: tuple[str, ...] = ("malicious", "suspicious"),
    task_type: str = _TASK_TYPE,
) -> StageResult:
    """Re-run a stage with a different-family model when the primary
    verdict is high-severity.

    Returns the primary result unchanged when:
    - the primary verdict is not high-severity,
    - no cross-family model is available,
    - the checker call fails.

    When both models agree, confidence stays. When they disagree, the
    conservative (higher-severity) verdict wins but confidence is capped
    at ``"medium"``.
    """
    if primary_result.model is None:
        return primary_result
    primary_verdict = getattr(primary_result.model, verdict_field, None)
    if primary_verdict not in high_severity_values:
        return primary_result

    checker_model = _select_checker(client)
    if checker_model is None:
        logger.debug("sca.llm: no cross-family model available")
        return primary_result

    checker_result = run_stage(
        client=client,
        system=system,
        untrusted_blocks=untrusted_blocks,
        slots=slots,
        schema_cls=schema_cls,
        model_id=checker_model,
        task_type=task_type + "_cross_check",
    )

    if checker_result.model is None:
        return primary_result

    checker_verdict = getattr(checker_result.model, verdict_field, None)
    if checker_verdict == primary_verdict:
        logger.info("sca.llm: cross-family check agreed: %s", primary_verdict)
        return primary_result

    logger.info(
        "sca.llm: cross-family disagreement: primary=%s checker=%s "
        "— taking conservative (primary)",
        primary_verdict, checker_verdict,
    )
    if hasattr(primary_result.model, "confidence"):
        updated = primary_result.model.model_copy(
            update={"confidence": "medium"},
        )
        return StageResult(
            model=updated,
            raw=primary_result.raw,
            preflight_hit=primary_result.preflight_hit,
            confidence_haircut=primary_result.confidence_haircut,
            cost=primary_result.cost + checker_result.cost,
        )
    return primary_result


def _select_checker(client) -> Optional[str]:
    """Pick a cross-family model from the client's config."""
    try:
        from core.security.llm_family import select_cross_family_checker
        primary = _resolve_model_id(client)
        candidates = []
        cfg = client.config
        if hasattr(cfg, "consensus_models"):
            candidates.extend(
                f"{m.provider}/{m.model_name}" for m in cfg.consensus_models
                if m.enabled
            )
        if hasattr(cfg, "fallback_models"):
            candidates.extend(
                f"{m.provider}/{m.model_name}" for m in cfg.fallback_models
                if m.enabled
            )
        return select_cross_family_checker(primary, candidates)
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _resolve_model_id(client) -> str:
    """Best-effort model ID for defence-profile selection."""
    try:
        cfg = client.config.primary_model
        return f"{cfg.provider}/{cfg.model_name}"
    except Exception:  # noqa: BLE001
        return "unknown"


def _sanitise_model(m: BaseModel) -> BaseModel:
    """Apply ``sanitise_string`` to every ``str`` / ``list[str]`` field."""
    updates: Dict[str, Any] = {}
    for name, field_info in m.__class__.model_fields.items():
        val = getattr(m, name)
        if isinstance(val, str):
            updates[name] = sanitise_string(val, max_chars=1000)
        elif isinstance(val, list) and val and isinstance(val[0], str):
            updates[name] = [sanitise_string(s, max_chars=500) for s in val]
    if updates:
        return m.model_copy(update=updates)
    return m


__all__ = [
    "StageResult",
    "UntrustedBlock",
    "TaintedString",
    "get_llm_client",
    "run_stage",
    "sanitise_string",
]
