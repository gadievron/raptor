"""Pre-run canary probe for envelope compatibility.

Before dispatching real findings, send a single controlled request
through the same dispatch path to verify the model understands the
envelope contract. The probe uses known-good content that the attacker
cannot influence — if the model fails, it's genuinely incompatible,
not being tricked.

Usage (in orchestrator, after model resolution):

    from core.security.envelope_probe import probe_envelope_compatibility

    result = probe_envelope_compatibility(model_id, profile, dispatch_fn)
    defense_telemetry.set_probe_result(model_id, result.compatible)
    if not result.compatible:
        profile = PASSTHROUGH  # fall back for this model
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from core.security.prompt_envelope import (
    ModelDefenseProfile,
    TaintedString,
    UntrustedBlock,
    build_prompt,
)

logger = logging.getLogger("raptor.security")


_CANARY_CODE = """\
void process_request(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);
    printf("Received: %s\\n", buffer);
}"""

_CANARY_SYSTEM = """\
You are a code security analyser. Respond with a JSON object containing exactly:
{"is_vulnerable": boolean, "vulnerability_type": string, "confidence": number}
Respond ONLY with the JSON object, no other text."""

_CANARY_RULE_ID = "CWE-120"
_CANARY_FILE = "canary_probe.c"


@dataclass(frozen=True)
class ProbeResult:
    compatible: bool
    valid_json: bool
    correct_verdict: bool
    nonce_leaked: bool
    raw_response: str
    error: str | None = None


def build_canary_prompt(profile: ModelDefenseProfile) -> tuple[str, str, str]:
    """Build the canary probe prompt. Returns (system, user, nonce)."""
    bundle = build_prompt(
        system=_CANARY_SYSTEM,
        profile=profile,
        untrusted_blocks=(UntrustedBlock(
            content=_CANARY_CODE,
            kind="source-code",
            origin=f"{_CANARY_FILE}:1",
        ),),
        slots={
            "rule_id": TaintedString(value=_CANARY_RULE_ID, trust="untrusted"),
            "file_path": TaintedString(value=_CANARY_FILE, trust="untrusted"),
        },
    )
    system = ""
    user = ""
    for m in bundle.messages:
        if m.role == "system":
            system = m.content
        elif m.role == "user":
            user = m.content
    return system, user, bundle.nonce


def evaluate_probe_response(raw_response: str, nonce: str) -> ProbeResult:
    """Evaluate a probe response for envelope compatibility.

    Checks three things:
    1. Valid JSON output (model can produce structured output with envelope)
    2. Correct verdict (model identified the buffer overflow)
    3. No nonce leakage (model respected the envelope contract)
    """
    from core.security.prompt_envelope import nonce_leaked_in
    nonce_leaked = nonce_leaked_in(nonce, raw_response)

    text = raw_response.strip()

    # Strip markdown code fences — many models wrap JSON in ```json ... ```
    if "```" in text:
        for part in text.split("```")[1::2]:
            lines = part.strip().split("\n", 1)
            candidate = lines[1].strip() if len(lines) > 1 else lines[0].strip()
            try:
                parsed = json.loads(candidate)
                text = candidate
                break
            except (json.JSONDecodeError, TypeError):
                continue

    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        error = ("Model leaked the envelope nonce" if nonce_leaked
                 else "Response is not valid JSON")
        return ProbeResult(
            compatible=False,
            valid_json=False,
            correct_verdict=False,
            nonce_leaked=nonce_leaked,
            raw_response=raw_response,
            error=error,
        )

    valid_json = isinstance(parsed, dict) and "is_vulnerable" in parsed
    correct_verdict = bool(parsed.get("is_vulnerable"))

    compatible = valid_json and correct_verdict and not nonce_leaked

    error = None
    if nonce_leaked:
        error = "Model leaked the envelope nonce"
    elif not valid_json:
        error = "Model did not produce valid structured output"
    elif not correct_verdict:
        error = "Model failed to identify a trivial buffer overflow"

    return ProbeResult(
        compatible=compatible,
        valid_json=valid_json,
        correct_verdict=correct_verdict,
        nonce_leaked=nonce_leaked,
        raw_response=raw_response,
        error=error,
    )


def probe_envelope_compatibility(
    model_id: str,
    profile: ModelDefenseProfile,
    dispatch_fn,
) -> ProbeResult:
    """Send a canary probe through the dispatch path.

    dispatch_fn must accept (prompt, schema, system_prompt, temperature, model)
    and return a DispatchResult (or raise on failure). This is the same
    signature used by dispatch_task() — pass the same function.

    Returns a ProbeResult with .compatible indicating whether the model
    handled the envelope correctly.
    """
    system, user, nonce = build_canary_prompt(profile)

    try:
        result = dispatch_fn(user, None, system, 0.0, model_id)
        raw = ""
        if hasattr(result, "result") and isinstance(result.result, dict):
            raw = result.result.get("content", "") or json.dumps(result.result)
        elif hasattr(result, "result"):
            raw = str(result.result)
        else:
            raw = str(result)
    except Exception as e:
        return ProbeResult(
            compatible=False,
            valid_json=False,
            correct_verdict=False,
            nonce_leaked=False,
            raw_response="",
            error=f"Dispatch failed: {e}",
        )

    probe_result = evaluate_probe_response(raw, nonce)

    if probe_result.compatible:
        logger.info(
            "Envelope probe passed for %s (profile: %s)",
            model_id, profile.name,
        )
    else:
        logger.warning(
            "DEFENSE WARNING: envelope probe FAILED for %s (profile: %s): %s. "
            "Falling back to passthrough mode — envelope defenses disabled "
            "for this model. The model-independent floor (autofetch "
            "redaction, control-char sanitisation, role separation) still "
            "applies.",
            model_id, profile.name, probe_result.error,
        )

    return probe_result
