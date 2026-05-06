"""Claude Code subprocess transport.

Builds ``claude -p`` commands and parses their JSON-envelope output.
The subprocess counterpart to the SDK providers in ``core.llm.providers``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from core.security.redaction import redact_secrets

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CCDispatchConfig:
    """Parameters for a ``claude -p`` invocation."""
    claude_bin: str
    tools: str = "Read,Grep,Glob"
    add_dirs: tuple[str, ...] = ()
    budget_usd: str = "1.00"
    timeout_s: int = 300
    json_schema: dict[str, Any] | None = None
    capture_json_envelope: bool = True


def build_cc_command(config: CCDispatchConfig) -> list[str]:
    """Build the argument list for ``claude -p``.

    Does not include the prompt (passed via stdin) or sandbox wrapping
    (caller decides sandbox posture).
    """
    cmd = [
        config.claude_bin, "-p",
        "--no-session-persistence",
        "--allowed-tools", config.tools,
        "--max-budget-usd", config.budget_usd,
    ]
    for d in config.add_dirs:
        cmd.extend(["--add-dir", str(d)])
    if config.capture_json_envelope:
        cmd.extend(["--output-format", "json"])
    if config.json_schema is not None:
        cmd.extend(["--json-schema", json.dumps(config.json_schema)])
    return cmd


def strip_json_fences(text: str) -> str:
    """Strip markdown code fences wrapping JSON.

    LLMs (especially Gemini) wrap JSON responses in ```json ... ``` fences.
    Returns the first valid JSON found inside fences, or the original text.
    """
    if "```" not in text:
        return text
    parts = text.split("```")
    for part in parts[1::2]:
        lines = part.strip().split("\n", 1)
        candidate = lines[1].strip() if len(lines) > 1 and not lines[0].startswith("{") else part.strip()
        if candidate and candidate[0] in "{[":
            return candidate
    return text


def extract_envelope_metadata(envelope: dict, into: dict) -> None:
    """Extract cost, duration, model, and token counts from a ``claude -p`` JSON envelope.

    Use explicit `is not None` / `in envelope` checks rather than
    truthiness — a legitimate zero (a cached call costing 0 USD, a
    sub-millisecond cache hit reporting 0 ms duration, a no-token
    response) should still be recorded faithfully. Pre-fix, the
    `if envelope.get(X):` pattern silently dropped zero values, so
    cost/token telemetry under-reported any "free" calls and the
    operator's spend-tracking was systematically biased.
    """
    cost = envelope.get("total_cost_usd")
    if isinstance(cost, (int, float)):
        into["cost_usd"] = cost
    duration_ms = envelope.get("duration_ms")
    if isinstance(duration_ms, (int, float)):
        into["duration_seconds"] = round(duration_ms / 1000, 1)
    model_usage = envelope.get("modelUsage", {})
    if isinstance(model_usage, dict) and model_usage:
        # Pre-fix `next(iter(model_usage))` picked one arbitrary key.
        # CC envelopes list ALL models that contributed to the turn —
        # a main reasoning model plus a smaller helper for tool-call
        # routing, for example. Recording only the first hides the
        # helper's contribution and silently misattributes cost
        # tracking when multiple models are summed under one name.
        # Sort for deterministic output (envelope dict ordering is
        # CC's choice, may vary across CC versions).
        into["analysed_by"] = ",".join(sorted(model_usage.keys()))
    else:
        into["analysed_by"] = "claude-code"
    usage = envelope.get("usage", {})
    in_tokens = usage.get("input_tokens", 0) or 0
    out_tokens = usage.get("output_tokens", 0) or 0
    if "input_tokens" in usage or "output_tokens" in usage:
        into["_tokens"] = in_tokens + out_tokens


def parse_cc_structured(
    stdout: str,
    stderr: str = "",
    finding_id: str = "unknown",
) -> dict[str, Any]:
    """Parse structured JSON from ``claude -p --output-format json``.

    Handles: clean JSON, envelope with structured_output, markdown-fenced
    JSON, partial output via raw_decode fallback.
    """
    content = stdout.strip()
    if not content:
        # Redact stderr before embedding into the error message —
        # CC subprocess stderr can carry API keys (Anthropic SDK's
        # verbose output shows the bearer header), URL-embedded
        # credentials, AWS keys, etc. The error string is propagated
        # up to logs and reports that may be shared.
        stderr_excerpt = redact_secrets((stderr or "")[:500])
        return {"finding_id": finding_id, "error": f"empty output: {stderr_excerpt}"}

    try:
        result = json.loads(content)
        if isinstance(result, dict):
            if "structured_output" in result and isinstance(result["structured_output"], dict):
                inner = result["structured_output"]
                inner.setdefault("finding_id", finding_id)
                extract_envelope_metadata(result, inner)
                return inner
            result.setdefault("finding_id", finding_id)
            return result
    except json.JSONDecodeError:
        pass

    if "```" in content:
        try:
            parts = content.split("```")
            for part in parts[1::2]:
                lines = part.strip().split("\n", 1)
                json_str = lines[1] if len(lines) > 1 and not lines[0].startswith("{") else part
                result = json.loads(json_str.strip())
                if isinstance(result, dict):
                    result.setdefault("finding_id", finding_id)
                    return result
        except (json.JSONDecodeError, IndexError):
            pass

    try:
        decoder = json.JSONDecoder()
        idx = content.index("{")
        result, _ = decoder.raw_decode(content, idx)
        if isinstance(result, dict):
            result.setdefault("finding_id", finding_id)
            return result
    except (ValueError, json.JSONDecodeError):
        pass

    # Same redaction rationale as the empty-output path above —
    # `content` here may include partial CC envelope text from a
    # broken response that streamed Authorization headers / API keys.
    return {
        "finding_id": finding_id,
        "error": f"unparseable output: {redact_secrets(content[:200])}",
    }


def parse_cc_freeform(stdout: str, stderr: str = "") -> dict[str, Any]:
    """Parse free-form CC output from ``--output-format json`` envelope.

    Extracts the text result and cost metadata.
    """
    content = stdout.strip()
    if not content:
        return {
            "content": "",
            "error": f"empty output: {redact_secrets((stderr or '')[:500])}",
        }

    try:
        envelope = json.loads(content)
        if isinstance(envelope, dict):
            parsed: dict[str, Any] = {"content": envelope.get("result", "")}
            # An envelope with is_error=true (or non-empty error) reports an
            # in-band failure; without this check, "" content would surface
            # as if it were a successful empty response. parse_cc_structured
            # already checks this — keep behaviour symmetric here.
            #
            # `is True` covers the canonical bool. We also accept string
            # `"true"` / `"True"` because some upstream JSON serialisers
            # / fixture builders coerce bool to string. The error-string
            # check rejects the literal `"false"` / `"none"` / `"null"`
            # which are truthy by Python's bool() but semantically empty
            # — `if envelope.get("error")` alone fired for `error: "false"`
            # on responses that were actually fine.
            err_field = envelope.get("error")
            if isinstance(err_field, str) and err_field.strip().lower() in (
                "false", "none", "null", "0", "",
            ):
                err_field = None
            is_error_flag = envelope.get("is_error")
            is_error = (
                is_error_flag is True
                or (isinstance(is_error_flag, str)
                    and is_error_flag.strip().lower() == "true")
            )
            if is_error or err_field:
                parsed["error"] = err_field or "claude -p reported is_error=true"
            extract_envelope_metadata(envelope, parsed)
            return parsed
    except json.JSONDecodeError:
        pass

    return {"content": content}
