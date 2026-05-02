"""Claude Code subprocess transport.

Builds ``claude -p`` commands and parses their JSON-envelope output.
The subprocess counterpart to the SDK providers in ``core.llm.providers``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

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
    """Extract cost, duration, model, and token counts from a ``claude -p`` JSON envelope."""
    if envelope.get("total_cost_usd"):
        into["cost_usd"] = envelope["total_cost_usd"]
    if envelope.get("duration_ms"):
        into["duration_seconds"] = round(envelope["duration_ms"] / 1000, 1)
    model_usage = envelope.get("modelUsage", {})
    into["analysed_by"] = next(iter(model_usage)) if model_usage else "claude-code"
    usage = envelope.get("usage", {})
    tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
    if tokens:
        into["_tokens"] = tokens


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
        stderr_excerpt = (stderr or "")[:500]
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

    return {"finding_id": finding_id, "error": f"unparseable output: {content[:200]}"}


def parse_cc_freeform(stdout: str, stderr: str = "") -> dict[str, Any]:
    """Parse free-form CC output from ``--output-format json`` envelope.

    Extracts the text result and cost metadata.
    """
    content = stdout.strip()
    if not content:
        return {"content": "", "error": f"empty output: {(stderr or '')[:500]}"}

    try:
        envelope = json.loads(content)
        if isinstance(envelope, dict):
            parsed: dict[str, Any] = {"content": envelope.get("result", "")}
            extract_envelope_metadata(envelope, parsed)
            return parsed
    except json.JSONDecodeError:
        pass

    return {"content": content}
