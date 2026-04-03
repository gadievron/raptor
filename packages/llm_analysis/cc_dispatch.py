"""Claude Code subprocess dispatch internals.

Handles invoking `claude -p` sub-agents, parsing their JSON envelope
output, building prompts and schemas for CC, and writing debug files.

Used by orchestrator.py via invoke_cc_simple as a dispatch_fn callable.
"""

import copy
import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict

from packages.llm_analysis.dispatch import DispatchResult
from packages.llm_analysis.prompts.schemas import FINDING_RESULT_SCHEMA

logger = logging.getLogger(__name__)

CC_TIMEOUT = 300  # 5 minutes per finding
CC_BUDGET_PER_FINDING = "1.00"  # string — passed as CLI arg to --max-budget-usd


def invoke_cc_simple(prompt, schema, repo_path, claude_bin, out_dir,
                     timeout=CC_TIMEOUT):
    """CC invocation with pre-built prompt. Returns DispatchResult.

    Used as a dispatch_fn callable by dispatch_task().
    """
    cmd = [
        claude_bin, "-p",
        "--output-format", "json",  # Always JSON envelope for cost metadata
        "--no-session-persistence",
        "--allowed-tools", "Read,Grep,Glob",
        "--add-dir", str(repo_path),
        "--max-budget-usd", CC_BUDGET_PER_FINDING,
    ]

    # Add structured schema constraint for analysis tasks
    if schema:
        effective_schema = build_schema()  # Uses FINDING_RESULT_SCHEMA
        cmd.extend(["--json-schema", json.dumps(effective_schema)])

    try:
        proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return DispatchResult(result={"error": f"timeout after {timeout}s"})

    if proc.returncode != 0:
        stderr_excerpt = (proc.stderr or "")[:500]
        result = {"error": f"exit code {proc.returncode}: {stderr_excerpt}"}
        write_debug(out_dir, "dispatch", proc.stdout, proc.stderr, result)
        return DispatchResult(result=result)

    if schema:
        parsed = parse_cc_result(proc.stdout, proc.stderr, "unknown")
    else:
        # Free-form with JSON envelope — extract text content and cost metadata
        parsed = parse_cc_freeform(proc.stdout, proc.stderr)

    cost = parsed.pop("cost_usd", 0)
    tokens = parsed.pop("_tokens", 0)
    model = parsed.pop("analysed_by", "claude-code")
    duration = parsed.pop("duration_seconds", 0)

    return DispatchResult(result=parsed, cost=cost, tokens=tokens, model=model, duration=duration)


def write_debug(
    out_dir: Path,
    finding_id: str,
    stdout: str,
    stderr: str,
    result: Dict[str, Any],
) -> None:
    """Write raw CC output to a debug file on failure."""
    try:
        debug_dir = out_dir / "debug"
        debug_dir.mkdir(parents=True, exist_ok=True)
        debug_file = debug_dir / f"cc_{finding_id}.txt"
        debug_file.write_text(f"STDOUT:\n{stdout or '(empty)'}\n\nSTDERR:\n{stderr or '(empty)'}")
        # Relative path so it works regardless of output dir location
        result["cc_debug_file"] = f"debug/cc_{finding_id}.txt"
    except OSError:
        pass  # Best effort — don't fail the finding over a debug file


def build_schema(no_exploits: bool = False, no_patches: bool = False) -> Dict[str, Any]:
    """Build JSON Schema for CC output, excluding fields the user didn't ask for."""
    schema = copy.deepcopy(FINDING_RESULT_SCHEMA)
    if no_exploits:
        schema["properties"].pop("exploit_code", None)
    if no_patches:
        schema["properties"].pop("patch_code", None)
    return schema


def build_finding_prompt(
    finding: Dict[str, Any],
    no_exploits: bool = False,
    no_patches: bool = False,
) -> str:
    """Build a lightweight prompt for a CC sub-agent.

    The prompt contains metadata only — rule ID, file path, line numbers,
    dataflow summary. No raw code from the target repo. The agent reads
    code itself via Read/Grep/Glob tools, which provides natural separation
    between instructions and attacker-controlled content.
    """
    finding_id = finding.get("finding_id", "unknown")
    rule_id = finding.get("rule_id", "unknown")
    file_path = finding.get("file_path", "unknown")
    start_line = finding.get("start_line", "?")
    end_line = finding.get("end_line", start_line)
    # message is scanner-generated but may contain target-repo identifiers
    # (variable names, file paths). Low risk given read-only tools + schema output.
    message = finding.get("message", "")
    level = finding.get("level", "warning")

    prompt = f"""You are a security researcher analysing a potential vulnerability.

## Finding
- ID: {finding_id}
- Rule: {rule_id}
- Severity: {level}
- File: {file_path}
- Lines: {start_line}-{end_line}
- Description: {message}
"""

    # Dataflow summary (metadata only, no code)
    dataflow = finding.get("dataflow")
    if dataflow:
        source = dataflow.get("source", {})
        sink = dataflow.get("sink", {})
        steps = dataflow.get("steps", [])
        sanitizers = dataflow.get("sanitizers_found", [])

        prompt += f"""
## Dataflow path
- Source: {source.get('file', '?')}:{source.get('line', '?')} ({source.get('label', '')})
- Sink: {sink.get('file', '?')}:{sink.get('line', '?')} ({sink.get('label', '')})
- Intermediate steps: {len(steps)}
- Sanitizers found: {len(sanitizers)}
"""
        if sanitizers:
            prompt += "- Sanitizer locations: " + ", ".join(
                f"{s.get('file', '?')}:{s.get('line', '?')}" for s in sanitizers
                if isinstance(s, dict)
            ) + "\n"

    # Feasibility data (small, high-value — include directly)
    feasibility = finding.get("feasibility")
    if feasibility:
        verdict = feasibility.get("verdict", "unknown")
        chain_breaks = feasibility.get("chain_breaks", [])
        what_would_help = feasibility.get("what_would_help", [])
        prompt += f"""
## Exploit feasibility analysis (from upstream validation pipeline)
This finding has already been through automated feasibility analysis.
The constraints below were empirically verified — treat them as ground truth.
Focus your analysis on attack paths that work within these constraints.

- Verdict: {verdict}
"""
        if chain_breaks:
            prompt += "- Techniques that WON'T work (verified blockers):\n"
            for cb in chain_breaks:
                prompt += f"  - {cb}\n"
        if what_would_help:
            prompt += "- Viable approaches to consider:\n"
            for wh in what_would_help:
                prompt += f"  - {wh}\n"

    # Instructions — follows exploitation-validator methodology (Stages A-D)
    prompt += """
## Your task — work through each stage

Read the code at the file path above using the Read tool. Examine the
surrounding context, imports, and any functions called in the vulnerable code.

**Stage A: One-shot verification**
Is the vulnerability pattern real? Does the code actually do what the scanner claims?
Attempt to confirm exploitability. If clearly a false positive, explain why.

**Stage B: Attack path analysis**
What is the attack path from attacker-controlled input to the vulnerable code?
What preconditions does an attacker need? Are those preconditions realistic?
What blocks exploitation? What enables it?

**Stage C: Sanity check**
Open and read the actual file. Verify the code at the stated line matches the finding.
Is the source-to-sink flow real? Is this code reachable from an entry point?

**Stage D: Ruling**
Is this test code, example code, or documentation?
Does exploitation require unrealistic preconditions?
If your reasoning hedges ("maybe", "in theory"), verify the claim or rule it out.

Rules: Investigate as if exploitable until proven otherwise. Do not guess or assume.
If uncertain, verify by reading the code. Show the vulnerable code for every claim.
Back causal claims with specifics (function name, line number). "Input is sanitized" is not sufficient; "htmlEscape() at line 47" is.
Your ruling, is_true_positive, and is_exploitable MUST be consistent with your reasoning.
"""

    if not no_exploits:
        prompt += """
**If exploitable**: Write a proof-of-concept exploit.
The exploit should be practical and demonstrate the vulnerability.
Include clear comments explaining the attack.
"""

    if not no_patches:
        prompt += """
**If exploitable**: Create a secure fix that preserves existing functionality.
Read the full file for context before writing the patch.
"""

    prompt += f"""
Return your analysis as structured JSON with finding_id "{finding_id}".
Rate exploitability_score from 0.0 (impossible) to 1.0 (trivial).
Set confidence to high, medium, or low.
Include a ruling: validated, false_positive, unreachable, test_code, dead_code, or mitigated.
Identify the CWE ID (e.g., CWE-79) and vuln_type category (e.g., xss, buffer_overflow).
Summarize the dataflow as source->sink chain in dataflow_summary.
Provide remediation guidance in the remediation field.
If false_positive, set false_positive_reason to explain why.
"""

    return prompt


def _extract_envelope_metadata(envelope: dict, into: dict) -> None:
    """Extract cost, duration, model, and token metadata from a claude -p JSON envelope."""
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


def parse_cc_result(
    stdout: str,
    stderr: str,
    finding_id: str,
) -> Dict[str, Any]:
    """Parse CC sub-agent JSON output.

    Handles: clean JSON, claude -p envelope, markdown-fenced JSON, partial output.
    """
    content = stdout.strip()
    if not content:
        stderr_excerpt = (stderr or "")[:500]
        return {"finding_id": finding_id, "error": f"empty output: {stderr_excerpt}"}

    # Try direct parse
    try:
        result = json.loads(content)
        if isinstance(result, dict):
            # claude -p --output-format json wraps output in a metadata envelope.
            # The actual structured output is in the "structured_output" field.
            if "structured_output" in result and isinstance(result["structured_output"], dict):
                inner = result["structured_output"]
                inner.setdefault("finding_id", finding_id)
                _extract_envelope_metadata(result, inner)
                return inner
            result.setdefault("finding_id", finding_id)
            return result
    except json.JSONDecodeError:
        pass

    # Try stripping markdown fences
    if "```" in content:
        try:
            parts = content.split("```")
            for part in parts[1::2]:  # odd-indexed parts are inside fences
                # Strip optional language tag
                lines = part.strip().split("\n", 1)
                json_str = lines[1] if len(lines) > 1 and not lines[0].startswith("{") else part
                result = json.loads(json_str.strip())
                if isinstance(result, dict):
                    result.setdefault("finding_id", finding_id)
                    return result
        except (json.JSONDecodeError, IndexError):
            pass

    # Last resort: find first valid JSON object using raw_decode
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


def parse_cc_freeform(stdout: str, stderr: str) -> Dict[str, Any]:
    """Parse free-form CC output from --output-format json envelope.

    Extracts the text result and cost metadata. Unlike parse_cc_result,
    doesn't expect structured_output — the result field is the text content.
    """
    content = stdout.strip()
    if not content:
        return {"content": "", "error": f"empty output: {(stderr or '')[:500]}"}

    try:
        envelope = json.loads(content)
        if isinstance(envelope, dict):
            parsed = {"content": envelope.get("result", "")}
            _extract_envelope_metadata(envelope, parsed)
            return parsed
    except json.JSONDecodeError:
        pass

    # Fallback: not a JSON envelope, treat as raw text
    return {"content": content}
