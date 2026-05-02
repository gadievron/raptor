"""Claude Code subprocess dispatch internals.

Handles invoking `claude -p` sub-agents, building prompts and schemas
for CC analysis, and writing debug files.

Used by orchestrator.py via invoke_cc_simple as a dispatch_fn callable.
Transport concerns (command building, envelope parsing) are delegated to
``core.llm.cc_adapter``.
"""

import copy
import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict

from core.llm.cc_adapter import (
    CCDispatchConfig,
    build_cc_command,
    parse_cc_structured,
    parse_cc_freeform,
)
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
    effective_schema = build_schema() if schema else None
    config = CCDispatchConfig(
        claude_bin=claude_bin,
        tools="Read,Grep,Glob",
        add_dirs=(str(repo_path),),
        budget_usd=CC_BUDGET_PER_FINDING,
        timeout_s=timeout,
        json_schema=effective_schema,
    )
    cmd = build_cc_command(config)

    try:
        from core.sandbox import run as sandbox_run
        proc = sandbox_run(cmd, input=prompt, capture_output=True, text=True,
                           timeout=timeout, target=str(repo_path), output=str(out_dir),
                           use_egress_proxy=True,
                           proxy_hosts=["api.anthropic.com"],
                           caller_label="claude-sub-agent")
    except subprocess.TimeoutExpired:
        return DispatchResult(result={"error": f"timeout after {timeout}s"})

    if proc.returncode != 0:
        stderr_excerpt = (proc.stderr or "")[:500]
        result = {"error": f"exit code {proc.returncode}: {stderr_excerpt}"}
        write_debug(out_dir, "dispatch", proc.stdout, proc.stderr, result)
        return DispatchResult(result=result)

    if schema:
        parsed = parse_cc_structured(proc.stdout, proc.stderr, "unknown")
    else:
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
        safe_id = Path(finding_id).name.replace("..", "_") if finding_id else "unknown"
        debug_file = debug_dir / f"cc_{safe_id}.txt"
        debug_file.write_text(f"STDOUT:\n{stdout or '(empty)'}\n\nSTDERR:\n{stderr or '(empty)'}")
        result["cc_debug_file"] = f"debug/cc_{safe_id}.txt"
    except OSError:
        pass


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
The PoC must produce observable evidence: a crash, changed output, callback, file read, error message, or measurable state change. "Ran without error" is not evidence.
"""

    if not no_patches:
        prompt += """
**If exploitable**: Create a secure fix that preserves existing functionality.
Read the full file for context before writing the patch.
"""

    prompt += f"""
Return your analysis as structured JSON with finding_id "{finding_id}".
Set is_true_positive and is_exploitable based on your analysis.
Rate exploitability_score from 0.0 (impossible) to 1.0 (trivial).
Set confidence to high, medium, or low.
Set ruling to exactly one of: validated, false_positive, unreachable, test_code, dead_code, mitigated.
Set severity_assessment to one of: critical, high, medium, low, informational.
Set cwe_id to the most specific applicable CWE — always provide one (e.g., CWE-120 for buffer overflow, CWE-78 for command injection, CWE-79 for XSS, CWE-89 for SQL injection, CWE-416 for use-after-free, CWE-134 for format string).
Set vuln_type category (e.g., command_injection, xss, buffer_overflow, format_string).
Set cvss_vector as a CVSS v3.1 vector: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_. The score is computed automatically — do not estimate it. Score the vulnerability's **inherent impact**, not binary mitigations. A heap overflow capable of code execution = C:H/I:H/A:H even with RELRO+PIE. AV = how the attacker reaches the code: CLI binary = AV:L, network service = AV:N.
Summarize the dataflow as source->sink chain in dataflow_summary.
Provide remediation guidance in the remediation field.
If false_positive, set false_positive_reason to explain why.

Consistency: ruling, is_true_positive, is_exploitable must agree with your reasoning. severity_assessment must be consistent with cvss_vector — high severity with low CVSS indicates an error.
"""

    return prompt
