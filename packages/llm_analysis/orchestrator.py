#!/usr/bin/env python3
"""
RAPTOR Orchestrator — Phase 4 of the /agentic workflow.

Dispatches structured findings from Phase 3 to Claude Code sub-agents
for parallel vulnerability analysis, exploit generation, and patch creation.

Three execution paths:
  Path 1 (CC available, no external LLM): Dispatch to claude -p sub-agents
  Path 2 (external LLM):                  Phase 3 already did analysis — passthrough
  Path 3 (nothing):                        Manual review — passthrough

Inside or outside Claude Code, dispatch uses claude -p subprocesses for
consistent enforcement of tools, budget, schema, and parallelism.
"""

import copy
import json
import logging
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# JSON Schema for CC sub-agent structured output.
# Required fields ensure every result is usable even if the agent
# produces minimal output.
FINDING_RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "finding_id": {"type": "string"},
        "is_true_positive": {"type": "boolean"},
        "is_exploitable": {"type": "boolean"},
        "exploitability_score": {
            "type": "number",
            "minimum": 0,
            "maximum": 1,
        },
        "severity_assessment": {"type": "string"},
        "reasoning": {"type": "string"},
        "attack_scenario": {"type": "string"},
        "exploit_code": {"type": ["string", "null"]},
        "patch_code": {"type": ["string", "null"]},
    },
    "required": ["finding_id", "is_true_positive", "is_exploitable", "reasoning"],
}

CC_TIMEOUT = 300  # 5 minutes per finding
CC_BUDGET_PER_FINDING = "1.00"  # string — passed as CLI arg to --max-budget-usd


def orchestrate(
    prep_report_path: Path,
    repo_path: Path,
    out_dir: Path,
    max_parallel: int = 3,
    no_exploits: bool = False,
    no_patches: bool = False,
) -> Optional[Dict[str, Any]]:
    """Orchestrate vulnerability analysis using Claude Code sub-agents.

    Called from raptor_agentic.py Phase 4. Dispatches CC sub-agents
    when claude is on PATH and no external LLM is configured (the
    prep-only case). All other cases are passthrough.

    Args:
        prep_report_path: Path to autonomous_analysis_report.json from Phase 3.
        repo_path: Target repository path.
        out_dir: Output directory for orchestration results.
        max_parallel: Maximum concurrent CC sub-agents.
        no_exploits: Skip exploit generation.
        no_patches: Skip patch generation.

    Returns:
        Orchestrated report dict, or None if orchestration was skipped.
    """
    # Load Phase 3 report
    try:
        report = json.loads(prep_report_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read Phase 3 report: {e}")
        print(f"\n  Failed to read analysis report: {e}")
        return None

    # Path 2/3: Phase 3 already did full analysis — nothing to add
    if report.get("mode") != "prep_only":
        logger.info("Phase 3 ran full analysis — orchestration not needed")
        return None

    # Verify claude binary exists before committing to dispatch
    claude_bin = shutil.which("claude")
    if not claude_bin:
        print("\n  claude not found on PATH — cannot dispatch sub-agents")
        print("  Install Claude Code: npm install -g @anthropic-ai/claude-code")
        return None

    findings = report.get("results", [])
    if not findings:
        print("\n  No findings to analyse")
        return None

    print(f"\n  Dispatching {len(findings)} findings to Claude Code agents "
          f"(max {max_parallel} parallel)")

    # Dispatch all findings in parallel
    start_time = time.monotonic()
    cc_results = _dispatch_findings(
        findings=findings,
        repo_path=repo_path,
        claude_bin=claude_bin,
        out_dir=out_dir,
        max_parallel=max_parallel,
        no_exploits=no_exploits,
        no_patches=no_patches,
    )
    elapsed = time.monotonic() - start_time

    # Merge and write
    merged = _merge_results(report, cc_results, no_exploits=no_exploits, no_patches=no_patches)
    merged["orchestration"] = {
        "mode": "cc_dispatch",
        "findings_dispatched": len(findings),
        "findings_analysed": sum(1 for r in cc_results if "error" not in r),
        "findings_failed": sum(1 for r in cc_results if "error" in r),
        "elapsed_seconds": round(elapsed, 1),
        "max_parallel": max_parallel,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "orchestrated_report.json"
    out_path.write_text(json.dumps(merged, indent=2))
    logger.info(f"Orchestrated report saved to {out_path}")

    # Summary
    orch = merged["orchestration"]
    print(f"\n  Orchestration complete: {orch['findings_analysed']} analysed, "
          f"{orch['findings_failed']} failed, {orch['elapsed_seconds']}s elapsed")
    print(f"  Report: {out_path}")

    return merged


def _print_result(finding_id: str, result: Dict[str, Any]) -> None:
    """Print a single finding result to console."""
    exploitable = result.get("is_exploitable", False)
    score = result.get("exploitability_score")
    try:
        status = f"exploitable ({float(score):.2f})" if exploitable else "not exploitable"
    except (ValueError, TypeError):
        status = "exploitable" if exploitable else "not exploitable"
    print(f"  [done] {finding_id}: {status}")


def _dispatch_findings(
    findings: List[Dict[str, Any]],
    repo_path: Path,
    claude_bin: str,
    out_dir: Path,
    max_parallel: int,
    no_exploits: bool,
    no_patches: bool,
) -> List[Dict[str, Any]]:
    """Dispatch findings to CC sub-agents in parallel.

    Returns a list of result dicts, one per finding (in completion order).
    Failed findings have an "error" key.
    """
    results: List[Dict[str, Any]] = []
    total = len(findings)
    abort = False

    with ThreadPoolExecutor(max_workers=max_parallel) as executor:
        future_to_finding = {}
        for idx, finding in enumerate(findings, 1):
            finding_id = finding.get("finding_id", f"finding-{idx}")
            rule_id = finding.get("rule_id", "unknown")
            file_path = finding.get("file_path", "?")
            start_line = finding.get("start_line", "?")

            print(f"  [{idx}/{total}] {rule_id} at {file_path}:{start_line} ...",
                  flush=True)

            future = executor.submit(
                _invoke_cc,
                finding=finding,
                repo_path=repo_path,
                claude_bin=claude_bin,
                out_dir=out_dir,
                no_exploits=no_exploits,
                no_patches=no_patches,
            )
            future_to_finding[future] = (idx, finding_id)

        for future in as_completed(future_to_finding):
            idx, finding_id = future_to_finding[future]
            try:
                result = future.result()
            except Exception as e:
                result = {"finding_id": finding_id, "error": str(e)}

            results.append(result)

            if "error" in result:
                err = result["error"]
                print(f"  [fail] {finding_id}: {err}")
                if result.get("cc_debug_file"):
                    print(f"         debug: {result['cc_debug_file']}")

                # Abort on auth/billing errors — remaining will fail too
                if _is_auth_error(err):
                    print("\n  Authentication/billing error — aborting remaining agents")
                    abort = True
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
            else:
                _print_result(finding_id, result)

    if abort:
        # Mark undispatched findings as aborted
        completed_ids = {r.get("finding_id") for r in results}
        for finding in findings:
            fid = finding.get("finding_id")
            if fid and fid not in completed_ids:
                results.append({"finding_id": fid, "error": "aborted (auth failure)"})

    return results


def _invoke_cc(
    finding: Dict[str, Any],
    repo_path: Path,
    claude_bin: str,
    out_dir: Path,
    no_exploits: bool = False,
    no_patches: bool = False,
    timeout: int = CC_TIMEOUT,
) -> Dict[str, Any]:
    """Invoke a single Claude Code sub-agent for one finding.

    The prompt is lightweight — metadata only, no raw code from the
    target repo. The agent reads code via Read/Grep/Glob tools. This
    keeps attacker-controlled content out of the prompt (prompt injection
    mitigation).

    Returns parsed result dict, or dict with "error" key on failure.
    """
    finding_id = finding.get("finding_id", "unknown")
    prompt = _build_finding_prompt(finding, no_exploits, no_patches)
    schema = _build_schema(no_exploits, no_patches)

    cmd = [
        claude_bin, "-p",
        "--output-format", "json",
        "--json-schema", json.dumps(schema),
        "--no-session-persistence",
        "--allowed-tools", "Read,Grep,Glob",
        "--add-dir", str(repo_path),
        "--max-budget-usd", CC_BUDGET_PER_FINDING,
    ]

    try:
        proc = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"finding_id": finding_id, "error": f"timeout after {timeout}s"}

    if proc.returncode != 0:
        stderr_excerpt = (proc.stderr or "")[:500]
        result = {"finding_id": finding_id, "error": f"exit code {proc.returncode}: {stderr_excerpt}"}
        _write_debug(out_dir, finding_id, proc.stdout, proc.stderr, result)
        return result

    parsed = _parse_cc_result(proc.stdout, proc.stderr, finding_id)
    if "error" in parsed:
        _write_debug(out_dir, finding_id, proc.stdout, proc.stderr, parsed)
    return parsed


def _write_debug(
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


def _build_schema(no_exploits: bool = False, no_patches: bool = False) -> Dict[str, Any]:
    """Build JSON Schema for CC output, excluding fields the user didn't ask for."""
    schema = copy.deepcopy(FINDING_RESULT_SCHEMA)
    if no_exploits:
        schema["properties"].pop("exploit_code", None)
    if no_patches:
        schema["properties"].pop("patch_code", None)
    return schema


def _build_finding_prompt(
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

    # Instructions
    prompt += """
## Your task

Read the code at the file path above using the Read tool. Examine the
surrounding context, imports, and any functions called in the vulnerable code.

1. **Analyse**: Is this a true positive? Is it exploitable in practice?
   What would an attacker need? What's the real-world impact?
   Rate exploitability_score from 0.0 (impossible) to 1.0 (trivial).
"""

    if not no_exploits:
        prompt += """
2. **Exploit**: If exploitable, write a proof-of-concept exploit.
   The exploit should be practical and demonstrate the vulnerability.
   Include clear comments explaining the attack.
"""

    if not no_patches:
        prompt += f"""
{"3" if not no_exploits else "2"}. **Patch**: Create a secure fix that preserves existing functionality.
   Read the full file for context before writing the patch.
"""

    prompt += f"""
Return your analysis as structured JSON with finding_id "{finding_id}".
"""

    return prompt


def _parse_cc_result(
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


def _merge_results(
    prep_report: Dict[str, Any],
    cc_results: List[Dict[str, Any]],
    no_exploits: bool = False,
    no_patches: bool = False,
) -> Dict[str, Any]:
    """Merge CC sub-agent results back into the prep report.

    Matches by finding_id. CC results update analysis fields while
    preserving all prep data (code, dataflow, feasibility).
    """
    merged = dict(prep_report)
    merged["mode"] = "orchestrated"

    # Index CC results by finding_id
    cc_by_id = {}
    for r in cc_results:
        fid = r.get("finding_id")
        if fid:
            cc_by_id[fid] = r

    # Deep copy results so we don't mutate the caller's data
    results = copy.deepcopy(merged.get("results", []))

    # Merge into findings
    analysed = 0
    exploitable = 0
    exploits_generated = 0
    patches_generated = 0

    for finding in results:
        fid = finding.get("finding_id")
        cc = cc_by_id.get(fid)
        if not cc or "error" in cc:
            # No CC result or failed — keep prep data, mark as unanalysed
            finding["cc_error"] = cc.get("error") if cc else "not dispatched"
            if cc and cc.get("cc_debug_file"):
                finding["cc_debug_file"] = cc["cc_debug_file"]
            continue

        analysed += 1

        # Update analysis fields from CC result
        finding["analysis"] = {
            "is_true_positive": cc.get("is_true_positive"),
            "is_exploitable": cc.get("is_exploitable"),
            "exploitability_score": cc.get("exploitability_score"),
            "severity_assessment": cc.get("severity_assessment"),
            "reasoning": cc.get("reasoning"),
            "attack_scenario": cc.get("attack_scenario"),
        }
        finding["exploitable"] = cc.get("is_exploitable", False)
        finding["exploitability_score"] = cc.get("exploitability_score", 0)

        if finding["exploitable"]:
            exploitable += 1

        if not no_exploits and cc.get("exploit_code"):
            finding["has_exploit"] = True
            finding["exploit_code"] = cc["exploit_code"]
            exploits_generated += 1

        if not no_patches and cc.get("patch_code"):
            finding["has_patch"] = True
            finding["patch_code"] = cc["patch_code"]
            patches_generated += 1

    merged["results"] = results
    merged["analyzed"] = analysed
    merged["exploitable"] = exploitable
    merged["exploits_generated"] = exploits_generated
    merged["patches_generated"] = patches_generated

    return merged


def _is_auth_error(error_str: str) -> bool:
    """Check if an error string indicates an authentication/billing failure."""
    lower = error_str.lower()
    return any(x in lower for x in [
        "401", "403", "authentication", "unauthorized",
        "invalid api key", "billing", "quota", "rate limit",
        "insufficient_quota", "credit",
    ])
