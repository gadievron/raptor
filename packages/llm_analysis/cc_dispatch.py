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
