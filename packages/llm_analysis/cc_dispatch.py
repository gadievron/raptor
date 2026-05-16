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
import re
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
    # Use the caller's schema. Pre-fix this was
    # `build_schema() if schema else None`, which IGNORED the
    # caller's argument and substituted FINDING_RESULT_SCHEMA
    # for every CC invocation. AnalysisTask happens to use a
    # subset of FINDING_RESULT_SCHEMA so analysis broadly worked,
    # but ConsensusTask, ExploitTask, PatchTask, JudgeTask,
    # GroupAnalysisTask, AggregationTask all pass DIFFERENT
    # schemas with different required-field sets. CC would be
    # asked (via `--json-schema`) to satisfy FINDING_RESULT_SCHEMA
    # while the caller's schema demanded different shapes. Then
    # `validate_structured_response(parsed, effective_schema)`
    # below would validate the response against the wrong schema
    # too — so the quality-score check passed for whatever shape
    # FINDING_RESULT_SCHEMA happened to require, irrespective of
    # what the caller actually wanted.
    effective_schema = schema  # None means freeform — preserved.
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
        from core.sandbox import run_untrusted_networked
        from core.llm.cc_proxy_hosts import (
            proxy_hosts_for_cc_dispatch,
            readable_paths_for_cc_dispatch,
        )
        # Sandboxed Claude Code dispatch with restrict_reads=True so the
        # sub-agent can't read host secrets ($HOME, /proc/<host_pid>/) on
        # Landlock-only hosts (Ubuntu 24.04+ default with
        # ``apparmor_restrict_unprivileged_userns=1`` blocks mount-ns).
        # See core/security/THREAT_MODEL.md (I2-(a)) for the threat model.
        # readable_paths and proxy_hosts both flow through
        # cc_proxy_hosts which prefers a calibrated SandboxProfile
        # for the resolved Claude Code binary + provider env when
        # available, falling back to the documented install layout
        # / hardcoded provider-aware list otherwise. Operator can
        # also override proxy_hosts via
        # ~/.config/raptor/cc-dispatch-proxy-hosts.json. Non-essential
        # traffic (mcp-proxy, datadog, growthbook) is denied by the
        # proxy — Claude Code degrades gracefully. Deliberately NOT
        # setting CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC /
        # ENABLE_CLAUDEAI_MCP_SERVERS env vars: undocumented Claude
        # Code internals; the egress proxy allowlist is OUR policy.
        proc = run_untrusted_networked(
            cmd, input=prompt, capture_output=True, text=True,
            timeout=timeout, target=str(repo_path), output=str(out_dir),
            readable_paths=readable_paths_for_cc_dispatch(claude_bin),
            proxy_hosts=proxy_hosts_for_cc_dispatch(claude_bin),
            caller_label="claude-sub-agent",
        )
    except subprocess.TimeoutExpired:
        return DispatchResult(result={"error": f"timeout after {timeout}s"})
    except (FileNotFoundError, PermissionError) as e:
        # Pre-fix only TimeoutExpired was caught. If `claude_bin`
        # was deleted/moved between the shutil.which() check at
        # caller-time and the subprocess invocation, FileNotFoundError
        # bubbled up as an uncaught exception and aborted the entire
        # dispatch loop (every remaining finding errored out as
        # "consecutive failures"). Same for permission flips on the
        # sandbox binary or out_dir. Convert to a graceful error
        # result so the loop continues.
        return DispatchResult(result={"error": f"sandbox-launch failure: {e!r}"})
    except OSError as e:
        # Catch-all for low-level OS failures (resource exhaustion,
        # ENOENT on a sandbox-internal path) — these are recoverable
        # at the per-finding level even when persistent.
        return DispatchResult(result={"error": f"OS error invoking sandbox: {e!r}"})

    if proc.returncode != 0:
        stderr_excerpt = (proc.stderr or "")[:500]
        result = {"error": f"exit code {proc.returncode}: {stderr_excerpt}"}
        write_debug(out_dir, "dispatch", proc.stdout, proc.stderr, result)
        return DispatchResult(result=result)

    # Parse with debug-on-failure. Pre-fix `parse_cc_structured` /
    # `parse_cc_freeform` exceptions (malformed JSON, missing
    # required envelope field, json.JSONDecodeError on `"...]"`
    # truncated mid-array) propagated up, crashing the dispatch
    # of THIS finding with no artifact saved — operators couldn't
    # see what the subprocess actually wrote, only the Python
    # traceback. write_debug here gives them the raw
    # stdout/stderr to diagnose.
    try:
        if schema:
            parsed = parse_cc_structured(proc.stdout, proc.stderr, "unknown")
        else:
            parsed = parse_cc_freeform(proc.stdout, proc.stderr)
    except (ValueError, KeyError, TypeError) as e:
        result = {"error": f"parse failure: {e!r}"}
        write_debug(out_dir, "dispatch_parse", proc.stdout, proc.stderr, result)
        return DispatchResult(result=result)

    cost = parsed.pop("cost_usd", 0)
    tokens = parsed.pop("_tokens", 0)
    model = parsed.pop("analysed_by", "claude-code")
    duration = parsed.pop("duration_seconds", 0)

    quality = 1.0
    if schema and isinstance(parsed, dict) and "error" not in parsed:
        from core.llm.response_validation import validate_structured_response
        validated = validate_structured_response(parsed, effective_schema)
        parsed = validated.data
        quality = validated.quality
        if validated.quality < 0.5:
            logger.warning("Low-quality CC response (q=%.2f), incomplete: %s",
                           validated.quality, validated.incomplete)

    return DispatchResult(result=parsed, cost=cost, tokens=tokens, model=model,
                          duration=duration, quality=quality)


_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9._-]")
_SAFE_ID_MAX = 80


def _safe_id(finding_id: str) -> str:
    """Sanitise a finding_id for filesystem use.

    Pre-fix `Path(finding_id).name.replace("..", "_")` was the
    only sanitisation. Three failure modes:

    * NUL bytes: `Path("foo\\x00bar").name` returned the
      original value on Linux, then `write_text` raised
      ValueError mid-write.
    * Long IDs: SARIF rule IDs can be 200+ chars (vendor-rule
      pack URIs); concatenated into `cc_<id>.txt` they
      exceeded ext4's 255-byte filename limit and
      `mkdir`/`write_text` failed with ENAMETOOLONG.
    * Path traversal via embedded slash: pre-fix the `.name`
      attribute of `"sub/dir/leaf"` is `"leaf"` — losing the
      sub/dir context but also opening the door to weird
      Windows-path interactions if `finding_id` contained
      backslashes (`Path("a\\\\b").name` is OS-dependent).

    Whitelist `[A-Za-z0-9._-]` (sub everything else with `_`)
    and cap at 80 chars (well under any FS limit, leaves room
    for the `cc_` prefix and `.txt` suffix). Empty / whitespace
    -> "unknown".
    """
    if not finding_id or not finding_id.strip():
        return "unknown"
    sanitised = _SAFE_ID_RE.sub("_", finding_id.strip())
    # Defence-in-depth: collapse multiple consecutive `..` runs
    # to one `_` so even after sanitisation no traversal token
    # remains (whitelist already excludes `/` so this is mostly
    # cosmetic, but keeps the filename predictable).
    sanitised = sanitised.replace("..", "_")
    if len(sanitised) > _SAFE_ID_MAX:
        # Pre-fix the truncation was a bare `sanitised[:_SAFE_ID_MAX]`,
        # which lost any disambiguation in the truncated tail.
        # Two finding_ids differing only in chars beyond position
        # 80 (vendor-rule URIs in SARIF often share a common
        # prefix and disambiguate by trailing rule/ID/SHA) then
        # sanitise to the SAME truncated string — second
        # finding's debug file CLOBBERS the first's, losing
        # debug evidence for the earlier finding. Operators
        # debugging "why didn't this CC dispatch produce
        # output?" looked at the file for finding A and saw
        # finding B's output instead.
        #
        # Append a short hash suffix derived from the FULL
        # finding_id so collisions are statistically unlikely
        # (8 hex chars from sha256 = 1 in ~4 billion). Trim the
        # prefix to leave room for the `_<hash>` suffix:
        #
        #   prefix(_SAFE_ID_MAX - 9) + "_" + 8-hex
        import hashlib as __hashlib
        _suffix = "_" + __hashlib.sha256(
            finding_id.encode("utf-8", errors="replace"),
        ).hexdigest()[:8]
        sanitised = sanitised[:_SAFE_ID_MAX - len(_suffix)] + _suffix
    return sanitised or "unknown"


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
        safe_id = _safe_id(finding_id)
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
