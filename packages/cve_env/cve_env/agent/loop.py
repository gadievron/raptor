"""Agent turn loop: drive ``claude_agent_sdk.query`` and derive one ``Outcome``.

Responsibilities:

1. Render the user prompt from a ``CveRecord`` + ``HostInfo``.
2. Register the 11 MCP tools and run the query under the SDK-enforced
   turn cap and dollar cap.
3. Observe each streamed message, map ``tool_use_id`` -> tool name, and
   parse tool results to detect:
   - ``verify.passed`` -> success
   - ``give_up.terminal`` -> unresolvable
4. Write one ``AuditEntry`` per message into the per-run audit JSONL.
5. Assemble a final ``Outcome`` from the SDK's ``ResultMessage`` + the
   derived success/give_up signals.

The SDK-side turn cap and budget raise are surfaced via ``stop_reason``;
we map those to ``turn_cap`` / ``budget_exhausted`` on the Outcome.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

from cve_env.agent.audit import AuditEntry, AuditStatus, AuditWriter
from cve_env.agent.health_constraints import (
    ServiceConstraint,
    format_constraints_for_prompt,
)
from cve_env.agent.llm import (
    BudgetCapExceeded,
    GiveUpReceived,
    NoProgressReached,
    SuccessReached,
    TurnCapReached,
    WallBudgetExceeded,
    run_agent,
)
from cve_env.agent.prompts import (
    BENIGN_VERIFY_CONTINUATION_PROMPT,
    CONTINUATION_USER_PROMPT,
    FORCE_RESOLVE_CONTINUATION_PROMPT,
    PROPRIETARY_VERIFY_CONTINUATION_PROMPT,
    SYSTEM_PROMPT,
    render_runtime_caps_block,
    render_user_prompt,
)
from cve_env.agent.refusals import RefusalScanner, append_events, default_log_path

# Per-CVE tool-state reset aggregator (one registry replaces hand-wired resets).
from cve_env.agent.tools import (
    ALL_TOOLS,
    reset_all_tool_state,
    set_cve_id_context,
    set_cve_version_context,
)
from cve_env.config import (
    AGENTIC_AUDIT_ROOT,
    INTERNAL_WALL_BUDGET_S,
    MAX_COST_USD_PER_CVE_SOFT,
    MAX_TOOL_ATTEMPT_EXTENSIONS,
    MAX_TURN_EXTENSIONS,
    MODEL,
    NO_PROGRESS_GIVEUP_TURNS,
    POST_BUILD_PRODUCTIVE_TOOLS,
    PRODUCTIVE_RECENCY_TURNS,
    PRODUCTIVE_TOOLS,
    STAGES,
    TURN_CAP,
    TURN_EXTENSION_PCT,
    VERSION_ASSERTION_CMD_PATTERN,
    estimate_cost_from_tokens,
    estimate_cost_from_turns,
    get_benign_verify_continuation_max,
    get_enable_benign_verify_continuation,
    get_enable_halt_on_verified_success,
    get_enable_proprietary_verify_continuation,
    get_force_resolve_budget_fraction,
    get_force_resolve_max,
    get_proprietary_verify_max,
    productive_extension_allowed,
    stage_for_tool,
)
from cve_env.config import get_recovery_eligible_stages as _get_recovery_eligible_stages
from cve_env.config import get_recovery_gap_turns as _get_recovery_gap_turns
from cve_env.config import get_tool_attempt_cap as _get_tool_attempt_cap
from cve_env.config import over_budget_stages as _over_budget_stages
from cve_env.config import should_extend_cost_cap as _should_extend_cost_cap
from cve_env.config import stage_hard_budget_breach as _stage_hard_budget_breach
from cve_env.models import CveRecord, HostInfo, Outcome, OutcomeStatus
from cve_env.tools._smoke import has_functional_smoke

# Emit per-tool ``T<turn> ✓ <tool_name> <hint>`` lines to stderr
# during the build so single-CVE runs aren't silent. Bench50.sh has its own
# live monitor (bench_status.sh); this brings the same story to one-off
# `cve-env build` smokes. Set CVE_ENV_QUIET=1 to suppress (tests do this
# to keep pytest output clean).
_LIVE_STDERR_DISABLED: bool = os.environ.get("CVE_ENV_QUIET", "").strip() in (
    "1",
    "true",
    "True",
)

# Fix #8 (continuation loop on premature end_turn): the prompt's
# commitment-enforcement rule alone does NOT close a measured follow-through gap
# (source-build-no-verify cases that are near-builds), so a runtime continuation
# backstops it. The runtime lives in ``_should_continue_for_verify`` + the
# continuation loop in ``build()`` (BOTH the prompt rule AND this runtime are
# kept). Reuses ``CONTINUATION_USER_PROMPT`` (prompts.py) + ``resume`` on
# ``run_agent`` (llm.py); the ``test_fix8_*`` tests are the behavioral spec.


# Lifecycle vs active payload check types.
#
# - Lifecycle checks prove the container is up + the port answers, but do
#   not exercise the app's normal operations on benign input.
# - Active payload check types are payload-injection / exec-runner /
#   raw-TCP probes. Their PRESENCE counts toward the functional-smoke
#   heuristic; their intent (which check is benign-input vs CVE-trigger)
#   is the agent's design choice and not classified by the runtime.
_LIFECYCLE_ONLY_CHECK_TYPES = frozenset(
    {"container_status", "http_check", "log_check", "stability_wait"}
)
_ACTIVE_CHECK_TYPES = frozenset({"http_request_check", "exec_check", "tcp_probe_check"})

# Backwards-compat alias retained briefly during transition.
_ACTIVE_PROBE_CHECK_TYPES = _ACTIVE_CHECK_TYPES

# Launch-stage tools whose ok=true result means a Docker
# environment is up. Used by _StreamState/launched_ok tracking +
# _map_status to surface the launched-but-never-verified anti-pattern.
_LAUNCH_TOOLS = frozenset({"docker_run", "docker_compose_up", "run_in_container"})

# Build-path tools. Single source of truth for "did the agent
# BUILD vs just RESOLVE+RUN?" The strict version-marker gate
# only fires for build-path runs because for image-pulled runs the
# registry tag is itself the version assertion.
_BUILD_TOOLS = frozenset({"docker_build", "dockerfile_gen", "source_build"})

# The bundled `claude` CLI halts with stop_reason="max_turns_reached" at SDK
# num_turns=30-39 regardless of the --max-turns value passed. Setting
# `sdk_max_turns = max_turns × 4` does NOT move the SDK out of its buggy zone —
# the SDK isn't bound by the configured budget at the halt point. The 4×
# multiplier is therefore harmless headroom: the F-9 + B-20 runtime caps (with
# unit-test coverage) cap state.turn at 96 (or 115 with the B-20 extension),
# well below the SDK's halt point. The multiplier remains so that IF the SDK
# premature-halt is ever fixed upstream, F-9 stays the authoritative cap
# enforcer rather than a smaller sdk_max_turns value silently halting the run.
_SDK_MAX_TURNS_SAFETY_MULTIPLIER = 4

# Mid-run stuck-after-launch turn-gap interventions are NOT safe — they
# false-positive (regressions observed in benches). The cost-based adaptive
# extension is the principled replacement. The TERMINAL classifier (in
# _map_status at the turn_cap branch) STAYS — it fires at terminal time only,
# no false-positive risk.

# Version-assertion detection. Pattern lives in `cve_env.config`
# so verify.py and loop.py share a single source of truth.


# API-Overload classifier. CVEs that hit an Anthropic 529 Overload during an
# outage can have an empty give_up_reason — the classification lives only in
# unstructured final_text. This helper detects the pattern; callers populate
# give_up_reason="api_overload" when it returns "api_overload".
def _classify_api_overload(final_text: str) -> str:
    """Classify final_text against the Anthropic 529 Overload pattern.

    Returns "api_overload" iff final_text starts with the canonical
    Anthropic API 529 Overloaded error wrapper. Returns "" otherwise.

    Args:
        final_text: outcome JSON's final_text field (or empty string)

    Returns:
        "api_overload" if pattern matches, "" otherwise.
    """
    if not isinstance(final_text, str) or not final_text:
        return ""
    # Anchored pattern: final_text must start with the API-Overload wrapper.
    # The full canonical form is "API Error: Repeated 529 Overloaded errors. ..."
    if final_text.startswith("API Error: Repeated 529 Overloaded errors"):
        return "api_overload"
    return ""


def _check_wall_budget(wall_start_time: float, budget_s: float, turn: int) -> None:
    """Raise WallBudgetExceeded when elapsed wall-clock exceeds budget.

    Uses time.time() (NOT time.monotonic()) because monotonic clocks also
    pause during macOS host sleep — only time.time() advances during sleep.
    External wall-guards (gtimeout/perl-alarm) suffer the same kernel-timer
    pause; this Python-side check is the durable backstop.

    Args:
        wall_start_time: time.time() snapshot at build() entry; 0.0 means
            uninitialized (check skipped).
        budget_s: max wall-clock seconds; 0 means disabled (check skipped).
        turn: current agent turn for the error message.

    Raises:
        WallBudgetExceeded: when budget_s > 0 AND wall_start_time > 0 AND
            (time.time() - wall_start_time) > budget_s.
    """
    if budget_s <= 0 or wall_start_time <= 0:
        return
    elapsed = time.time() - wall_start_time
    if elapsed > budget_s:
        raise WallBudgetExceeded(
            f"internal wall budget {budget_s:.0f}s exceeded "
            f"after {elapsed:.0f}s at turn {turn}"
        )


def _check_no_progress(
    current_turn: int, last_productive_turn: int, threshold: int
) -> None:
    """Anti-thrash: raise NoProgressReached when the agent has gone
    more than ``threshold`` turns with no productive progress.

    ``last_productive_turn`` is updated (by _is_productive_outcome) on any
    PRODUCTIVE_TOOLS ok OR any post-build verify/run_in_container — so the gap
    only grows while the agent is making NO progress (cheap research/Bash churn,
    not the convergent post-build verify loop, which keeps the marker fresh).

    Strictly-greater so the data-floor (≥72; a winning CVE had a 71-turn
    productive gap) is honored at the boundary.

    Args:
        current_turn: the live agent turn.
        last_productive_turn: turn of the most recent productive outcome (0 = none yet).
        threshold: CVE_ENV_NO_PROGRESS_GIVEUP_TURNS; 0 means disabled (skip).

    Raises:
        NoProgressReached: when threshold > 0 AND (current_turn - last_productive_turn) > threshold.
    """
    if threshold <= 0:
        return
    gap = current_turn - last_productive_turn
    if gap > threshold:
        raise NoProgressReached(
            f"no productive progress for {gap} turns "
            f"(turn={current_turn}, last_productive_turn={last_productive_turn}, "
            f"threshold={threshold})"
        )


def _is_version_assertion_exec_check(check_entry: dict[str, Any]) -> bool:
    """Does this exec_check entry look like a version assertion?

    Inspects the command text for known version-discovery shapes. Returns
    False for non-exec_check entries, missing/non-string commands, or
    commands that don't match any whitelisted pattern.
    """
    if check_entry.get("type") != "exec_check":
        return False
    details = check_entry.get("details")
    if not isinstance(details, dict):
        return False
    command = details.get("command")
    if not isinstance(command, str):
        return False
    return bool(VERSION_ASSERTION_CMD_PATTERN.search(command))


# A "specific" version marker must contain at least major.minor digits.
# Reject bare product names ('Apache'), single-digit major-only ('8.', '8'),
# or empty markers — these let any deployed version pass and defeat the
# gate's purpose.
_SPECIFIC_VERSION_MARKER_RE = re.compile(r"\d+\.\d+")


def _has_specific_version_marker(check_entry: dict[str, Any]) -> bool:
    """True iff this exec_check's `expected_stdout_contains` is set AND
    contains a specific version pattern (≥ major.minor digits).

    Pairs with `_is_version_assertion_exec_check`: that helper checks
    the COMMAND was version-discovery; this one checks the EXPECTED
    STDOUT pins a real version. Together they enforce the version-marker
    rule deterministically:

    - `expected_stdout_contains: "Apache"` → False (no digits)
    - `expected_stdout_contains: "8."` → False (no minor)
    - `expected_stdout_contains: "8.5"` → True
    - `expected_stdout_contains: "Apache/2.4.49"` → True
    - missing / non-string → False (no marker at all)

    The runtime gate (in `_classify_verify_outcome`) downgrades to
    `verified_partial` when at least one version-assertion exec_check
    fired but NONE of them carried a specific marker.
    """
    if check_entry.get("type") != "exec_check":
        return False
    details = check_entry.get("details")
    if not isinstance(details, dict):
        return False
    expected = details.get("expected_stdout_contains")
    if not isinstance(expected, str):
        return False
    return bool(_SPECIFIC_VERSION_MARKER_RE.search(expected))


@dataclass
class _StreamState:
    """Mutable state threaded through the message stream."""

    # Grows monotonically across continuations; bounded by turn caps.
    # No trim needed for current deployment.
    tool_name_by_id: dict[str, str] = field(default_factory=dict)
    # Parallel map for tool inputs, captured at the llm_turn handler (mirroring
    # tool_name_by_id) and retrieved at the tool_result writer so AuditEntry rows
    # for tool_ok / tool_error / recovery entries carry the originating input
    # dict. Without this, ALL tool_result entries would have empty
    # `tool_input: {}` across ALL tool types, corrupting downstream forensic
    # queries that join tool_use → tool_result.
    tool_input_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    tool_uses_seen: list[dict[str, Any]] = field(default_factory=list)
    verify_passed: bool = False
    last_verify_result: dict[str, Any] | None = None
    give_up_reason: str = ""
    give_up_detail: str = ""
    # force-resolve-before-giveup: set once a force-resolve continuation has been
    # spent on this CVE, so it never re-fires.
    force_resolve_attempted: bool = False
    # proprietary-verify continuation: one-shot guard so an
    # unprobed give_up(proprietary) gets at most ONE verify probe.
    proprietary_verify_attempted: bool = False
    # Live session id captured from streaming messages (AssistantMessage carries
    # it). The SDK's terminal ResultMessage — the only thing that sets
    # run.session_id — arrives at query END, AFTER a mid-stream give_up raises,
    # so run.session_id is empty for a give_up run. This lets the force-resolve
    # continuation resume the same session anyway.
    last_session_id: str = ""
    final_text: str = ""
    turn: int = 0
    result_received: bool = False  # True after the SDK emits a ResultMessage
    # Union of check types from every passing verify call. We use
    # the *passing* call's plan to decide environment-build completeness.
    # Failed verify calls don't count.
    passing_verify_check_types: set[str] = field(default_factory=set)
    # True iff at least one exec_check in any passing verify
    # matched a version-assertion command pattern. Required for `success`
    # classification (right version numbers, pre-patch).
    passing_verify_has_version_assertion: bool = False
    # True iff at least one version-assertion exec_check ALSO had a specific
    # version marker in expected_stdout_contains (>=major.minor digits). Without
    # this the prompt rule is the only enforcement; with it, a verify plan that
    # runs `apache2 -v` but asserts `expected_stdout_contains="Apache"`
    # (no version pin) deterministically downgrades to verified_partial
    # WHEN the run took the build path (see has_built below). For
    # image-pulled runs the registry tag is the version assertion, so
    # a loose marker is acceptable (accept versions if they come with a
    # relevant image, but enforce it if we build).
    passing_verify_has_specific_version_marker: bool = False
    # True iff the agent invoked any of the build-path tools
    # (docker_build, dockerfile_gen, source_build). The build path picks
    # versions via FROM lines / install commands and has more drift
    # surface than image_resolve+docker_run; only enforce specific
    # markers in this case.
    has_built: bool = False
    # True iff the passing verify plan included functional smoke
    # verbs proving the app's normal operations work on benign input.
    # Heuristic: >=3 active-class checks present, OR >=1 http_check with
    # content_check_performed, OR >=2 distinct-path http_checks. Required
    # for `success` (build a working environment).
    passing_verify_has_functional_smoke: bool = False
    # True iff ANY ResultMessage during the run had a refusal-class
    # stop_reason. The SDK can emit multiple ResultMessages (auth_error retry
    # storm, mid-run refusals); only the LAST one ends up in run.stop_reason.
    # Checking only the final stop_reason misses cases where an earlier
    # ResultMessage was "refusal" but the final one is "end_turn".
    refusal_stop_reason_seen: bool = False
    # Set when a docker_build/daemon tool result is classified
    # ``daemon_corruption`` (corrupted containerd storage / failed to retrieve
    # image list). HOST infra corruption, not engine — surfaced on the Outcome so
    # the bench can heal (colima restart) + re-run rather than count unresolvable.
    daemon_corruption_seen: bool = False
    # Track WHEN the latest refusal happened and when verify last passed, to
    # distinguish "refusal-then-recovery" (verify passed AFTER the refusal —
    # success) from "verify-then-refusal" (refusal corrupted the post-verify
    # state — incomplete). Without these, the refusal latch is overly
    # pessimistic and labels recovered runs as incomplete.
    refusal_stop_reason_turn: int | None = None
    verify_passed_turn: int | None = None
    # The SDK's ResultMessage may arrive (with cost + turn count) and THEN
    # run_agent may throw. Without this, the exception-path Outcome constructor
    # would default num_turns/total_cost_usd to 0/0.0 because only the happy
    # path's `run` object carries those fields. We track the max across all
    # ResultMessages (the SDK may emit multiple) so the exception-path Outcome
    # can read them.
    last_cost_usd: float = 0.0
    last_num_turns: int = 0
    # Token accumulator. Used to estimate cost when the SDK reports
    # total_cost_usd=0 despite real LLM rounds (observed on max_turns_reached
    # and certain end_turn-after-give_up paths). Outcome uses
    # ``max(last_cost_usd, run.total_cost_usd, estimate_from_tokens)``.
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    # B-20 productive-extension state.
    # ``last_productive_turn`` is set when a build-class tool (image_resolve,
    # docker_build, docker_run, docker_compose_up, source_build) returns
    # ok=True. ``extension_count`` tracks how many auto-extensions the loop
    # has granted this CVE. ``effective_max_turns`` starts at the configured
    # max_turns and is bumped by ``should_extend_turn_cap`` decisions.
    last_productive_turn: int = 0
    extension_count: int = 0
    effective_max_turns: int = 0
    # Wall-clock anchor for the internal wall-budget check. Set to time.time()
    # at build() entry. on_message compares (time.time() - wall_start_time)
    # against INTERNAL_WALL_BUDGET_S to detect runs that exceed wall budget —
    # works even when macOS sleep pauses external kernel alarm timers.
    # 0.0 = uninitialized (check skipped).
    wall_start_time: float = 0.0
    # True iff ANY launch-stage tool returned ok=true. Used by the classifier to
    # distinguish "agent launched but never tried verify" from "agent never
    # reached launch" (no_verify_pass with no launch evidence). Set on
    # tool_result for docker_run, docker_compose_up, run_in_container.
    launched_ok: bool = False
    # Set when docker_build.ok=True at least once this run. Used by the turn-cap
    # trigger to emit a distinct `stuck_after_launch_after_build` triage marker
    # when the agent built an image but never called docker_run + never reached
    # verify. Same terminal status (turn_cap); richer reason for analysis.
    docker_built_ok: bool = False
    # Set when image_resolve returned ok=true at least once this run. Used by the
    # classifier branch to distinguish "agent had a usable image_ref but never
    # tried docker_run" (the Shellshock pattern) from generic research-only paths.
    image_resolve_ok: bool = False
    # Per-stage cost attribution for the budget engine.
    # `stage_costs[stage]` = USD attributed to that stage.
    # `stage_calls[stage]` = # of llm_turn tool_use events per stage.
    # `last_tool_stage` = stage of the most-recent ToolUseBlock processed.
    #
    # Attribution mechanism: a per-segment dual-path approach:
    #   (a) PRIMARY: AssistantMessage token-derived attribution
    #       (`_accum_tokens` + `estimate_cost_from_tokens`) — credits each AM
    #       to the most-recent tool's stage in real time. Captures the
    #       under-attribution mode where ResultMessage cost does not equal
    #       sum-of-stage-costs for retry-storms.
    #   (b) RESIDUAL: ResultMessage path computes
    #       `residual = rm_reported_cost - am_credited_in_segment` and credits
    #       residual to last_tool_stage. Closes the under-attribution mode.
    # Per-segment credit equals `max(AM_token_estimate, RM_reported_cost)` —
    # NOT a strict either-or; sum/total ≈ 100% on non-trivial CVEs.
    # Telemetry ONLY — no decisions are baked on these fields.
    stage_costs: dict[str, float] = field(
        default_factory=lambda: {s: 0.0 for s in STAGES}
    )
    stage_calls: dict[str, int] = field(default_factory=lambda: {s: 0 for s in STAGES})
    last_tool_stage: str = "OTHER"
    # Per-segment cost-attribution accounting. A "segment" is the sequence of
    # AssistantMessages culminating in a ResultMessage.
    # ``current_segment_id`` increments after each ResultMessage.
    # ``am_credited_per_segment[seg_id]`` tracks dollars already attributed
    # to stages via the AssistantMessage token-estimate path for that
    # segment. The ResultMessage path uses this to compute a RESIDUAL
    # (``rm_cost - am_credited``) so per-segment credit equals
    # ``max(AM_token_estimate, RM_reported_cost)`` — not a strict either-or.
    # A boolean ``attributed_segments`` dedup would over-skip RM cost when AM
    # credited a tiny amount, so the residual approach is used instead.
    current_segment_id: int = 0
    am_credited_per_segment: dict[int, float] = field(default_factory=dict)
    # Adaptive cost-cap extension state. Mirrors B-20's `extension_count` +
    # `effective_max_turns` for cost. `effective_max_cost_usd` starts at
    # `max_cost_usd` (set in build()) and is bumped on each granted extension.
    cost_extension_count: int = 0
    effective_max_cost_usd: float = 0.0
    # Per-tool attempt counts. Incremented on each ToolUseBlock. Compared against
    # ``config.get_tool_attempt_cap(tool_name)`` — when cap > 0 and count > cap,
    # the run terminates with ``give_up_reason="max_tool_attempts_<tool>"``.
    # Default cap=0 means unbounded (current behavior). Opt-in.
    tool_attempt_count: dict[str, int] = field(default_factory=dict)
    # Per-tool count of progress-aware cap EXTENSIONS granted (bounded by
    # MAX_TOOL_ATTEMPT_EXTENSIONS). Mirrors B-20's extension_count.
    tool_cap_extension_count: dict[str, int] = field(default_factory=dict)
    # Recovery audit telemetry tracking.
    # ``last_tool_error_turn[tool_name]`` = most-recent failure turn for
    # that tool; cleared on success (recovery emit) or when gap exceeds K.
    # ``tool_error_count_since_last_ok[tool_name]`` = consecutive failures
    # since last success; used to populate ``errors_in_window`` in the
    # recovery row. See :func:`_process_tool_result_for_recovery`.
    last_tool_error_turn: dict[str, int] = field(default_factory=dict)
    tool_error_count_since_last_ok: dict[str, int] = field(default_factory=dict)
    # True iff the agent ever called `verify` (passing or failing). Distinct from
    # `verify_passed`. Together with `launched_ok` lets _map_status surface the
    # launched-but-never-verified anti-pattern (e.g. agent runs docker_run.ok=true,
    # then a Bash 'docker logs', then end_turn, never invoking verify).
    verify_attempted: bool = False


def _parse_tool_result_payload(block: ToolResultBlock) -> dict[str, Any] | None:
    """Extract the JSON payload our tools embed in ``content[0].text``."""
    content = block.content
    if not isinstance(content, list):
        return None
    for item in content:
        if not isinstance(item, dict) or item.get("type") != "text":
            continue
        text = item.get("text")
        if not isinstance(text, str):
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _mcp_suffix(name: str) -> str:
    """Strip the ``mcp__<server>__`` prefix added by the SDK."""
    parts = name.split("__", 2)
    if len(parts) == 3 and parts[0] == "mcp":
        return parts[2]
    return name


def _accum_tokens(state: _StreamState, usage: Any) -> None:
    """Add ``usage``'s input/output tokens to ``state`` totals.

    ``usage`` is dict[str, Any] | object | None per the SDK type hint
    (``claude_agent_sdk.types.ResultMessage.usage`` and
    ``AssistantMessage.usage``). No-op when usage is falsy.
    """
    if not usage:
        return
    if isinstance(usage, dict):
        state.total_input_tokens += int(usage.get("input_tokens", 0) or 0)
        state.total_output_tokens += int(usage.get("output_tokens", 0) or 0)
    else:
        state.total_input_tokens += int(getattr(usage, "input_tokens", 0) or 0)
        state.total_output_tokens += int(getattr(usage, "output_tokens", 0) or 0)


def _merge_cumulative_tokens(state: _StreamState, usage: Any) -> None:
    """Merge a CUMULATIVE-per-session usage block (``ResultMessage.usage``) into
    the running token totals via ``max()``, NOT ``+=``.

    ``ResultMessage.usage`` is the session aggregate (SDK ``types.py``:
    "Cumulative API usage for the session"), whereas ``AssistantMessage.usage``
    (counted via :func:`_accum_tokens`) is per-message. Summing both
    double-counts the session's tokens (~2x, worse across multi-ResultMessage
    retry storms). ``max()`` lifts the totals to the cumulative floor without
    re-adding the per-message tokens already counted, and never lowers them — so
    a give_up run that never reaches a terminal ResultMessage keeps its
    per-message accumulation. No-op when ``usage`` is falsy.

    ASSUMPTION (benign — these totals only feed the token-estimate floor in
    _floor_cost, which never wins the max() under session auth, so cost is
    unaffected): the session-cumulative continues across continuation runs, which
    all resume the same session (``run_agent(..., resume=...)``). If a future SDK
    were to RESET the cumulative on resume, this max() would freeze at the largest
    single-run value and under-count tokens across continuations; the per-message
    AssistantMessage += would then be the more accurate signal.
    """
    if not usage:
        return
    if isinstance(usage, dict):
        in_tok = int(usage.get("input_tokens", 0) or 0)
        out_tok = int(usage.get("output_tokens", 0) or 0)
    else:
        in_tok = int(getattr(usage, "input_tokens", 0) or 0)
        out_tok = int(getattr(usage, "output_tokens", 0) or 0)
    state.total_input_tokens = max(state.total_input_tokens, in_tok)
    state.total_output_tokens = max(state.total_output_tokens, out_tok)


def _accumulate_result_cost_and_turns(state: _StreamState, msg: Any) -> None:
    """ResultMessage cost/turn aggregation, extracted from ``on_message``
    (behavior-preserving). Handles the multi-ResultMessage cost storm: credit the
    RESIDUAL (this RM's cost minus what the AssistantMessages in the current
    segment already credited) to the current stage, accumulate total cost + max
    turns, then advance ``current_segment_id`` so subsequent AssistantMessages
    start a fresh segment. ``last_cost_usd`` is accumulated unconditionally — it
    drives the cap check, not stage telemetry.
    """
    # Assumption: SDK cost_usd is per-segment, not session-cumulative.
    # Verified for claude_agent_sdk 0.x. If SDK changes to cumulative,
    # this will double-count.
    cost_delta = msg.total_cost_usd or 0.0
    if cost_delta > 0:
        am_credited = state.am_credited_per_segment.get(state.current_segment_id, 0.0)
        residual = cost_delta - am_credited
        if residual > 0:
            state.stage_costs[state.last_tool_stage] = (
                state.stage_costs.get(state.last_tool_stage, 0.0) + residual
            )
    state.last_cost_usd += cost_delta
    state.last_num_turns = max(state.last_num_turns, msg.num_turns or 0)
    state.current_segment_id += 1


def _latch_assistant_token_cost(state: _StreamState, msg: Any, model: str) -> None:
    """AssistantMessage token accumulation + per-call cost attribution, extracted
    from ``on_message`` (behavior-preserving). Accumulates tokens and attributes
    THIS LLM call's token-derived cost to ``last_tool_stage`` (the stage of the
    tool whose result motivated this turn), recording the amount per-segment so the
    ResultMessage handler can credit only the RESIDUAL (closes both the all-zeros
    and under-attribution failure modes).
    """
    usage_obj = getattr(msg, "usage", None)
    _accum_tokens(state, usage_obj)
    if usage_obj is not None:
        if isinstance(usage_obj, dict):
            in_t = int(usage_obj.get("input_tokens", 0) or 0)
            out_t = int(usage_obj.get("output_tokens", 0) or 0)
        else:
            in_t = int(getattr(usage_obj, "input_tokens", 0) or 0)
            out_t = int(getattr(usage_obj, "output_tokens", 0) or 0)
        if in_t > 0 or out_t > 0:
            cost = estimate_cost_from_tokens(in_t, out_t, model)
            state.stage_costs[state.last_tool_stage] = (
                state.stage_costs.get(state.last_tool_stage, 0.0) + cost
            )
            state.am_credited_per_segment[state.current_segment_id] = (
                state.am_credited_per_segment.get(state.current_segment_id, 0.0) + cost
            )


# Terminal statuses where the SDK was INTERRUPTED mid-run (no clean end_turn
# ResultMessage emitted) so its reported cost is unreliable — the turns-based
# floor applies only to these. Covers every abnormal termination in the
# OutcomeStatus taxonomy (models.py): the turn/budget caps, a mid-run exception
# (``error`` and the generic ``interrupted``/``incomplete`` alias — the default
# terminal status on the exception path), and a 529 throttle giving up
# (``rate_limited``). Clean exits — success, verified_partial, verify_failed,
# launched_no_verify, and the give-up family (unresolvable), which all end via a
# natural end_turn with the SDK's full cost reported — are excluded so the floor
# never inflates a correctly-reported cost.
_INTERRUPTED_EXIT_STATUSES = frozenset(
    {
        "turn_cap",
        "budget_exhausted",
        "error",
        "interrupted",
        "incomplete",
        "rate_limited",
    }
)


def _floor_cost(
    status: str,
    num_turns: int,
    last_cost_usd: float,
    cont_cost_usd: float,
    input_tokens: int,
    output_tokens: int,
    model: str,
    effective_max_cost_usd: float,
) -> float:
    """Resolve the final ``total_cost_usd`` with all floors applied.

    Base = max(SDK-reported cost, continuation-summed cost, token estimate).
    Adds a turns-based floor for any INTERRUPTED exit (turn_cap / budget / error
    / ...). Under Claude Code session auth the SDK under-reports cost on an
    interrupted run AND ``usage`` is a tiny NONZERO stub (observed in=10, out=2),
    so both the SDK cost and the token estimate collapse and a multi-turn run
    would otherwise log ~$0. The floor is a ``max()`` bounded by
    ``effective_max_cost_usd``, so it only ever RAISES: a correctly-reported
    token-bearing (API-key) run keeps its real cost (its token estimate already
    exceeds the conservative per-turn floor), and the floor never exceeds the
    run's budget cap. Clean exits are excluded by ``_INTERRUPTED_EXIT_STATUSES``
    membership (NOT by a token check — production never reports exactly 0 tokens).
    """
    cost = max(
        last_cost_usd,
        cont_cost_usd,
        estimate_cost_from_tokens(input_tokens, output_tokens, model),
    )
    if status in _INTERRUPTED_EXIT_STATUSES:
        turns_floor = estimate_cost_from_turns(num_turns, model)
        if effective_max_cost_usd > 0:
            turns_floor = min(turns_floor, effective_max_cost_usd)
        cost = max(cost, turns_floor)
    return cost


def _latch_text_and_scan(
    state: _StreamState,
    block: Any,
    *,
    refusal_scanner: RefusalScanner,
    pending_tool_use: dict[str, Any] | None,
    writer: AuditWriter,
    cve: CveRecord,
) -> None:
    """TextBlock handling extracted from ``on_message`` (behavior-preserving):
    capture ``final_text``, scan + observe the assistant text for refusals, and
    audit the turn's text.
    """
    state.final_text = block.text
    refusal_scanner.scan_text(
        turn=state.turn, text=block.text, tool_call=pending_tool_use
    )
    refusal_scanner.observe(
        {"turn": state.turn, "kind": "assistant_text", "text": block.text[:600]}
    )
    writer.write(
        cve_id=cve.cve_id,
        entry=AuditEntry(
            turn=state.turn,
            status="llm_turn",
            llm_message={"text": block.text[:4000]},
        ),
    )


def _process_tool_result_for_recovery(
    state: _StreamState,
    *,
    tool_name: str,
    turn: int,
    tool_status: str,
    tool_result: Any,
) -> AuditEntry | None:
    """Detect tool-failure→tool-success recovery and emit
    an ``AuditEntry(status="recovery", ...)`` when conditions hold.

    Recovery conditions (all must hold):
      1. ``tool_name``'s stage is in the eligible set (default
         ACQUIRE/RESOLVE/LAUNCH/VERIFY — DIAGNOSTIC/RESEARCH excluded for
         noise; routine Bash/Read retries don't carry recovery signal).
      2. The tool previously emitted a failure (recorded in
         ``state.last_tool_error_turn``) within ``RECOVERY_GAP_TURNS``
         turns (default 20).
      3. The current call is a success: ``tool_status == "tool_ok"`` AND
         no negative ``ok``/``passed`` field in payload.

    Failure signal: ``tool_status == "tool_error"`` OR
    ``isinstance(tool_result, dict) and (tool_result.get("ok") is False
    or tool_result.get("passed") is False)``. Build-path tools use
    ``ok``; ``verify`` uses ``passed``. The audit JSONL records
    status="tool_ok" for both shapes; the failure lives in the payload.

    Same-tool only by design: cross-tool transitions (e.g.,
    ``source_build`` error → ``dockerfile_gen`` ok) are PIVOTS, not
    recoveries — surfaced separately.

    Idempotent: emit once per error→ok pair, then clear state. Re-armed
    by the next failure.

    Returns the recovery ``AuditEntry`` (caller writes via the same
    audit writer used for ordinary rows) or ``None``.
    """
    stage = stage_for_tool(tool_name)
    if stage not in _get_recovery_eligible_stages():
        return None
    is_failure = tool_status == "tool_error" or (
        isinstance(tool_result, dict)
        and (tool_result.get("ok") is False or tool_result.get("passed") is False)
    )
    if is_failure:
        state.last_tool_error_turn[tool_name] = turn
        state.tool_error_count_since_last_ok[tool_name] = (
            state.tool_error_count_since_last_ok.get(tool_name, 0) + 1
        )
        return None
    if tool_status != "tool_ok":
        return None
    if tool_name not in state.last_tool_error_turn:
        return None
    err_turn = state.last_tool_error_turn[tool_name]
    gap = turn - err_turn
    if gap > _get_recovery_gap_turns():
        # Too stale: clear without emit.
        state.last_tool_error_turn.pop(tool_name, None)
        state.tool_error_count_since_last_ok.pop(tool_name, None)
        return None
    errors_in_window = state.tool_error_count_since_last_ok.get(tool_name, 1)
    state.last_tool_error_turn.pop(tool_name, None)
    state.tool_error_count_since_last_ok.pop(tool_name, None)
    return AuditEntry(
        turn=turn,
        status="recovery",
        tool_name=tool_name,
        tool_result={
            "error_turn": err_turn,
            "recovery_turn": turn,
            "gap": gap,
            "stage": stage,
            "errors_in_window": errors_in_window,
        },
    )


def _live_progress_hint(tool_name: str, payload: Any) -> str:
    """Format the one-line stderr-progress hint per tool result.

    Returns the most informative ``"key=value"`` field from the payload,
    or ``""`` when no payload field applies. Pure; no I/O, no state,
    no side effects.
    """
    if not isinstance(payload, dict):
        return ""
    if payload.get("decision"):
        return f"decision={payload['decision']}"
    if payload.get("reason_class") and payload["reason_class"] != "ok":
        return f"reason={payload['reason_class']}"
    if tool_name == "verify":
        results = payload.get("results") or []
        if isinstance(results, list):
            ok = sum(1 for r in results if isinstance(r, dict) and r.get("passed"))
            return f"{ok}/{len(results)} passed"
    if tool_name == "give_up":
        return f"reason={payload.get('reason', '')}"
    return ""


def _terminal_status_for_result(state: _StreamState, sr_lower: str) -> AuditStatus:
    """Map a ResultMessage to its terminal AuditStatus."""
    # Verify-phase refusal salvage: mirror the _map_status salvage so the audit
    # terminal entry stays consistent with the Outcome — a refused-but-launched,
    # verify-not-passed run logs final_no_verify (the honest partial) instead of
    # losing it to interrupted. SCOPED to exclude cap signals: a CURRENT
    # budget/max_turns stop_reason keeps its cap classification below (cap wins
    # REGARDLESS — the salvage only rescues the non-cap refusal cases that would
    # otherwise be lost). The cap-token set matches the cap branch immediately
    # below (single source of the cap-signal definition).
    _cap_signal = (
        "budget" in sr_lower or "max_turns" in sr_lower or "turn_cap" in sr_lower
    )
    if (
        ("refusal" in sr_lower or state.refusal_stop_reason_seen)
        and not _cap_signal
        and not state.verify_passed
        and (state.launched_ok or state.docker_built_ok)
    ):
        return "final_no_verify"
    # Cap signals in the CURRENT stop_reason beat verify-pass / give_up. Mirrors
    # the priority in _map_status. Without this, the audit terminal entry would
    # log 'final_success' for runs that hit the budget cap (verify_passed=True +
    # budget_exceeded), while the Outcome correctly classifies as
    # budget_exhausted — that audit/outcome inconsistency would mislead forensic
    # analysis.
    if "budget" in sr_lower:
        return "budget_exhausted"
    if "max_turns" in sr_lower or "turn_cap" in sr_lower:
        # SDK actually hit its turn cap (max_turns_reached etc.).
        # NOTE: "end_turn" contains "turn" but is NOT a cap fire —
        # match only the specific cap signatures.
        return "final_turn_cap"
    if state.verify_passed:
        return "final_success"
    if state.give_up_reason:
        return "final_give_up"
    # SDK ended via end_turn (or other non-cap stop_reason) without verify-pass
    # and without give_up. Must NOT fall through to final_turn_cap (no turn cap
    # fired). Use final_no_verify so triage tools can distinguish.
    return "final_no_verify"


def _should_halt_on_verified_success(terminal_status: str) -> bool:
    """Halt-on-verified-success gate. Returns True iff the per-ResultMessage
    terminal status is ``final_success`` AND the default-OFF flag is enabled.

    ``final_success`` is produced by ``_terminal_status_for_result`` ONLY for a
    non-cap stop_reason (clean end_turn) with ``verify_passed`` — the cap branches
    (max_turns / budget) precede the verify branch and return
    ``final_turn_cap`` / ``budget_exhausted`` instead. So this gate can NEVER fire
    on a cap termination, preserving the cap-overrides-verify lock."""
    return terminal_status == "final_success" and get_enable_halt_on_verified_success()


def should_extend_turn_cap(
    *,
    current_turn: int,
    current_max_turns: int,
    last_productive_turn: int,
    extension_count: int,
    current_cost_usd: float,
    max_cost_usd: float,
    max_extensions: int,
    extension_pct: float,
    recency_window: int,
) -> int | None:
    """Decide whether to grant an automatic turn-cap
    extension when the agent is on a productive build path.

    Returns the new ``max_turns`` value if an extension should be granted,
    or ``None`` if denied.

    Granted iff ALL of:
    - ``max_extensions > 0`` (feature enabled)
    - ``extension_count < max_extensions`` (budget remaining)
    - ``last_productive_turn > 0`` (agent has made build progress at all)
    - ``current_turn - last_productive_turn <= recency_window`` (progress is recent)
    - ``current_cost_usd < max_cost_usd * 0.85`` (more turns ≈ more cost;
      stop if we're already near the cost cap)
    """
    if not productive_extension_allowed(
        last_productive_turn=last_productive_turn,
        current_turn=current_turn,
        extension_count=extension_count,
        max_extensions=max_extensions,
        recency_window=recency_window,
    ):
        return None
    if current_cost_usd >= max_cost_usd * 0.85:
        return None
    # Multiplicative: 96->115->138 with 20%. Bounded by max_extensions (typically 1-2).
    return int(current_max_turns * (1.0 + extension_pct))


def _is_productive_outcome(tool_name: str, payload: Any, docker_built_ok: bool) -> bool:
    """Does this tool outcome mark the agent as 'productive'
    (so ``should_extend_turn_cap`` can grant a turn-cap extension)?

    Two cases:
    - A ``PRODUCTIVE_TOOLS`` member with ok=True (build/resolve/run path) —
      the base B-20 signal.
    - A ``POST_BUILD_PRODUCTIVE_TOOLS`` member (verify / run_in_container)
      ONLY when a build already succeeded (``docker_built_ok``). A
      build-then-verify CVE iterating on verify near its cap is making
      progress; gating on docker_built_ok keeps research-only loops (no
      build) from extending. ok-state is NOT required for the post-build
      tools — a verify that ran-but-failed is still active progress on a
      built env.
    """
    if not isinstance(payload, dict):
        return False
    if tool_name in PRODUCTIVE_TOOLS and payload.get("ok") is True:
        return True
    return tool_name in POST_BUILD_PRODUCTIVE_TOOLS and docker_built_ok


def _classify_verify_outcome(state: _StreamState) -> tuple[OutcomeStatus, str]:
    """Shared helper used by both happy-path
    `_map_status` and the exception relabel branch.

    Pre-condition: caller must have already confirmed the verify call passed
    (`state.verify_passed is True`).

    Semantics are decoupled from any exploit-trigger requirement. The product's
    goal is to build pre-patch environments; success here means the BUILD is
    correct, not that the exploit fires.

    - ``success`` requires (verify passed) AND (version-assertion present)
      AND (functional smoke present). Right version + working app on
      benign input = the product's deliverable.
    - ``verified_partial`` is a passing verify that's missing one or both
      of those guarantees. Honest signal that the build reached
      docker_run + verify but evidence is incomplete.

    Active payload checks (http_request_check / tcp_probe_check) are
    available verify primitives but not separately tracked or required —
    they count toward the functional-smoke heuristic like any other
    active check.
    """
    has_version = state.passing_verify_has_version_assertion
    has_specific = state.passing_verify_has_specific_version_marker
    has_smoke = state.passing_verify_has_functional_smoke
    # When the agent BUILT the image (via docker_build / dockerfile_gen /
    # source_build), the version-discovery exec_check MUST also pin a specific
    # version (>= major.minor digits). For image-pulled-only runs (image_resolve
    # + docker_run/compose), the registry tag itself is the version assertion —
    # accept the looser marker. A prompt rule alone is not enough enforcement;
    # this runtime gate closes the gap while accepting versions that come with a
    # relevant image and enforcing them when we build.
    if state.has_built and has_version and not has_specific:
        return (
            "verified_partial",
            "verify passed on a BUILD path (docker_build / dockerfile_gen "
            "/ source_build) and ran a version-discovery command, but no "
            "exec_check carried a specific version marker in "
            "expected_stdout_contains (≥major.minor digits, e.g. '2.4.49' "
            "or '8.5'). Phase 52.1 requires the marker to pin the EXACT "
            "pre-patch version from nvd_lookup; bare product names "
            "('Apache') let any deployed version pass.",
        )
    if has_version and has_smoke:
        return "success", ""
    if not has_version and not has_smoke:
        return (
            "verified_partial",
            "verify passed but missing BOTH version-assertion exec_check "
            "(e.g. '--version', 'dpkg -l', 'pip show') AND functional "
            "smoke (Phase 48 benign-input checks). Build correctness "
            "unproven.",
        )
    if not has_version:
        return (
            "verified_partial",
            "verify passed but missing version-assertion exec_check "
            "(e.g. '--version', 'dpkg -l', 'pip show'); cannot prove "
            "deployed binaries are the pre-patch versions the CVE "
            "requires.",
        )
    return (
        "verified_partial",
        "verify passed but missing functional smoke (Phase 48: 2-3 "
        "benign-input verbs). Version asserted, but a failed CVE-specific "
        "check would be ambiguous (env broken vs vuln not present).",
    )


def _map_status(stop_reason: str, state: _StreamState) -> tuple[OutcomeStatus, str]:
    """Map the SDK ``stop_reason`` + stream signals to an OutcomeStatus.

    Refusal forces ``incomplete``: a Claude Code safety refusal can fire AFTER
    the agent had a passing verify earlier in the run. Checking
    ``state.verify_passed`` first while ignoring ``stop_reason`` would produce a
    false-positive ``success``. Refusal means the SDK was forcibly terminated;
    the run did NOT complete cleanly. The categorical termination signal beats
    any stale per-turn signal.

    PRIORITY ORDER — **DO NOT REORDER**. Each branch below encodes an invariant;
    moving one silently flips classifications. The exception path
    ``_terminal_status_for_result`` mirrors this order — keep them in lockstep.
      1. refusal salvage -> ``launched_no_verify`` — SCOPED ``not verify_passed``
         AND ``not _cap_signal`` so it can never weaken a cap.
      2. cap signals ("budget"/"max_turns" in stop_reason) -> budget_exhausted /
         turn_cap — a cap is a hard resource fact; it BEATS a mid-run verify-pass
         (cap-overrides-verify).
      3. refusal -> ``interrupted`` — categorical termination beats a stale
         ``verify_passed``.
      4. verify-pass classification — success / verified_partial /
         verify_failed via ``_classify_verify_outcome``.
      5. give_up reason / end_turn fall-throughs.
    Regression-locked by test_map_status.py + status-enum parity.
    Documented (not refactored) because reordering is HIGH risk and table-driving
    it buys little vs the locked-down current form.
    """
    sr_lower = (stop_reason or "").lower()
    # Verify-phase refusal salvage: a refusal (current stop_reason OR a latched
    # mid-run one) that fired AFTER the env was built/launched, with verify NOT
    # yet passed, must NOT be lost to the least-informative `interrupted` — the
    # env IS up; report launched_no_verify (honest partial). SCOPED so it CANNOT
    # weaken established cap invariants:
    #   - `not verify_passed` → never touches the refusal-after-verify-pass →
    #     interrupted branch below.
    #   - `not _cap_signal` → a CURRENT budget/max_turns stop_reason keeps its
    #     budget_exhausted / turn_cap (REGARDLESS) classification. The cap signal
    #     is a hard resource fact the operator must see; the launched-ness is
    #     already surfaced via the stuck_after_launch reason marker on the
    #     turn_cap path.
    # Net: the salvage only rescues the non-cap refusal cases (the `interrupted`
    # bucket). The refusal→turn_cap spin is left to the agentic benign-verify
    # continuation, which prevents it rather than relabelling it. Cap-token set
    # matches the cap branch + _terminal_status.
    _cap_signal = (
        "budget" in sr_lower or "max_turns" in sr_lower or "turn_cap" in sr_lower
    )
    _refused = (
        "refusal" in sr_lower
        or "usage policy" in sr_lower
        or state.refusal_stop_reason_seen
    )
    if (
        _refused
        and not _cap_signal
        and not state.verify_passed
        and (state.launched_ok or state.docker_built_ok)
    ):
        return "launched_no_verify", (
            f"refusal after build/launch (launched_ok={state.launched_ok}, "
            f"docker_built_ok={state.docker_built_ok}); verify not passed — "
            f"salvaged to launched_no_verify (stop_reason={stop_reason!r})"
        )
    # Refusal / forced termination overrides everything — even a passing
    # verify mid-run does not mean the engine completed its work.
    # Also classify as incomplete if ANY mid-run ResultMessage was
    # refusal-class (state.refusal_stop_reason_seen). This catches the
    # case where the SDK emitted multiple ResultMessages (retry storm) and
    # only the last one survived — that last one might be "end_turn" even
    # though earlier ones were "refusal".
    # The CURRENT (last) stop_reason is refusal → unconditionally incomplete:
    # the run terminated on refusal, no recovery possible.
    if "refusal" in sr_lower or "usage policy" in sr_lower:
        return "interrupted", (
            f"SDK refused (verify_passed={state.verify_passed}, "
            f"stop_reason={stop_reason!r})"
        )
    # An EARLIER ResultMessage was refusal-class but the LATEST is clean.
    # Distinguish recovery-after-refusal (verify passed AFTER the refusal —
    # agent recovered) from corruption-after-verify (verify passed BEFORE the
    # refusal — refusal corrupted the post-verify state). Returning 'incomplete'
    # for both would miss the recovery case (refusal, then a later
    # verify-pass-+-end_turn).
    if state.refusal_stop_reason_seen:
        # When a mid-run refusal latched but the SDK's TERMINAL stop_reason is a
        # cap signal (budget/turn), the cap classification wins. The cap is the
        # actual cause of run termination — refusal-mid-run is overshadowed.
        # Use tight cap-signal patterns ("max_turns" / "turn_cap") so "end_turn"
        # does NOT match.
        if "budget" in sr_lower:
            return "budget_exhausted", stop_reason
        if "max_turns" in sr_lower or "turn_cap" in sr_lower:
            return "turn_cap", stop_reason
        recovered = (
            state.verify_passed
            and state.verify_passed_turn is not None
            and state.refusal_stop_reason_turn is not None
            and state.verify_passed_turn > state.refusal_stop_reason_turn
        )
        if not recovered:
            return "interrupted", (
                f"SDK refused mid-run "
                f"(verify_passed={state.verify_passed}, "
                f"refusal_turn={state.refusal_stop_reason_turn}, "
                f"verify_pass_turn={state.verify_passed_turn})"
            )
        # Recovered: fall through to verify-passed classification below.
    # Cap signals in the CURRENT stop_reason beat the verify-passed branch. When
    # the SDK terminates with budget_exceeded / max_turns_reached, the cap is the
    # actual cause of run termination — mid-run verify-pass is overshadowed.
    # Tight cap-signal patterns ("max_turns" / "turn_cap") so "end_turn" does NOT
    # false-match.
    if "budget" in sr_lower:
        return "budget_exhausted", stop_reason
    if "max_turns" in sr_lower or "turn_cap" in sr_lower:
        # turn_cap fired after the agent reached LAUNCH
        # (docker_run/compose_up.ok=true) but before any verify attempt —
        # distinguish from generic turn_cap (agent never left RESEARCH).
        # Status stays turn_cap (backwards-compat); only the reason gets a
        # 'stuck_after_launch' marker for triage.
        if state.launched_ok and not state.verify_attempted:
            return (
                "turn_cap",
                f"{stop_reason}; stuck_after_launch: "
                "docker_run/compose_up.ok=true seen but verify never attempted",
            )
        # TRIAGE-ENRICHMENT for the docker_build-but-no-docker_run case: a
        # docker_build success but no docker_run + no verify would otherwise be a
        # plain turn_cap with no triage signal. Distinct marker
        # (`stuck_after_launch_after_build`) so triage can tell pre-build-stuck
        # from post-launch-stuck. Same terminal status. Precondition: launched_ok
        # handled above takes precedence (more specific signal — agent reached
        # docker_run too). TRIAGE-ENRICHMENT, not a behavior change.
        if state.docker_built_ok and not state.verify_attempted:
            return (
                "turn_cap",
                f"{stop_reason}; stuck_after_launch_after_build: "
                "docker_build.ok=true seen but docker_run never succeeded "
                "and verify never attempted",
            )
        return "turn_cap", stop_reason
    if state.verify_passed:
        return _classify_verify_outcome(state)
    if state.give_up_reason:
        return "unresolvable", state.give_up_reason
    # Distinguish "launched but never even tried verify" from "never reached
    # launch". The former is an agent bug pattern (most often: agent emits
    # end_turn after a single Bash poke at the container's logs without ever
    # calling verify). Surfacing it as its own status lets triage tables count +
    # remediate it separately.
    if state.launched_ok and not state.verify_attempted and sr_lower.startswith("end_turn"):
        return (
            "launched_no_verify",
            "agent launched (docker_run/compose_up.ok=true) but emitted "
            "end_turn without calling verify",
        )
    if stop_reason == "end_turn":
        # Surface partial-pass count when verify ran but didn't fully pass.
        # Distinguishes "verify checks failed but agent learned what to fix" from
        # "agent never attempted verify". Helps triage + agent self-recovery.
        if (
            state.verify_attempted
            and state.last_verify_result
            and isinstance(state.last_verify_result, dict)
        ):
            results = state.last_verify_result.get("results") or []
            if isinstance(results, list) and results:
                n_total = len(results)
                n_passed = sum(
                    1 for r in results if isinstance(r, dict) and r.get("passed")
                )
                if 0 < n_passed < n_total:
                    return (
                        "verify_failed",
                        f"verify {n_passed}/{n_total} passed; agent ended without retry",
                    )
        # Distinguish end_turn-without-verify by which tool categories the agent
        # exercised. tool_uses_seen already tracks all tool calls — consult it
        # instead of adding new state.
        tool_names = {u.get("name", "") for u in state.tool_uses_seen}
        research_tools = {
            "nvd_lookup",
            "github_fetch",
            "web_fetch",
            "WebFetch",
            "WebSearch",
        }
        build_tools = {"docker_build", "dockerfile_gen"}
        # TRIAGE-ENRICHMENT marker for the docker_build-SUCCEEDED-but-no-launch
        # case (parallel to the turn_cap marker stuck_after_launch_after_build).
        # When docker_build.ok=true was seen but the agent never reached
        # docker_run, distinguish from the generic "called build tool but build
        # never succeeded" (quit_without_verify_or_giveup). Ships as symmetric
        # insurance with the turn_cap marker. Fires BEFORE the source_build /
        # build_tools branches because docker_build success is the more specific
        # signal regardless of whether source_build was also attempted.
        if state.docker_built_ok and not state.launched_ok:
            state.give_up_reason = "quit_without_verify_after_build"
            state.give_up_detail = (
                "docker_build.ok=true seen; agent emitted end_turn without "
                "docker_run + verify and without explicit give_up. "
                "Runtime synthesized give_up per Phase 51B post-build "
                "commitment rule."
            )
            return "unresolvable", state.give_up_detail
        # The Shellshock pattern — agent reached image_resolve.ok=True (had a
        # usable image_ref) but emitted end_turn without docker_run /
        # docker_compose_up / source_build / verify. Distinct from the
        # docker_built_ok branch (earlier this function) because the agent never
        # even called docker_build. Distinct from the research_or_diag fallback
        # (later) because the agent HAD a usable image to launch. Fires BEFORE the
        # source_build branch so the "no source_build attempt" case gets the more
        # specific marker.
        if (
            state.image_resolve_ok
            and not state.docker_built_ok
            and not state.launched_ok
            and "source_build" not in tool_names
            # Only fire when NO build was attempted. An agent that resolves an
            # image then calls dockerfile_gen/docker_build (that didn't succeed)
            # before quitting did NOT "quit after image_resolve" — it attempted a
            # build; let the build-path branch below label it
            # quit_without_verify_or_giveup.
            and not (tool_names & build_tools)
        ):
            state.give_up_reason = "quit_after_image_resolve"
            state.give_up_detail = (
                "image_resolve.ok=true seen; agent emitted end_turn without "
                "docker_run / docker_compose_up / source_build / verify and "
                "without explicit give_up. Runtime synthesized give_up per "
                "Phase 54-deep.2 post-image_resolve commitment rule."
            )
            return "unresolvable", state.give_up_detail
        # When the agent ran build-path tools then emitted end_turn without
        # verify-pass and without explicit give_up (which the prompt's P0-X rule
        # forbids), the runtime SYNTHESIZES give_up so triage sees a clean
        # classification rather than a silent no_verify_pass that needs human
        # inference. Mutates state so Outcome.give_up_reason / give_up_detail are
        # populated. The prompt rule alone has ~0% follow-through.
        if "source_build" in tool_names:
            state.give_up_reason = "quit_without_verify_or_giveup"
            state.give_up_detail = (
                "source_build attempted; agent emitted end_turn without "
                "verify-pass and without explicit give_up. Runtime synthesized "
                "give_up per P0-X rule."
            )
            return "unresolvable", state.give_up_detail
        if tool_names & build_tools:
            state.give_up_reason = "quit_without_verify_or_giveup"
            state.give_up_detail = (
                "build-path tool attempted (docker_build / dockerfile_gen); "
                "agent emitted end_turn without verify-pass and without "
                "explicit give_up. Runtime synthesized give_up per P0-X rule."
            )
            return "unresolvable", state.give_up_detail
        # Include Bash/Read/Write in the research-or-diag set so that runs which
        # used only diagnostic tools (no build, no verify) classify as
        # research-only rather than the generic "no successful verify" fallback.
        research_or_diag = research_tools | {
            "image_resolve",
            "ToolSearch",
            "Bash",
            "Read",
            "Write",
        }
        if tool_names and tool_names <= research_or_diag:
            return "verify_failed", "research-only path; no build artifacts produced"
        return "verify_failed", "agent ended without a successful verify"
    # SDK-side cap hits surface via stop_reason strings we pass through.
    if "budget" in sr_lower:
        return "budget_exhausted", stop_reason
    if sr_lower in ("max_turns", "max_turns_reached", "turn_limit"):
        return "turn_cap", stop_reason
    return "error", stop_reason or "unknown"


# Fix #8 staging tools — a tool_ok from one of these (suffix-matched so the
# MCP-prefixed forms like ``mcp__cve_env__dockerfile_gen`` also match) before a
# premature end_turn warrants a verify-continuation.
_FIX8_STAGING_TOOLS = frozenset({"Bash", "Write", "dockerfile_gen", "image_resolve"})
_FIX8_MAX_CONTINUATIONS = 2
_FIX8_BUDGET_FRACTION = 0.70

# force-resolve-before-giveup bounds are CONFIG-DRIVEN: see
# config.get_force_resolve_max() (env CVE_ENV_FORCE_RESOLVE_MAX, default 1; 0 =
# disabled) + config.get_force_resolve_budget_fraction() (env
# CVE_ENV_FORCE_RESOLVE_BUDGET_FRACTION, default 0.50 — leaves headroom for the
# Fix #8 verify gate at 0.70). Resolved at call time in _should_continue_for_resolve.


def _should_continue_for_verify(
    run: Any,
    state: _StreamState,
    continuation_count: int,
    cost_acc: float,
    max_cost_usd: float,
) -> bool:
    """Fix #8: the agent ended the turn after a successful build/staging step but
    never ran verify and never gave up → return True to re-prompt it (resume +
    CONTINUATION_USER_PROMPT) to finish. Backstops a measured follow-through gap
    (source-build-no-verify cases that are near-builds) that the prompt rule alone
    does not close.

    Bounds (mandatory): clean end_turn only; ≤2 continuations; only while
    accumulated cost < 70% of the cap. NEVER fires once verify was attempted
    (even if it FAILED — don't re-loop a genuine verify failure), once verify
    passed, or once give_up was called.
    """
    if run.stop_reason != "end_turn":
        return False
    if state.verify_passed or state.verify_attempted or state.give_up_reason:
        return False
    if continuation_count >= _FIX8_MAX_CONTINUATIONS:
        return False
    if max_cost_usd and cost_acc >= _FIX8_BUDGET_FRACTION * max_cost_usd:
        return False
    names = [str(u.get("name", "")).split("__")[-1] for u in state.tool_uses_seen]
    last_staging = bool(names) and names[-1] in _FIX8_STAGING_TOOLS
    # Data-justified EXTENSION beyond the original staging-only trigger: a
    # build/launch that succeeded (the near-builds live here — docker_build /
    # docker_run / source_build), which the staging set alone missed.
    build_ok = state.docker_built_ok or state.launched_ok or "source_build" in names
    return last_staging or build_ok


# build-engagement gate: non-proprietary pre-build give-up reasons that
# force-resolve will re-prompt past. proprietary (closed-source, genuinely
# unbuildable) and arch_incompatible (host-limited) are deliberately EXCLUDED —
# never burn a continuation forcing a build on the proprietary corpus slice.
_FORCE_RESOLVE_ELIGIBLE_REASONS: frozenset[str] = frozenset(
    {
        "skipped_image_lookup",  # no_image emitted without image_resolve (cascade-skip)
        "no_image",  # incl. resolve-only: image_resolve not_found, no build pivot
        "unresolvable_metadata",
    }
)


def _build_attempted(state: _StreamState) -> bool:
    """True iff the agent called an ACTUAL build tool (docker_build /
    dockerfile_gen / source_build). image_resolve alone is NOT a build — a
    resolve that returned not_found without a source_build/dockerfile_gen pivot
    is exactly the resolve-only cascade-skip the gate targets (corpus-wide,
    wins reach a build tool far more often than losses)."""
    return any(u.get("name") in _BUILD_TOOLS for u in state.tool_uses_seen)


def _should_continue_for_resolve(
    run: Any,
    state: _StreamState,
    count: int,
    cost_acc: float,
    max_cost_usd: float,
) -> bool:
    """build-engagement gate (generalized force-resolve): the agent emitted a
    NON-proprietary pre-build give-up (``skipped_image_lookup`` / ``no_image`` /
    ``unresolvable_metadata``) WITHOUT attempting an actual build tool
    (docker_build / dockerfile_gen / source_build). image_resolve alone is NOT a
    build — a resolve that returned not_found and then gave up without a
    source_build/dockerfile_gen pivot is a resolve-only cascade-skip. Re-prompt
    ONCE (resume + FORCE_RESOLVE_CONTINUATION_PROMPT) to actually attempt a build
    before the give_up stands — the engine forces the missing step rather than
    trusting a prompt rule (Fix #8 pattern; prompt-only rules have ~0%
    follow-through). Corpus-wide, wins reach a build tool far more often than
    losses.

    The critical guard: ``proprietary`` (closed-source, genuinely unbuildable)
    and ``arch_incompatible`` (host-limited) are NOT in
    ``_FORCE_RESOLVE_ELIGIBLE_REASONS`` — they never fire, protecting the
    proprietary corpus slice from wasted continuations.

    Bounds (all config-driven): ``run.stop_reason == 'end_turn'`` (give_up
    converts to end_turn in llm._consume); reason in the eligible set AND no
    build tool attempted; ``count < get_force_resolve_max()`` (0 disables);
    accumulated cost < ``get_force_resolve_budget_fraction()`` of the cap (leaves
    headroom for the Fix #8 0.70 verify gate); and a NON-EMPTY ``session_id``
    (a give_up can raise before any ResultMessage arrives → empty session_id,
    which would break ``resume``).
    """
    if run.stop_reason != "end_turn":
        return False
    if state.give_up_reason not in _FORCE_RESOLVE_ELIGIBLE_REASONS:
        return False
    if _build_attempted(state):
        # An actual build tool was already attempted — the agent engaged the
        # cascade; honor the give_up rather than force another attempt.
        return False
    if state.force_resolve_attempted:
        return False
    if count >= get_force_resolve_max():
        return False
    if max_cost_usd and cost_acc >= get_force_resolve_budget_fraction() * max_cost_usd:
        return False
    # A resumable session is required. give_up raises mid-stream, BEFORE the
    # terminal ResultMessage that sets run.session_id, so run.session_id is
    # usually empty here — fall back to the session id captured from streaming
    # AssistantMessages (state.last_session_id). Without either, resume can't work.
    return bool(state.last_session_id or run.session_id)


def _should_continue_for_proprietary_verify(
    run: Any,
    state: _StreamState,
    count: int,
    cost_acc: float,
    max_cost_usd: float,
) -> bool:
    """proprietary-verify continuation (agentic, env-gated default-ON):
    the agent gave up ``proprietary`` WITHOUT ever calling ``image_resolve`` — it
    reasoned the target unbuildable from its name/metadata without probing.
    "Proprietary/unbuildable" is then an UNVERIFIED assumption, and many proprietary
    VENDORS also ship open-source products (Oracle→MySQL, VMware→Spring), so a
    name-only give-up can wrongly skip a buildable OSS product. This gate is the
    runtime backstop for such an unprobed give-up.
    RESUME ONCE (PROPRIETARY_VERIFY_CONTINUATION_PROMPT) to run a single
    image_resolve before the give-up is final — the runtime "verify-the-negative"
    (mirrors ``_should_continue_for_resolve``; prompt-only rules have ~0%
    follow-through).

    The critical efficiency guard: if image_resolve was ALREADY called (a confirmed
    negative), the gate does NOT fire, so genuinely-proprietary targets pay at most
    ONE extra probe and only when no probe was done.

    Bounds (mirror force-resolve): env-gate enabled; ``run.stop_reason == 'end_turn'``;
    ``give_up_reason == 'proprietary'``; NO image_resolve in ``tool_uses_seen``; not
    already attempted; ``count < get_proprietary_verify_max()`` (0 disables);
    accumulated cost < the force-resolve budget fraction of the cap; a resumable
    session id (``last_session_id`` or ``run.session_id``)."""
    if not get_enable_proprietary_verify_continuation():
        return False
    if run.stop_reason != "end_turn":
        return False
    if state.give_up_reason != "proprietary":
        return False
    if any(u.get("name") == "image_resolve" for u in state.tool_uses_seen):
        # Already probed (confirmed negative) — honor the give_up, don't re-probe.
        return False
    if state.proprietary_verify_attempted:
        return False
    pv_max = get_proprietary_verify_max()
    if pv_max <= 0 or count >= pv_max:
        return False
    if max_cost_usd and cost_acc >= get_force_resolve_budget_fraction() * max_cost_usd:
        return False
    return bool(state.last_session_id or run.session_id)


# benign-verify continuation (agentic, default-off). Runs LAST of the
# continuation gates (after force-resolve 0.50 + Fix #8 0.70), so a higher
# cost-headroom fraction is appropriate — by here the env is already
# built+launched and only cheap health checks remain.
_BENIGN_VERIFY_BUDGET_FRACTION: float = 0.85


def _should_continue_for_post_launch_refusal(
    run: Any,
    state: _StreamState,
    count: int,
    cost_acc: float,
    max_cost_usd: float,
) -> bool:
    """benign-verify continuation (agentic, env-gated default-off): a POST-LAUNCH
    refusal blocked verify — the refusal latched (``refusal_stop_reason_seen``),
    the env is launched (``launched_ok``), and verify was NEVER attempted or
    passed. RESUME the SAME session (keeping the built-env context) with an
    explicit benign-only verify prompt so the model runs safe health checks
    instead of the CVE-trigger activity that drew the refusal. An agentic recovery
    that can convert refused→verified; the structural ``launched_no_verify`` floor
    is the fallback when this does not fire or does not succeed.

    Distinct from run_agent's de-escalation retry (FRESH session, generic
    preamble, ~10% post-build follow-through): this RESUMES with a verify-only
    benign framing, so the model need not rebuild — only health-check.

    Unlike the other gates this does NOT require ``stop_reason == 'end_turn'``: a
    TERMINAL refusal (stop_reason='refusal') is the prime case to rescue, and a
    latched-refusal+end_turn qualifies too. Bounds: env-gate enabled; refusal
    latched; env launched; verify NOT attempted/passed; ``count`` < configured
    max (0 disables); accumulated cost < 85% of the cap; a resumable session id
    (``last_session_id`` or ``run.session_id``).
    """
    if not get_enable_benign_verify_continuation():
        return False
    if not state.refusal_stop_reason_seen:
        return False
    if not state.launched_ok:
        return False
    if state.verify_passed or state.verify_attempted:
        return False
    bv_max = get_benign_verify_continuation_max()
    if bv_max <= 0 or count >= bv_max:
        return False
    if max_cost_usd and cost_acc >= _BENIGN_VERIFY_BUDGET_FRACTION * max_cost_usd:
        return False
    return bool(state.last_session_id or run.session_id)


async def build(
    cve: CveRecord,
    host: HostInfo,
    *,
    run_id: str,
    audit_root: Path | None = None,
    model: str = MODEL,
    max_turns: int = TURN_CAP,
    max_cost_usd: float = MAX_COST_USD_PER_CVE_SOFT,
    constraints: list[ServiceConstraint] | None = None,
    max_turn_extensions: int | None = None,
    turn_extension_pct: float | None = None,
) -> Outcome:
    """Drive one agent session for ``cve`` and return its ``Outcome``.

    Every streamed message is audited to
    ``<audit_root>/<run_id>/<sanitized cve_id>.jsonl``.
    """
    # Start each CVE with a clean slate: clear the docker_run sticky-retry
    # memory AND tear down any compose stacks left over from prior CVEs.
    # Also clear the per-product rate-limit budget so a CVE on a fresh product
    # doesn't inherit a prior CVE's exhausted counter.
    reset_all_tool_state()  # resets all per-CVE tool state via one registry
    # Register the CVE's version with the verify tool wrapper so the runtime
    # injector can fill in expected_stdout_contains when the agent omits or
    # under-specifies the version literal.
    set_cve_version_context(cve.version)
    # Register the CVE id so docker_build labels every built image
    # cve-env.cve-id=<id>, enabling exact per-CVE result-image cleanup.
    set_cve_id_context(cve.cve_id)
    writer = AuditWriter(
        run_id=run_id,
        root=audit_root or AGENTIC_AUDIT_ROOT,
    )
    audit_path = writer._path_for(cve_id=cve.cve_id)
    refusal_scanner = RefusalScanner(
        project="cve-env",
        cve_id=cve.cve_id,
        run_id=run_id,
        audit_path=audit_path,
        model=model,
        host_arch=host.arch,
    )
    pending_tool_use: dict[str, Any] | None = None
    state = _StreamState()
    # Anchor wall-clock for the internal wall-budget check. Uses time.time()
    # (NOT time.monotonic()) because monotonic pauses during macOS host sleep;
    # only time.time() advances during sleep.
    state.wall_start_time = time.time()
    user_prompt = render_user_prompt(cve, host, run_id=run_id)

    # Productive-extension knob defaults from config.
    eff_max_turn_extensions = (
        max_turn_extensions if max_turn_extensions is not None else MAX_TURN_EXTENSIONS
    )
    eff_turn_extension_pct = (
        turn_extension_pct if turn_extension_pct is not None else TURN_EXTENSION_PCT
    )
    state.effective_max_turns = max_turns
    # Initialize effective_max_cost_usd from the build()'s cap; this is the cap
    # used by the adaptive extension. Bumped by should_extend_cost_cap when
    # productive progress is detected.
    state.effective_max_cost_usd = max_cost_usd
    # The SDK has its own max_turns gate that fires before our F-9 if both are set
    # to the same value. Solution: tell the SDK a HIGHER max_turns (= max + all
    # possible extensions) so the SDK never halts before our logic. F-9 + B-20
    # enforce the real cap via state.effective_max_turns.
    #
    # See the module-level _SDK_MAX_TURNS_SAFETY_MULTIPLIER comment block for the
    # multiplier rationale.
    sdk_max_turns = int(
        max_turns
        * max(
            1.0 + eff_turn_extension_pct * eff_max_turn_extensions,
            float(_SDK_MAX_TURNS_SAFETY_MULTIPLIER),
        )
    )

    def on_message(msg: Any) -> None:
        nonlocal pending_tool_use
        # Counts every SDK message (Assistant+User+Result), not LLM turns;
        # effective_max_turns compensated via _SDK_MAX_TURNS_SAFETY_MULTIPLIER
        state.turn += 1
        # Capture the live session id from any message that carries it
        # (AssistantMessage does). The terminal ResultMessage arrives only at
        # query END — AFTER a mid-stream give_up raises — so run.session_id is
        # empty for give_up runs; this is the only reliable session handle for the
        # force-resolve resume.
        _sid = getattr(msg, "session_id", None)
        if _sid:
            state.last_session_id = _sid
        # Internal wall-budget check (default off). Fires BEFORE turn-cap so
        # wall-time takes priority when both could trigger. Survives macOS host
        # sleep — see _check_wall_budget.
        _check_wall_budget(state.wall_start_time, INTERNAL_WALL_BUDGET_S, state.turn)
        # Anti-thrash: early give-up after prolonged no-progress churn (default
        # off, threshold 0). Fires AFTER wall-budget, BEFORE the turn-cap so a
        # stuck CVE is reclaimed before burning the full cap. The gap only grows
        # while NO productive tool fires (research/Bash loops); post-build verify
        # churn keeps last_productive_turn fresh, so this never kills a convergent
        # verify loop. Log the give-up to the audit BEFORE re-raising.
        try:
            _check_no_progress(
                state.turn, state.last_productive_turn, NO_PROGRESS_GIVEUP_TURNS
            )
        except NoProgressReached as exc:
            writer.write(
                cve_id=cve.cve_id,
                entry=AuditEntry(
                    turn=state.turn,
                    status="llm_turn",
                    reason=f"anti-thrash no_progress give-up: {exc}",
                ),
            )
            raise
        # Defensive runtime turn-cap with productive-extension.
        # If agent is approaching cap with recent build progress, auto-extend
        # by ``turn_extension_pct`` (default +20%) up to ``max_turn_extensions``
        # times. Otherwise raise TurnCapReached so _run_query_once halts.
        if state.turn > state.effective_max_turns:
            new_cap = should_extend_turn_cap(
                current_turn=state.turn,
                current_max_turns=state.effective_max_turns,
                last_productive_turn=state.last_productive_turn,
                extension_count=state.extension_count,
                current_cost_usd=state.last_cost_usd,
                max_cost_usd=max_cost_usd,
                max_extensions=eff_max_turn_extensions,
                extension_pct=eff_turn_extension_pct,
                recency_window=PRODUCTIVE_RECENCY_TURNS,
            )
            if new_cap is not None:
                # Grant the extension; log to audit so post-bench analysis
                # can see when/why the cap was bumped.
                state.extension_count += 1
                state.effective_max_turns = new_cap
                writer.write(
                    cve_id=cve.cve_id,
                    entry=AuditEntry(
                        turn=state.turn,
                        status="llm_turn",
                        reason=(
                            f"B-20 turn-cap auto-extended to {new_cap} "
                            f"(extension #{state.extension_count}/"
                            f"{eff_max_turn_extensions}; "
                            f"last_productive_turn={state.last_productive_turn})"
                        ),
                    ),
                )
                # Don't raise — let the agent continue.
            else:
                raise TurnCapReached(
                    f"state.turn={state.turn} > max_turns="
                    f"{state.effective_max_turns} (extensions used: "
                    f"{state.extension_count}/{eff_max_turn_extensions})"
                )
        if isinstance(msg, AssistantMessage):
            # Tokens are reported on EACH AssistantMessage (per-call), not just
            # the final ResultMessage. Listening only on ResultMessage would lose
            # all token data for runs that emit no ResultMessage. Accumulate here
            # too. Token accumulation + per-call cost attribution MUST run before
            # this message's ToolUseBlocks update last_tool_stage.
            _latch_assistant_token_cost(state, msg, model)
            for block in msg.content:
                if isinstance(block, ToolUseBlock):
                    short_name = _mcp_suffix(block.name)
                    state.tool_name_by_id[block.id] = short_name
                    # Capture input parallel to name so the tool_result writer can
                    # recover it.
                    state.tool_input_by_id[block.id] = (
                        dict(block.input) if isinstance(block.input, dict) else {}
                    )
                    state.tool_uses_seen.append(
                        {"name": short_name, "input": block.input}
                    )
                    # Per-stage telemetry — record this tool's stage so the next
                    # ResultMessage's cost-delta can be attributed to it.
                    state.last_tool_stage = stage_for_tool(short_name)
                    state.stage_calls[state.last_tool_stage] = (
                        state.stage_calls.get(state.last_tool_stage, 0) + 1
                    )
                    # Per-tool attempts cap (opt-in, default 0), PROGRESS-AWARE
                    # (mirrors B-20). When the cap is exceeded but the agent made
                    # recent productive build progress, EXTEND it (+1×base, up to
                    # MAX_TOOL_ATTEMPT_EXTENSIONS) instead of giving up — only a
                    # true no-progress spiral fires.
                    state.tool_attempt_count[short_name] = (
                        state.tool_attempt_count.get(short_name, 0) + 1
                    )
                    _cap = _get_tool_attempt_cap(short_name)
                    _ext = state.tool_cap_extension_count.get(short_name, 0)
                    if (
                        _cap > 0
                        and state.tool_attempt_count[short_name] > _cap * (1 + _ext)
                        and not state.give_up_reason
                    ):
                        if productive_extension_allowed(
                            last_productive_turn=state.last_productive_turn,
                            current_turn=state.turn,
                            extension_count=_ext,
                            max_extensions=MAX_TOOL_ATTEMPT_EXTENSIONS,
                        ):
                            # Recent productive progress → extend. The turn /
                            # cost-cap sites write an audit line on each extension;
                            # here we bump telemetry state only (per-tool extensions
                            # are high-frequency) — tool_cap_extension_count holds
                            # it. Only a no-progress spiral reaches give_up below.
                            state.tool_cap_extension_count[short_name] = _ext + 1
                        else:
                            state.give_up_reason = f"max_tool_attempts_{short_name}"
                            state.give_up_detail = (
                                f"per-tool attempts cap exceeded: {short_name} "
                                f"called {state.tool_attempt_count[short_name]} "
                                f"times; cap={_cap}×{1 + _ext} extension(s) (env "
                                f"CVE_ENV_MAX_{short_name.upper()}_ATTEMPTS); "
                                f"no recent productive progress."
                            )
                    pending_tool_use = {"name": short_name, "input": block.input}
                    refusal_scanner.observe(
                        {
                            "turn": state.turn,
                            "kind": "assistant_tool_use",
                            "tool_name": short_name,
                            "input": dict(block.input)
                            if isinstance(block.input, dict)
                            else {},
                        }
                    )
                    writer.write(
                        cve_id=cve.cve_id,
                        entry=AuditEntry(
                            turn=state.turn,
                            status="llm_turn",
                            tool_name=short_name,
                            tool_input=dict(block.input)
                            if isinstance(block.input, dict)
                            else {},
                        ),
                    )
                elif isinstance(block, TextBlock):
                    _latch_text_and_scan(
                        state,
                        block,
                        refusal_scanner=refusal_scanner,
                        pending_tool_use=pending_tool_use,
                        writer=writer,
                        cve=cve,
                    )
        elif isinstance(msg, UserMessage):
            if isinstance(msg.content, list):
                for block in msg.content:
                    if not isinstance(block, ToolResultBlock):
                        continue
                    tool_name = state.tool_name_by_id.get(block.tool_use_id, "")
                    payload = _parse_tool_result_payload(block)
                    # Track launch-stage tool successes + verify attempts so the
                    # classifier can distinguish "launched but never tried verify"
                    # from "never reached launch".
                    if (
                        tool_name in _LAUNCH_TOOLS
                        and isinstance(payload, dict)
                        and payload.get("ok") is True
                    ):
                        state.launched_ok = True
                    # Track docker_build success for the
                    # stuck_after_launch_after_build triage marker. Set ONCE at
                    # first success and remains True for the run (parallel to
                    # launched_ok semantics).
                    if (
                        tool_name == "docker_build"
                        and isinstance(payload, dict)
                        and payload.get("ok") is True
                    ):
                        state.docker_built_ok = True
                    # A build/daemon tool result classified daemon_corruption =
                    # HOST containerd corruption (infra, not engine). Latch it so
                    # the Outcome surfaces it (any tool that carries reason_class —
                    # docker_build/run/compose).
                    if (
                        isinstance(payload, dict)
                        and payload.get("reason_class") == "daemon_corruption"
                    ):
                        state.daemon_corruption_seen = True
                    # Track image_resolve success for the classifier branch
                    # (quit_after_image_resolve). Set once at first ok=True
                    # (parallel to launched_ok / docker_built_ok semantics).
                    if (
                        tool_name == "image_resolve"
                        and isinstance(payload, dict)
                        and payload.get("ok") is True
                    ):
                        state.image_resolve_ok = True
                    # Track most-recent productive turn so
                    # ``should_extend_turn_cap`` can grant a turn-cap extension
                    # when the agent is making build progress. verify and
                    # run_in_container count as productive AFTER a build succeeded
                    # (state.docker_built_ok) — see _is_productive_outcome.
                    if _is_productive_outcome(
                        tool_name, payload, state.docker_built_ok
                    ):
                        state.last_productive_turn = state.turn
                    # Track "did we BUILD?" — used by the strict version-marker
                    # gate. Set on result (not use) -- if SDK crashes between
                    # use/result, the lenient marker check applies. Acceptable:
                    # crashed builds shouldn't get strict checking.
                    if tool_name in _BUILD_TOOLS:
                        state.has_built = True
                    if tool_name == "verify":
                        state.verify_attempted = True
                    if tool_name == "verify" and isinstance(payload, dict):
                        state.last_verify_result = payload
                        if payload.get("passed") is True:
                            state.verify_passed = True
                            # Record turn-of-latest-verify-pass for the
                            # refusal-recovery comparison in _map_status.
                            state.verify_passed_turn = state.turn
                            # Union the check types from this passing verify. Flag
                            # version-assertion exec_check and classify functional
                            # smoke (heuristic mirrors
                            # verify._compute_verify_quality_warning) and
                            # vuln-confirmed (payload-class checks only).
                            results = payload.get("results") or []
                            for entry in results:
                                if not isinstance(entry, dict):
                                    continue
                                t = entry.get("type")
                                if isinstance(t, str) and t:
                                    state.passing_verify_check_types.add(t)
                                if _is_version_assertion_exec_check(entry):
                                    state.passing_verify_has_version_assertion = True
                                # Credit a SPECIFIC version marker INDEPENDENTLY of
                                # command shape. A passing exec_check whose
                                # expected_stdout_contains carries a specific
                                # \d+\.\d+ marker pins the version even when the
                                # command is not a whitelisted version-discovery
                                # shape (e.g. `head -3 .../lesspipe.sh`). Nesting
                                # this credit under the command-shape gate would
                                # orphan file-read version checks and downgrade
                                # success to verified_partial.
                                # _has_specific_version_marker still guards
                                # type==exec_check + a real \d+\.\d+ marker.
                                if _has_specific_version_marker(entry):
                                    state.passing_verify_has_specific_version_marker = (
                                        True
                                    )
                            # The functional-smoke predicate lives in the shared
                            # helper in verify.py (single source of truth — matches
                            # the same heuristic that drives verify_quality_warning
                            # emission).
                            if has_functional_smoke(results):
                                state.passing_verify_has_functional_smoke = True
                    elif tool_name == "give_up" and isinstance(payload, dict):
                        if payload.get("terminal") is True:
                            raw_reason = str(payload.get("reason", ""))
                            raw_detail = str(payload.get("detail", ""))
                            # Runtime classifiers for give_up(reason='no_image').
                            # Two patterns mask as a no_image finding; both checked
                            # here in priority order before passing through.
                            if raw_reason == "no_image":
                                has_refusals = (
                                    state.refusal_stop_reason_seen
                                    or len(refusal_scanner.events) > 0
                                )
                                has_image_resolve = any(
                                    u.get("name") == "image_resolve"
                                    for u in state.tool_uses_seen
                                )
                                if has_refusals:
                                    # Refusals corrupted the run; no_image was the
                                    # agent's fallback when blocked, not a genuine
                                    # cascade-exhausted finding.
                                    refusal_n = max(
                                        len(refusal_scanner.events),
                                        int(state.refusal_stop_reason_seen),
                                    )
                                    state.give_up_reason = "refusal_no_recovery"
                                    state.give_up_detail = (
                                        f"agent gave up with reason='no_image' "
                                        f"after {refusal_n} refusal event(s); "
                                        f"refusals are the likely root cause, "
                                        f"not registry-cascade exhaustion. "
                                        f"Original detail: {raw_detail[:200]}"
                                    )
                                elif not has_image_resolve:
                                    # Cascade-skip pattern: give_up(no_image)
                                    # without any image_resolve call.
                                    state.give_up_reason = "skipped_image_lookup"
                                    state.give_up_detail = (
                                        "agent emitted give_up(reason='no_image') "
                                        "without ever calling image_resolve; "
                                        "cascade-skip pattern. "
                                        f"Original detail: {raw_detail[:200]}"
                                    )
                                else:
                                    # Legitimate cascade-exhausted no_image.
                                    state.give_up_reason = raw_reason
                                    state.give_up_detail = raw_detail
                            else:
                                state.give_up_reason = raw_reason
                                state.give_up_detail = raw_detail
                    tool_status: AuditStatus = (
                        "tool_error" if getattr(block, "is_error", False) else "tool_ok"
                    )
                    tool_result_value: Any = (
                        payload if payload is not None else str(block.content)[:4000]
                    )
                    refusal_scanner.observe(
                        {
                            "turn": state.turn,
                            "kind": "tool_result",
                            "tool_name": tool_name,
                            "result_preview": (
                                str(payload)[:600]
                                if payload is not None
                                else str(block.content)[:600]
                            ),
                        }
                    )
                    # Retrieve input recorded at the paired llm_turn handler so
                    # tool_ok / tool_error rows carry the originating input dict.
                    tool_input_for_result = state.tool_input_by_id.get(
                        block.tool_use_id, {}
                    )
                    writer.write(
                        cve_id=cve.cve_id,
                        entry=AuditEntry(
                            turn=state.turn,
                            status=tool_status,
                            tool_name=tool_name,
                            tool_input=tool_input_for_result,
                            tool_result=tool_result_value,
                        ),
                    )
                    # Recovery audit telemetry. When this tool has a same-tool
                    # failure within RECOVERY_GAP_TURNS turns AND the stage is
                    # eligible (ACQUIRE/RESOLVE/LAUNCH/VERIFY by default), emit a
                    # ``status="recovery"`` audit row alongside the ordinary
                    # tool_ok row. The detector inspects the parsed payload dict
                    # (``payload``, not ``tool_result_value`` which may be a string
                    # fallback). Idempotent: one recovery per error→ok pair.
                    recovery_entry = _process_tool_result_for_recovery(
                        state,
                        tool_name=tool_name,
                        turn=state.turn,
                        tool_status=tool_status,
                        tool_result=payload,
                    )
                    if recovery_entry is not None:
                        writer.write(cve_id=cve.cve_id, entry=recovery_entry)
                    # Emit ONE-LINE live progress to stderr per tool result so
                    # single-CVE `cve-env build` runs aren't silent for the full
                    # ~5 minute run. Bench50.sh has its own live bench_status.sh;
                    # this gives the same story for one-off smokes.
                    # Format: ``T<turn> <glyph> <tool_name> <hint>``.
                    if not _LIVE_STDERR_DISABLED:
                        glyph = "✗" if tool_status == "tool_error" else "✓"
                        hint = _live_progress_hint(tool_name, payload)
                        print(
                            f"  T{state.turn:<3} {glyph} {tool_name}"
                            + (f"  {hint}" if hint else ""),
                            file=sys.stderr,
                            flush=True,
                        )
        elif isinstance(msg, ResultMessage):
            state.result_received = True
            # Latch refusal across multiple ResultMessages. The SDK can emit
            # several (mid-run refusal, retry, retry); only the last one survives
            # in run.stop_reason. We need to remember if ANY was refusal-class so
            # _map_status can classify "incomplete" even when the final
            # stop_reason is "end_turn".
            sr = (msg.stop_reason or "").lower()
            if "refusal" in sr or "usage policy" in sr:
                state.refusal_stop_reason_seen = True
                state.refusal_stop_reason_turn = state.turn  # track LATEST
            terminal_status: AuditStatus = _terminal_status_for_result(state, sr)
            refusal_scanner.observe(
                {
                    "turn": state.turn,
                    "kind": "result",
                    "stop_reason": msg.stop_reason or "",
                    "total_cost_usd": msg.total_cost_usd or 0.0,
                    "num_turns": msg.num_turns,
                }
            )
            # Aggregate cost + turns across multi-ResultMessage retry storms.
            #   cost_usd: per-segment (the SDK emits each segment's cost
            #     individually). Use SUM so Outcome reflects true billed cost.
            #   num_turns: cumulative turn counter inside the run_agent
            #     call (each ResultMessage's num_turns is total-so-far).
            #     Use MAX (last ResultMessage's value, monotonically largest).
            # Per-stage cost attribution: ResultMessage cost-delta attributed to
            # the most-recent tool's stage. Proxy: real per-call cost varies with
            # context, but call-stage-of-last-tool is the best signal available at
            # ResultMessage time. Attribute the RESIDUAL between this RM's reported
            # cost and what the AssistantMessage path already credited for this
            # segment. Net per-segment credit = max(AM_estimate, RM_reported_cost).
            # This closes the under-attribution mode where a boolean dedup would
            # skip RM entirely when AM credited a tiny amount.
            # ``state.last_cost_usd`` is still summed unconditionally — it drives
            # the cap check, not stage telemetry. After processing this
            # ResultMessage, advance the segment id so subsequent AMs start a fresh
            # segment.
            _accumulate_result_cost_and_turns(state, msg)
            # Per-stage HARD-mode enforcement. If any stage with mode="hard"
            # exceeded its budget, synthesize a give_up so the existing
            # GiveUpReceived path halts the run. Default mode is "soft" → no
            # termination; users opt-in via ``CVE_ENV_BUDGET_<STAGE>_MODE=hard``.
            if not state.give_up_reason:
                breached_stage = _stage_hard_budget_breach(state.stage_costs)
                if breached_stage is not None:
                    state.give_up_reason = f"stage_budget_exhausted_{breached_stage}"
                    state.give_up_detail = (
                        f"HARD-mode stage budget exceeded: stage {breached_stage} "
                        f"cost ${state.stage_costs[breached_stage]:.3f} > budget; "
                        f"terminating run (Phase 12.3)."
                    )
            # Merge the ResultMessage's CUMULATIVE session usage via max() (not
            # +=) so it doesn't double-count the per-message AssistantMessage
            # usage already accumulated; lets us estimate cost when the SDK
            # reports total_cost_usd=0 despite real LLM rounds.
            _merge_cumulative_tokens(state, msg.usage)
            # If accumulated cost (across multi-ResultMessage retry storms)
            # exceeded max_cost_usd, halt SDK iteration. Without this, SDK retries
            # consume budget independently and total can exceed cap by 2-3×.
            #
            # Before raising BudgetCapExceeded, check if the agent qualifies for an
            # adaptive cost-cap extension (productive activity recent + extensions
            # remaining). If granted, bump effective_max_cost_usd and continue.
            # Otherwise raise as before. Default MAX_COST_EXTENSIONS=1 PCT=0.10
            # (10% bump, max 1 extension). Set CVE_ENV_MAX_COST_EXTENSIONS=0 to
            # disable.
            if state.last_cost_usd > state.effective_max_cost_usd:
                new_cost_cap = _should_extend_cost_cap(
                    current_cost_usd=state.last_cost_usd,
                    max_cost_usd=state.effective_max_cost_usd,
                    last_productive_turn=state.last_productive_turn,
                    current_turn=state.turn,
                    cost_extension_count=state.cost_extension_count,
                )
                if new_cost_cap is not None:
                    state.cost_extension_count += 1
                    state.effective_max_cost_usd = new_cost_cap
                    # Audit: extension granted
                    writer.write(
                        cve_id=cve.cve_id,
                        entry=AuditEntry(
                            turn=state.turn,
                            status="llm_turn",
                            reason=(
                                f"phase_12.4_cost_extension granted "
                                f"#{state.cost_extension_count}: new_cap="
                                f"${state.effective_max_cost_usd:.2f}; "
                                f"last_productive_turn={state.last_productive_turn}"
                            ),
                        ),
                    )
                else:
                    raise BudgetCapExceeded(
                        f"state.last_cost_usd=${state.last_cost_usd:.2f} > "
                        f"effective_max_cost_usd=${state.effective_max_cost_usd:.2f} "
                        f"(extensions used: {state.cost_extension_count})"
                    )
            writer.write(
                cve_id=cve.cve_id,
                entry=AuditEntry(
                    turn=state.turn,
                    status=terminal_status,
                    input_tokens=int(getattr(msg.usage, "input_tokens", 0) or 0)
                    if msg.usage
                    else 0,
                    output_tokens=int(getattr(msg.usage, "output_tokens", 0) or 0)
                    if msg.usage
                    else 0,
                    cost_usd=msg.total_cost_usd or 0.0,
                    reason=msg.stop_reason or "",
                ),
            )
            # Halt-on-verified-success (default-OFF): symmetric to the give_up halt
            # below. A `final_success` terminal status means a clean end_turn with
            # verify_passed; raise AFTER the audit write so triage sees the success
            # event, then stop the SDK iteration before the agent can over-run into
            # max_turns (which would mis-grade it turn_cap via cap-overrides-verify).
            # Cap terminations never produce `final_success`, so this cannot weaken
            # the cap-overrides-verify lock.
            if _should_halt_on_verified_success(terminal_status):
                raise SuccessReached(
                    f"verify passed + clean end_turn (turn={state.turn}, "
                    f"stop_reason={sr!r}); halting before over-run"
                )

        # Intentional: once give_up_reason is set, every subsequent on_message
        # re-raises to halt the SDK. Caught by _run_query_once._consume().
        # If give_up.terminal=True was processed in this on_message call (or any
        # prior), halt the SDK iteration. on_message's audit write for the give_up
        # tool result has already happened above by the time we reach this point
        # (for agent-issued give_ups). For per-tool attempt cap give_ups, the
        # GiveUpReceived fires before the tool_result arrives — write a tool_error
        # entry so the audit trail is complete.
        if state.give_up_reason:
            if state.give_up_reason.startswith("max_tool_attempts_"):
                _cap_tool = state.give_up_reason[len("max_tool_attempts_"):]
                writer.write(
                    cve_id=cve.cve_id,
                    entry=AuditEntry(
                        turn=state.turn,
                        status="tool_error",
                        tool_name=_cap_tool,
                        reason=state.give_up_detail or "tool attempt cap exceeded",
                    ),
                )
            raise GiveUpReceived(
                f"agent issued give_up(reason={state.give_up_reason!r})"
            )

    # Prepend doctor → agent constraints to the system prompt when present (e.g.
    # Docker Hub rate-limited → tell the agent to AVOID vulhub-* methods this run).
    # Empty when no constraints. Also prepend the runtime caps block so the agent
    # knows the actual turn/cost budget + extension policy for this run.
    constraints_prefix = format_constraints_for_prompt(constraints or [])
    caps_block = render_runtime_caps_block(
        max_turns=max_turns,
        max_cost_usd=max_cost_usd,
        max_extensions=eff_max_turn_extensions,
        extension_pct=eff_turn_extension_pct,
    )
    if constraints_prefix:
        system_prompt_final = f"{constraints_prefix}\n{caps_block}\n{SYSTEM_PROMPT}"
    else:
        system_prompt_final = f"{caps_block}\n{SYSTEM_PROMPT}"
    # Experimental: ``CVE_ENV_EXTRA_PROMPT_PREFIX`` lets bench harnesses
    # inject a per-run instruction block at the very top of the system
    # prompt without modifying source. Used for method-exploration runs
    # (e.g., "deny vulhub + docker.io, exercise alternate cascades").
    # Empty/unset == no-op.
    extra_prefix = os.environ.get("CVE_ENV_EXTRA_PROMPT_PREFIX", "").strip()
    if extra_prefix:
        system_prompt_final = f"{extra_prefix}\n\n{system_prompt_final}"
    try:
        run = await run_agent(
            system_prompt=system_prompt_final,
            user_prompt=user_prompt,
            tools=ALL_TOOLS,
            model=model,
            # Pass the SDK an upper bound that accommodates all possible
            # auto-extensions; F-9 + B-20 enforce the actual per-CVE cap via
            # state.effective_max_turns.
            max_turns=sdk_max_turns,
            max_cost_usd=max_cost_usd,
            on_message=on_message,
            # Retry a refusal-terminal run with de-escalation, unless a verify
            # already passed (don't discard an earned success).
            verify_passed_check=lambda: state.verify_passed,
        )
    except Exception as exc:  # noqa: BLE001 -- surface whatever the SDK throws
        # If the agent already called give_up (terminal decision) or passed
        # verify, a late stream-drain exception is cosmetic -- the run had reached
        # a logical conclusion. Relabel to the corresponding terminal status
        # instead of masking a real outcome as 'error'.
        #
        # Only trust state.verify_passed if the SDK actually emitted a
        # ResultMessage. Otherwise the verify call may have come from a partial
        # dead retry whose run never converged (a usage-policy refusal across
        # retries can leave state.verify_passed=True with num_turns=0, mistagging
        # a refusal as success).
        # Refusal-class exceptions force `incomplete` even if verify passed
        # earlier (same pattern as _map_status above). Reuses llm._is_refusal —
        # the canonical refusal-signature matcher.
        from cve_env.agent.llm import InStreamRefusal, _is_refusal

        # An InStreamRefusal that survived all run_agent retries (the run kept
        # terminating on a refusal stop_reason) is refusal-class too.
        is_refusal_exc = _is_refusal(exc) or isinstance(exc, InStreamRefusal)
        # Runtime api_overload classifier wiring. Without it, the runtime hot path
        # would leave state.give_up_reason="" on 529 Overloaded exceptions,
        # surfacing as status="error" with empty give_up_reason in Outcome JSON.
        # Fires BEFORE the is_refusal_exc branch so api_overload (an external
        # Anthropic outage) is distinguished from refusal-class (which trips the
        # safety classifier).
        if _classify_api_overload(str(exc)) == "api_overload":
            state.give_up_reason = "api_overload"
            state.give_up_detail = (
                f"Anthropic API 529 Overloaded exception: {type(exc).__name__}: "
                f"{str(exc)[:200]}"
            )
        if is_refusal_exc:
            # Post-build refusal classifier. A refusal AFTER
            # state.launched_ok=True is a distinct class — the verify-plan
            # composition or downstream tool input tripped Anthropic's safety
            # classifier, not the NVD-description (which the sanitizer already
            # covers). Emit a dedicated audit entry BEFORE the terminal-status
            # mapping so post-bench forensic can count this class without
            # re-deriving from raw state. Paired with the prompts.py open-clause
            # verify-plan composition rule.
            if state.launched_ok:
                writer.write(
                    cve_id=cve.cve_id,
                    entry=AuditEntry(
                        turn=state.turn,
                        status="post_build_refusal",
                        reason=(
                            f"refusal exception after launched_ok=True "
                            f"(verify_passed={state.verify_passed}, "
                            f"docker_built_ok={state.docker_built_ok}): "
                            f"{type(exc).__name__}: {exc}"
                        ),
                    ),
                )
            terminal_status_on_err: OutcomeStatus = "interrupted"
            terminal_reason = (
                f"SDK terminated with refusal exception "
                f"(verify_passed={state.verify_passed}): "
                f"{type(exc).__name__}: {exc}"
            )
        elif state.give_up_reason == "api_overload":
            # Anthropic API 529/overload exception — NOT a CVE-merit failure (the
            # build never got a fair chance). Dedicated `rate_limited` status so
            # humans, cards, and bench_select_retry treat it as re-runnable, not as
            # "this CVE can't be built." Without this branch, api_overload would
            # fall into the generic give_up branch below and be mis-labeled
            # `unresolvable`. Must precede the generic ``elif
            # state.give_up_reason:`` so the specific reason wins.
            terminal_status_on_err = "rate_limited"
            terminal_reason = (
                state.give_up_detail or "Anthropic API rate-limited (529 Overloaded)"
            )
        elif state.give_up_reason:
            # The agent's voluntary give_up wins over any racing runtime cap
            # exception. A TurnCapReached / BudgetCapExceeded firing AFTER give_up
            # but BEFORE the SDK's ResultMessage must NOT cause the run to be
            # classified by the runtime exception class rather than the agent's own
            # decision. If give_up_reason is set at except-time, this is
            # unresolvable, full stop. Kept ABOVE the cap-exception branches so the
            # "give_up > cap" precedence is preserved.
            terminal_status_on_err = "unresolvable"
            terminal_reason = state.give_up_reason
        elif isinstance(exc, TurnCapReached):
            # Defensive turn-cap raised; map to turn_cap status. HOISTED above the
            # verify-pass branch: cap signals win over mid-run verify-pass,
            # mirroring the priority in _map_status. This path is reached only if
            # future changes let the exception propagate past the llm.py catch; it
            # locks the "cap > verify-pass" invariant everywhere it could trigger.
            # The give_up branch staying above preserves "give_up > cap".
            terminal_status_on_err = "turn_cap"
            terminal_reason = f"runtime turn-cap fired ({exc})"
        elif isinstance(exc, BudgetCapExceeded):
            # Accumulated cost overran cap; map to budget_exhausted. HOISTED above
            # the verify-pass branch (see TurnCapReached comment above).
            terminal_status_on_err = "budget_exhausted"
            terminal_reason = f"runtime budget cap fired ({exc})"
        elif isinstance(exc, WallBudgetExceeded):
            # Internal wall-budget fired. Reuses budget_exhausted status (cost vs
            # wall both denote "ran out of the named budget"); the descriptive
            # reason field carries the wall-vs-cost distinction. HOISTED above the
            # verify-pass branch to preserve the "cap > verify-pass" invariant.
            terminal_status_on_err = "budget_exhausted"
            terminal_reason = f"internal wall budget exhausted ({exc})"
        elif isinstance(exc, NoProgressReached):
            # Anti-thrash: prolonged no-progress churn give-up. Reuses turn_cap
            # status (the CVE was heading to the turn cap anyway — we reclaim the
            # wasted tail early); the distinct ``no_progress`` reason makes it
            # greppable for accounting. HOISTED above the verify-pass branch to
            # preserve the "cap > verify-pass" invariant (mirrors TurnCap/Wall
            # above).
            terminal_status_on_err = "turn_cap"
            terminal_reason = f"anti-thrash no_progress give-up ({exc})"
        elif state.verify_passed and state.result_received:
            # Delegate to the shared helper for parity with _map_status. DEMOTED
            # below the cap-exception branches. Non-cap exceptions (transport
            # drops, connection resets, generic RuntimeError) still classify via
            # this branch when verify_passed=True.
            terminal_status_on_err, terminal_reason = _classify_verify_outcome(state)
        else:
            terminal_status_on_err = "error"
            terminal_reason = f"{type(exc).__name__}: {exc}"
        # Finalize refusal audit on the exception path too. Without this, refusal
        # events captured before the SDK threw are lost.
        refusal_scanner.finalize(
            final_outcome_status=terminal_status_on_err,
            verify_passed=state.verify_passed,
        )
        if refusal_scanner.events:
            with contextlib.suppress(OSError):
                append_events(refusal_scanner.events, log_path=default_log_path())
        return Outcome(
            cve_id=cve.cve_id,
            status=terminal_status_on_err,
            reason=terminal_reason,
            # Propagate accumulated cost/turns from any ResultMessage that arrived
            # BEFORE the exception (otherwise these default to 0). Floor num_turns
            # at len(tool_uses_seen) so post-hoc analysis sees real work even when
            # no ResultMessage arrived before the exception (proprietary fast-fail
            # and give_up paths can report t=0 despite ≥3 tool calls). Include
            # state.turn — the AUTHORITATIVE engine counter (incremented per
            # on_message, enforces the turn cap); the SDK's msg.num_turns
            # (→ state.last_num_turns) UNDERREPORTS it, confounding
            # turn-cap-vs-cost-bound diagnosis. max() keeps the existing floors.
            num_turns=max(state.turn, state.last_num_turns, len(state.tool_uses_seen)),
            # Floors: SDK-reported cost, then a token-based estimate, then a
            # turns-based estimate for interrupted exits with no token usage
            # (session auth). max() ensures a floor only kicks in when the
            # reported cost is zero/missing. See _floor_cost.
            total_cost_usd=_floor_cost(
                terminal_status_on_err,
                max(state.turn, state.last_num_turns, len(state.tool_uses_seen)),
                state.last_cost_usd,
                0.0,
                state.total_input_tokens,
                state.total_output_tokens,
                model,
                state.effective_max_cost_usd,
            ),
            verify_passed=state.verify_passed,
            verify_result=state.last_verify_result,
            give_up_reason=state.give_up_reason,
            give_up_detail=state.give_up_detail,
            final_text=state.final_text,
            tool_names_called=[u["name"] for u in state.tool_uses_seen],
            error=str(exc) if terminal_status_on_err == "error" else "",
            audit_path=writer._path_for(cve_id=cve.cve_id),
            # Refusal count from RefusalScanner + SDK-level latch. len(events)
            # captures pattern-matched refusals (LLM text + SDK error wrappers);
            # + 1 if the SDK ResultMessage had a refusal stop_reason but no text
            # pattern fired (ensures we never under-count when only one detection
            # layer caught it).
            refusals=max(
                len(refusal_scanner.events),
                int(state.refusal_stop_reason_seen),
            ),
            # Host containerd-corruption flag on the exception-path too.
            daemon_corruption=state.daemon_corruption_seen,
            # Per-stage telemetry on the exception-path too.
            stage_costs=dict(state.stage_costs),
            stage_calls=dict(state.stage_calls),
            # Over-budget stages on the exception-path too.
            over_budget_stages_list=_over_budget_stages(state.stage_costs),
        )

    # Fix #8 force-verify continuation. The agent often builds an env then
    # end_turns without verify (many such cases are near-builds). Re-prompt it to
    # finish via resume + CONTINUATION_USER_PROMPT, bounded to 2 attempts + a
    # 70%-cost gate. Cost/turns accumulate across runs; on a clean success/give_up
    # the loop stops and _map_status classifies as usual.
    cont_cost_acc = state.last_cost_usd or run.total_cost_usd or 0.0
    cont_turns_acc = run.num_turns or 0
    continuation_count = 0

    # proprietary-verify continuation (agentic, env-gated default-ON): the agent
    # gave up `proprietary` WITHOUT calling image_resolve (it reasoned the target
    # unbuildable from its name/metadata without probing). Re-prompt ONCE to run a
    # single image_resolve before the give-up is final — verify-the-negative
    # against the open-source-by-proprietary-vendor false-positive class
    # (Spring4Shell/vmware). Runs FIRST so a successful resolve cascades into the
    # force-resolve/Fix #8 build+verify gates below; SKIPS CVEs that already
    # probed (confirmed negative). Shares the cost/turn accumulators.
    proprietary_verify_count = 0
    while _should_continue_for_proprietary_verify(
        run, state, proprietary_verify_count, cont_cost_acc, max_cost_usd
    ):
        proprietary_verify_count += 1
        state.proprietary_verify_attempted = True
        saved_give_up_reason = state.give_up_reason
        saved_give_up_detail = state.give_up_detail
        saved_verify_attempted = state.verify_attempted
        state.give_up_reason = ""
        state.give_up_detail = ""
        state.verify_attempted = False
        resume_sid = state.last_session_id or run.session_id
        writer.write(
            cve_id=cve.cve_id,
            entry=AuditEntry(
                turn=state.turn,
                status="proprietary_verify_continuation",
                reason=(
                    "give_up(proprietary) without image_resolve probe "
                    "(unprobed name-only give-up); re-prompting to verify-the-negative; "
                    f"resume={resume_sid}"
                ),
            ),
        )
        try:
            run = await run_agent(
                system_prompt=system_prompt_final,
                user_prompt=PROPRIETARY_VERIFY_CONTINUATION_PROMPT,
                tools=ALL_TOOLS,
                model=model,
                max_turns=max(2, sdk_max_turns - cont_turns_acc),
                max_cost_usd=max_cost_usd,
                on_message=on_message,
                resume=resume_sid,
                verify_passed_check=lambda: state.verify_passed,
            )
        except Exception:  # noqa: BLE001 -- a continuation that raises just stops; restore the give_up
            state.give_up_reason = saved_give_up_reason
            state.give_up_detail = saved_give_up_detail
            state.verify_attempted = saved_verify_attempted
            break
        cont_cost_acc += run.total_cost_usd or 0.0
        cont_turns_acc += run.num_turns or 0
        # Restore the proprietary give_up UNLESS the probe improved things: a
        # successful build/launch, verify_passed, or a fresh terminal give_up the
        # agent re-emitted (non-empty give_up_reason — e.g. proprietary now WITH
        # image_resolve called, which this gate will no longer re-fire on).
        if (
            not state.give_up_reason
            and not state.verify_passed
            and not (state.docker_built_ok or state.launched_ok)
        ):
            state.give_up_reason = saved_give_up_reason
            state.give_up_detail = saved_give_up_detail
            state.verify_attempted = saved_verify_attempted

    # build-engagement gate: a NON-proprietary pre-build give-up
    # (skipped_image_lookup / no_image / unresolvable_metadata) emitted WITHOUT
    # attempting an actual build tool (docker_build/dockerfile_gen/source_build)
    # is a cascade-skip — incl. resolve-only (image_resolve not_found, no build
    # pivot). Re-prompt the agent ONCE to actually build before the give_up
    # stands. Runs BEFORE the Fix #8 verify loop and shares its cost/turn
    # accumulators, so a successful resolve+build then flows into Fix #8.
    force_resolve_count = 0
    while _should_continue_for_resolve(
        run, state, force_resolve_count, cont_cost_acc, max_cost_usd
    ):
        force_resolve_count += 1
        state.force_resolve_attempted = True
        # Save, then clear so the re-query can reach a fresh outcome;
        # restored below unless the continuation actually improves.
        saved_give_up_reason = state.give_up_reason
        saved_give_up_detail = state.give_up_detail
        saved_verify_attempted = state.verify_attempted
        state.give_up_reason = ""
        state.give_up_detail = ""
        state.verify_attempted = False
        # Prefer the streamed session id (run.session_id is empty for give_up
        # runs — the terminal ResultMessage never arrived).
        resume_sid = state.last_session_id or run.session_id
        writer.write(
            cve_id=cve.cve_id,
            entry=AuditEntry(
                turn=state.turn,
                status="force_resolve_continuation",
                reason=(
                    "pre-build give_up without any build tool attempted "
                    "(build-engagement gate); "
                    f"re-prompting to resolve; resume={resume_sid}"
                ),
            ),
        )
        try:
            run = await run_agent(
                system_prompt=system_prompt_final,
                user_prompt=FORCE_RESOLVE_CONTINUATION_PROMPT,
                tools=ALL_TOOLS,
                model=model,
                max_turns=max(2, sdk_max_turns - cont_turns_acc),
                max_cost_usd=max_cost_usd,
                on_message=on_message,
                resume=resume_sid,
                verify_passed_check=lambda: state.verify_passed,
            )
        except Exception:  # noqa: BLE001 -- a continuation that raises just stops; restore the give_up
            state.give_up_reason = saved_give_up_reason
            state.give_up_detail = saved_give_up_detail
            state.verify_attempted = saved_verify_attempted
            break
        cont_cost_acc += run.total_cost_usd or 0.0
        cont_turns_acc += run.num_turns or 0
        # Restore the original give_up UNLESS the continuation improved —
        # reached verify_passed, a successful build/launch, or a fresh terminal
        # give_up (e.g. now-legitimate no_image with image_resolve called, which
        # the detector repopulates). Otherwise keep the cascade-skip classification.
        if (
            not state.give_up_reason
            and not state.verify_passed
            and not (state.docker_built_ok or state.launched_ok)
        ):
            state.give_up_reason = saved_give_up_reason
            state.give_up_detail = saved_give_up_detail
            state.verify_attempted = saved_verify_attempted

    while _should_continue_for_verify(
        run, state, continuation_count, cont_cost_acc, max_cost_usd
    ):
        continuation_count += 1
        writer.write(
            cve_id=cve.cve_id,
            entry=AuditEntry(
                turn=state.turn,
                status="fix8_continuation",
                reason=(
                    f"end_turn after build/staging without verify "
                    f"(continuation {continuation_count}/{_FIX8_MAX_CONTINUATIONS}; "
                    f"docker_built_ok={state.docker_built_ok} "
                    f"launched_ok={state.launched_ok}); resume={run.session_id}"
                ),
            ),
        )
        try:
            run = await run_agent(
                system_prompt=system_prompt_final,
                user_prompt=CONTINUATION_USER_PROMPT,
                tools=ALL_TOOLS,
                model=model,
                max_turns=max(2, sdk_max_turns - cont_turns_acc),
                max_cost_usd=max_cost_usd,
                on_message=on_message,
                resume=state.last_session_id or run.session_id,
                verify_passed_check=lambda: state.verify_passed,
            )
        except Exception:  # noqa: BLE001 -- a continuation that raises just stops the loop
            break
        cont_cost_acc += run.total_cost_usd or 0.0
        cont_turns_acc += run.num_turns or 0

    # benign-verify continuation (agentic, env-gated default-off): a POST-LAUNCH
    # refusal blocked verify — the env is up but verify never ran (the generic
    # Fix #8 continuation above re-refuses ~10% of the time on the same
    # exploit-flavored framing). RESUME the session with a benign-only verify
    # prompt so the model runs safe health checks instead. Runs LAST, shares the
    # cost/turn accumulators; the structural launched_no_verify floor remains the
    # fallback when this does not fire or does not succeed.
    benign_verify_count = 0
    while _should_continue_for_post_launch_refusal(
        run, state, benign_verify_count, cont_cost_acc, max_cost_usd
    ):
        benign_verify_count += 1
        resume_sid = state.last_session_id or run.session_id
        writer.write(
            cve_id=cve.cve_id,
            entry=AuditEntry(
                turn=state.turn,
                status="benign_verify_continuation",
                reason=(
                    "post-launch refusal blocked verify (env launched, verify "
                    "not attempted); re-prompting benign-only verify "
                    f"({benign_verify_count}/"
                    f"{get_benign_verify_continuation_max()}); resume={resume_sid}"
                ),
            ),
        )
        try:
            run = await run_agent(
                system_prompt=system_prompt_final,
                user_prompt=BENIGN_VERIFY_CONTINUATION_PROMPT,
                tools=ALL_TOOLS,
                model=model,
                max_turns=max(2, sdk_max_turns - cont_turns_acc),
                max_cost_usd=max_cost_usd,
                on_message=on_message,
                resume=resume_sid,
                verify_passed_check=lambda: state.verify_passed,
            )
        except Exception:  # noqa: BLE001 -- a continuation that raises just stops the loop
            break
        cont_cost_acc += run.total_cost_usd or 0.0
        cont_turns_acc += run.num_turns or 0

    status, reason = _map_status(run.stop_reason, state)
    refusal_scanner.finalize(
        final_outcome_status=status,
        verify_passed=state.verify_passed,
    )
    if refusal_scanner.events:
        # Logging must never block the outcome; disk full / permission deny etc.
        with contextlib.suppress(OSError):
            append_events(refusal_scanner.events, log_path=default_log_path())
    return Outcome(
        cve_id=cve.cve_id,
        status=status,
        reason=reason,
        # Use accumulated state values, not the last ResultMessage's values from
        # `run`. For a single-ResultMessage call (the common case), state.last_*
        # equals run.* — for retry-storm calls the state has the SUM of cost across
        # segments and the MAX of turns. The SDK can report
        # stop_reason="max_turns_reached" while emitting num_turns=0 in the same
        # ResultMessage; floor num_turns at len(tool_uses_seen) so post-hoc
        # analysis sees real work even when the SDK contradicts itself.
        # cont_turns_acc / cont_cost_acc SUM across continuation runs (==run.* for
        # the common single-run case, so no regression there). state.turn (the
        # authoritative engine counter, per on_message, accumulates across
        # continuation runs) is the real turn count; the SDK msg.num_turns
        # underreports it. max() keeps the existing floors.
        num_turns=max(
            state.turn, state.last_num_turns, cont_turns_acc, len(state.tool_uses_seen)
        ),
        # Include a token-based estimate as a third floor, then a turns-based
        # floor for interrupted exits with no token usage (session auth). The SDK
        # has been observed reporting total_cost_usd=0 on max_turns_reached even
        # after multiple LLM rounds; the floors recover that data. See _floor_cost.
        total_cost_usd=_floor_cost(
            status,
            max(
                state.turn,
                state.last_num_turns,
                cont_turns_acc,
                len(state.tool_uses_seen),
            ),
            state.last_cost_usd,
            cont_cost_acc,
            state.total_input_tokens,
            state.total_output_tokens,
            model,
            state.effective_max_cost_usd,
        ),
        session_id=run.session_id,
        stop_reason=run.stop_reason,
        verify_passed=state.verify_passed,
        verify_result=state.last_verify_result,
        give_up_reason=state.give_up_reason,
        give_up_detail=state.give_up_detail,
        final_text=state.final_text,
        tool_names_called=[u["name"] for u in state.tool_uses_seen],
        audit_path=audit_path,
        # See exception-path comment above for rationale.
        refusals=max(
            len(refusal_scanner.events),
            int(state.refusal_stop_reason_seen),
        ),
        # Host containerd-corruption flag for the bench heal.
        daemon_corruption=state.daemon_corruption_seen,
        # Per-stage cost + call telemetry.
        stage_costs=dict(state.stage_costs),
        stage_calls=dict(state.stage_calls),
        # Stages that exceeded their soft budget.
        over_budget_stages_list=_over_budget_stages(state.stage_costs),
    )
