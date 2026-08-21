"""Outcome classification and shared agent-engine machinery.

Historically this module WAS the agent engine — a 2,700-line driver for
the vendored claude-agent-sdk. The backend A/B (two rounds, ten CVEs,
fully symmetric verdicts) retired that engine: the core ToolUseLoop
backend (:mod:`cve_env.agent.core_loop`) is now the only driver, and
the SDK path was deleted rather than kept as a fallback.

What remains here is the engine-neutral machinery the surviving
backend (and the classifier test corpus) consume:

* :class:`_StreamState` — the per-run stream state every signal folds
  into;
* :func:`_track_tool_result` — one tool result → state (launch/build/
  verify/give_up tracking, the give_up reclassifiers);
* :func:`_map_status` / :func:`_classify_verify_outcome` /
  :func:`_terminal_status_for_result` — the terminal classification
  (priority order is regression-locked; see the docstrings);
* :func:`_compose_system_prompt` — constraints + runtime-caps + static
  system prompt assembly;
* :func:`should_extend_turn_cap` / :func:`_is_productive_outcome` —
  the productive-extension policy (the cost twin lives in config);
* :func:`_classify_api_overload`, the version-assertion helpers, and
  the recovery-telemetry emitter.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from cve_env.agent.audit import AuditEntry, AuditStatus
from cve_env.agent.health_constraints import (
    ServiceConstraint,
    format_constraints_for_prompt,
)
from cve_env.agent.prompts import (
    SYSTEM_PROMPT,
    render_runtime_caps_block,
)
from cve_env.config import (
    POST_BUILD_PRODUCTIVE_TOOLS,
    PRODUCTIVE_TOOLS,
    STAGES,
    VERSION_ASSERTION_CMD_PATTERN,
    productive_extension_allowed,
    stage_for_tool,
)
from cve_env.config import (
    get_recovery_eligible_stages as _get_recovery_eligible_stages,
)
from cve_env.config import (
    get_recovery_gap_turns as _get_recovery_gap_turns,
)
from cve_env.models import OutcomeStatus
from cve_env.tools._smoke import has_functional_smoke

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


def _is_version_assertion_exec_check(check_entry: dict[str, Any]) -> bool:
    """Does this exec_check entry look like a version assertion?

    Inspects the command text for known version-discovery shapes. Returns
    False for non-exec_check entries, missing/non-string commands, or
    commands that don't match any allowlisted pattern.
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
    # Per-stage cost attribution (telemetry only — no decisions ride on
    # these): each completed turn's cost credits the stage of the most
    # recent tool (OTHER before any tool call); stage_calls counts tool
    # dispatches per stage.
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


def _compose_system_prompt(
    constraints: list[ServiceConstraint] | None,
    *,
    max_turns: int,
    max_cost_usd: float,
    max_extensions: int,
    extension_pct: float,
) -> str:
    """Assemble the run's system prompt.

    Doctor → agent constraints are prepended when present (e.g. Docker
    Hub rate-limited → avoid vulhub-* methods this run), then the
    runtime caps block (actual turn/cost budget + extension policy),
    then the static SYSTEM_PROMPT. ``CVE_ENV_EXTRA_PROMPT_PREFIX``
    (bench harness experimental hook) goes at the very top —
    length-capped and control-character-rejected.
    """
    constraints_prefix = format_constraints_for_prompt(constraints or [])
    caps_block = render_runtime_caps_block(
        max_turns=max_turns,
        max_cost_usd=max_cost_usd,
        max_extensions=max_extensions,
        extension_pct=extension_pct,
    )
    if constraints_prefix:
        system_prompt_final = f"{constraints_prefix}\n{caps_block}\n{SYSTEM_PROMPT}"
    else:
        system_prompt_final = f"{caps_block}\n{SYSTEM_PROMPT}"
    _EXTRA_PREFIX_MAX_CHARS = 2000
    extra_prefix = os.environ.get("CVE_ENV_EXTRA_PROMPT_PREFIX", "").strip()
    if extra_prefix:
        if len(extra_prefix) > _EXTRA_PREFIX_MAX_CHARS:
            extra_prefix = extra_prefix[:_EXTRA_PREFIX_MAX_CHARS]
        if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', extra_prefix):
            extra_prefix = ""
        if extra_prefix:
            system_prompt_final = f"{extra_prefix}\n\n{system_prompt_final}"
    return system_prompt_final


def _track_tool_result(
    state: _StreamState,
    tool_name: str,
    payload: dict[str, Any] | None,
    *,
    refusal_event_count: int,
) -> None:
    """Fold one tool result into the stream state (extracted from
    ``build``'s ``on_message`` verbatim; shared with the core agent
    backend so both backends feed the outcome classifier identically).
    ``refusal_event_count`` is the scanner's current event tally — the
    give_up(no_image) reclassifier needs it without holding a scanner
    reference."""
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
                # command is not an allowlisted version-discovery
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
                    or refusal_event_count > 0
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
                        refusal_event_count,
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

