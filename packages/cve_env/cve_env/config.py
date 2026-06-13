"""Runtime configuration: model id, caps, paths.

Cost is reported by claude-agent-sdk's ResultMessage.total_cost_usd, but on
certain stop_reasons (max_turns_reached, end_turn after low-turn give_up)
the SDK emits cost=0.0 even after multiple LLM rounds.
``MODEL_TOKEN_RATES_PER_M_USD`` provides a token-based fallback so
cost-loss never leaves Outcome.total_cost_usd=0 when actual LLM tokens
were consumed. Tune caps here; everything else derives.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


# Optional TOML config file `cve-env.toml`.
# Precedence (highest wins):
#   1. Environment variable (CVE_ENV_<UPPER_SNAKE>)
#   2. TOML config file
#   3. Code defaults (in this file)
#
# Loaded once at module init. Path resolution:
#   1. `CVE_ENV_CONFIG_FILE` env var if set
#   2. `cve-env.toml` in CWD
#   3. None → empty dict; no errors raised
#
# Requires Python 3.11+ for stdlib `tomllib`. cve-env's pyproject pins
# 3.11+ via build-system requirements.
def _load_toml_config() -> dict[str, Any]:
    """Load optional ``cve-env.toml`` config file. Returns {} if absent
    or unreadable. Errors are intentionally non-fatal (env vars + code
    defaults still work). Uses stdlib ``tomllib`` (Python 3.11+; pinned
    in pyproject.toml)."""
    import tomllib

    path_str = os.environ.get("CVE_ENV_CONFIG_FILE", "cve-env.toml")
    path = Path(path_str)
    if not path.is_file():
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


_TOML_CONFIG: dict[str, Any] = _load_toml_config()


def _get_toml_value(toml_path: list[str], default: Any = None) -> Any:
    """Read a nested value from the loaded TOML config.

    ``toml_path`` is a list of dotted keys (e.g., ``["budget", "research"]``
    maps to ``[budget].research = <val>`` in TOML). Returns ``default``
    if any key is missing or the type mismatches.
    """
    d: Any = _TOML_CONFIG
    for key in toml_path:
        if not isinstance(d, dict) or key not in d:
            return default
        d = d[key]
    return d

DEFAULT_MODEL: str = "claude-opus-4-7"
"""Override via CVE_ENV_MODEL env."""

MODEL: str = os.environ.get("CVE_ENV_MODEL", DEFAULT_MODEL)

# Agent caps.
MAX_COST_USD_PER_CVE_SOFT: float = 0.60
TURN_CAP: int = 24
"""Sized for compose-path staging headroom (github_fetch ×N + Bash + Write ×N
+ docker_compose_up consume ~5-7 turns before the first verify), widening
recovery room without changing the runtime-enforced ceiling logic."""

# Productive-extension. When the agent is approaching its turn cap AND made
# build progress within the recent window, the loop auto-extends the cap by
# TURN_EXTENSION_PCT, up to MAX_TURN_EXTENSIONS times. Recovers cases where
# the agent was on a productive source-build path when the cap hit.
TURN_EXTENSION_PCT: float = 0.20
"""+20% per extension granted. Override via --turn-extension-pct CLI arg."""

MAX_TURN_EXTENSIONS: int = 2
"""Extensions per CVE. Build-THEN-verify CVEs (bring a compose env up then run
multiple verify + run_in_container before the cap) need more than one +20%
bump to finish the verify loop. Extensions are gated on recent PRODUCTIVE
progress + cost<85% cap, so only actively-building/verifying CVEs extend —
not the whole corpus. Override via --max-turn-extensions CLI arg."""

PRODUCTIVE_TOOLS: frozenset[str] = frozenset({
    "image_resolve", "docker_build", "docker_run",
    "docker_compose_up", "source_build",
})
"""Tools whose successful (.ok=True) outcome marks the agent as 'productive'.
Used by ``loop.should_extend_turn_cap`` to gate auto-extension."""

POST_BUILD_PRODUCTIVE_TOOLS: frozenset[str] = frozenset({
    "verify", "run_in_container",
})
"""Tools that count as 'productive' ONLY after a build has already succeeded
(state.docker_built_ok). A build-then-verify CVE iterating on
verify/run_in_container near its turn cap is making progress, not thrashing —
but verify/run_in_container are NOT in PRODUCTIVE_TOOLS, so the turn extension
would not otherwise fire for them. Gating on docker_built_ok prevents
research-only loops (no build) from extending. See
``loop._is_productive_outcome``."""

PRODUCTIVE_RECENCY_TURNS: int = 5
"""Extension granted only if last_productive_turn is within this many turns
of the cap-hit. Beyond this window the agent is presumed stuck."""

# Per-stage cost attribution map.
# Each LLM tool call is assigned to one stage; cost-deltas from
# ResultMessages are attributed to the most-recently-called tool's stage.
# Provides telemetry for budget engine.
#
# Sibling tables (different schemas, same conceptual mapping):
#   - src/cve_env/cli.py::_STAGE_BY_TOOL — lowercase for end-of-run report
#   - scripts/cve_evidence.py::_STAGE_BY_TOOL — 3-letter codes for evidence JSONL
#   - scripts/heartbeat_status.sh::STAGE_BY_TOOL — long names for heartbeat
# When adding a new tool, update all four. Sync (modulo documented
# divergence) enforced by refactor/tests/unit/test_stage_table_sync.py.
STAGES: tuple[str, ...] = (
    "RESEARCH", "RESOLVE", "ACQUIRE", "LAUNCH",
    "VERIFY", "DIAGNOSTIC", "TERMINAL", "OTHER",
)
"""Stages tracked for cost attribution. ``OTHER`` is the fallback bucket
for tool names not in :data:`TOOL_TO_STAGE`."""

TOOL_TO_STAGE: dict[str, str] = {
    # RESEARCH — discovery, lookup, fetching evidence
    "ToolSearch": "RESEARCH", "nvd_lookup": "RESEARCH",
    "github_fetch": "RESEARCH", "WebFetch": "RESEARCH", "WebSearch": "RESEARCH",
    # RESOLVE — image lookup and registry resolution
    "image_resolve": "RESOLVE", "vulhub_lookup": "RESOLVE",
    # ACQUIRE — build artifacts (docker images, source trees)
    "docker_build": "ACQUIRE", "dockerfile_gen": "ACQUIRE", "source_build": "ACQUIRE",
    # LAUNCH — start the container or service
    "docker_run": "LAUNCH", "docker_compose_up": "LAUNCH", "run_in_container": "LAUNCH",
    # VERIFY — confirm the environment behaves as expected
    "verify": "VERIFY", "log_check": "VERIFY",
    # DIAGNOSTIC — agent's introspection / scratch work
    "Bash": "DIAGNOSTIC", "Read": "DIAGNOSTIC", "Write": "DIAGNOSTIC",
    "Edit": "DIAGNOSTIC", "Grep": "DIAGNOSTIC",
    # TERMINAL — explicit give_up
    "give_up": "TERMINAL",
}
"""Maps a (suffix-stripped) tool name to its budget stage.
Unrecognized tools attributed to ``OTHER``. Derived empirically from
cost analysis across benched runs."""


def stage_for_tool(tool_name: str) -> str:
    """Resolve a tool name to its budget stage (or ``OTHER``)."""
    return TOOL_TO_STAGE.get(tool_name, "OTHER")


# Recovery audit telemetry tunables.
# The detector emits a ``kind: "recovery"`` audit row when a build-path
# tool succeeds within ``RECOVERY_GAP_TURNS`` turns of a same-tool
# failure, AND the tool's stage is in ``RECOVERY_ELIGIBLE_STAGES``.
#
# Defaults: K=20 turns from empirical observed gaps {4,6,16}. Eligibility
# excludes DIAGNOSTIC (Bash/Read/Write/Edit/Grep) where recoveries are
# routine retries not load-bearing signals. RESEARCH (nvd_lookup,
# github_fetch) excluded for the same reason.
#
# Overrides: ``CVE_ENV_RECOVERY_GAP_TURNS=<int>``,
# ``CVE_ENV_RECOVERY_ELIGIBLE_STAGES=<comma,list>``.
_DEFAULT_RECOVERY_GAP_TURNS: int = 20
_DEFAULT_RECOVERY_ELIGIBLE_STAGES: frozenset[str] = frozenset(
    {"ACQUIRE", "RESOLVE", "LAUNCH", "VERIFY"}
)


def get_recovery_gap_turns() -> int:
    """Return the max gap (in turns) between same-tool failure and recovery."""
    env_val = os.environ.get("CVE_ENV_RECOVERY_GAP_TURNS")
    if env_val is not None:
        try:
            v = int(env_val)
            if v > 0:
                return v
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return _DEFAULT_RECOVERY_GAP_TURNS


# Python-side internal wall-budget (sleep-resilient backstop).
# External wall-guards (gtimeout/perl-alarm in bench50.sh) silently pause
# during macOS host sleep — kernel alarm timers don't advance while
# suspended (a build can run for hours past its intended wall). Internal
# check uses time.time() which DOES advance during sleep (unlike
# time.monotonic()).
#
# Default 0.0 = OFF for back-compat. Users who want overnight-sleep-resilient
# wall-guard set ``CVE_ENV_INTERNAL_WALL_S=1800`` (30min) or higher.
_DEFAULT_INTERNAL_WALL_BUDGET_S: float = 0.0


def get_internal_wall_budget_s() -> float:
    """Return the internal wall-budget seconds. 0.0 = disabled."""
    env_val = os.environ.get("CVE_ENV_INTERNAL_WALL_S")
    if env_val is not None:
        try:
            v = float(env_val)
            if v >= 0:
                return v
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return _DEFAULT_INTERNAL_WALL_BUDGET_S


# Module-level constant resolved once at import time. on_message reads this
# to keep the per-message check branch-free when disabled.
INTERNAL_WALL_BUDGET_S: float = get_internal_wall_budget_s()


# Anti-thrash no-progress give-up. The turn_cap/budget loss is dominated by
# cheap CHURN, not expensive builds: many capped CVEs never built and made
# zero productive progress for the final 80+ turns (research Bash/github
# loops). A budget RESERVE would buy more churn; instead, terminate early once
# the agent has gone this many turns with NO productive progress (no
# PRODUCTIVE_TOOLS ok + no post-build verify/run_in_container), reusing
# ``last_productive_turn`` (already tracked for should_extend_turn_cap).
# Efficiency only; default 0 = OFF so the default build path is unchanged.
_DEFAULT_NO_PROGRESS_GIVEUP_TURNS: int = 0


def get_no_progress_giveup_turns() -> int:
    """Return the anti-thrash no-progress give-up threshold (turns). 0 = OFF.

    DATA-DERIVED safe floor: across observed SUCCESS CVEs, the largest gap
    between consecutive productive events in a CVE that *eventually succeeded*
    was 71 turns (CVE-2020-15308) — so any threshold ≤ 71 would kill an
    observed winner. Safe floor is ≥ 72; 80 is recommended for margin (catches
    capped CVEs with 80+ turn no-progress tails, kills 0 observed winners).
    Negative / non-int env values fall back to OFF.
    """
    env_val = os.environ.get("CVE_ENV_NO_PROGRESS_GIVEUP_TURNS")
    if env_val is not None:
        try:
            v = int(env_val)
            if v >= 0:
                return v
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return _DEFAULT_NO_PROGRESS_GIVEUP_TURNS


# Resolved once at import time so on_message stays branch-free when disabled.
NO_PROGRESS_GIVEUP_TURNS: int = get_no_progress_giveup_turns()


# Connectivity circuit-breaker idle-timeout. The SDK is silent during long
# in-process MCP tool calls, so this is a TOOL-AWARE inter-message idle bound
# (see agent/_activity.py): max seconds with no SDK message AND no tool in
# flight before _run_query_once aborts the query as api_unreachable. Bounds
# the zombie-at-wall hang where the API goes unreachable mid-run. Default 300s
# only bounds API-wait gaps (model generation latency, typically <60s); 3×300
# < the 1440s external wall even if all SDK retries fire. Set 0 to disable.
# Resolved at call time so tests / per-run env overrides take effect.
_DEFAULT_SDK_IDLE_TIMEOUT_S: float = 300.0


def get_sdk_idle_timeout_s() -> float:
    """Return the connectivity-breaker idle-timeout seconds. 0 = off."""
    env_val = os.environ.get("CVE_ENV_SDK_IDLE_TIMEOUT_S")
    if env_val is not None:
        try:
            v = float(env_val)
            if v >= 0:
                return v
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return _DEFAULT_SDK_IDLE_TIMEOUT_S


# Tool-in-flight MAX backstop. The connectivity breaker EXEMPTS an in-flight
# tool indefinitely (legit builds are silent), so a WEDGED tool handler (a
# docker subprocess stuck on a dead VM socket that run_with_timeout could not
# reap) would otherwise ride to the 1440s wall. This bounds a single tool's
# in-flight time. Default 900s > docker_build (600) + compose + margin, so it
# never clips a legit build. 0 = off. Resolved at call time.
_DEFAULT_TOOL_MAX_INFLIGHT_S: float = 900.0


def get_tool_max_inflight_s() -> float:
    """Return the max seconds a single tool may stay in-flight before the
    connectivity breaker trips it as wedged. 0 = off."""
    env_val = os.environ.get("CVE_ENV_TOOL_MAX_INFLIGHT_S")
    if env_val is not None:
        try:
            v = float(env_val)
            if v >= 0:
                return v
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return _DEFAULT_TOOL_MAX_INFLIGHT_S


# The remaining two connectivity-breaker knobs (poll cadence + idle-retry cap)
# are exposed here so the breaker is FULLY config-driven, like the idle (5-min
# default) and inflight (900s, build-safe) bounds above. Resolved at call time
# so per-run/test env overrides take effect.
_DEFAULT_SDK_IDLE_POLL_S: float = 5.0


def get_sdk_idle_poll_s() -> float:
    """Watchdog poll cadence for the connectivity breaker (seconds).
    Smaller = more responsive but more wakeups. Must be > 0; default 5.0."""
    env_val = os.environ.get("CVE_ENV_SDK_IDLE_POLL_S")
    if env_val is not None:
        try:
            v = float(env_val)
            if v > 0:
                return v
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return _DEFAULT_SDK_IDLE_POLL_S


_DEFAULT_SDK_IDLE_MAX_ATTEMPTS: int = 2


def get_sdk_idle_max_attempts() -> int:
    """Cap on consecutive ``SdkIdleTimeout`` retries before giving up. Default 2
    (1 try + 1 retry): a truly unreachable API won't recover within the 2s/4s
    backoff, and 3×idle could approach the 1440s external wall. Must be >= 1."""
    env_val = os.environ.get("CVE_ENV_SDK_IDLE_MAX_ATTEMPTS")
    if env_val is not None:
        try:
            v = int(env_val)
            if v >= 1:
                return v
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return _DEFAULT_SDK_IDLE_MAX_ATTEMPTS


# force-resolve-before-giveup knobs: make the cascade-skip re-query
# continuation an operator dial — its compute cost on genuinely unbuildable
# cascade-skips (~6× a clean unresolvable) is a trade-off.
# `CVE_ENV_FORCE_RESOLVE_MAX=0` disables it entirely.
_DEFAULT_FORCE_RESOLVE_MAX: int = 1


def get_force_resolve_max() -> int:
    """Max force-resolve-before-giveup continuations per CVE. 0 = disabled
    (cost-control dial). Default 1. Resolved at call time for per-run override."""
    env_val = os.environ.get("CVE_ENV_FORCE_RESOLVE_MAX")
    if env_val is not None:
        try:
            v = int(env_val)
            if v >= 0:
                return v
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return _DEFAULT_FORCE_RESOLVE_MAX


_DEFAULT_FORCE_RESOLVE_BUDGET_FRACTION: float = 0.50


def get_force_resolve_budget_fraction() -> float:
    """Cost-cap fraction below which a force-resolve continuation may start
    (leaves headroom for the verify gate at 0.70). Default 0.50;
    must be in (0, 1]."""
    env_val = os.environ.get("CVE_ENV_FORCE_RESOLVE_BUDGET_FRACTION")
    if env_val is not None:
        try:
            v = float(env_val)
            if 0 < v <= 1:
                return v
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return _DEFAULT_FORCE_RESOLVE_BUDGET_FRACTION


_DEFAULT_BENIGN_VERIFY_CONTINUATION_MAX: int = 1


def get_enable_benign_verify_continuation() -> bool:
    """On a POST-LAUNCH refusal that blocked verify (env up, verify never
    reached), RESUME the session with a benign-only verify prompt
    (container_status + a version exec_check + http_check on base paths — NO CVE
    payloads / exploit checks). An agentic recovery that can convert
    refused→verified, complementing the structural launched_no_verify floor.

    DEFAULT OFF (``CVE_ENV_ENABLE_BENIGN_VERIFY_CONTINUATION``) — promote on
    bench A/B (the M-rule that gates the ``_PER_TOOL_DEFAULT_CAPS`` /
    force-resolve dials). Distinct from run_agent's de-escalation retry (fresh
    session, generic preamble, ~10% follow-through): this RESUMES so the model
    keeps the env it built and only runs safe health checks."""
    return _env_bool("CVE_ENV_ENABLE_BENIGN_VERIFY_CONTINUATION", default=False)


def get_benign_verify_continuation_max() -> int:
    """Max benign-verify continuations per CVE. 0 = disabled. Default 1.
    Resolved at call time for per-run override."""
    env_val = os.environ.get("CVE_ENV_BENIGN_VERIFY_CONTINUATION_MAX")
    if env_val is not None:
        try:
            v = int(env_val)
            if v >= 0:
                return v
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return _DEFAULT_BENIGN_VERIFY_CONTINUATION_MAX


_DEFAULT_PROPRIETARY_VERIFY_CONTINUATION_MAX: int = 1


def get_enable_proprietary_verify_continuation() -> bool:
    """Proprietary-verify continuation (agentic, default-ON): when the agent
    gives up ``proprietary`` WITHOUT having probed ``image_resolve`` (a
    name-only give-up by agent reasoning), RESUME the session ONCE to run a
    single image_resolve before the give-up is final. If an image resolves, the
    proprietary give-up is rejected and the build continues; otherwise it
    stands. This is the runtime "verify-the-negative" guard against the
    open-source-by-proprietary-vendor false-positive class that the
    OSS-reference override only partially covers (it needs an OSS host in the
    NVD refs).

    DEFAULT ON (``CVE_ENV_ENABLE_PROPRIETARY_VERIFY_CONTINUATION``): this gate
    is the SOLE runtime backstop for proprietary detection, so it is on by
    default. Cost is negligible (~$0.0007/probe). It SKIPS proprietary CVEs that
    already probed image_resolve (confirmed-negative class), so a
    genuinely-proprietary target costs ≤1 extra probe. Explicitly DISABLE with
    ``CVE_ENV_ENABLE_PROPRIETARY_VERIFY_CONTINUATION`` in {0, false, no, off}."""
    v = os.environ.get("CVE_ENV_ENABLE_PROPRIETARY_VERIFY_CONTINUATION", "").strip().lower()
    return v not in ("0", "false", "no", "off")


def get_enable_halt_on_verified_success() -> bool:
    """Halt-on-verified-success (agentic, default-OFF): when a ResultMessage's
    terminal status is ``final_success`` (a NON-cap stop_reason — clean end_turn
    — AND verify_passed), raise ``SuccessReached`` to halt SDK iteration
    immediately, symmetric to the ``give_up`` -> ``GiveUpReceived`` failure
    halt. Prevents a verified run from over-running into ``max_turns`` (where
    the cap-overrides-verify invariant mis-grades the real build ``turn_cap``):
    a run can verify, emit a clean end_turn, then burn further research turns
    into max_turns and be graded turn_cap despite verify_passed=True.

    DEFAULT OFF (``CVE_ENV_ENABLE_HALT_ON_VERIFIED_SUCCESS``) — promote on bench A/B
    (M-rule). SAFETY: the halt only fires on ``final_success``; cap signals
    (max_turns / budget) yield ``final_turn_cap`` / ``budget_exhausted`` instead
    (cap branch precedes the verify branch in ``_terminal_status_for_result``), so
    it can NEVER weaken the BUG-007/008 cap-overrides-verify lock. TRADE-OFF: in the
    rare case where an agent emits a clean end_turn after only a PARTIAL verify and
    intended further checks, halting may grade ``verified_partial`` instead of full
    ``success`` — both are BUILT, so build-rate is unaffected (only the
    success/partial split)."""
    return _env_bool("CVE_ENV_ENABLE_HALT_ON_VERIFIED_SUCCESS", default=False)


def get_proprietary_verify_max() -> int:
    """Max proprietary-verify continuations per CVE. 0 = disabled. Default 1.
    Resolved at call time for per-run override
    (``CVE_ENV_PROPRIETARY_VERIFY_CONTINUATION_MAX``)."""
    env_val = os.environ.get("CVE_ENV_PROPRIETARY_VERIFY_CONTINUATION_MAX")
    if env_val is not None:
        try:
            v = int(env_val)
            if v >= 0:
                return v
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return _DEFAULT_PROPRIETARY_VERIFY_CONTINUATION_MAX


# image_resolve aggregate per-call budget. A single image_resolve call can run
# ~1430s (10 candidates x ~70s + a 30s cooldown re-probe), alone approaching
# the 1440s bench wall — and the connectivity breaker is suppressed during it
# (image_resolve is a tool). This monotonic per-call deadline stops the cascade
# early. Default 600s is well under the wall and far above a normal probe
# (seconds); 0 disables. Resolved at call time so per-run/test env overrides
# take effect.
_DEFAULT_IMAGE_RESOLVE_BUDGET_S: float = 600.0


def get_image_resolve_budget_s() -> float:
    """Return the image_resolve per-call wall budget seconds. 0 = off."""
    env_val = os.environ.get("CVE_ENV_IMAGE_RESOLVE_BUDGET_S")
    if env_val is not None:
        try:
            v = float(env_val)
            if v >= 0:
                return v
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return _DEFAULT_IMAGE_RESOLVE_BUDGET_S


def get_recovery_eligible_stages() -> frozenset[str]:
    """Return the stage set where recovery emission is enabled."""
    env_val = os.environ.get("CVE_ENV_RECOVERY_ELIGIBLE_STAGES")
    if env_val:
        parts = {s.strip().upper() for s in env_val.split(",") if s.strip()}
        if parts:
            return frozenset(parts)
    return _DEFAULT_RECOVERY_ELIGIBLE_STAGES


# Per-stage soft budget thresholds (in USD).
# Defaults derived from cost-analysis across benched runs: 95th-percentile
# apportioned cost per stage across methods.
#
# Override per stage: ``CVE_ENV_BUDGET_<STAGE>=<usd>`` env var.
#
# These are SOFT thresholds by default (telemetry only). Enable HARD
# enforcement via ``CVE_ENV_BUDGET_<STAGE>_MODE=hard``.
_DEFAULT_STAGE_BUDGETS: dict[str, float] = {
    "RESEARCH": 0.50,
    "RESOLVE": 0.20,
    "ACQUIRE": 0.40,
    "LAUNCH": 0.30,
    "VERIFY": 0.30,
    "DIAGNOSTIC": 0.50,
    # No defaults for TERMINAL / OTHER — set to 0 = unbounded.
    "TERMINAL": 0.0,
    "OTHER": 0.0,
}


def get_stage_budget(stage: str) -> float:
    """Return USD soft budget for ``stage``.

    Precedence:
      1. Env var ``CVE_ENV_BUDGET_<STAGE>``
      2. TOML config ``[budget].<stage_lower> = <usd>``
      3. Code default (empirical)

    Returns 0 for unbounded. Stage names match :data:`STAGES`.
    """
    env_key = f"CVE_ENV_BUDGET_{stage}"
    env_val = os.environ.get(env_key)
    if env_val is not None:
        try:
            return float(env_val)
        except ValueError:
            return _DEFAULT_STAGE_BUDGETS.get(stage, 0.0)
    toml_val = _get_toml_value(["budget", stage.lower()])
    if toml_val is not None:
        try:
            return float(toml_val)
        except (TypeError, ValueError):
            pass
    return _DEFAULT_STAGE_BUDGETS.get(stage, 0.0)


def over_budget_stages(stage_costs: dict[str, float]) -> list[str]:
    """Return stages whose actual cost exceeded their soft budget.

    Empty list means no stage is over. ``get_stage_budget(s) == 0``
    means unbounded; skip the check. Used by the outcome generator
    to populate ``Outcome.over_budget_stages``.
    """
    over: list[str] = []
    for stage, cost in stage_costs.items():
        budget = get_stage_budget(stage)
        if budget > 0 and cost > budget:
            over.append(stage)
    return over


# Per-stage budget enforcement mode.
# Three modes:
#   "soft" (default) — telemetry + over_budget_stages_list; NO termination
#   "hard"           — over-budget terminates the run with
#                      give_up_reason = f"stage_budget_exhausted_{stage}"
#   "off"            — skip the budget check entirely (no telemetry,
#                      no enforcement; useful when stage budgets aren't
#                      meaningful for a particular use case)
_VALID_BUDGET_MODES: frozenset[str] = frozenset({"soft", "hard", "off"})


def get_stage_budget_mode(stage: str) -> str:
    """Return enforcement mode for ``stage``.

    Precedence: env var ``CVE_ENV_BUDGET_<STAGE>_MODE`` (lowercased) >
    default ``soft``. Invalid values fall back to ``soft``.
    """
    env_key = f"CVE_ENV_BUDGET_{stage}_MODE"
    val = os.environ.get(env_key, "soft").lower()
    if val not in _VALID_BUDGET_MODES:
        return "soft"
    return val


def stage_hard_budget_breach(stage_costs: dict[str, float]) -> str | None:
    """If any stage in HARD mode has exceeded its budget, return that
    stage name. None otherwise. First-triggered wins for determinism.
    """
    for stage, cost in stage_costs.items():
        if get_stage_budget_mode(stage) != "hard":
            continue
        budget = get_stage_budget(stage)
        if budget > 0 and cost > budget:
            return stage
    return None


# Adaptive cost extension constants. Mirrors the productive-extension for the
# cost dimension. Defaults are deliberately conservative (1 × 10% by default);
# users opt in to more aggressive behavior via env vars.
COST_EXTENSION_PCT: float = float(
    os.environ.get("CVE_ENV_COST_EXTENSION_PCT", "0.10")
)
"""Multiplier applied to ``max_cost_usd`` on each granted extension.
Default 0.10 (10% more budget). Override via env var
``CVE_ENV_COST_EXTENSION_PCT``."""

MAX_COST_EXTENSIONS: int = int(
    os.environ.get("CVE_ENV_MAX_COST_EXTENSIONS", "1")
)
"""Maximum number of cost-cap extensions per CVE. Default 1 (single
extension); set to 0 to fully disable adaptive extension. Override via env var
``CVE_ENV_MAX_COST_EXTENSIONS``."""


# Per-tool default attempt caps.
# Backstops for cost-spirals; agent still reasons per-input. Each entry MUST
# have M-class evidence (≥3 benches) AND be set at-or-above
# max-across-successful-CVEs so no historical success is regressed.
# Env var CVE_ENV_MAX_<TOOL>_ATTEMPTS still overrides.
#
# image_resolve=5: catches 6-call resolve spirals. Evidence: across benched
#   runs, sampled successful CVEs show image_resolve max-successful=5, p95=3,
#   p50=1 → cap=5 fires at attempt 6, zero historical regression.
#
# Other tools retain default 0 (unbounded) until their own M-class evidence
# + pre-flight grounds a default. A verify spiral needs a consecutive-error
# counter (not total-call counter) — deferred.
_PER_TOOL_DEFAULT_CAPS: dict[str, int] = {
    "image_resolve": 5,
}


def get_tool_attempt_cap(tool_name: str) -> int:
    """Return per-tool attempts cap for ``tool_name``.

    Env var ``CVE_ENV_MAX_<TOOL_NAME_UPPER>_ATTEMPTS`` (e.g.,
    ``CVE_ENV_MAX_IMAGE_RESOLVE_ATTEMPTS=4``) overrides the per-tool
    default. When the env var is absent or unparseable, falls back to
    ``_PER_TOOL_DEFAULT_CAPS[tool_name]`` (0 / unbounded if not listed).

    Per-tool defaults are only added when ≥3 benches confirm the spiral
    (M-class evidence) AND pre-flight shows zero regression risk against
    historical successes.
    """
    env_key = f"CVE_ENV_MAX_{tool_name.upper()}_ATTEMPTS"
    val = os.environ.get(env_key)
    default = _PER_TOOL_DEFAULT_CAPS.get(tool_name, 0)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def get_disallowed_tools() -> list[str]:
    """SDK/builtin tool names to disallow, from ``CVE_ENV_DISALLOWED_TOOLS``
    (comma-separated). Wired into ``ClaudeAgentOptions.disallowed_tools``.

    The operator dial to curb the research-spiral — e.g.
    ``CVE_ENV_DISALLOWED_TOOLS=Agent`` disables sub-agent spawning. DEFAULT is
    empty → NO behavior change. A default-disable waits for bench A/B evidence
    (the 3-bench M-rule that governs ``_PER_TOOL_DEFAULT_CAPS``).

    NOTE: default-disabling the built-in ``WebFetch`` / ``WebSearch`` here is
    NOT a no-op: a bench audit shows those tools fire in a meaningful fraction
    of CVE runs, so disabling them removes real research capability the agent
    uses (the MCP ``web_fetch`` handler was removed, leaving built-in
    ``WebFetch`` as the agent's only general fetch). Operators who want the SSRF
    attack-surface reduction can still set
    ``CVE_ENV_DISALLOWED_TOOLS=WebFetch,WebSearch`` explicitly."""
    raw = os.environ.get("CVE_ENV_DISALLOWED_TOOLS", "")
    return [t.strip() for t in raw.split(",") if t.strip()]


MAX_TOOL_ATTEMPT_EXTENSIONS: int = int(
    os.environ.get("CVE_ENV_MAX_TOOL_ATTEMPT_EXTENSIONS", "2")
)
"""Max progress-aware extensions of a per-tool attempt cap.
When a per-tool cap is exceeded BUT the agent made recent productive progress,
the cap is extended (by ×base each time) up to this many times before firing.
Mirrors MAX_TURN_EXTENSIONS / MAX_COST_EXTENSIONS.
0 = flat cap. Env: CVE_ENV_MAX_TOOL_ATTEMPT_EXTENSIONS."""


def productive_extension_allowed(
    *,
    last_productive_turn: int,
    current_turn: int,
    extension_count: int,
    max_extensions: int,
    recency_window: int = PRODUCTIVE_RECENCY_TURNS,
) -> bool:
    """Shared productive-extension gate: an automatic cap extension is allowed iff the feature is
    enabled, extension budget remains, and the agent made productive progress
    recently. The single home for the progress-recency rule — used by
    :func:`should_extend_cost_cap`, :func:`agent.loop.should_extend_turn_cap`, and
    the 3F per-tool attempt cap. (Callers add their own dimension-specific gates,
    e.g. cost-runaway / cost-near-cap.)"""
    if max_extensions <= 0:
        return False
    if extension_count >= max_extensions:
        return False
    if last_productive_turn <= 0:
        return False
    return current_turn - last_productive_turn <= recency_window


def should_extend_cost_cap(
    *,
    current_cost_usd: float,
    max_cost_usd: float,
    last_productive_turn: int,
    current_turn: int,
    cost_extension_count: int,
    max_cost_extensions: int = MAX_COST_EXTENSIONS,
    extension_pct: float = COST_EXTENSION_PCT,
    recency_window: int = PRODUCTIVE_RECENCY_TURNS,
) -> float | None:
    """Decide whether to grant a cost-cap extension.

    Mirrors :func:`agent.loop.should_extend_turn_cap` for the cost
    dimension. Grant only if:
      - ``max_cost_extensions > 0`` (feature enabled)
      - ``cost_extension_count < max_cost_extensions`` (budget remains)
      - ``last_productive_turn > 0`` (agent made build progress)
      - ``current_turn - last_productive_turn <= recency_window``
        (progress is recent)
      - ``current_cost_usd <= max_cost_usd * 1.5`` (runaway protection —
        don't extend if already 50% past cap; covers the SDK retry-burst
        edge cases like CVE-2022-32101)

    Returns new ``max_cost_usd`` if granted, else ``None``.
    """
    if not productive_extension_allowed(
        last_productive_turn=last_productive_turn,
        current_turn=current_turn,
        extension_count=cost_extension_count,
        max_extensions=max_cost_extensions,
        recency_window=recency_window,
    ):
        return None
    # Runaway protection: don't extend if cost is wildly past cap.
    if current_cost_usd > max_cost_usd * 1.5:
        return None
    return max_cost_usd * (1.0 + extension_pct)

# The SDK can emit ResultMessage.total_cost_usd=0 even when input/output
# tokens were consumed. Token-based fallback provides a conservative cost
# estimate so cost-loss never zeros out the per-CVE total. Rates are USD per
# 1,000,000 tokens; (input_rate, output_rate). Sources: anthropic.com/pricing
# as of 2026-01.
MODEL_TOKEN_RATES_PER_M_USD: dict[str, tuple[float, float]] = {
    "claude-opus-4-7": (15.0, 75.0),
    "claude-opus-4-6": (15.0, 75.0),
    "claude-opus-4-5": (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-sonnet-4-5": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (1.0, 5.0),
    "claude-haiku-4-5": (1.0, 5.0),
}


def get_token_rates(model: str = MODEL) -> tuple[float, float]:
    """Return ``(input_per_M_USD, output_per_M_USD)`` for ``model``.

    Env override: ``CVE_ENV_INPUT_RATE_PER_M`` + ``CVE_ENV_OUTPUT_RATE_PER_M``
    (both must be set; partial-override is ignored).

    Unknown models fall back to Sonnet rates (mid-tier conservative);
    a fallback estimate is better than $0.00.
    """
    env_in = os.environ.get("CVE_ENV_INPUT_RATE_PER_M")
    env_out = os.environ.get("CVE_ENV_OUTPUT_RATE_PER_M")
    if env_in is not None and env_out is not None:
        # A malformed override must not crash the cost path — fall through to
        # the per-model defaults, matching the parse-with-fallback idiom used
        # by the other config getters.
        try:
            return float(env_in), float(env_out)
        except ValueError:
            pass  # malformed env override -> fall back to the default below
    return MODEL_TOKEN_RATES_PER_M_USD.get(model, (3.0, 15.0))


def estimate_cost_from_tokens(
    input_tokens: int, output_tokens: int, model: str = MODEL
) -> float:
    """Conservative cost estimate from token counts.

    Used as a fallback: ``max(reported_cost, estimate)`` so cost data is never
    lost when the SDK reports $0 but tokens > 0.
    """
    in_rate, out_rate = get_token_rates(model)
    return (input_tokens * in_rate + output_tokens * out_rate) / 1_000_000.0


# Conservative per-turn token volume for the turns-based cost floor. Sized from
# observed agentic rounds (cf. tests/unit/test_b19_b20_cost_extension.py:
# "~5K in, ~500 out per LLM round").
_TURN_COST_INPUT_TOKENS = 5000
_TURN_COST_OUTPUT_TOKENS = 500


def estimate_cost_from_turns(num_turns: int, model: str = MODEL) -> float:
    """Lower-bound cost estimate from the engine turn count.

    For interrupted runs (turn_cap / budget) where the SDK reports neither a
    usable ``total_cost_usd`` nor token ``usage`` — the Claude Code session-auth
    case — both ``estimate_cost_from_tokens`` (tokens are 0) and the SDK cost
    collapse, leaving a multi-turn run logged as ~$0. This recovers a defensible
    floor from ``num_turns``. Returns 0.0 for non-positive ``num_turns``.
    """
    if num_turns <= 0:
        return 0.0
    return estimate_cost_from_tokens(
        num_turns * _TURN_COST_INPUT_TOKENS,
        num_turns * _TURN_COST_OUTPUT_TOKENS,
        model,
    )


# Opt-in lifecycle hooks. After ``cve-env build`` exits (success OR failure),
# run cleanup helpers if enabled. All default false to preserve existing
# behavior. Both env var and CLI flag are supported; CLI OR-merges with env
# (i.e. either enables → effective on). A CLI flag cannot disable an
# env-var-enabled option; a future ``--no-auto-*`` would be additive.

def _env_bool(name: str, default: bool = False) -> bool:
    """Parse a boolean env var. Truthy: 'true', '1', 'yes', 'on' (case-insensitive).
    Falsy or unset returns ``default``. Unknown values also return default."""
    val = os.environ.get(name, "").strip().lower()
    if val in ("true", "1", "yes", "on"):
        return True
    return default


AUTO_CLEANUP_CONTAINERS: bool = _env_bool("CVE_ENV_AUTO_CLEANUP_CONTAINERS")
"""When True, post-build ``docker rm -f`` this run's labeled
containers. CLI override: ``--auto-cleanup-containers`` (cli.py)."""

AUTO_PRUNE_IMAGES: bool = _env_bool("CVE_ENV_AUTO_PRUNE_IMAGES")
"""When True, post-build ``docker image prune -f`` (dangling
only — safer than -a). CLI override: ``--auto-prune-images`` (cli.py)."""

AUTO_STOP_COLIMA: bool = _env_bool("CVE_ENV_AUTO_STOP_COLIMA")
"""When True, post-build ``colima stop`` IFF no other cve-env
build is running (lockfile guard at /tmp/cve-env-active.lock).
CLI override: ``--auto-stop-colima`` (cli.py)."""

# Docker resource label — the single contract between the WRITERS that tag
# per-CVE docker resources (docker_run / docker_build / docker_compose_up) and
# the READERS that clean them up by filter (lifecycle.cleanup_containers /
# cleanup_result_images). Defined ONCE here so a rename can't desync a writer
# from a reader.
CVE_LABEL = "cve-env.cve-id"

# Paths.
def _find_repo_root() -> Path:
    """Resolve the project root, layout-independent.

    Order:
      1. ``CVE_ENV_REPO_ROOT`` env var — escape hatch for pip-installed
         users whose package lives in site-packages (no marker reachable
         upward).
      2. Walk up from this file looking for a ``pyproject.toml`` or
         ``.git`` marker. Handles clones at any nesting depth (works
         for both ``<repo>/src/cve_env/config.py`` and any future
         flatter/deeper layout without code changes).
      3. Fall back to ``parents[2]`` of this file — the legacy behavior.
         For pip install this resolves to the
         system Python lib (broken), but ``--audit-root`` CLI arg +
         the env var above are the documented production overrides;
         this fallback only fires when neither is provided AND no
         marker is reachable, in which case the broken legacy is
         preserved (no regression).
    """
    env = os.environ.get("CVE_ENV_REPO_ROOT")
    if env:
        return Path(env).resolve()
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "pyproject.toml").is_file() or (candidate / ".git").is_dir():
            return candidate
    return here.parents[2]


REPO_ROOT: Path = _find_repo_root()


def _find_output_root() -> Path:
    """Resolve the artifact output root.

    ``CVE_ENV_OUTPUT_ROOT`` decouples *where artifacts are written* from
    ``REPO_ROOT`` (which only locates the source tree). raptor wires this
    to ``$RAPTOR_DIR/out`` so cve-env's audit JSONLs, outcome sidecars,
    and refusals log land under raptor's ``out/`` tree alongside the other
    packages' run dirs. Unset → the standalone default
    (``REPO_ROOT/output``), so behavior is identical outside raptor.
    """
    env = os.environ.get("CVE_ENV_OUTPUT_ROOT")
    if env:
        return Path(env).resolve()
    return REPO_ROOT / "output"


OUTPUT_ROOT: Path = _find_output_root()
DATA_ROOT: Path = REPO_ROOT / "data"
AGENTIC_AUDIT_ROOT: Path = OUTPUT_ROOT / "agentic"

# Network tool defaults.
WEB_FETCH_MAX_BYTES: int = 256 * 1024  # 256 KiB cap on response bodies
WEB_FETCH_TIMEOUT_SECONDS: float = 15.0

NVD_API_BASE: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API_BASE: str = "https://api.github.com"

# Shared between loop.py (outcome gate) and verify.py
# (verify_quality_warning emission). Heuristic — matches commands that
# discover a deployed package/binary version. Used by the
# version-assertion gate.
VERSION_ASSERTION_CMD_PATTERN: re.Pattern[str] = re.compile(
    r"--version\b"
    r"|\b-V\b"
    r"|\bversion\b"
    r"|\bdpkg -l\b"
    r"|\bdpkg-query\b"
    r"|\bapt-cache policy\b"
    r"|\bpip3? show\b"
    r"|\bpip3? freeze\b"
    r"|\bgem list\b"
    r"|\bbundle list\b"
    r"|\bnpm (ls|list)\b"
    r"|\byarn list\b"
    r"|\bgo version\b"
    r"|\bfind .*\.jar\b"
    r"|\bunzip -l\b"
    r"|\bunzip -p .*MANIFEST\.MF\b"
    r"|\bcat .*pom\.xml\b"
    r"|\bphp -m\b"
    r"|\bphpversion\b"
    r"|\bapache2 -v\b"
    r"|\bapache2ctl -M\b"
    r"|\bhttpd -M\b"
    r"|\bnginx -v\b"
    r"|\bjava -version\b"
    r"|\bdrush status\b"
    r"|\bwp core version\b"
    r"|\brpm -qa?\b"
    r"|\bcat /etc/.*-release\b"
    r"|\bcat /etc/issue\b"
    # Lockfile-grep + versioned-dir finds are legitimate version proofs. The
    # strict-marker gate (loop._has_specific_version_marker) still requires the
    # exec_check's expected_stdout_contains to carry the actual version digits,
    # so a bare lockfile-grep without a version marker cannot false-promote a
    # broken build to `success`.
    r"|\bcomposer\.lock\b"
    r"|\bpackage-lock\.json\b"
    r"|\bPipfile\.lock\b"
    r"|\bfind .* -name ['\"]?[a-z]+[_.-]\d+\.\d+",
    re.IGNORECASE,
)
