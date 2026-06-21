"""Shared data types: CVE record, host info, final Outcome.

Kept deliberately thin -- Pydantic only where the agent actually touches
the shape.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

OutcomeStatus = Literal[
    "success",
    "success_partial",  # legacy alias for verified_partial
    "verified_partial",  # canonical replacement for success_partial
    "unresolvable",
    "budget_exhausted",
    "turn_cap",
    "no_verify_pass",  # legacy alias for verify_failed
    "verify_failed",  # canonical replacement for no_verify_pass
    "launched_unverified",  # legacy alias for launched_no_verify
    "launched_no_verify",  # canonical replacement for launched_unverified
    "incomplete",  # legacy alias for interrupted
    "interrupted",  # canonical replacement for incomplete
    # Anthropic 529/overload throttle — re-runnable, not a merit failure.
    "rate_limited",
    "error",
]
"""Final status of one ``build(cve_id)`` call.

UX clarity status rename. Engine code EMITS the new canonical names
(verified_partial / verify_failed / launched_no_verify / interrupted).
The OLD names remain in the Literal so historical outcome JSONs still
parse and the replay-corpus tests don't break.

Use :data:`OUTCOME_STATUS_ALIAS_MAP` to translate OLD→NEW when reading
historical data. Engine internals (_map_status etc.) construct Outcomes
with the NEW names. Consumers should check NEW first, OR-fall-back to
OLD for backward compat.

Semantic decoupling. The product goal is to build pre-patch CVE
environments with all dependencies at the right version numbers. So:

- ``success`` = verify_passed AND version-assertion exec_check present
  AND functional smoke present (verbs proving the app's normal
  operations work on benign input). The environment is built correctly
  and works.

- ``verified_partial`` (was ``success_partial``) = verify_passed but
  missing version-assertion OR functional smoke. The build reached
  docker_run + verify but evidence is incomplete. The runtime
  version-assertion injector closes the version-marker gap; this status
  remains for the functional-smoke-missing case.

``interrupted`` (was ``incomplete``) is distinct from ``error``. Used
when the SDK was forcibly terminated (Claude Code safety refusal,
mid-stream interruption) but the engine itself didn't crash — the run
simply did not finish. A passing verify mid-run does NOT count as
success when the overall conversation ended in refusal.
"""


OUTCOME_STATUS_ALIAS_MAP: dict[str, str] = {
    "success_partial": "verified_partial",
    "no_verify_pass": "verify_failed",
    "launched_unverified": "launched_no_verify",
    "incomplete": "interrupted",
}


GIVE_UP_REASON_ALIAS_MAP: dict[str, str] = {
    "silent_end_turn": "quit_without_verify_or_giveup",
    "no_image_without_resolve": "skipped_image_lookup",
    "refusal_persistent": "refusal_no_recovery",
}
"""OLD → NEW canonical give_up_reason names.

Same pattern as :data:`OUTCOME_STATUS_ALIAS_MAP`. Engine code EMITS the
canonical NEW names; this map normalizes any incoming reason string
(e.g., from a historical audit JSONL) into the current canonical form.
Read-path consumers use ``GIVE_UP_REASON_ALIAS_MAP.get(reason, reason)``.

Why renamed:
* ``silent_end_turn`` → reader couldn't tell what's silent or when;
  ``quit_without_verify_or_giveup`` describes the actual antipattern.
* ``no_image_without_resolve`` → reads as nonsense to readers unfamiliar
  with the cascade; ``skipped_image_lookup`` is plain English.
* ``refusal_persistent`` → cryptic; ``refusal_no_recovery`` clarifies.
"""


@dataclass(frozen=True)
class CveRecord:
    """Minimum fields the agent needs to reason about a CVE."""

    cve_id: str
    product: str = ""
    version: str = ""
    description: str = ""
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class HostInfo:
    """Observed host facts relevant to arch/emulation decisions."""

    arch: str
    os: str = field(default_factory=lambda: platform.system().lower())
    docker_backend: str = ""
    rosetta_available: bool = False


@dataclass
class Outcome:
    """Terminal outcome of one ``build(cve_id)`` call."""

    cve_id: str
    status: OutcomeStatus
    reason: str = ""
    num_turns: int = 0
    total_cost_usd: float = 0.0
    session_id: str = ""
    stop_reason: str = ""
    verify_passed: bool = False
    verify_result: dict[str, Any] | None = None
    give_up_reason: str = ""
    give_up_detail: str = ""
    final_text: str = ""
    tool_names_called: list[str] = field(default_factory=list)
    audit_path: Path | None = None
    error: str = ""
    # Count of refusal events the RefusalScanner observed during the run
    # (LLM refusal text matches OR SDK API Error wrappers). Surfaces the
    # same signal bench50.sh prints as ``refusals=N@T<turn>`` so post-bench
    # JSON analysis can tally refusal rates without re-parsing bench.log
    # narrative. 0 == no refusals.
    #
    # SIGNAL DISAMBIGUATION: this field counts BOTH transient
    # sanitizer-firing events AND any terminal refusal classification. It
    # is NOT identical to the audit JSONL ``reason==refusal`` event count.
    #
    # Three related signals exist; pick deliberately:
    #   1. ``outcome.refusals`` (THIS field) — count of transient+terminal
    #      refusal events.
    #   2. Audit JSONL ``reason==refusal`` events — only emits the
    #      terminal refusal that survived recovery; not transient.
    #   3. ``give_up_reason == "refusal_no_recovery"`` (formerly
    #      ``refusal_persistent``) — the terminal-classification signal
    #      that refusal pre-emption actually targets.
    #
    # When citing "0 refusals" in a closeout, NAME the signal; ground truth
    # depends on which of the three is meant.
    refusals: int = 0
    # A docker_build/daemon tool result classified ``daemon_corruption``
    # (corrupted containerd storage / failed to retrieve image list) was
    # seen — HOST infra corruption, NOT an engine/merit failure. Surfaced
    # here (not just the audit JSONL) so the bench heal + bench_select_retry
    # can detect it from the outcome JSON and trigger a colima restart +
    # re-run rather than counting it as unresolvable. Default False.
    daemon_corruption: bool = False
    # Per-stage cost attribution. Optional dict of {stage: usd}. Stages are
    # config.STAGES; OTHER is the fallback bucket. Telemetry only — surfaces
    # where the agent's budget was spent. Sum across stages == total_cost_usd
    # modulo estimate-vs-reported reconciliation.
    stage_costs: dict[str, float] | None = None
    stage_calls: dict[str, int] | None = None
    # Stages that exceeded their soft budget. Computed at outcome
    # construction from stage_costs vs ``config.get_stage_budget()``. Empty
    # list = no stage over budget. None = legacy outcome without this field.
    over_budget_stages_list: list[str] | None = None


def derive_build_method(tool_names_called: list[str]) -> str:
    """Best-effort label(s) for HOW the env was built/launched, derived from
    the tool trail, for the per-CVE sidecar JSON + corpus-append.

    Previously absent from the sidecar: ``scripts/update_corpus.py`` only passes
    a ``method`` key through if present, and nothing produced it. Comma-joins
    when the run CASCADED across methods (e.g. source-build then compose).

    Taxonomy MIRRORS ``scripts/heartbeat_status.sh`` (method detection, ~line
    200) — the two MUST stay in sync. Returns ``researching`` when no build/
    launch tool ran.
    """
    seq = tool_names_called or []

    def has(name: str) -> bool:
        return name in seq

    methods: list[str] = []
    if has("source_build"):
        methods.append("source-build")
    if has("docker_compose_up"):
        methods.append("vulhub-compose")
    if has("dockerfile_gen") and has("docker_build") and "source-build" not in methods:
        methods.append("custom-dockerfile")
    if (
        has("image_resolve")
        and has("docker_run")
        and not (
            has("source_build") or has("dockerfile_gen") or has("docker_compose_up")
        )
    ):
        methods.append("vulhub-image")
    return ", ".join(methods) if methods else "researching"
