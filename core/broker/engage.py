"""Engagement planning — fleet assessment and operator confirmation.

Before routing tasks, the broker evaluates the fleet against the
engagement's scope (which modes will be used) and proposes a role
assignment for each system.  The operator confirms, overrides, or
excludes systems before work begins.

An ``EngagementPlan`` is immutable once confirmed.  Task routing
checks the active plan first; systems excluded from the plan are
never routed to, and mode→system assignments are respected unless
the operator explicitly overrides at task time.

Workflow::

    # 1. Propose — broker scores fleet against engagement scope
    proposal = propose_engagement(inventory, modes, target_desc)

    # 2. Operator reviews, overrides, confirms
    plan = confirm_engagement(proposal, overrides={...})

    # 3. Plan is persisted — tasks honour it
    save_engagement(plan)

    # 4. Task routing checks plan first
    router.route(spec)  # respects plan assignments
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Mapping, Optional, Sequence

from core.broker.capabilities import (
    MODE_REQUIREMENTS,
    ModeRequirements,
    OperatingSystem,
    SystemCapabilities,
)
from core.broker.inventory import Inventory
from core.broker.scoring import ScoredSystem, TaskConstraints, rank_fleet
from core.broker.transport import RemoteSystemEntry, TransportKind

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RoleAssignment:
    """One system's role in the engagement."""
    alias: str
    modes: frozenset[str]
    score: float
    rationale: str
    capable_modes: frozenset[str]
    excluded: bool = False


@dataclass(frozen=True)
class ModeAssignment:
    """Which system handles a specific mode, and why."""
    mode: str
    primary_alias: str
    primary_score: float
    fallback_alias: Optional[str] = None
    fallback_score: Optional[float] = None
    rationale: str = ""
    unassignable: bool = False
    unassignable_reason: str = ""


@dataclass(frozen=True)
class EngagementProposal:
    """Broker's recommended fleet deployment — awaiting operator confirmation."""
    target_description: str
    modes: frozenset[str]
    role_assignments: tuple[RoleAssignment, ...]
    mode_assignments: tuple[ModeAssignment, ...]
    fleet_summary: str
    proposed_at: float = 0.0


@dataclass(frozen=True)
class EngagementPlan:
    """Confirmed fleet deployment — immutable contract for the engagement."""
    target_description: str
    modes: frozenset[str]
    mode_assignments: tuple[ModeAssignment, ...]
    excluded_aliases: frozenset[str]
    confirmed_at: float = 0.0
    overrides_applied: tuple[str, ...] = ()

    def system_for_mode(self, mode: str) -> Optional[str]:
        """Look up the assigned system for a mode. None if unassigned."""
        for ma in self.mode_assignments:
            if ma.mode == mode and not ma.unassignable:
                return ma.primary_alias
        return None

    def is_excluded(self, alias: str) -> bool:
        return alias in self.excluded_aliases

    def fallback_for_mode(self, mode: str) -> Optional[str]:
        for ma in self.mode_assignments:
            if ma.mode == mode:
                return ma.fallback_alias
        return None


ENGAGEMENT_SCOPES: dict[str, frozenset[str]] = {
    "full": frozenset({"scan", "codeql", "fuzz", "web", "agentic", "frida"}),
    "source-audit": frozenset({"scan", "codeql", "agentic"}),
    "binary": frozenset({"fuzz", "frida", "crash-analysis"}),
    "web-assessment": frozenset({"scan", "web", "agentic"}),
    "mobile": frozenset({"frida", "scan", "agentic"}),
    "reversing": frozenset({"frida", "crash-analysis"}),
}


def propose_engagement(
    inventory: Inventory,
    modes: frozenset[str],
    target_description: str = "",
    *,
    constraints: Optional[dict[str, TaskConstraints]] = None,
) -> EngagementProposal:
    """Score the fleet against the engagement scope and propose assignments.

    For each mode in the engagement, ranks every fleet member and picks
    the best.  Aggregates per-system across all modes to produce role
    summaries.  Returns a proposal for operator review.
    """
    fleet = inventory.list_all_with_capabilities()
    local_caps = SystemCapabilities.detect_local()
    local_entry = RemoteSystemEntry(
        alias="localhost", host="127.0.0.1", port=0, user="",
        transport=TransportKind.SSH,
    )
    all_systems = [(local_entry, local_caps)] + list(fleet)

    mode_assignments: list[ModeAssignment] = []
    system_modes: dict[str, list[str]] = {}
    system_capable: dict[str, set[str]] = {}
    system_scores: dict[str, float] = {}

    per_mode_constraints = constraints or {}

    for mode in sorted(modes):
        mc = per_mode_constraints.get(mode)
        ranked = rank_fleet(
            all_systems, mode,
            require_capable=True,
            constraints=mc,
        )

        if not ranked:
            mode_assignments.append(ModeAssignment(
                mode=mode,
                primary_alias="",
                primary_score=0.0,
                unassignable=True,
                unassignable_reason=f"no fleet member can run '{mode}'",
            ))
            continue

        primary = ranked[0]
        fallback = ranked[1] if len(ranked) > 1 else None

        rationale = _build_rationale(primary, mode, ranked)

        mode_assignments.append(ModeAssignment(
            mode=mode,
            primary_alias=primary.entry.alias,
            primary_score=primary.score,
            fallback_alias=fallback.entry.alias if fallback else None,
            fallback_score=fallback.score if fallback else None,
            rationale=rationale,
        ))

        system_modes.setdefault(primary.entry.alias, []).append(mode)
        if primary.entry.alias not in system_scores:
            system_scores[primary.entry.alias] = 0.0
        system_scores[primary.entry.alias] = max(
            system_scores[primary.entry.alias], primary.score,
        )

        for s in ranked:
            system_capable.setdefault(s.entry.alias, set()).add(mode)

    role_assignments: list[RoleAssignment] = []
    for entry, caps in all_systems:
        assigned = frozenset(system_modes.get(entry.alias, []))
        capable = frozenset(system_capable.get(entry.alias, set()))
        score = system_scores.get(entry.alias, 0.0)

        if not capable:
            role_assignments.append(RoleAssignment(
                alias=entry.alias,
                modes=frozenset(),
                score=0.0,
                rationale="not capable of any engagement mode",
                capable_modes=frozenset(),
                excluded=True,
            ))
            continue

        parts = []
        if assigned:
            parts.append(f"primary for: {', '.join(sorted(assigned))}")
        standby = capable - assigned
        if standby:
            parts.append(f"fallback for: {', '.join(sorted(standby))}")

        role_assignments.append(RoleAssignment(
            alias=entry.alias,
            modes=assigned,
            score=score,
            rationale="; ".join(parts),
            capable_modes=capable,
        ))

    fleet_lines = [f"{len(all_systems)} systems evaluated, {len(modes)} modes"]
    assigned_count = sum(1 for r in role_assignments if r.modes)
    fleet_lines.append(f"{assigned_count} systems assigned primary roles")
    unassignable = [ma for ma in mode_assignments if ma.unassignable]
    if unassignable:
        fleet_lines.append(
            f"{len(unassignable)} mode(s) cannot be assigned: "
            + ", ".join(ma.mode for ma in unassignable)
        )

    return EngagementProposal(
        target_description=target_description,
        modes=modes,
        role_assignments=tuple(role_assignments),
        mode_assignments=tuple(mode_assignments),
        fleet_summary="; ".join(fleet_lines),
        proposed_at=time.time(),
    )


def confirm_engagement(
    proposal: EngagementProposal,
    *,
    overrides: Optional[dict[str, str]] = None,
    exclude: frozenset[str] = frozenset(),
) -> EngagementPlan:
    """Lock in the engagement plan with optional operator overrides.

    Parameters
    ----------
    overrides:
        ``{mode: alias}`` — reassign a mode to a different system.
    exclude:
        System aliases to exclude from the engagement entirely.
    """
    overrides = overrides or {}
    applied: list[str] = []

    final_assignments: list[ModeAssignment] = []
    for ma in proposal.mode_assignments:
        if ma.mode in overrides:
            new_alias = overrides[ma.mode]
            final_assignments.append(ModeAssignment(
                mode=ma.mode,
                primary_alias=new_alias,
                primary_score=0.0,
                fallback_alias=ma.primary_alias,
                fallback_score=ma.primary_score,
                rationale=f"operator override: {ma.primary_alias} → {new_alias}",
                unassignable=False,
            ))
            applied.append(f"{ma.mode}: {ma.primary_alias} → {new_alias}")
        elif ma.primary_alias in exclude:
            if ma.fallback_alias and ma.fallback_alias not in exclude:
                final_assignments.append(ModeAssignment(
                    mode=ma.mode,
                    primary_alias=ma.fallback_alias,
                    primary_score=ma.fallback_score or 0.0,
                    rationale=f"primary {ma.primary_alias} excluded, promoted fallback",
                ))
                applied.append(
                    f"{ma.mode}: {ma.primary_alias} excluded, "
                    f"promoted {ma.fallback_alias}"
                )
            else:
                final_assignments.append(ModeAssignment(
                    mode=ma.mode,
                    primary_alias="",
                    primary_score=0.0,
                    unassignable=True,
                    unassignable_reason=(
                        f"primary {ma.primary_alias} excluded, no fallback"
                    ),
                ))
                applied.append(f"{ma.mode}: unassignable after exclusion")
        else:
            final_assignments.append(ma)

    return EngagementPlan(
        target_description=proposal.target_description,
        modes=proposal.modes,
        mode_assignments=tuple(final_assignments),
        excluded_aliases=exclude,
        confirmed_at=time.time(),
        overrides_applied=tuple(applied),
    )


def _build_rationale(
    winner: ScoredSystem,
    mode: str,
    ranked: Sequence[ScoredSystem],
) -> str:
    parts = [f"score {winner.score:.1f}"]

    caps = winner.capabilities
    if mode in ("fuzz", "crash-analysis"):
        parts.append(f"{caps.cores} cores")
    if mode in ("codeql", "agentic"):
        parts.append(f"{caps.ram_mb} MB RAM")
    if caps.os:
        parts.append(caps.os.value)

    if len(ranked) > 1:
        margin = winner.score - ranked[1].score
        if margin > 5:
            parts.append(f"+{margin:.1f} over {ranked[1].entry.alias}")
        elif margin < 1:
            parts.append(f"close call vs {ranked[1].entry.alias}")

    return "; ".join(parts)


# ── persistence ──────────────────────────────────────────────────────

_ENGAGE_DIR = Path.home() / ".raptor" / "broker" / "engagements"


def save_engagement(plan: EngagementPlan, name: str = "active") -> Path:
    """Persist an engagement plan to disk."""
    _ENGAGE_DIR.mkdir(parents=True, exist_ok=True)
    path = _ENGAGE_DIR / f"{name}.json"

    data = {
        "target_description": plan.target_description,
        "modes": sorted(plan.modes),
        "mode_assignments": [
            {
                "mode": ma.mode,
                "primary_alias": ma.primary_alias,
                "primary_score": ma.primary_score,
                "fallback_alias": ma.fallback_alias,
                "fallback_score": ma.fallback_score,
                "rationale": ma.rationale,
                "unassignable": ma.unassignable,
                "unassignable_reason": ma.unassignable_reason,
            }
            for ma in plan.mode_assignments
        ],
        "excluded_aliases": sorted(plan.excluded_aliases),
        "confirmed_at": plan.confirmed_at,
        "overrides_applied": list(plan.overrides_applied),
    }
    path.write_text(json.dumps(data, indent=2) + "\n")
    return path


def load_engagement(name: str = "active") -> Optional[EngagementPlan]:
    """Load a persisted engagement plan."""
    path = _ENGAGE_DIR / f"{name}.json"
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            logger.warning("engagement plan %s is not a JSON object", path)
            return None

        raw_modes = data["modes"]
        if not isinstance(raw_modes, list):
            logger.warning("engagement plan %s: modes is not a list", path)
            return None

        raw_assignments = data["mode_assignments"]
        if not isinstance(raw_assignments, list):
            logger.warning("engagement plan %s: mode_assignments is not a list", path)
            return None

        return EngagementPlan(
            target_description=str(data.get("target_description", "")),
            modes=frozenset(str(m) for m in raw_modes),
            mode_assignments=tuple(
                ModeAssignment(
                    mode=str(ma["mode"]),
                    primary_alias=str(ma["primary_alias"]),
                    primary_score=float(ma.get("primary_score", 0.0)),
                    fallback_alias=ma.get("fallback_alias"),
                    fallback_score=ma.get("fallback_score"),
                    rationale=str(ma.get("rationale", "")),
                    unassignable=bool(ma.get("unassignable", False)),
                    unassignable_reason=str(ma.get("unassignable_reason", "")),
                )
                for ma in raw_assignments
            ),
            excluded_aliases=frozenset(
                str(a) for a in data.get("excluded_aliases", [])
            ),
            confirmed_at=float(data.get("confirmed_at", 0.0)),
            overrides_applied=tuple(
                str(o) for o in data.get("overrides_applied", [])
            ),
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        logger.warning("failed to load engagement plan %s: %s", path, exc)
        return None


def clear_engagement(name: str = "active") -> bool:
    """Remove an engagement plan."""
    path = _ENGAGE_DIR / f"{name}.json"
    if path.exists():
        path.unlink()
        return True
    return False


def format_proposal(proposal: EngagementProposal) -> str:
    """Human-readable proposal for operator review."""
    lines: list[str] = []
    lines.append(f"Engagement: {proposal.target_description or '(unnamed)'}")
    lines.append(f"Scope: {', '.join(sorted(proposal.modes))}")
    lines.append(f"Fleet: {proposal.fleet_summary}")
    lines.append("")

    lines.append("Mode Assignments:")
    lines.append(f"  {'Mode':<16} {'System':<16} {'Score':>7} {'Fallback':<16} {'Rationale'}")
    lines.append("  " + "-" * 80)

    for ma in proposal.mode_assignments:
        if ma.unassignable:
            lines.append(
                f"  {ma.mode:<16} {'NONE':<16} {'—':>7} {'—':<16} "
                f"{ma.unassignable_reason}"
            )
        else:
            fb = ma.fallback_alias or "—"
            lines.append(
                f"  {ma.mode:<16} {ma.primary_alias:<16} "
                f"{ma.primary_score:>7.1f} {fb:<16} {ma.rationale}"
            )

    lines.append("")
    lines.append("System Roles:")
    lines.append(f"  {'System':<16} {'Status':<10} {'Primary For':<30} {'Capable Of'}")
    lines.append("  " + "-" * 80)

    for ra in proposal.role_assignments:
        status = "excluded" if ra.excluded else "active"
        primary = ", ".join(sorted(ra.modes)) if ra.modes else "—"
        capable = ", ".join(sorted(ra.capable_modes)) if ra.capable_modes else "none"
        lines.append(
            f"  {ra.alias:<16} {status:<10} {primary:<30} {capable}"
        )

    return "\n".join(lines)


def format_plan(plan: EngagementPlan) -> str:
    """Human-readable confirmed plan."""
    lines: list[str] = []
    lines.append(f"Engagement Plan: {plan.target_description or '(unnamed)'}")
    lines.append(f"Confirmed: {time.strftime('%Y-%m-%d %H:%M', time.localtime(plan.confirmed_at))}")
    lines.append(f"Scope: {', '.join(sorted(plan.modes))}")
    if plan.excluded_aliases:
        lines.append(f"Excluded: {', '.join(sorted(plan.excluded_aliases))}")
    lines.append("")

    lines.append(f"  {'Mode':<16} {'System':<16} {'Fallback':<16} {'Notes'}")
    lines.append("  " + "-" * 60)

    for ma in plan.mode_assignments:
        if ma.unassignable:
            lines.append(f"  {ma.mode:<16} {'UNASSIGNED':<16} {'—':<16} {ma.unassignable_reason}")
        else:
            fb = ma.fallback_alias or "—"
            lines.append(f"  {ma.mode:<16} {ma.primary_alias:<16} {fb:<16} {ma.rationale}")

    if plan.overrides_applied:
        lines.append("")
        lines.append("Overrides:")
        for o in plan.overrides_applied:
            lines.append(f"  - {o}")

    return "\n".join(lines)
