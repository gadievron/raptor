"""Live classification accumulator — intra-run learning from LLM review outcomes.

During an audit run, the LLM reviews functions one at a time. Each review
produces signals about the function's callees: "this callee is a dangerous
sink", "this callee sanitizes input", "this callee handles external input".

These signals are currently buried in free-text observations and lost after
the review. This module captures them as structured sets that grow during
the run, influencing triage of not-yet-reviewed functions.

The same mechanism applies to sinks, sanitizers, and entry points:
1. LLM reports discovery via structured schema fields
2. Orchestrator extracts and adds to the live set
3. Not-yet-reviewed callers get triage adjusted
4. End-of-run persists confirmed discoveries to project context
5. Next run loads them and uses them from the start
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class LiveClassifications:
    """Mutable classification state that grows during an audit run.

    Thread-safe for the serial executor. For parallel execution,
    the caller must synchronize access.
    """
    sinks: set[str] = field(default_factory=set)
    sanitizers: set[str] = field(default_factory=set)
    entry_points: set[str] = field(default_factory=set)

    _sink_sources: dict[str, str] = field(default_factory=dict)
    _sanitizer_sources: dict[str, str] = field(default_factory=dict)

    def add_sink(self, callee: str, *, discovered_by: str = "") -> bool:
        """Register a newly-discovered dangerous callee.

        Returns True if this is a new discovery (not already known).
        """
        if callee in self.sinks:
            return False
        self.sinks.add(callee)
        if discovered_by:
            self._sink_sources[callee] = discovered_by
        logger.info("live sink discovered: %s (by %s)", callee, discovered_by)
        return True

    def add_sanitizer(self, callee: str, *, discovered_by: str = "") -> bool:
        if callee in self.sanitizers:
            return False
        self.sanitizers.add(callee)
        if discovered_by:
            self._sanitizer_sources[callee] = discovered_by
        logger.info("live sanitizer discovered: %s (by %s)", callee, discovered_by)
        return True

    def add_entry_point(self, func_key: str) -> bool:
        if func_key in self.entry_points:
            return False
        self.entry_points.add(func_key)
        logger.info("live entry point discovered: %s", func_key)
        return True

    def should_upgrade_triage(self, gap_key: str, callees: list[str]) -> str | None:
        """Check if a function's triage should be upgraded based on live discoveries.

        Returns a reason string if upgrade is warranted, None otherwise.
        """
        for callee in callees:
            if callee in self.sinks:
                return f"calls live-discovered sink {callee}"
        return None

    def as_persistable(self) -> dict:
        """Export for end-of-run persistence to project context."""
        result = {}
        if self.sinks:
            result["sinks"] = [
                {"name": s, "discovered_by": self._sink_sources.get(s, "")}
                for s in sorted(self.sinks)
            ]
        if self.sanitizers:
            result["sanitizers"] = [
                {"name": s, "discovered_by": self._sanitizer_sources.get(s, "")}
                for s in sorted(self.sanitizers)
            ]
        return result

    def stats(self) -> str:
        parts = []
        if self.sinks:
            parts.append(f"{len(self.sinks)} sinks")
        if self.sanitizers:
            parts.append(f"{len(self.sanitizers)} sanitizers")
        if self.entry_points:
            parts.append(f"{len(self.entry_points)} entry points")
        if not parts:
            return "no live discoveries"
        return ", ".join(parts)


def extract_from_outcome(
    outcome: object,
    gap: dict,
    live: LiveClassifications,
) -> int:
    """Extract classification signals from a review outcome.

    Reads structured fields (dangerous_callees, sanitizer_callees)
    from the LLM's review_result. Also infers sinks from preconditions
    with check_type="function_reaches_sink".

    Returns the number of new discoveries.
    """
    review = getattr(outcome, "review_result", None)
    if not review or not isinstance(review, dict):
        return 0

    source = f"{gap.get('file', '')}:{gap.get('name', '')}"
    added = 0

    for callee in review.get("dangerous_callees") or []:
        if isinstance(callee, str) and callee.strip():
            if live.add_sink(callee.strip(), discovered_by=source):
                added += 1

    for callee in review.get("sanitizer_callees") or []:
        if isinstance(callee, str) and callee.strip():
            if live.add_sanitizer(callee.strip(), discovered_by=source):
                added += 1

    for pc in review.get("preconditions") or []:
        if not isinstance(pc, dict):
            continue
        if pc.get("check_type") == "function_reaches_sink":
            loc = pc.get("location", {})
            if isinstance(loc, dict):
                fn = loc.get("function", "")
                if fn and fn != gap.get("name", ""):
                    if live.add_sink(fn, discovered_by=source):
                        added += 1

    hypothesis = review.get("hypothesis", "")
    if hypothesis and getattr(outcome, "status", "") in ("finding", "suspicious"):
        _extract_sinks_from_hypothesis(hypothesis, source, live)

    return added


_DANGEROUS_VERBS = frozenset({
    "executes", "spawns", "invokes", "runs", "calls",
    "writes to", "deletes", "removes", "opens",
})


def _extract_sinks_from_hypothesis(
    hypothesis: str,
    source: str,
    live: LiveClassifications,
) -> None:
    """Best-effort extraction of dangerous callees from hypothesis text.

    Only fires on high-signal patterns like "passes unsanitized input to
    custom_exec()" — we don't want false positives inflating the live set.
    """
    import re
    pattern = re.compile(
        r"(?:passes|sends|forwards|pipes)\s+(?:unsanitized|unvalidated|"
        r"attacker.controlled|user.controlled|tainted)\s+\w+\s+to\s+"
        r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(",
    )
    for match in pattern.finditer(hypothesis):
        callee = match.group(1)
        live.add_sink(callee, discovered_by=f"{source} (hypothesis)")


def expand_wrapper_sinks(
    live: LiveClassifications,
    call_edges: list[dict],
    *,
    min_callers: int = 2,
) -> int:
    """Find functions that wrap live-discovered sinks and mark them as sinks too.

    A wrapper is a function that calls a live sink and is itself called by
    at least *min_callers* distinct callers. This extends the live sink set
    to second-order sinks the initial heuristic pass couldn't see.

    Returns the number of new wrapper sinks added.
    """
    if not live.sinks or not call_edges:
        return 0

    callers_of: dict[str, set[str]] = {}
    callees_of: dict[str, set[str]] = {}
    for edge in call_edges:
        caller_key = f"{edge.get('caller_file', '')}:{edge.get('caller', '')}"
        callee_name = edge.get("callee", "")
        if not callee_name:
            continue
        callees_of.setdefault(caller_key, set()).add(callee_name)
        callers_of.setdefault(callee_name, set()).add(caller_key)

    added = 0
    for func_key, callees in callees_of.items():
        calls_live_sink = callees & live.sinks
        if not calls_live_sink:
            continue
        func_name = func_key.split(":", 1)[1] if ":" in func_key else func_key
        if func_name in live.sinks:
            continue
        caller_count = len(callers_of.get(func_name, set()))
        if caller_count < min_callers:
            continue
        if live.add_sink(func_name, discovered_by=f"wrapper({next(iter(calls_live_sink))})"):
            added += 1

    if added:
        logger.info("wrapper expansion: %d second-order sinks from live discoveries", added)
    return added


def find_sanitizer_re_review_targets(
    live: LiveClassifications,
    outcomes: list,
) -> list[tuple[object, str]]:
    """Find finding/suspicious outcomes whose callee is a live sanitizer.

    If the LLM flagged a function as finding/suspicious because it passes
    input to a sink unsanitized, but we later discovered one of its callees
    is actually a sanitizer, the original review missed that context.

    Returns (outcome, reason) pairs for re-review.
    """
    if not live.sanitizers:
        return []

    targets = []
    for outcome in outcomes:
        if getattr(outcome, "status", "") not in ("finding", "suspicious"):
            continue
        review = getattr(outcome, "review_result", None)
        if not review or not isinstance(review, dict):
            continue
        callees = set()
        for pc in review.get("preconditions") or []:
            if isinstance(pc, dict):
                loc = pc.get("location", {})
                if isinstance(loc, dict) and loc.get("function"):
                    callees.add(loc["function"])
        body = getattr(outcome, "body", "") or ""
        for san in live.sanitizers:
            if san in callees or re.search(r'(?:^|_|\b)' + re.escape(san) + r'(?:$|_|\b)', body):
                targets.append((
                    outcome,
                    f"callee {san} is a live-discovered sanitizer",
                ))
                break

    return targets


def load_from_project_context(
    project_learnings: list[dict] | None,
    checklist: dict | None = None,
) -> LiveClassifications:
    """Seed live classifications from prior-run project learnings.

    When *checklist* is provided, only load sinks/sanitizers whose name
    appears as a function in the current target's inventory.  This
    prevents prior-run classifications from unrelated targets leaking
    into the current run when the project-context file is shared.
    """
    live = LiveClassifications()
    if not project_learnings:
        return live

    inventory_names: set[str] | None = None
    if checklist:
        inventory_names = set()
        for fentry in checklist.get("files", []):
            for item in fentry.get("items", fentry.get("functions", [])):
                name = item.get("name", "")
                if name:
                    inventory_names.add(name)

    for learning in project_learnings:
        cat = learning.get("category", "")
        text = learning.get("text", "")
        if not text:
            continue
        if inventory_names is not None and text not in inventory_names:
            continue
        if cat == "sink":
            live.add_sink(text, discovered_by="project_context")
        elif cat == "sanitizer":
            live.add_sanitizer(text, discovered_by="project_context")
        elif cat == "entry_point":
            live.add_entry_point(text)

    if live.sinks or live.sanitizers:
        logger.info(
            "loaded prior-run classifications: %s", live.stats(),
        )
    return live
