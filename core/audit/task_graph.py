"""Task graph for parallel /audit review scheduling.

Wraps the workqueue with dependency tracking derived from the call graph.
A function task becomes *ready* when all its callee tasks (that are in the
workqueue) have completed.  This guarantees taint summaries are available
before callers start.

When ``max_workers=1``, ``pop_ready(1)`` returns tasks in the same
topological order as the current serial loop.
"""

from __future__ import annotations

import heapq
import logging
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_UNBLOCKING_WEIGHT = 0.2


@dataclass(frozen=True)
class ReviewTask:
    key: str
    gap: dict[str, Any]
    depends_on: frozenset[str]
    priority: float


def _break_cycles(
    caller_to_callees: dict[str, set[str]],
    scores: dict[str, float],
) -> set[tuple[str, str]]:
    """Find intra-SCC back-edges to drop, keeping a spanning tree per SCC.

    Within each SCC a DFS spanning tree is built rooted at the
    lowest-priority member (so higher-priority functions retain their
    callee summaries).  Only the back-edges — those that close cycles —
    are returned for removal.
    """
    from .topo_order import detect_sccs

    adj_lists: dict[str, list[str]] = {}
    for caller, callees in caller_to_callees.items():
        adj_lists.setdefault(caller, []).extend(callees)

    sccs = detect_sccs(adj_lists)
    edges_to_drop: set[tuple[str, str]] = set()

    for scc in sccs:
        if not scc.is_cycle:
            continue
        members = scc.members
        root = min(members, key=lambda k: scores.get(k, 0.0))
        tree_edges: set[tuple[str, str]] = set()
        visited: set[str] = set()

        stack = [root]
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            for callee in caller_to_callees.get(node, set()):
                if callee in members and callee not in visited:
                    tree_edges.add((node, callee))
                    stack.append(callee)

        scc_dropped: set[tuple[str, str]] = set()
        for caller in members:
            for callee in caller_to_callees.get(caller, set()):
                if callee in members and (caller, callee) not in tree_edges:
                    scc_dropped.add((caller, callee))
        edges_to_drop |= scc_dropped

        if scc_dropped:
            logger.info(
                "cycle break: %d-member SCC rooted at %s, "
                "keeping %d tree edges, dropping %d back-edges",
                len(members),
                root.rsplit(":", 1)[-1],
                len(tree_edges),
                len(scc_dropped),
            )

    return edges_to_drop


def _relax_bottlenecks(
    caller_to_callees: dict[str, set[str]],
    scores: dict[str, float],
    max_workers: int,
    *,
    max_repass: int = 0,
) -> set[tuple[str, str]]:
    """Relax edges from bottleneck callees to widen the dependency wavefront.

    A callee is a bottleneck only if it has more dependents than
    *max_workers* AND has its own dependencies (leaf nodes resolve in
    the first wave and don't cause narrowing).  For qualifying nodes,
    the *max_workers* highest-priority callers keep the dependency;
    the rest proceed without waiting and get repassed later.

    *max_repass* caps the total number of relaxed edges.  When 0
    (the default), no cap is applied; the production caller passes
    ``max(total_tasks // 20, max_workers)`` to keep relaxation at
    roughly 5%.
    """
    callee_to_callers: dict[str, set[str]] = {}
    for caller, callees in caller_to_callees.items():
        for callee in callees:
            callee_to_callers.setdefault(callee, set()).add(caller)

    candidates: list[tuple[int, str, set[str]]] = []
    for callee, callers in callee_to_callers.items():
        if len(callers) <= max_workers:
            continue
        if callee not in caller_to_callees:
            continue
        candidates.append((len(callers), callee, callers))
    candidates.sort(reverse=True)

    budget = max_repass
    edges_to_drop: set[tuple[str, str]] = set()
    bottleneck_count = 0
    for _dep_count, callee, callers in candidates:
        ranked = sorted(callers, key=lambda c: scores.get(c, 0.0), reverse=True)
        relaxable = ranked[max_workers:]
        if budget > 0 and len(edges_to_drop) + len(relaxable) > budget:
            relaxable = relaxable[:max(0, budget - len(edges_to_drop))]
        if not relaxable:
            break
        for caller in relaxable:
            edges_to_drop.add((caller, callee))
        bottleneck_count += 1

    if bottleneck_count:
        logger.info(
            "bottleneck relax: %d non-leaf nodes with >%d dependents, "
            "relaxing %d edges (callers repassed later)",
            bottleneck_count, max_workers, len(edges_to_drop),
        )

    return edges_to_drop


@dataclass(frozen=True)
class GraphStats:
    """Construction-time statistics for the task graph."""

    total_tasks: int = 0
    total_edges: int = 0
    cycle_back_edges_dropped: int = 0
    bottleneck_edges_dropped: int = 0
    repass_tasks: int = 0
    initial_ready: int = 0
    max_fan_out: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total_tasks": self.total_tasks,
            "total_edges": self.total_edges,
            "cycle_back_edges_dropped": self.cycle_back_edges_dropped,
            "bottleneck_edges_dropped": self.bottleneck_edges_dropped,
            "repass_tasks": self.repass_tasks,
            "initial_ready": self.initial_ready,
            "max_fan_out": self.max_fan_out,
        }


@dataclass
class TaskGraph:
    """DAG of review tasks with ready-set tracking.

    Ready-set ordering (``schedule``):

    * ``"priority"`` (default) — highest effective priority first
      (base score + unblocking bonus). Optimises time-to-first-finding
      and is the only sensible order for a serial run.
    * ``"cost"`` — longest-predicted-duration first within the ready
      set (LPT packing), effective priority as the tie-break. With
      multiple workers, dispatching the expensive reviews early
      shrinks the makespan: a 300s review started last idles three
      workers at the tail. Duration predictions come from
      ``duration_hints`` (the orchestrator derives them from triage
      token budgets + SLOC); tasks without a hint sort last.
      Chain-injected tasks (``inject_task``) stay urgent — a
      confirmed finding's neighbours are the most valuable next
      reviews under either objective.
    """

    _tasks: dict[str, ReviewTask] = field(default_factory=dict)
    _remaining_deps: dict[str, set[str]] = field(default_factory=dict)
    _dependents: dict[str, list[str]] = field(default_factory=dict)
    _ready: list[tuple[float, float, str]] = field(default_factory=list)
    _completed: set[str] = field(default_factory=set)
    _repass_keys: frozenset[str] = field(default_factory=frozenset)
    _effective_priority: dict[str, float] = field(default_factory=dict)
    _requeued: set[str] = field(default_factory=set)
    # Keys handed out by ``pop_ready`` and not yet completed. The ready
    # heap can hold duplicate entries for one key (reprioritising
    # ``inject_task`` pushes again); without this set two ``pop_ready``
    # calls could hand the same task to two parallel workers.
    _issued: set[str] = field(default_factory=set)
    _duration_hints: dict[str, float] = field(default_factory=dict)
    _schedule: str = "priority"
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    stats: GraphStats = field(default_factory=GraphStats)

    def _push_ready(
        self, key: str, priority_value: float, *, urgent: bool = False,
    ) -> None:
        """Push *key* onto the ready heap under the active schedule.

        Heap entries are ``(-primary, -secondary, key)``. In priority
        mode ``primary`` is a constant 0 so ordering degenerates to
        the classic priority ordering; in cost mode ``primary`` is
        the duration hint (urgent pushes jump the queue entirely).
        """
        if self._schedule == "cost":
            primary = (
                float("inf") if urgent
                else self._duration_hints.get(key, 0.0)
            )
        else:
            primary = 0.0
        heapq.heappush(self._ready, (-primary, -priority_value, key))

    @classmethod
    def from_workqueue(
        cls,
        workqueue: list[dict[str, Any]],
        call_edges: list[dict[str, Any]],
        *,
        priority_scores: dict[str, float] | None = None,
        max_workers: int = 1,
        duration_hints: dict[str, float] | None = None,
        schedule: str = "priority",
    ) -> TaskGraph:
        scores = priority_scores or {}
        if schedule not in ("priority", "cost"):
            logger.warning(
                "task graph: unknown schedule %r — using 'priority'",
                schedule,
            )
            schedule = "priority"

        wq_keys: set[str] = set()
        gaps_by_key: dict[str, dict[str, Any]] = {}
        bare_to_lined: dict[str, set[str]] = {}
        for gap in workqueue:
            key = f"{gap['file']}:{gap['name']}:{gap.get('line_start', 0)}"
            bare = f"{gap['file']}:{gap['name']}"
            wq_keys.add(key)
            gaps_by_key[key] = gap
            bare_to_lined.setdefault(bare, set()).add(key)

        caller_to_callees: dict[str, set[str]] = {}
        for edge in call_edges:
            caller_bare = f"{edge.get('caller_file', '')}:{edge.get('caller', '')}"
            callee_file = edge.get("callee_file") or edge.get("caller_file", "")
            callee_bare = f"{callee_file}:{edge.get('callee', '')}"
            if caller_bare == callee_bare:
                continue
            for caller_key in bare_to_lined.get(caller_bare, ()):
                for callee_key in bare_to_lined.get(callee_bare, ()):
                    caller_to_callees.setdefault(caller_key, set()).add(callee_key)

        repass_callers: set[str] = set()
        total_edges = sum(len(v) for v in caller_to_callees.values())

        dropped = _break_cycles(caller_to_callees, scores)
        n_cycle_edges = len(dropped)
        if dropped:
            for caller, callee in dropped:
                repass_callers.add(caller)
                s = caller_to_callees.get(caller)
                if s:
                    s.discard(callee)

        n_bottleneck_edges = 0
        if max_workers > 1:
            repass_cap = max(len(gaps_by_key) // 20, max_workers)
            relaxed = _relax_bottlenecks(
                caller_to_callees, scores, max_workers,
                max_repass=repass_cap,
            )
            n_bottleneck_edges = len(relaxed)
            if relaxed:
                for caller, callee in relaxed:
                    repass_callers.add(caller)
                    s = caller_to_callees.get(caller)
                    if s:
                        s.discard(callee)

        graph = cls()
        graph._schedule = schedule
        graph._duration_hints = dict(duration_hints or {})

        for key, gap in gaps_by_key.items():
            deps = frozenset(caller_to_callees.get(key, set()))
            task = ReviewTask(
                key=key,
                gap=gap,
                depends_on=deps,
                priority=scores.get(key, gap.get("priority_score", 0.0)),
            )
            graph._tasks[key] = task
            graph._remaining_deps[key] = set(deps)
            for dep in deps:
                graph._dependents.setdefault(dep, []).append(key)

        # Compute effective priority: base + unblocking bonus.
        max_dep_count = max(
            (len(v) for v in graph._dependents.values()), default=1
        ) or 1
        for key, task in graph._tasks.items():
            dep_count = len(graph._dependents.get(key, []))
            bonus = (dep_count / max_dep_count) * _UNBLOCKING_WEIGHT
            graph._effective_priority[key] = task.priority + bonus

        for key, remaining in graph._remaining_deps.items():
            if not remaining:
                graph._push_ready(key, graph._effective_priority[key])

        graph._repass_keys = frozenset(
            k for k in repass_callers if k in graph._tasks
        )

        graph.stats = GraphStats(
            total_tasks=len(graph._tasks),
            total_edges=total_edges,
            cycle_back_edges_dropped=n_cycle_edges,
            bottleneck_edges_dropped=n_bottleneck_edges,
            repass_tasks=len(graph._repass_keys),
            initial_ready=len(graph._ready),
            max_fan_out=max(
                (len(v) for v in graph._dependents.values()), default=0,
            ),
        )

        return graph

    def pop_ready(self, n: int = 1) -> list[ReviewTask]:
        """Pop up to *n* ready tasks in schedule order.

        Duplicate heap entries for one key (an ``inject_task``
        reprioritisation pushes a second entry) collapse here: a key
        already issued to a worker — or already completed — is
        skipped, so parallel workers never double-dispatch a task.
        """
        with self._lock:
            result: list[ReviewTask] = []
            while self._ready and len(result) < n:
                *_, key = heapq.heappop(self._ready)
                if key in self._completed or key in self._issued:
                    continue
                self._issued.add(key)
                result.append(self._tasks[key])
            return result

    def mark_complete(self, key: str) -> list[str]:
        """Mark *key* done. Returns keys of newly-ready tasks."""
        with self._lock:
            self._completed.add(key)
            self._issued.discard(key)
            newly_ready: list[str] = []
            for dep_key in self._dependents.get(key, []):
                remaining = self._remaining_deps.get(dep_key)
                if remaining is not None:
                    remaining.discard(key)
                    if (
                        not remaining
                        and dep_key not in self._completed
                        and dep_key not in self._issued
                    ):
                        ep = self._effective_priority.get(
                            dep_key, self._tasks[dep_key].priority,
                        )
                        self._push_ready(dep_key, ep)
                        newly_ready.append(dep_key)
            return newly_ready

    @property
    def pending(self) -> int:
        return len(self._tasks) - len(self._completed)

    def has_dependents(self, key: str) -> bool:
        """True when other tasks depend on *key*'s taint summary."""
        return bool(self._dependents.get(key))

    def repass_tasks(self) -> list[ReviewTask]:
        """Callers whose dependency edges were relaxed (cycle-breaking or
        bottleneck relaxation) — re-review with full callee context."""
        tasks = [self._tasks[k] for k in self._repass_keys]
        tasks.sort(key=lambda t: t.priority, reverse=True)
        return tasks

    def inject_task(
        self,
        key: str,
        gap: dict[str, Any],
        priority: float,
        *,
        requeue: bool = False,
    ) -> bool:
        """Inject a new task or reprioritise an existing one.

        Used for mid-loop chain following: when a finding is confirmed,
        its callers/callees are injected at elevated priority so the
        executor reviews them next rather than waiting for a post-loop
        pass.

        When *requeue* is True, a completed task is moved back to the
        ready queue for re-review with chain context.  Each task can be
        requeued at most once to prevent infinite cascades.

        Returns True if the task was injected or reprioritised, False if
        already completed and not eligible for requeue.
        """
        with self._lock:
            return self._inject_task_locked(key, gap, priority, requeue=requeue)

    def _inject_task_locked(
        self,
        key: str,
        gap: dict[str, Any],
        priority: float,
        *,
        requeue: bool = False,
    ) -> bool:
        if key in self._completed:
            if not requeue or key in self._requeued:
                return False
            self._completed.discard(key)
            self._issued.discard(key)
            self._requeued.add(key)
            old_task = self._tasks[key]
            self._tasks[key] = ReviewTask(
                key=key, gap=gap, depends_on=old_task.depends_on,
                priority=priority,
            )
            self._effective_priority[key] = priority
            self._push_ready(key, priority, urgent=True)
            logger.debug(
                "inject_task: requeued %s at priority %.1f",
                key.rsplit(":", 1)[0], priority,
            )
            return True
        if key in self._tasks:
            existing_gap = self._tasks[key].gap
            if gap.get("force_review"):
                existing_gap["force_review"] = True
            old_ep = self._effective_priority.get(key, 0.0)
            if priority > old_ep:
                self._effective_priority[key] = priority
                # Only push tasks whose dependencies are satisfied and
                # that no worker holds: an urgent push of a task with
                # unfinished callees dispatched it before its taint
                # summaries existed, and a push of an in-flight task
                # double-dispatched it. Elevating the effective
                # priority alone is enough — ``mark_complete`` pushes
                # with the elevated value once the deps drain.
                if (
                    not self._remaining_deps.get(key)
                    and key not in self._issued
                ):
                    self._push_ready(key, priority, urgent=True)
                logger.debug(
                    "inject_task: reprioritised %s (%.1f -> %.1f)",
                    key.rsplit(":", 1)[0], old_ep, priority,
                )
            return True
        task = ReviewTask(
            key=key, gap=gap, depends_on=frozenset(), priority=priority,
        )
        self._tasks[key] = task
        self._remaining_deps[key] = set()
        self._effective_priority[key] = priority
        self._push_ready(key, priority, urgent=True)
        logger.debug(
            "inject_task: added %s at priority %.1f",
            key.rsplit(":", 1)[0], priority,
        )
        return True

    @property
    def injected_count(self) -> int:
        """Tasks added after initial construction."""
        return len(self._tasks) - self.stats.total_tasks

    def __len__(self) -> int:
        return len(self._tasks)

    def serial_order(self) -> list[ReviewTask]:
        """Return all tasks in topological (priority-weighted) order.

        Useful for serial execution: identical to the current behaviour
        when ``max_workers=1``.
        """
        order: list[ReviewTask] = []
        remaining = {k: set(v) for k, v in self._remaining_deps.items()}
        ready: list[tuple[float, str]] = []
        for key, deps in remaining.items():
            if not deps:
                ep = self._effective_priority.get(key, self._tasks[key].priority)
                heapq.heappush(ready, (-ep, key))

        visited: set[str] = set()
        while ready:
            _, key = heapq.heappop(ready)
            if key in visited:
                continue
            visited.add(key)
            order.append(self._tasks[key])
            for dep_key in self._dependents.get(key, []):
                rem = remaining.get(dep_key)
                if rem is not None:
                    rem.discard(key)
                    if not rem and dep_key not in visited:
                        ep = self._effective_priority.get(
                            dep_key, self._tasks[dep_key].priority,
                        )
                        heapq.heappush(ready, (-ep, dep_key))

        return order
