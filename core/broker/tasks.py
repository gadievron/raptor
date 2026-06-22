"""Task routing and remote execution.

A *task* is a unit of work — a RAPTOR mode invocation against a target —
that can be routed to the fleet member best suited to run it.  The
router scores every capable system (see ``scoring.py``), picks the
winner, and the executor handles the upload → run → collect lifecycle.

Typical flow::

    router = TaskRouter(inventory)
    assignment = router.route(TaskSpec(mode="fuzz", target_path="/src"))
    # → picks the 32-core Linux box over the 4-core MacBook

    executor = TaskExecutor()
    result = executor.execute(assignment)
    # → uploads /src, runs fuzz remotely, downloads results
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, replace
from enum import Enum
from typing import Optional, Sequence

from core.broker.broker import _build_transport
from core.broker.capabilities import (
    MODE_REQUIREMENTS,
    ModeRequirements,
    SystemCapabilities,
)
from core.broker.inventory import Inventory
from core.broker.scoring import ScoredSystem, rank_fleet
from core.broker.transport import (
    CommandResult,
    RemoteSystemEntry,
    Transport,
    TransportError,
)

logger = logging.getLogger(__name__)


class TaskState(Enum):
    PENDING = "pending"
    ROUTED = "routed"
    UPLOADING = "uploading"
    RUNNING = "running"
    COLLECTING = "collecting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class TaskSpec:
    """What work needs doing."""
    mode: str
    target_path: str
    args: tuple[str, ...] = ()
    labels: frozenset[str] = frozenset()
    prefer_alias: Optional[str] = None
    timeout: int = 3600

    @property
    def is_url_target(self) -> bool:
        return self.target_path.startswith(("http://", "https://"))


@dataclass(frozen=True)
class TaskAssignment:
    """Routing decision — which system runs this task and why."""
    task_id: str
    spec: TaskSpec
    system: ScoredSystem
    alternatives: tuple[ScoredSystem, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class TaskResult:
    """Outcome of a remote task execution."""
    task_id: str
    state: TaskState
    system_alias: str
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    output_dir: Optional[str] = None
    error: Optional[str] = None
    duration_secs: Optional[float] = None


def _generate_task_id(spec: TaskSpec) -> str:
    """Short deterministic-ish task ID from spec + timestamp."""
    raw = f"{spec.mode}:{spec.target_path}:{time.time()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class TaskRouter:
    """Pick the best fleet member for a task."""

    def __init__(self, inventory: Inventory) -> None:
        self._inventory = inventory

    def route(self, spec: TaskSpec) -> TaskAssignment:
        """Score the fleet and assign the task to the best system.

        Raises ``TaskRoutingError`` if no system qualifies.
        """
        fleet = self._inventory.list_all_with_capabilities()
        if not fleet:
            raise TaskRoutingError(
                f"no systems registered — add one with 'raptor broker add'"
            )

        ranked = rank_fleet(
            fleet,
            spec.mode,
            require_capable=True,
            labels=spec.labels,
        )

        if not ranked:
            raise TaskRoutingError(
                f"no fleet member can run mode '{spec.mode}' — "
                f"register a capable system or provision an existing one"
            )

        if spec.prefer_alias:
            preferred = [s for s in ranked if s.entry.alias == spec.prefer_alias]
            if preferred:
                winner = preferred[0]
                others = tuple(s for s in ranked if s is not winner)
                reason = f"operator preference ({spec.prefer_alias}), score {winner.score}"
            else:
                winner = ranked[0]
                others = tuple(ranked[1:])
                reason = (
                    f"preferred system '{spec.prefer_alias}' not capable; "
                    f"best: {winner.entry.alias} (score {winner.score})"
                )
        else:
            winner = ranked[0]
            others = tuple(ranked[1:])
            reason = f"best score for {spec.mode}: {winner.score}"

        task_id = _generate_task_id(spec)

        logger.info(
            "task %s routed to %s (score %.1f, %d alternatives)",
            task_id, winner.entry.alias, winner.score, len(others),
        )

        return TaskAssignment(
            task_id=task_id,
            spec=spec,
            system=winner,
            alternatives=others,
            reason=reason,
        )


class TaskExecutor:
    """Execute a routed task on the assigned remote system.

    Lifecycle: connect → create workspace → upload target →
    run command → download results → clean up → disconnect.
    """

    _WORKSPACE_PREFIX = "/tmp/raptor-task-"

    def execute(self, assignment: TaskAssignment) -> TaskResult:
        """Run the assigned task end-to-end.  Returns a TaskResult."""
        task_id = assignment.task_id
        spec = assignment.spec
        entry = assignment.system.entry
        workspace = f"{self._WORKSPACE_PREFIX}{task_id}"

        transport = _build_transport(entry)
        t0 = time.time()

        try:
            transport.connect()

            transport.mkdir(workspace)
            target_dir = f"{workspace}/target"
            output_dir = f"{workspace}/output"
            transport.mkdir(output_dir)

            if not spec.is_url_target:
                logger.info("[%s] uploading target to %s", task_id, entry.alias)
                transport.upload(spec.target_path, target_dir)
                remote_target = target_dir
            else:
                remote_target = spec.target_path

            cmd = self._build_command(spec, remote_target, output_dir)
            logger.info("[%s] running on %s: %s", task_id, entry.alias, cmd)

            result = transport.run(cmd, timeout=spec.timeout, cwd=workspace)

            local_output = self._collect_results(
                transport, output_dir, task_id
            )

            duration = round(time.time() - t0, 1)

            if result.ok:
                logger.info(
                    "[%s] completed on %s in %.1fs",
                    task_id, entry.alias, duration,
                )
                return TaskResult(
                    task_id=task_id,
                    state=TaskState.COMPLETED,
                    system_alias=entry.alias,
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    output_dir=local_output,
                    duration_secs=duration,
                )

            return TaskResult(
                task_id=task_id,
                state=TaskState.FAILED,
                system_alias=entry.alias,
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
                error=f"command exited {result.exit_code}",
                duration_secs=duration,
            )

        except TransportError as exc:
            duration = round(time.time() - t0, 1)
            logger.error("[%s] transport error: %s", task_id, exc)
            return TaskResult(
                task_id=task_id,
                state=TaskState.FAILED,
                system_alias=entry.alias,
                error=str(exc),
                duration_secs=duration,
            )
        finally:
            try:
                transport.run(f"rm -rf {workspace}", timeout=30)
            except Exception:
                pass
            try:
                transport.disconnect()
            except Exception:
                pass

    def _build_command(
        self,
        spec: TaskSpec,
        remote_target: str,
        output_dir: str,
    ) -> str:
        """Build the shell command to run on the remote."""
        parts = [spec.mode, remote_target]
        parts.extend(spec.args)
        parts.extend(["--output", output_dir])
        args_str = " ".join(parts)
        return f"raptor {args_str}"

    def _collect_results(
        self,
        transport: Transport,
        remote_output: str,
        task_id: str,
    ) -> Optional[str]:
        """Download remote output to local storage."""
        if not transport.path_exists(remote_output):
            return None

        local_dir = os.path.join("out", "tasks", task_id)
        os.makedirs(local_dir, exist_ok=True)

        try:
            transport.download(remote_output, local_dir)
            logger.info("[%s] results downloaded to %s", task_id, local_dir)
            return local_dir
        except TransportError as exc:
            logger.warning("[%s] result download failed: %s", task_id, exc)
            return None


class TaskRoutingError(Exception):
    """No system in the fleet can handle the requested task."""
