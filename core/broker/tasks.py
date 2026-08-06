"""Task routing and remote execution.

A *task* is a unit of work — a RAPTOR mode invocation against a target —
that can be routed to the fleet member best suited to run it.  The
router scores every capable system (see ``scoring.py``), picks the
winner, and the executor handles the upload → run → collect lifecycle.

Two execution modes:

    **Blocking** (default for short tasks like ``scan``)::

        result = executor.execute(assignment)
        # blocks until complete, then returns TaskResult

    **Detached** (for long-running tasks like ``fuzz``)::

        handle = executor.launch(assignment)
        # starts in tmux/screen, returns immediately

        state = executor.poll(handle)
        # reconnects to check status

        result = executor.collect(handle)
        # downloads results after completion
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Sequence

if TYPE_CHECKING:
    from core.broker.engage import EngagementPlan

from core.broker.broker import _build_transport
from core.broker.capabilities import (
    MODE_REQUIREMENTS,
    ModeRequirements,
    OperatingSystem,
    SystemCapabilities,
)
from core.broker.inventory import Inventory
from core.broker.scoring import ScoredSystem, TaskConstraints, rank_fleet
from core.broker.sessions import (
    RemoteTaskState,
    SessionBackend,
    cleanup_workspace,
    detect_session_backend,
    kill_session,
    poll,
    start_detached,
)
from core.broker.transport import (
    CommandResult,
    RemoteSystemEntry,
    Transport,
    TransportError,
)

logger = logging.getLogger(__name__)

_TASK_STATE_DIR = Path.home() / ".raptor" / "broker" / "tasks"


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
    detach: bool = False
    constraints: Optional[TaskConstraints] = None

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


@dataclass(frozen=True)
class TaskHandle:
    """Reconnection handle for a detached task."""
    task_id: str
    system_alias: str
    workspace: str
    backend: str
    started_at: float
    spec_mode: str
    spec_target: str


def _generate_task_id(spec: TaskSpec) -> str:
    """Short deterministic-ish task ID from spec + timestamp."""
    raw = f"{spec.mode}:{spec.target_path}:{time.time()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _output_base() -> Path:
    """Resolve output base directory from RAPTOR env or cwd."""
    raptor_dir = os.environ.get("RAPTOR_DIR")
    if raptor_dir:
        return Path(raptor_dir) / "out" / "tasks"
    return Path.cwd() / "out" / "tasks"


def _save_task_handle(handle: TaskHandle) -> None:
    """Persist handle so the operator can reconnect from a new session."""
    _TASK_STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = _TASK_STATE_DIR / f"{handle.task_id}.json"
    data = {
        "task_id": handle.task_id,
        "system_alias": handle.system_alias,
        "workspace": handle.workspace,
        "backend": handle.backend,
        "started_at": handle.started_at,
        "spec_mode": handle.spec_mode,
        "spec_target": handle.spec_target,
    }
    path.write_text(json.dumps(data, indent=2) + "\n")


def _load_task_handle(task_id: str) -> Optional[TaskHandle]:
    """Load a persisted handle."""
    path = _TASK_STATE_DIR / f"{task_id}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            return None
        return TaskHandle(
            task_id=str(data["task_id"]),
            system_alias=str(data["system_alias"]),
            workspace=str(data["workspace"]),
            backend=str(data["backend"]),
            started_at=float(data["started_at"]),
            spec_mode=str(data["spec_mode"]),
            spec_target=str(data["spec_target"]),
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        logger.warning("failed to load task handle %s: %s", task_id, exc)
        return None


def _remove_task_handle(task_id: str) -> None:
    path = _TASK_STATE_DIR / f"{task_id}.json"
    path.unlink(missing_ok=True)


def list_active_tasks() -> list[TaskHandle]:
    """List all persisted task handles (may include completed ones)."""
    if not _TASK_STATE_DIR.exists():
        return []
    handles = []
    for p in sorted(_TASK_STATE_DIR.glob("*.json")):
        try:
            handles.append(_load_task_handle(p.stem))
        except Exception:
            continue
    return [h for h in handles if h is not None]


class TaskRouter:
    """Pick the best fleet member for a task.

    If an active engagement plan exists (see ``engage.py``), the
    router honours it: the plan's assigned system for the mode is
    used unless the operator overrides with ``prefer_alias``.
    Excluded systems are never routed to.
    """

    def __init__(
        self,
        inventory: Inventory,
        engagement: Optional["EngagementPlan"] = None,
    ) -> None:
        self._inventory = inventory
        self._engagement = engagement

    def route(self, spec: TaskSpec) -> TaskAssignment:
        """Score the fleet and assign the task to the best system.

        Raises ``TaskRoutingError`` if no system qualifies.
        """
        fleet = self._inventory.list_all_with_capabilities()
        if not fleet:
            raise TaskRoutingError(
                "no systems registered — add one with 'raptor broker add'"
            )

        if self._engagement:
            fleet = [
                (e, c) for e, c in fleet
                if not self._engagement.is_excluded(e.alias)
            ]

        ranked = rank_fleet(
            fleet,
            spec.mode,
            require_capable=True,
            labels=spec.labels,
            constraints=spec.constraints,
        )

        if not ranked:
            raise TaskRoutingError(
                f"no fleet member can run mode '{spec.mode}' — "
                f"register a capable system or provision an existing one"
            )

        effective_prefer = spec.prefer_alias

        if not effective_prefer and self._engagement:
            plan_alias = self._engagement.system_for_mode(spec.mode)
            if plan_alias:
                effective_prefer = plan_alias

        if effective_prefer:
            preferred = [s for s in ranked if s.entry.alias == effective_prefer]
            if preferred:
                winner = preferred[0]
                others = tuple(s for s in ranked if s is not winner)
                if spec.prefer_alias:
                    reason = f"operator override ({effective_prefer}), score {winner.score}"
                elif self._engagement:
                    reason = f"engagement plan ({effective_prefer}), score {winner.score}"
                else:
                    reason = f"operator preference ({effective_prefer}), score {winner.score}"
            else:
                winner = ranked[0]
                others = tuple(ranked[1:])
                reason = (
                    f"preferred system '{effective_prefer}' not capable; "
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

    Supports both blocking execution (short tasks) and detached
    execution via tmux/screen (long-running tasks like fuzzing).
    """

    _UNIX_WORKSPACE = "/tmp/raptor-task-"
    _WIN_WORKSPACE = "C:\\temp\\raptor-task-"

    @staticmethod
    def _workspace_path(task_id: str, is_windows: bool, is_android: bool = False) -> str:
        if is_windows:
            return f"C:\\temp\\raptor-task-{task_id}"
        if is_android:
            return f"/data/local/tmp/raptor-task-{task_id}"
        return f"/tmp/raptor-task-{task_id}"

    @staticmethod
    def _join(base: str, child: str, is_windows: bool) -> str:
        if is_windows:
            return f"{base}\\{child}"
        return f"{base}/{child}"

    def execute(self, assignment: TaskAssignment) -> TaskResult:
        """Run the assigned task end-to-end (blocking).

        For long-running tasks, use ``launch()`` + ``poll()`` +
        ``collect()`` instead.
        """
        task_id = assignment.task_id
        spec = assignment.spec
        entry = assignment.system.entry
        is_windows = assignment.system.capabilities.os == OperatingSystem.WINDOWS
        workspace = self._workspace_path(task_id, is_windows)

        transport = _build_transport(entry)
        t0 = time.time()

        try:
            transport.connect()
            self._setup_workspace(transport, workspace, spec, task_id, is_windows)
            target_dir = self._join(workspace, "target", is_windows)
            output_dir = self._join(workspace, "output", is_windows)
            remote_target = target_dir if not spec.is_url_target else spec.target_path

            cmd = self._build_command(spec, remote_target, output_dir, is_windows)
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
                cleanup_workspace(transport, workspace, is_windows=is_windows)
            except Exception:
                pass
            try:
                transport.disconnect()
            except Exception:
                pass

    def launch(self, assignment: TaskAssignment) -> TaskHandle:
        """Start a task in a detached tmux/screen/PowerShell session.

        Returns a TaskHandle for later ``poll()`` and ``collect()``.
        The remote process survives SSH/WinRM disconnects.
        """
        task_id = assignment.task_id
        spec = assignment.spec
        entry = assignment.system.entry
        remote_os = assignment.system.capabilities.os
        is_windows = remote_os == OperatingSystem.WINDOWS
        workspace = self._workspace_path(task_id, is_windows)

        transport = _build_transport(entry)

        try:
            transport.connect()

            backend = detect_session_backend(transport, remote_os)
            self._setup_workspace(transport, workspace, spec, task_id, is_windows)

            target_dir = self._join(workspace, "target", is_windows)
            output_dir = self._join(workspace, "output", is_windows)
            remote_target = target_dir if not spec.is_url_target else spec.target_path

            cmd = self._build_command(spec, remote_target, output_dir, is_windows)
            start_detached(transport, task_id, cmd, workspace, backend)

            handle = TaskHandle(
                task_id=task_id,
                system_alias=entry.alias,
                workspace=workspace,
                backend=backend.value,
                started_at=time.time(),
                spec_mode=spec.mode,
                spec_target=spec.target_path,
            )
            _save_task_handle(handle)

            logger.info(
                "[%s] launched detached on %s (%s)",
                task_id, entry.alias, backend.value,
            )
            return handle

        finally:
            try:
                transport.disconnect()
            except Exception:
                pass

    def poll_task(
        self,
        handle: TaskHandle,
        inventory: Inventory,
    ) -> RemoteTaskState:
        """Reconnect and check a detached task's status."""
        entry = inventory.get(handle.system_alias)
        if not entry:
            raise TaskRoutingError(
                f"system '{handle.system_alias}' no longer in inventory"
            )

        transport = _build_transport(entry)
        is_windows = _is_windows_system(inventory, handle.system_alias)
        try:
            transport.connect()
            return poll(
                transport, handle.task_id, handle.workspace,
                is_windows=is_windows,
            )
        finally:
            try:
                transport.disconnect()
            except Exception:
                pass

    def collect(
        self,
        handle: TaskHandle,
        inventory: Inventory,
        *,
        cleanup: bool = True,
    ) -> TaskResult:
        """Download results from a completed detached task."""
        entry = inventory.get(handle.system_alias)
        if not entry:
            raise TaskRoutingError(
                f"system '{handle.system_alias}' no longer in inventory"
            )

        transport = _build_transport(entry)
        is_windows = _is_windows_system(inventory, handle.system_alias)

        try:
            transport.connect()

            state = poll(
                transport, handle.task_id, handle.workspace,
                is_windows=is_windows,
            )
            if state.running:
                return TaskResult(
                    task_id=handle.task_id,
                    state=TaskState.RUNNING,
                    system_alias=handle.system_alias,
                    stdout=state.tail_stdout,
                    stderr=state.tail_stderr,
                )

            sep = "\\" if is_windows else "/"
            output_dir = f"{handle.workspace}{sep}output"
            local_output = self._collect_results(
                transport, output_dir, handle.task_id,
            )

            duration = round(time.time() - handle.started_at, 1)

            if cleanup:
                cleanup_workspace(
                    transport, handle.workspace, is_windows=is_windows,
                )
                _remove_task_handle(handle.task_id)

            completed = state.exit_code == 0
            return TaskResult(
                task_id=handle.task_id,
                state=TaskState.COMPLETED if completed else TaskState.FAILED,
                system_alias=handle.system_alias,
                exit_code=state.exit_code,
                stdout=state.tail_stdout,
                stderr=state.tail_stderr,
                output_dir=local_output,
                error=None if completed else f"command exited {state.exit_code}",
                duration_secs=duration,
            )

        except TransportError as exc:
            return TaskResult(
                task_id=handle.task_id,
                state=TaskState.FAILED,
                system_alias=handle.system_alias,
                error=str(exc),
            )
        finally:
            try:
                transport.disconnect()
            except Exception:
                pass

    def cancel(
        self,
        handle: TaskHandle,
        inventory: Inventory,
    ) -> bool:
        """Kill a running detached task and clean up."""
        entry = inventory.get(handle.system_alias)
        if not entry:
            return False

        is_windows = _is_windows_system(inventory, handle.system_alias)

        transport = _build_transport(entry)
        try:
            transport.connect()
            backend = SessionBackend(handle.backend)
            killed = kill_session(
                transport, handle.task_id, handle.workspace, backend,
            )
            cleanup_workspace(
                transport, handle.workspace, is_windows=is_windows,
            )
            _remove_task_handle(handle.task_id)
            return killed
        except Exception:
            return False
        finally:
            try:
                transport.disconnect()
            except Exception:
                pass

    # -- internal helpers --------------------------------------------------

    def _setup_workspace(
        self,
        transport: Transport,
        workspace: str,
        spec: TaskSpec,
        task_id: str,
        is_windows: bool = False,
    ) -> None:
        """Create workspace and upload target if needed."""
        transport.mkdir(workspace)
        target_dir = self._join(workspace, "target", is_windows)
        output_dir = self._join(workspace, "output", is_windows)
        transport.mkdir(output_dir)

        if not spec.is_url_target:
            logger.info("[%s] uploading target", task_id)
            transport.upload(spec.target_path, target_dir)

    def _build_command(
        self,
        spec: TaskSpec,
        remote_target: str,
        output_dir: str,
        is_windows: bool = False,
    ) -> str:
        """Build the shell command to run on the remote.

        On Windows, uses ``python raptor.py`` since the ``raptor``
        shell wrapper won't exist.  On Unix, uses ``raptor``.
        """
        parts = [spec.mode, remote_target]
        parts.extend(spec.args)
        parts.extend(["--output", output_dir])
        args_str = " ".join(parts)

        if is_windows:
            return f"python raptor.py {args_str}"
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

        local_dir = str(_output_base() / task_id)
        os.makedirs(local_dir, exist_ok=True)

        try:
            transport.download(remote_output, local_dir)
            logger.info("[%s] results downloaded to %s", task_id, local_dir)
            return local_dir
        except TransportError as exc:
            logger.warning("[%s] result download failed: %s", task_id, exc)
            return None


def _is_windows_system(inventory: Inventory, alias: str) -> bool:
    caps = inventory.get_capabilities(alias)
    return caps is not None and caps.os == OperatingSystem.WINDOWS


class TaskRoutingError(Exception):
    """No system in the fleet can handle the requested task."""
