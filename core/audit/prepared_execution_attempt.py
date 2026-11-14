"""Run-local input selection, separate from observed execution provenance.

An owned reference binds one immutable parent snapshot to one dispatch handoff.
Selection is a parent action, not a measurement of execution, namespace, or
effective child context. No reference or result from this module admits a build.
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import RLock

from .prepared_execution_inputs import InputsUnavailable, ParentExecInputs, snapshot_parent_inputs


@dataclass(frozen=True)
class ExecutionAttemptReference:
    ordinal: int


@dataclass(frozen=True)
class ExecutionInputHandoff:
    attempt: ExecutionAttemptReference
    inputs: ParentExecInputs = field(repr=False)

    @property
    def authenticated_build(self) -> bool:
        return False

    @property
    def observed_child_context(self) -> bool:
        return False


@dataclass
class _Attempt:
    reference: ExecutionAttemptReference
    handoff: ExecutionInputHandoff
    dispatched: bool = False


class ExecutionInputOwner:
    """Bounded, one-public-invocation custody of explicit parent input bytes.

    The wrapper must create a new owner per public invocation, reserve after
    trusted overlays, hand off once for each actual backend attempt, and select
    the attempt that produced its terminal result. This class does not perform
    or authenticate those wrapper actions. References use object identity, not
    ordinal equality or serialised fields; they are not a defence against
    arbitrary code executing inside the trusted parent process. Same-thread
    signal/cancellation-handler reentry is refused rather than interleaved.

    Bounds cover retained attempt count and encoded payload bytes, not heap
    size. Closing drops owner-held raw material; previously returned snapshots
    remain readable by their holders. No raw context is written or logged here.
    """

    def __init__(self, *, max_attempts: int, max_retained_bytes: int):
        if any(type(v) is not int or v < 1 for v in (max_attempts, max_retained_bytes)):
            raise InputsUnavailable("invalid_attempt_budget")
        self._lock = RLock()
        self._max_attempts = max_attempts
        self._max_retained_bytes = max_retained_bytes
        self._attempts: dict[int, _Attempt] = {}
        self._selected: ExecutionAttemptReference | None = None
        self._closed = False
        self._active = False

    @contextmanager
    def _operation(self):
        with self._lock:
            if self._active:
                raise InputsUnavailable("input_owner_reentered")
            try:
                self._active = True
                yield
            finally:
                self._active = False

    def _open(self):
        if self._closed:
            raise InputsUnavailable("input_owner_closed")

    def _record(self, reference):
        self._open()
        record = self._attempts.get(id(reference))
        if (type(reference) is not ExecutionAttemptReference or record is None
                or record.reference is not reference):
            raise InputsUnavailable("unowned_attempt_reference")
        return record

    def reserve(self, argv, environment, cwd, *, max_args: int, max_env: int,
                max_item_bytes: int, max_total_bytes: int) -> ExecutionAttemptReference:
        """Capture bounded inputs; interrupted publication can retain a slot.

        Such a slot remains charged until close, even if its reference was
        never returned to the caller. No separate byte counter can drift.
        """
        with self._operation():
            self._open()
            if self._selected is not None:
                raise InputsUnavailable("terminal_attempt_already_selected")
            if len(self._attempts) >= self._max_attempts:
                raise InputsUnavailable("attempt_count_budget")
            inputs = snapshot_parent_inputs(
                argv, environment, cwd, max_args=max_args, max_env=max_env,
                max_item_bytes=max_item_bytes, max_total_bytes=max_total_bytes,
            )
            retained_bytes = sum(record.handoff.inputs.payload_bytes
                                 for record in self._attempts.values())
            if inputs.payload_bytes > self._max_retained_bytes - retained_bytes:
                raise InputsUnavailable("retained_input_byte_budget")
            reference = ExecutionAttemptReference(len(self._attempts))
            handoff = ExecutionInputHandoff(reference, inputs)
            record = _Attempt(reference, handoff)
            self._attempts[id(reference)] = record
            return reference

    def handoff_for_dispatch(self, reference: ExecutionAttemptReference) -> ExecutionInputHandoff:
        """Return the owned bytes once; this does not observe a dispatch."""
        with self._operation():
            record = self._record(reference)
            if self._selected is not None:
                raise InputsUnavailable("terminal_attempt_already_selected")
            if record.dispatched:
                raise InputsUnavailable("attempt_already_handed_off")
            record.dispatched = True
            return record.handoff

    def select_terminal(self, reference: ExecutionAttemptReference) -> None:
        """Select an already handed-off attempt without declaring success."""
        with self._operation():
            record = self._record(reference)
            if self._selected is not None:
                raise InputsUnavailable("terminal_attempt_already_selected")
            if not record.dispatched:
                raise InputsUnavailable("attempt_not_handed_off")
            self._selected = reference

    def read_selected(self, expected_attempt: ExecutionAttemptReference) -> ExecutionInputHandoff:
        with self._operation():
            record = self._record(expected_attempt)
            if self._selected is None:
                raise InputsUnavailable("terminal_attempt_unselected")
            if self._selected is not expected_attempt:
                raise InputsUnavailable("selected_attempt_mismatch")
            return record.handoff

    def close(self) -> None:
        with self._operation():
            self._closed = True
            self._selected = None
            self._attempts.clear()
    