"""Normal-review request capture and ownership for the knowledge loop.

The orchestrator owns dispatch and verdict publication. This adapter retains
pre-call origins, local reference answers and typed source requests; none of
these objects supplies confirmation or refutation authority.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from contextvars import ContextVar
from dataclasses import asdict, dataclass, replace
from functools import wraps
import json
from pathlib import Path
from threading import Event, Lock, RLock
from time import monotonic
from uuid import UUID, uuid4, uuid5
from typing import TypedDict

from core.concepts.subject_study import StudySubjects, SubjectExplanation, SubjectPacket, SubjectMaterial
from core.language_reference import ReferenceAnswer, ReferenceContext, lookup
from core.source.lines import split_lines

from .caller_review_context import (CallerContextAnswer, CallerContextRequest, register_caller_context_requests,
                                    resolve_caller_context, validate_caller_context)
from .knowledge_requests import KnowledgeBatch, KnowledgeOrigin, KnowledgeRequest, register_requests
from .study_job_ledger import SemanticStudyJobLedger, StudyDispatchLease, StudyJobDescriptor
from .binary_review_scope import (BinaryKnowledgeOrigin, BinaryModuleSnapshot, BinaryReviewPublicationScope,
                                  capture_binary_input_identity, capture_binary_publication_scope,
                                  origin_input_identity, same_review_snapshot)
from .refutation_source import capture_source_identity
from .review_input_scope import CapturedReviewInput, ReviewInputScope
from .review_cycle import KnowledgeContinuation, KnowledgeCycle
from .study_inputs import StudyInputBindings


class _CyclePolicy(TypedDict):
    window: float
    max_continuations: int
    max_model_calls: int


@dataclass(frozen=True)
class KnowledgeReservation:
    origin: KnowledgeOrigin
    packet: KnowledgeContinuation


@dataclass(frozen=True)
class _OwnedUnitLease:
    key: tuple[str, str, int]
    closed: Event


@dataclass(frozen=True)
class _DeferredSourceDispatch:
    requests: tuple[KnowledgeRequest, ...]
    packet: SubjectPacket
    jobs: tuple[StudyJobDescriptor, ...]
    replay_context: object


class AuditKnowledgeRuntime:
    """One audit's knowledge ownership, using its existing study queue.

    Call counts cover owned review dispatch attempts. Unknown custom review
    producers remain explicitly unknown; these are not counts of hidden
    provider retries or unmigrated verification calls. The shared budget client
    still owns all paid spend and transport retry admission.
    """

    def __init__(self, target_root: Path, study_queue, *, deadline: float, window: float = 10.0,
                 max_continuations: int = 2, max_model_calls: int = 6, caller_inventory: dict | None = None,
                 study_job_call_limit: int | None = None, required_review_calls: int = 1):
        self.target_root = Path(target_root)
        self.study_queue = study_queue
        self.deadline = deadline
        self.bindings = StudyInputBindings(self.target_root)
        self._lock = RLock()
        self._foundation_namespace = uuid4().hex
        self._write_lock = Lock()
        self._wakeup = Event()
        if type(required_review_calls) is not int or required_review_calls < 1:
            raise ValueError("review reservation requires a positive known dispatch count")
        self._required_calls = (required_review_calls
                                if type(study_job_call_limit) is int and study_job_call_limit > 0 else 1)
        self._initial_review_required_calls = self._required_calls
        self._policy: _CyclePolicy = dict(window=window, max_continuations=max_continuations, max_model_calls=max_model_calls)
        self._busy: dict[tuple[str, str, int], int] = {}
        self._unit_lease: ContextVar[_OwnedUnitLease | None] = ContextVar(
            "audit_owned_unit_lease", default=None)
        self._pending_sources: set[str] = set()
        self._request_status: dict[str, dict] = {}
        self._semantic_requests: dict[tuple, str] = {}
        self._binary_initial_guarded: set[str] = set()
        self._binary_subject_pending: dict[tuple[str, str, int], object] = {}
        self._binary_subject_locks: dict[tuple[str, str, int], Lock] = {}
        self._binary_caller_pending: dict[tuple[str, str, int], object] = {}
        self._binary_caller_locks: dict[tuple[str, str, int], Lock] = {}
        self._source_answers: dict[str, list[SubjectExplanation]] = {}
        self._active: dict[str, KnowledgeReservation] = {}
        self._active_units: dict[tuple[str, str, int], KnowledgeReservation] = {}
        self._reserving: set[tuple[str, str, int]] = set()
        self._context_deltas: dict[tuple, dict] = {}
        self._binary_external_payloads: dict[tuple, tuple[str, object]] = {}
        self._external_deliveries: dict[str, list[list[dict]]] = {}
        self._knowledge_deliveries: dict[str, list[dict[str, list[dict]]]] = {}
        self._caller_deliveries: dict[str, list[list[dict]]] = {}
        self._live_input_sets: dict[str, list[tuple[CapturedReviewInput, ...]]] = {}
        self._live_input_errors: set[str] = set()
        self._binary_review_scopes: dict[tuple[str, str], tuple[BinaryReviewPublicationScope, BinaryKnowledgeOrigin]] = {}
        self._source_review_scopes: dict[tuple[str, str], ReviewInputScope] = {}
        self._binary_cycle_scopes: dict[tuple[str, str, int], tuple[BinaryReviewPublicationScope, BinaryKnowledgeOrigin]] = {}
        self._binary_context_records: dict[str, list[dict]] = {}
        self._binary_context_origins: dict[str, BinaryKnowledgeOrigin] = {}
        self._publication_rejections: set[tuple[str, str]] = set()
        self._sources_closed = False
        self._written_events: dict[str, int] = {}
        self._requests: dict[str, KnowledgeRequest] = {}
        self._cycles: dict[tuple[str, str, int], KnowledgeCycle] = {}
        self._calls: dict[tuple[str, str, int], int] = {}
        self._unknown_calls: set[tuple[str, str, int]] = set()
        self._events: list[dict] = []
        self._source_jobs: list[StudySubjects] = []
        self._closed = False
        self._caller_inventory = caller_inventory
        self._caller_requests: dict[str, CallerContextRequest] = {}
        self._caller_answers: dict[str, CallerContextAnswer] = {}
        self._caller_semantic: dict[tuple, str] = {}
        self._study_jobs = (SemanticStudyJobLedger(study_job_call_limit)
                            if type(study_job_call_limit) is int and study_job_call_limit > 0 else None)
        self._source_job_owners: dict[int, tuple[StudySubjects, str]] = {}
        self._source_dispatch_units: dict[str, tuple[tuple[str, str, int], ...]] = {}
        self._source_dispatch_inputs: dict[str, tuple[SubjectMaterial, ...]] = {}
        self._source_dispatch_packets: dict[str, SubjectPacket] = {}
        self._source_dispatch_tokens: dict[str, StudyDispatchLease] = {}
        self._source_dispatch_retired: set[str] = set()
        self._deferred_source_dispatches: dict[tuple[str, ...], _DeferredSourceDispatch] = {}
        self._deferred_source_dispatch_states: dict[tuple[str, ...], str] = {}
        self._transient_source_refusal_ids: set[str] = set()
        self._study_review_credits: dict[tuple[str, str, int], set[str]] = {}
        self._study_review_finished: set[tuple[str, str, int]] = set()
        self._study_review_touched: set[tuple[str, str, int]] = set()
        self._study_review_reservations: dict[tuple[str, str, int], tuple[int, frozenset[str]]] = {}

    @property
    def study_jobs_enabled(self) -> bool:
        return self._study_jobs is not None

    def source_job_owner(self, subjects: StudySubjects) -> str:
        with self._lock:
            record = self._source_job_owners.get(id(subjects))
            if record is None:
                record = (subjects, uuid4().hex)
                self._source_job_owners[id(subjects)] = record
            return record[1]

    def _study_review_credit(self, key: tuple[str, str, int], attempt_id: str) -> None:
        if self._study_jobs is not None:
            self._study_review_credits.setdefault(key, set()).add(attempt_id)

    def _study_review_returned(self, key: tuple[str, str, int], attempt_id: str, *, success: bool) -> None:
        if self._study_jobs is None:
            return
        with self._lock:
            if success or attempt_id in self._study_review_credits.get(key, ()):
                self._study_review_touched.add(key)
                if not self._busy.get(key):
                    self._study_review_finished.add(key)

    def _study_reserved_calls(self, key: tuple[str, str, int]) -> int:
        credits = self._study_review_credits.get(key, set())
        first = (max(0, self._initial_review_required_calls - len(credits))
                 if key not in self._study_review_finished else 0)
        active = self._study_review_reservations.get(key)
        remaining = max(0, active[0] - len(credits - active[1])) if active else 0
        # An initial context reservation and its first-review reservation may
        # name the same planned calls. Do not reserve those calls twice.
        return max(first, remaining)

    def begin_source_dispatch(self, *, requests: tuple[KnowledgeRequest, ...], packet: SubjectPacket,
                              jobs: tuple[StudyJobDescriptor, ...], owner_id: str
                              ) -> tuple[StudyDispatchLease | None, str]:
        if not isinstance(packet, SubjectPacket):
            return None, "unowned_study_packet"
        if self._study_jobs is not None:
            admitted, reason = self.bindings.admit_inputs(packet.materials)
            if not admitted:
                return None, reason
        with self._lock:
            if self._study_jobs is None:
                return None, "study_job_policy_unavailable"
            if self._closed or self._sources_closed or monotonic() >= self.deadline:
                return None, "source_study_stopped"
            if (not requests or not isinstance(packet, SubjectPacket)
                    or len({r.request_id for r in requests}) != len(requests)
                    or tuple(s.request_id for s in packet.subjects) != tuple(r.request_id for r in requests)
                    or type(packet.extra_context_excluded) is not bool
                    or any((subject.subject, subject.context, subject.resolution, subject.source_file)
                           != (request.subject, request.context, request.resolution, request.origin.file)
                           for subject, request in zip(packet.subjects, requests))
                    or any(self._requests.get(r.request_id) != r for r in requests)):
                return None, "unowned_study_packet"
            keys = tuple(sorted({self._key(r.origin) for r in requests}))
            if any(key not in self._cycles for key in keys):
                return None, "unowned_study_unit"
            token, reason = self._study_jobs.begin(
                owner_id=owner_id, jobs=jobs, request_ids=tuple(r.request_id for r in requests),
                input_binding_ids=tuple(m.binding_id for m in packet.materials),
                unit_caps=tuple(self._cycles[key].max_model_calls for key in keys),
            )
            if token is not None:
                self._source_dispatch_units[token.lease_id] = keys
                self._source_dispatch_inputs[token.lease_id] = packet.materials
                self._source_dispatch_packets[token.lease_id] = packet
                self._source_dispatch_tokens[token.lease_id] = token
                self._events.append({"event": "semantic_study_dispatch", "lease_id": token.lease_id,
                                     "request_ids": list(token.request_ids)})
            return token, reason

    def source_dispatch_valid(self, token: StudyDispatchLease | None) -> None:
        from .knowledge_calls import KnowledgeCallRefused

        if type(token) is not StudyDispatchLease:
            raise KnowledgeCallRefused("study_job_lease_unavailable")
        with self._lock:
            reason = ("source_study_stopped" if self._closed or self._sources_closed
                      or monotonic() >= self.deadline else
                      self._study_jobs.validity_rejection(token) if self._study_jobs is not None
                      else "study_job_policy_unavailable")
            inputs = self._source_dispatch_inputs.get(token.lease_id, ())
        if reason:
            raise KnowledgeCallRefused(reason)
        admitted, reason = self.bindings.admit_inputs(inputs)
        if not admitted:
            raise KnowledgeCallRefused(reason)
        with self._lock:
            reason = self._study_jobs.validity_rejection(token) if self._study_jobs else "study_job_policy_unavailable"
            if self._closed or self._sources_closed or monotonic() >= self.deadline:
                reason = "source_study_stopped"
            if reason:
                raise KnowledgeCallRefused(reason)

    def mark_source_dispatch_unknown(self, token: StudyDispatchLease) -> None:
        with self._lock:
            if self._study_jobs is not None:
                self._study_jobs.mark_unknown(token, "opaque_study_client_attempts")

    def finish_source_dispatch(self, token: StudyDispatchLease) -> None:
        """Only the actual synchronous invocation's finally retires its lease."""
        if type(token) is not StudyDispatchLease:
            return
        with self._lock:
            if (self._study_jobs is not None
                    and self._source_dispatch_tokens.get(token.lease_id) is token
                    and token.lease_id not in self._source_dispatch_retired):
                keys = self._source_dispatch_units.get(token.lease_id, ())
                self._study_jobs.retire(token, accounting_known=bool(keys) and not any(
                    key in self._unknown_calls for key in keys))
                self._source_dispatch_retired.add(token.lease_id)
                self._events.append({"event": "semantic_study_dispatch_retired", "lease_id": token.lease_id})
        self._queue_retired_source_dispatches()

    def defer_live_source_dispatch(self, *, requests: tuple[KnowledgeRequest, ...], packet: SubjectPacket,
                                   jobs: tuple[StudyJobDescriptor, ...], replay_context: object) -> bool:
        """Keep one original packet pending; it cannot borrow another attempt's answer."""
        copied_context = deepcopy(replay_context)
        request_ids = tuple(request.request_id for request in requests)
        with self._lock:
            if (self._study_jobs is None or self._closed or self._sources_closed
                    or not request_ids or len(set(request_ids)) != len(request_ids)
                    or not jobs or any(type(job) is not StudyJobDescriptor for job in jobs)
                    or tuple(subject.request_id for subject in packet.subjects) != request_ids
                    or any(self._requests.get(request.request_id) != request
                           or request.request_id not in self._pending_sources for request in requests)):
                return False
            prior = self._deferred_source_dispatches.get(request_ids)
            if prior is not None and (prior.requests != requests or prior.packet != packet or prior.jobs != jobs):
                return False
            if any(set(request_ids) & set(other) for other in self._deferred_source_dispatches
                   if other != request_ids):
                return False
            self._deferred_source_dispatches[request_ids] = prior or _DeferredSourceDispatch(
                requests, packet, jobs, copied_context)
            self._deferred_source_dispatch_states[request_ids] = "pending"
            # The refusing phase may drain after retirement has already
            # settled or replayed this packet. Its stale transient refusal
            # must not replace that later owner decision or explanation.
            self._transient_source_refusal_ids.update(request_ids)
            for request_id in request_ids:
                self._request_status[request_id] = {"state": "queued", "reason": "study_job_dispatch_live"}
            self._events.append({"event": "semantic_study_dispatch_pending", "request_ids": list(request_ids),
                                 "reason": "study_job_dispatch_live"})
        # The previous physical call can retire between begin's refusal and
        # this registration. Recheck after retaining the original packet.
        self._queue_retired_source_dispatches()
        self.notify()
        return True

    def transient_source_request_ids(self) -> frozenset[str]:
        with self._lock:
            return frozenset(request_id for ids, state in self._deferred_source_dispatch_states.items()
                             if state in {"pending", "queued"} for request_id in ids)

    def source_dispatch_replays(self, requests: tuple[KnowledgeRequest, ...]):
        """Expand a queued subset to its original packet and consume it only once."""
        with self._lock:
            if self._study_jobs is None:
                return (), requests
            selected_ids = {request.request_id for request in requests}
            replays = []
            deferred_ids: set[str] = set()
            for ids, pending in self._deferred_source_dispatches.items():
                deferred_ids.update(ids)
                if not selected_ids.intersection(ids):
                    continue
                if (self._deferred_source_dispatch_states.get(ids) == "queued"
                        and all(request_id in self._pending_sources for request_id in ids)):
                    self._deferred_source_dispatch_states[ids] = "replaying"
                    replays.append((pending.requests, pending.packet, pending.replay_context))
            live_ids = {request_id for token in self._source_dispatch_tokens.values()
                        if token.lease_id not in self._source_dispatch_retired for request_id in token.request_ids}
            fresh = tuple(request for request in requests if request.request_id in self._pending_sources
                          and request.request_id not in deferred_ids and request.request_id not in live_ids)
            return tuple(replays), fresh

    def _pending_dispatch_rejection(self, pending: _DeferredSourceDispatch, jobs: dict) -> str:
        # Called under the Runtime lock; no source reads or foreign callbacks.
        if self._closed or self._sources_closed or monotonic() >= self.deadline:
            return "source_study_stopped"
        rows: list[dict] = []
        for job in pending.jobs:
            row = jobs.get(job.lineage)
            if row is None:
                return "study_job_inputs_unavailable"
            rows.append(row)
        if not rows:
            return "study_job_inputs_unavailable"
        if any(row["active_lease"] is not None for row in rows):
            return "study_job_dispatch_live"
        if any(row["accounting_unknown"] for row in rows):
            return "study_job_accounting_unknown"
        if any(row["generation"] != job.generation for row, job in zip(rows, pending.jobs)):
            return "study_job_generation_changed"
        assert self._study_jobs is not None
        if any(row["spent"] >= self._study_jobs.job_call_limit for row in rows):
            return "study_job_call_limit"
        keys = {self._key(request.origin) for request in pending.requests}
        if any(key in self._unknown_calls for key in keys):
            return "model_call_count_unavailable"
        if any(key not in self._cycles for key in keys):
            return "unowned_study_unit"
        if any(self._calls.get(key, 0) + 1 + self._study_reserved_calls(key)
               > self._cycles[key].max_model_calls for key in keys):
            return "model_call_limit"
        return ""

    def _queue_retired_source_dispatches(self) -> None:
        queued, refused = [], []
        with self._lock:
            if self._study_jobs is None:
                return
            jobs = {row["lineage"]: row for row in self._study_jobs.snapshot()["jobs"]}
            for ids, pending in tuple(self._deferred_source_dispatches.items()):
                if self._deferred_source_dispatch_states.get(ids) != "pending":
                    continue
                if not all(request_id in self._pending_sources for request_id in ids):
                    del self._deferred_source_dispatches[ids]
                    self._deferred_source_dispatch_states.pop(ids, None)
                    continue
                reason = self._pending_dispatch_rejection(pending, jobs)
                if reason == "study_job_dispatch_live":
                    continue
                if reason:
                    del self._deferred_source_dispatches[ids]
                    self._deferred_source_dispatch_states.pop(ids, None)
                    refused.append((pending, reason))
                else:
                    self._deferred_source_dispatch_states[ids] = "queued"
                    queued.append((ids, pending))
        # Queue and cycle callbacks run outside the Runtime lock. The queue's
        # batch operation retains the original request group atomically.
        for ids, pending in queued:
            enqueue = getattr(self.study_queue, "enqueue_knowledge_batch", None)
            try:
                accepted = callable(enqueue) and enqueue(pending.requests) is True
            except Exception:
                accepted = False
            if not accepted:
                with self._lock:
                    if self._deferred_source_dispatches.get(ids) is pending:
                        self._deferred_source_dispatches.pop(ids, None)
                        self._deferred_source_dispatch_states.pop(ids, None)
                refused.append((pending, "study_queue_closed"))
        for pending, reason in refused:
            for request in pending.requests:
                with self._lock:
                    cycle = (self._cycles.get(self._key(request.origin))
                             if request.request_id in self._pending_sources else None)
                if cycle is not None:
                    self._defer_source(request, cycle, reason)
        if queued or refused:
            self.notify()

    def _study_answer_scope_owned(self, answer: SubjectExplanation) -> bool:
        if self._study_jobs is None:
            return True
        for lease_id, packet in self._source_dispatch_packets.items():
            token = self._source_dispatch_tokens[lease_id]
            if (answer.inputs == packet.materials
                    and answer.excluded_inputs == packet.excluded_materials
                    and answer.extra_context_excluded is packet.extra_context_excluded
                    and self._study_jobs.permits_answer(
                        answer.request_id, tuple(material.binding_id for material in answer.inputs), token=token)):
                return True
        return False

    @staticmethod
    def _key(origin: KnowledgeOrigin) -> tuple[str, str, int]:
        return origin.file, origin.function, origin.line_start

    @staticmethod
    def _gap_key(gap: dict) -> tuple[str, str, int]:
        # Match the existing origin factory's unknown-line representation.
        start = gap.get("line_start", 0)
        if type(start) is not int or start < 1:
            start = 0
        return gap.get("file", ""), gap.get("name", gap.get("function", "")), start

    def notify(self) -> None:
        self._wakeup.set()

    def wait_for_update(self, timeout: float) -> bool:
        import math
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("knowledge wait must be finite and non-negative")
        return self._wakeup.wait(timeout)

    def wrap_unit(self, review_one_fn: Callable) -> Callable:
        """A unit stays busy through verification, commit and tracking."""
        if getattr(review_one_fn, "_knowledge_unit_owner", None) is self:
            return review_one_fn

        @wraps(review_one_fn)
        def unit(gap, *args, **kwargs):
            key = self._gap_key(gap)
            with self._lock:
                self._busy[key] = self._busy.get(key, 0) + 1
            lease = _OwnedUnitLease(key, Event())
            unit_token = self._unit_lease.set(lease)
            try:
                from .knowledge_calls import owned_call_scope
                with owned_call_scope(lambda purpose, method: self._admit_client_key(key, purpose, method),
                                      validity=self.client_lifetime_valid,
                                      on_unobserved_attempts=lambda: self._mark_call_key_unknown(
                                          key, "opaque_client_attempts")):
                    return review_one_fn(gap, *args, **kwargs)
            finally:
                lease.closed.set()
                self._unit_lease.reset(unit_token)
                with self._lock:
                    self._busy[key] -= 1
                    if not self._busy[key]:
                        del self._busy[key]
                    if self._study_jobs is not None and key in self._study_review_touched:
                        self._study_review_finished.add(key)
                self.notify()

        setattr(unit, "_knowledge_unit_owner", self)
        return unit

    def mark_call_count_unknown(self, gap: dict, reason: str = "unowned_model_helper") -> None:
        self._mark_call_key_unknown(self._gap_key(gap), reason)

    def _mark_call_key_unknown(self, key: tuple[str, str, int], reason: str) -> None:
        with self._lock:
            self._unknown_calls.add(key)
            self._events.append({"event": "attempt_count_unknown", "unit": list(key), "reason": reason})
        self.notify()

    @staticmethod
    def _same_snapshot(left: KnowledgeOrigin, right: KnowledgeOrigin) -> bool:
        return same_review_snapshot(left, right)

    def _origin(self, ctx: dict) -> KnowledgeOrigin:
        # Reuse the exact inverse of the normal numbered review view. A stale
        # or unrecognised view cannot acquire a fresh whole-file identity.
        from .orchestrator import _raw_ihv_review_source

        from core.inventory.binary_builder import BINARY_PATH_PREFIX

        file_path = ctx.get("file")
        if ctx.get("is_binary") is True or isinstance(file_path, str) and file_path.startswith(BINARY_PATH_PREFIX):
            module = ctx.get("_binary_module_snapshot")
            scope = capture_binary_publication_scope(ctx, module) if isinstance(module, BinaryModuleSnapshot) else None
            binary = (capture_binary_input_identity(ctx, scope)
                      if scope is not None and scope.current(self.target_root) else None)
            if binary is not None:
                return BinaryKnowledgeOrigin(uuid4().hex, ctx["file"], ctx["function"], 0, 0, None,
                                             binary_identity=binary)
            return KnowledgeOrigin(uuid4().hex, ctx["file"], ctx["function"], 0, 0, None)
        start = ctx.get("line_start", 0)
        if type(start) is not int or start < 1:
            start = 0
        raw = _raw_ihv_review_source(ctx.get("source"), start)
        end = start + len(split_lines(raw)) - 1 if isinstance(raw, str) and raw else start
        identity = None
        if start and isinstance(raw, str) and raw:
            identity = capture_source_identity(
                self.target_root, ctx["file"], excerpt=raw, line_start=start,
            )
        return KnowledgeOrigin(uuid4().hex, ctx["file"], ctx["function"], start, end, identity)

    def wrap_review(self, review_fn: Callable) -> Callable:
        """Capture source before a call; keep proposals separate from publication."""
        if getattr(review_fn, "_knowledge_review_owner", None) is self:
            return review_fn

        @wraps(review_fn)
        def review(ctx, config):
            from .binary_review_scope import BinaryModuleSnapshot
            from .review_availability import require_binary_implementation

            require_binary_implementation(ctx)
            supplied_binary = ctx.get("_binary_module_snapshot")
            binary_snapshot = supplied_binary if isinstance(supplied_binary, BinaryModuleSnapshot) else None
            binary_target = ctx.get("target_path")
            from .binary_review_scope import capture_binary_publication_scope
            binary_scope = (capture_binary_publication_scope(ctx, binary_snapshot)
                            if binary_snapshot is not None else None)
            if binary_snapshot is not None and binary_scope is None:
                from .knowledge_calls import KnowledgeCallRefused
                raise KnowledgeCallRefused("binary_occurrence_unavailable")
            captured = self._origin(ctx)
            if binary_scope is not None and not isinstance(captured, BinaryKnowledgeOrigin):
                from .knowledge_calls import KnowledgeCallRefused
                raise KnowledgeCallRefused("binary_view_identity_unavailable")
            key = self._key(captured)
            lease = self._unit_lease.get()
            refusal = ("unit_scope_closed" if lease is not None and lease.closed.is_set()
                       else "review_unit_identity_mismatch" if lease is not None and key != lease.key
                       else None)
            if refusal is not None and lease is not None:
                from .knowledge_calls import KnowledgeCallRefused
                with self._lock:
                    self._events.append({"event": "review_unit_refused", "unit": list(lease.key),
                                         "requested_unit": list(key),
                                         "reason": refusal})
                raise KnowledgeCallRefused(refusal)
            with self._lock:
                reservation = self._active_units.get(key)
            if reservation is not None:
                if not self._same_snapshot(captured, reservation.origin) or not self.can_publish(reservation):
                    raise ValueError("knowledge continuation source changed before review")
                origin = replace(captured, pass_id=reservation.packet.pass_id)
            else:
                origin = captured
            from .binary_initial_type_delivery import capture_initial_type_inventory
            initial_type_inventory = (capture_initial_type_inventory(ctx, origin=origin)
                                      if isinstance(origin, BinaryKnowledgeOrigin) else None)
            from .reference_foundation import foundation_answers, foundation_required_for_file
            owned_references = reservation.packet.references if reservation is not None else ()
            initial_answers: tuple[ReferenceAnswer, ...] = ()
            if origin.source_identity is not None and foundation_required_for_file(origin.file):
                foundation_id = "foundation:" + uuid5(UUID(self._foundation_namespace),
                    repr((self._key(origin), origin.source_identity))).hex
                from .orchestrator import _raw_ihv_review_source
                initial_answers = foundation_answers(ctx.get("language"), request_id=foundation_id,
                    source=_raw_ihv_review_source(ctx.get("source"), origin.line_start), file=origin.file)
                owned_references = (*owned_references, *initial_answers)
            # These immutable answers have stable identities across the unit's
            # panel. Shared compatibility fields never establish delivery.
            ctx["language_reference_answers"] = owned_references
            attempt_id = uuid4().hex
            with self._lock:
                if getattr(review_fn, "_knowledge_observed_client_contract", None) is not True:
                    self._calls[key] = self._calls.get(key, 0) + 1
                    self._study_review_credit(key, attempt_id)
                if getattr(review_fn, "_knowledge_observed_client_contract", None) is not True:
                    self._unknown_calls.add(key)
                self._events.append({"event": "review_attempt", "attempt_id": attempt_id, "origin": asdict(origin)})
                # Retain resolved material even if fitting omits it or the
                # callback fails. This is not a prompt-delivery receipt.
                for answer in initial_answers:
                    self._events.append({"event": "initial_reference_answer", "attempt_id": attempt_id,
                                         "origin": asdict(origin), "answer": asdict(answer)})
            try:
                from .knowledge_calls import owned_call_scope
                def review_admit(purpose, method):
                    if self._study_jobs is not None:
                        return self._admit_client_key(key, purpose, method, review_attempt_id=attempt_id)
                    return self.admit_client_call(
                        {"file": origin.file, "name": origin.function, "line_start": origin.line_start},
                        purpose, method)

                with owned_call_scope(review_admit,
                        work_id="review:" + origin.pass_id, beneficiaries=(origin.pass_id,),
                        validity=self.client_lifetime_valid,
                        on_unobserved_attempts=lambda: self._mark_call_key_unknown(
                            key, "opaque_client_attempts")):
                    outcome = review_fn(ctx, config)
            except BaseException:
                self._study_review_returned(key, attempt_id, success=False)
                with self._lock:
                    self._events.append({"event": "review_failed", "attempt_id": attempt_id,
                                         "pass_id": origin.pass_id})
                self.notify()
                raise
            self._study_review_returned(key, attempt_id, success=True)
            from .review_claims import begin_review
            # Pipeline-owned: a model cannot supply the original source stamp.
            outcome.review_result = dict(outcome.review_result or {})
            history = begin_review(origin, attempt_id)
            if binary_scope is not None:
                outcome.binary_publication_scope = binary_scope
                outcome.review_result["binary_review_binding"] = binary_scope.record()
                with self._lock:
                    assert isinstance(origin, BinaryKnowledgeOrigin)
                    self._binary_review_scopes[(origin.pass_id, attempt_id)] = (binary_scope, origin)
            # This is descriptive attribution to the actual completed
            # renderer invocation, never proof authority or current freshness.
            if (getattr(review_fn, "_knowledge_observed_client_contract", None) is True
                    and outcome.review_result.get("status") == outcome.status
                    and outcome.review_result.get("counter_escalated") is not True):
                from .assessment_basis import record_assessment_basis
                recorded = record_assessment_basis(history, origin=origin,
                    attempt_id=attempt_id, status=outcome.status)
                if recorded is not None:
                    history = recorded
            if "caller_context_delivery" in outcome.review_result:
                from .review_context_inputs import context_inputs_from_delivery
                dependencies = context_inputs_from_delivery(outcome.review_result["caller_context_delivery"], origin)
                if dependencies is not None:
                    history["source_inputs"] = dependencies
            from .review_context_inputs import context_inputs_from_sources, merge_context_inputs
            from .reference_inputs import reference_inputs_from_delivery
            study_manifest, live_inputs, live_valid = self._capture_delivered_inputs(
                origin, reservation, outcome.review_result)
            reference_manifest = reference_inputs_from_delivery(
                outcome.review_result.get("language_reference_delivery"),
                owned_references)
            if reference_manifest is not None:
                history["reference_inputs"] = reference_manifest
                # Reference-only assessments still bind their original target,
                # and use root-qualified source records under the ctx3 contract.
                primary_manifest = context_inputs_from_sources(
                    [("target", origin.file, origin.source_identity.sha256)]
                    if origin.source_identity is not None else [],
                    complete=origin.source_identity is not None)
                study_manifest = merge_context_inputs(study_manifest, primary_manifest)
            if ctx.get("synthesis_review_context") is not None:
                from .synthesis_review_context import SynthesisReviewContext
                if isinstance(ctx["synthesis_review_context"], SynthesisReviewContext):
                    # The match's producer/source correspondence is not a
                    # separately validated source dependency. Retain that loss.
                    study_manifest = merge_context_inputs(study_manifest, context_inputs_from_sources(
                        [("target", origin.file, origin.source_identity.sha256)]
                        if origin.source_identity is not None else [], complete=False))
            dependencies = merge_context_inputs(history.get("source_inputs"), study_manifest)
            if dependencies is not None:
                history["source_inputs"] = dependencies
            outcome.review_result["review_claims"] = history
            if dependencies is not None and live_valid:
                from .review_context_inputs import context_inputs_record_digest
                record_digest = context_inputs_record_digest(dependencies)
                if record_digest is not None:
                    outcome.review_input_scope = ReviewInputScope(origin, record_digest, live_inputs)
            if reservation is not None:
                with self._lock:
                    self._live_input_sets.setdefault(reservation.packet.pass_id, []).append(live_inputs)
                    if not live_valid:
                        self._live_input_errors.add(reservation.packet.pass_id)
                        self._events.append({"event": "review_inputs_unbound", "attempt_id": attempt_id,
                            "pass_id": reservation.packet.pass_id, "reason": "delivered_input_binding_unavailable"})
            current = capture_source_identity(self.target_root, origin.file)
            if reservation is not None:
                knowledge_delivery = {field: deepcopy(outcome.review_result[field])
                    for field in ("language_reference_delivery", "source_study_delivery")
                    if isinstance(outcome.review_result.get(field), list)}
                if knowledge_delivery:
                    with self._lock:
                        self._knowledge_deliveries.setdefault(reservation.packet.pass_id, []).append(knowledge_delivery)
                delivered = outcome.review_result.get("caller_context_delivery")
                if isinstance(delivered, list):
                    with self._lock:
                        self._caller_deliveries.setdefault(reservation.packet.pass_id, []).append(deepcopy(delivered))
                external = outcome.review_result.get("external_context_delivery")
                if (isinstance(external, list)
                        and getattr(review_fn, "_knowledge_observed_client_contract", None) is True):
                    with self._lock:
                        self._external_deliveries.setdefault(reservation.packet.pass_id, []).append(deepcopy(external))
            if reservation is not None and isinstance(origin, BinaryKnowledgeOrigin):
                from .binary_context_inputs import capture_binary_context_inputs, binary_context_record_digest
                external = outcome.review_result.get("external_context_delivery")
                record = (capture_binary_context_inputs(ctx, origin, external)
                          if getattr(review_fn, "_knowledge_observed_client_contract", None) is True else None)
                digest = binary_context_record_digest(record)
                expected = set(reservation.packet.external_context_ids)
                retained = {row["context_id"] for row in record["contexts"]} if record is not None else set()
                if record is None or digest is None or retained != expected or binary_scope is None:
                    with self._lock:
                        self._live_input_errors.add(reservation.packet.pass_id)
                        self._binary_review_scopes.pop((origin.pass_id, attempt_id), None)
                    # Missing required context cannot downgrade this attempted
                    # continuation into a publishable plain binary review.
                    outcome.binary_publication_scope = None
                    outcome.review_result["binary_review_binding"] = None
                else:
                    history["binary_inputs"] = record
                    outcome.review_result["review_claims"] = history
                    bound = replace(binary_scope, context_digest=digest)
                    outcome.binary_publication_scope = bound
                    outcome.review_result["binary_review_binding"] = bound.record()
                    with self._lock:
                        self._binary_review_scopes[(origin.pass_id, attempt_id)] = (bound, origin)
                        self._binary_context_records.setdefault(origin.pass_id, []).append(deepcopy(record))
                        self._binary_context_origins[origin.pass_id] = origin
            # Retain this invocation's fitting, including explicit omissions.
            # This is disclosure only; continuation credit uses owned receipts.
            reference_fitting = outcome.review_result.get("language_reference_delivery")
            # Retain the original pre-call binding. A callback cannot refresh
            # changed bytes by replacing its context's transient snapshot.
            binary_current = binary_snapshot is None or (
                ctx.get("_binary_module_snapshot") is binary_snapshot
                and ctx.get("target_path") == binary_target and binary_snapshot.current())
            binary_view_current = True
            if binary_snapshot is not None:
                try:
                    binary_view_current = self._same_snapshot(self._origin(ctx), origin)
                except (KeyError, TypeError, ValueError, UnicodeError):
                    binary_view_current = False
            initial_binary_types = None
            if (isinstance(origin, BinaryKnowledgeOrigin) and binary_current and binary_view_current
                    and getattr(review_fn, "_knowledge_observed_client_contract", None) is True):
                from .binary_initial_type_delivery import capture_initial_type_delivery
                initial_binary_types = capture_initial_type_delivery(
                    outcome.review_result.get("binary_initial_type_delivery"), origin=origin, ctx=ctx,
                    inventory=initial_type_inventory)
            if initial_binary_types is not None:
                outcome.review_result["binary_initial_type_delivery"] = initial_binary_types.records()
            else:
                outcome.review_result.pop("binary_initial_type_delivery", None)
            with self._lock:
                self._events.append({"event": "review_assessment", "attempt_id": attempt_id,
                    "pass_id": origin.pass_id, "status": outcome.status,
                    "body": (outcome.body or "")[:4000],
                    "body_omitted_chars": max(0, len(outcome.body or "") - 4000),
                    "hypothesis": outcome.hypothesis, "hypotheses": deepcopy(outcome.hypotheses),
                    "model": outcome.model, "cost_usd": outcome.cost_usd,
                    **({"language_reference_delivery": deepcopy(reference_fitting)}
                       if isinstance(reference_fitting, list) else {}),
                    **({"binary_initial_type_delivery": initial_binary_types.records()}
                       if initial_binary_types is not None else {}),
                    "source_unchanged_after_call": origin.source_identity is not None and current == origin.source_identity,
                    **({"binary_module_unchanged_after_call": binary_current,
                        "binary_view_unchanged_after_call": binary_view_current} if binary_snapshot is not None else {})})
            if not binary_current or not binary_view_current:
                from .knowledge_calls import KnowledgeCallRefused

                reason = "binary_module_changed_or_unavailable" if not binary_current else "binary_view_changed_or_unavailable"
                with self._lock:
                    # Paid attribution survives in events, but a failed call
                    # must never become a scheduling owner after view restore.
                    self._binary_review_scopes.pop((origin.pass_id, attempt_id), None)
                    if reservation is not None:
                        self._live_input_errors.add(reservation.packet.pass_id)
                        self._binary_context_records.pop(reservation.packet.pass_id, None)
                        self._binary_context_origins.pop(reservation.packet.pass_id, None)
                    self._events.append({"event": "review_input_invalidated", "attempt_id": attempt_id,
                        "pass_id": origin.pass_id, "domain": "binary", "phase": "post_call", "reason": reason})
                self.notify()
                raise KnowledgeCallRefused(reason)
            self._register(origin, ctx, outcome.review_result, delivered_references=reference_manifest,
                           initial_binary_types=initial_binary_types, initial_type_inventory=initial_type_inventory)
            self._register_caller_requests(origin, outcome.review_result, ctx=ctx)
            if reservation is None and isinstance(outcome.review_input_scope, ReviewInputScope):
                with self._lock:
                    self._source_review_scopes[(origin.pass_id, attempt_id)] = outcome.review_input_scope
            self.notify()
            return outcome

        setattr(review, "_knowledge_review_owner", self)
        return review

    def _capture_delivered_inputs(self, origin: KnowledgeOrigin, reservation: KnowledgeReservation | None,
                                  review: dict) -> tuple[dict | None, tuple[CapturedReviewInput, ...], bool]:
        """Use owned supplied material bindings, never model dependency guesses."""
        from .review_context_inputs import context_inputs_from_sources

        captured: list[CapturedReviewInput] = []
        study_seen = False
        valid = True
        explanations = reservation.packet.explanations if reservation is not None else ()
        caller_answers = {answer.request_id: answer for answer in
                          (reservation.packet.caller_contexts if reservation is not None else ())}
        if explanations and "source_study_delivery" not in review:
            study_seen = True
            valid = False
        study_rows = review.get("source_study_delivery", [])
        if not isinstance(study_rows, list):
            study_seen = True
            valid = False
            study_rows = []
        for row in study_rows:
            if not isinstance(row, dict) or type(row.get("delivered")) is not bool:
                study_seen = True
                valid = False
                continue
            if row["delivered"] is not True:
                continue
            study_seen = True
            linked = [answer for answer in explanations if answer.request_id == row.get("request_id")]
            materials = tuple(material for answer in linked for material in answer.inputs)
            expected_ids = list(dict.fromkeys(material.binding_id for material in materials))
            if not linked or not materials or row.get("input_binding_ids") != expected_ids:
                valid = False
                continue
            exported = self.bindings.snapshot_inputs(materials)
            if exported is None:
                valid = False
            else:
                captured.extend(exported)
        if caller_answers and "caller_context_delivery" not in review:
            valid = False
        caller_rows = review.get("caller_context_delivery", [])
        if not isinstance(caller_rows, list):
            valid = False
            caller_rows = []
        for row in caller_rows:
            if not isinstance(row, dict) or type(row.get("delivered")) is not bool:
                valid = False
                continue
            if row["delivered"] is not True:
                continue
            request_id = row.get("request_id")
            if not isinstance(request_id, str):
                valid = False
                continue
            answer = caller_answers.get(request_id)
            material = answer.material if answer is not None else None
            supplied = row.get("source_materials")
            if (material is None or not isinstance(supplied, list) or len(supplied) != 1
                    or not isinstance(supplied[0], dict)
                    or supplied[0].get("file") != material.file
                    or supplied[0].get("sha256") != material.source_identity.sha256
                    or supplied[0].get("source_version") != list(material.source_identity.version)):
                valid = False
                continue
            captured.append(CapturedReviewInput("target", self.target_root.resolve(),
                                               material.file, material.source_identity))
        manifest = None
        if study_seen or not valid:
            sources = [(source.root_label, source.file, source.source_identity.sha256) for source in captured]
            if origin.source_identity is None:
                valid = False
            else:
                sources.append(("target", origin.file, origin.source_identity.sha256))
            manifest = context_inputs_from_sources(sources, complete=valid)
        return manifest, tuple(dict.fromkeys(captured)), valid

    def publication_input_scope(self, reservation: KnowledgeReservation, candidate) -> ReviewInputScope | None:
        """Bind fresh contributing inputs to the candidate's exact durable set."""
        from .review_claims import read_history
        from .review_context_inputs import context_inputs_record_digest

        if not self._owned_reservation(reservation):
            return None
        history = read_history((candidate.review_result or {}).get("review_claims"))
        if history is None or "source_inputs" not in history:
            return None
        digest = context_inputs_record_digest(history["source_inputs"])
        if digest is None:
            return None
        with self._lock:
            if reservation.packet.pass_id in self._live_input_errors:
                return None
            sources = tuple(dict.fromkeys(
                source for group in self._live_input_sets.get(reservation.packet.pass_id, ())
                for source in group))
        return ReviewInputScope(reservation.origin, digest, sources)

    def bind_review_input_scope(self, outcome, *, members=None) -> None:
        """Attach the combined pass scope after panel reconstruction."""
        from .review_claims import read_history

        from core.inventory.binary_builder import BINARY_PATH_PREFIX
        if outcome.file.startswith(BINARY_PATH_PREFIX):
            self._bind_binary_publication_scope(outcome)
            return
        if members is not None:
            outcome.review_input_scope = None
        line = outcome.line or 0
        if type(line) is not int or line <= 0:
            history = read_history((outcome.review_result or {}).get("review_claims"))
            review = history.get("review") if history is not None else None
            origin = review.get("origin") if isinstance(review, dict) else None
            if (not isinstance(origin, dict)
                    or (origin.get("file"), origin.get("function")) != (outcome.file, outcome.function)):
                return
            line = origin.get("line_start")
        if type(line) is not int or line <= 0:
            return
        with self._lock:
            reservation = self._active_units.get((outcome.file, outcome.function, line))
        if reservation is not None:
            outcome.review_input_scope = self.publication_input_scope(reservation, outcome)
        else:
            from .source_panel_scope import combine_source_panel_scope

            # Explicit initial-member admission must never retain an earlier
            # attached scope when one contributor or the aggregate is invalid.
            outcome.review_input_scope = None
            def owned(key):
                with self._lock:
                    return self._source_review_scopes.get(key)

            outcome.review_input_scope = combine_source_panel_scope(
                outcome, members=members, owned=owned, target_root=self.target_root)

    def _bind_binary_publication_scope(self, outcome) -> None:
        """Restore only original owner-held scopes after panel reconstruction."""
        from .review_claims import read_history

        review_result = dict(outcome.review_result or {})
        history = read_history(review_result.get("review_claims"))
        reviews = []
        if history is not None:
            if isinstance(history.get("review"), dict):
                reviews.append(history["review"])
            reviews.extend(intake["review"] for intake in history["intakes"]
                           if isinstance(intake.get("review"), dict))
        scopes: list[BinaryReviewPublicationScope] = []
        with self._lock:
            for review in reviews:
                origin = review.get("origin")
                if (not isinstance(origin, dict) or (origin.get("file"), origin.get("function"))
                        != (outcome.file, outcome.function)):
                    scopes = []
                    break
                pass_id, attempt_id = origin.get("pass_id"), review.get("attempt_id")
                if (not isinstance(pass_id, str) or not pass_id
                        or not isinstance(attempt_id, str) or not attempt_id
                        or type(origin.get("line_start")) is not int or origin.get("line_start") != 0
                        or origin.get("source_identity") is not None):
                    scopes = []
                    break
                owned = self._binary_review_scopes.get((pass_id, attempt_id))
                if pass_id in self._live_input_errors or owned is None:
                    scopes = []
                    break
                scope, owned_origin = owned
                expected_origin = asdict(owned_origin)
                # Canonical JSON normalizes tuple/list transport while keeping
                # numeric types distinct (a float/bool is not an input stamp).
                if json.dumps(origin, sort_keys=True, allow_nan=False) != json.dumps(
                        expected_origin, sort_keys=True, allow_nan=False):
                    scopes = []
                    break
                scopes.append(scope)
        admitted = bool(scopes) and all(scope == scopes[0] and scope.current(self.target_root) for scope in scopes)
        outcome.binary_publication_scope = scopes[0] if admitted else None
        review_result["binary_review_binding"] = scopes[0].record() if admitted else None
        outcome.review_result = review_result

    def source_roots(self) -> dict[str, Path]:
        return self.bindings.registered_roots()

    def _signature(self, request: KnowledgeRequest, ctx: dict) -> tuple:
        language = ctx.get("language") if isinstance(ctx.get("language"), str) else ""
        return (self._key(request.origin), origin_input_identity(request.origin), request.kind, request.subject,
                request.context, request.resolution, request.entry_id, request.source_line,
                language if request.kind == "language_reference" else "")

    def _duplicate_is_reusable(self, request_id: str) -> bool:
        with self._lock:
            answers = tuple(self._source_answers.get(request_id, ()))
        # A changed dependency may make a previously answered subject useful
        # again, without renewing the unit's round/model-call allowance.
        return (not answers or not any(a.materials for a in answers)
                or any(self.bindings.admit(a)[0] for a in answers if a.materials))

    def binary_assessment_observation(self, outcome) -> tuple[BinaryReviewPublicationScope, BinaryKnowledgeOrigin] | None:
        """Return an original live observation owned by this Runtime only.

        Historical JSON and a supplied scope cannot authenticate a prior review.
        This read path reuses the panel reconstruction registry checks; it does
        not admit another call or confer verification authority.
        """
        from .review_claims import read_history

        if type(getattr(outcome, "line", None)) is not int or outcome.line != 0:
            return None
        self.bind_review_input_scope(outcome)
        scope = getattr(outcome, "binary_publication_scope", None)
        if (not isinstance(scope, BinaryReviewPublicationScope)
                or scope.view_identity is None or scope.view_identity.analysis_sha256 is None):
            return None
        result = getattr(outcome, "review_result", None)
        history = read_history(result.get("review_claims")) if isinstance(result, dict) else None
        review = history.get("review") if history is not None else None
        if not isinstance(review, dict):
            return None
        origin = review.get("origin")
        if not isinstance(origin, dict):
            return None
        pass_id, attempt_id = origin.get("pass_id"), review.get("attempt_id")
        if not isinstance(pass_id, str) or not isinstance(attempt_id, str):
            return None
        with self._lock:
            if self._closed:
                return None
            owned = self._binary_review_scopes.get((pass_id, attempt_id))
            if (owned is None or owned[0] is not scope
                    or owned[1].pass_id in self._live_input_errors):
                return None
        return owned if scope.current(self.target_root) else None

    def _register_binary_subjects(self, origin: BinaryKnowledgeOrigin, ctx: dict,
                                  batch: KnowledgeBatch, *, initial_delivery=None, initial_inventory=None) -> None:
        """Keep recovered metadata out of source-study requests and receipts."""
        from .binary_subjects import (BinarySubjectContext, coalesce_binary_subject_contexts,
                                      resolve_binary_subjects)
        from .continuation_context import context_version

        key = self._key(origin)
        accepted = []
        # Fitting progress is local metadata availability, not a restarted
        # study/producer job. Compute material checks outside the runtime lock.
        from .binary_initial_type_delivery import InitialBinaryTypeDelivery, InitialBinaryTypeInventory
        omitted, prefiltered = set(), set()
        if isinstance(initial_inventory, InitialBinaryTypeInventory) and initial_inventory.origin == origin:
            delivery = (initial_delivery if isinstance(initial_delivery, InitialBinaryTypeDelivery)
                        and initial_delivery.origin == origin else None)
            rows = delivery.records() if delivery is not None else []
            for request in batch.accepted:
                if request.kind != "target_study" or not initial_inventory.contains(request.subject):
                    continue
                if delivery is not None and delivery.permits_omission(request.subject, ctx, origin):
                    omitted.add(request.request_id)
                if not any(row["subject"] == request.subject and row["status"] == "omitted" for row in rows):
                    prefiltered.add(request.request_id)
        with self._lock:
            self._events.append({"event": "requests_registered", "origin": asdict(origin),
                                 "accepted": [asdict(r) for r in batch.accepted],
                                 "rejected": [asdict(r) for r in batch.rejected]})
            for request in batch.accepted:
                signature = self._signature(request, ctx)
                duplicate = self._semantic_requests.get(signature)
                self._requests[request.request_id] = request
                if request.request_id in prefiltered:
                    self._binary_initial_guarded.add(request.request_id)
                prior_status = self._request_status.get(duplicate, {}) if duplicate is not None else {}
                if (duplicate is not None and request.request_id in omitted
                        and (duplicate in self._binary_initial_guarded
                             or prior_status.get("state") == "unavailable"
                             and prior_status.get("reason") == "initial_type_delivery_unmeasured")):
                    # No producer lookup ran for the earlier prefilter refusal.
                    # Keep its request/status and every consumed model credit.
                    duplicate = None
                if duplicate is not None:
                    self._request_status[request.request_id] = {"state": "duplicate", "duplicate_of": duplicate}
                    self._events.append({"event": "request_duplicate", "request_id": request.request_id,
                                         "duplicate_of": duplicate, "pass_id": origin.pass_id})
                else:
                    self._semantic_requests[signature] = request.request_id
                    accepted.append(request)
            owned = next((scope for scope, original in self._binary_review_scopes.values()
                          if original == origin), None)
            refusal = ("runtime_closed" if self._closed else
                       "deadline" if monotonic() >= self.deadline else
                       "model_call_count_unavailable" if key in self._unknown_calls else "")
        targets = []
        for request in accepted:
            if request.kind == "language_reference":
                answer = lookup(request.request_id, request.subject, ReferenceContext("binary"),
                                entry_id=request.entry_id)
                with self._lock:
                    self._request_status[request.request_id] = {
                        "state": "unavailable" if answer.status == "unsupported" else "deferred",
                        "reason": answer.reason if answer.status == "unsupported" else
                                  "binary_reference_continuation_unavailable"}
                    self._events.append({"event": "reference_answer", "answer": asdict(answer),
                                         "origin": asdict(origin)})
            else:
                targets.append(request)
        if not targets:
            return
        if refusal or owned is None or not owned.current(self.target_root):
            with self._lock:
                for request in targets:
                    self._request_status[request.request_id] = {
                        "state": "deferred", "reason": refusal or "binary_original_input_unavailable"}
            return
        resolved = resolve_binary_subjects(tuple(targets), ctx, owned, initial_delivery=initial_delivery,
                                          initial_inventory=initial_inventory)
        if resolved is None:
            with self._lock:
                for request in targets:
                    self._request_status[request.request_id] = {
                        "state": "deferred", "reason": "binary_original_input_unavailable"}
            return
        with self._lock:
            for subject_answer in resolved.answers:
                self._request_status[subject_answer.request_id] = {
                    "state": "resolved_partial" if subject_answer.status == "partial" else "unavailable",
                    "reason": subject_answer.reason}
                self._events.append({"event": "binary_subject_answer", "origin": asdict(origin),
                    "request_id": subject_answer.request_id, "subject": subject_answer.subject, "status": subject_answer.status,
                    "reason": subject_answer.reason, "material": subject_answer.material,
                    "role": "recovered_binary_type_context_not_evidence"})
        with self._lock:
            subject_lock = self._binary_subject_locks.setdefault(key, Lock())
        # Resolve outside this lock, but serialize union and offer per unit.
        # An older thread must not overwrite a newer accumulated version.
        # Currentness callbacks never run under the Runtime-wide lock.
        with subject_lock:
            previous = self._binary_subject_pending.get(key, ctx.get("binary_subject_context"))
            if isinstance(previous, BinarySubjectContext) and previous.current(ctx):
                merged, why = coalesce_binary_subject_contexts(previous, resolved, ctx)
                if merged is None:
                    with self._lock:
                        for request in targets:
                            self._request_status[request.request_id] = {"state": "deferred", "reason": why}
                            self._events.append({"event": "binary_subject_context_deferred",
                                "request_id": request.request_id, "origin": asdict(origin), "reason": why})
                    return
                resolved = merged
            rendered = resolved.render()
            if not rendered or not resolved.current(ctx):
                return
            self._binary_subject_pending[key] = resolved
            version = context_version(rendered)
            # Initial contexts remain untouched; only the reserved continuation
            # receives the union of original, still-current observations.
            offered_ctx = dict(ctx)
            offered_ctx["binary_subject_context"] = resolved
            self.offer_context_delta(offered_ctx, kind="binary_target_semantics", version=version)

    def _register(self, origin: KnowledgeOrigin, ctx: dict, review_result, *, delivered_references=None,
                  initial_binary_types=None, initial_type_inventory=None) -> None:
        batch = register_requests(review_result, origin)
        if isinstance(origin, BinaryKnowledgeOrigin):
            self._register_binary_subjects(origin, ctx, batch, initial_delivery=initial_binary_types,
                                            initial_inventory=initial_type_inventory)
            return
        key = self._key(origin)
        current = capture_source_identity(self.target_root, origin.file)
        accepted = []
        for request in batch.accepted:
            signature = self._signature(request, ctx)
            with self._lock:
                duplicate = self._semantic_requests.get(signature)
            reusable = duplicate is not None and self._duplicate_is_reusable(duplicate)
            with self._lock:
                self._requests[request.request_id] = request
                if reusable:
                    self._request_status[request.request_id] = {"state": "duplicate", "duplicate_of": duplicate}
                    self._events.append({"event": "request_duplicate", "request_id": request.request_id,
                                         "duplicate_of": duplicate, "pass_id": origin.pass_id})
                else:
                    self._semantic_requests[signature] = request.request_id
                    accepted.append(request)
                    self._request_status[request.request_id] = {"state": "registered"}
        # A repeated question about text this exact invocation already saw
        # is not materially new information and must not buy another pass.
        if (delivered_references is not None and origin.source_identity is not None
                and current == origin.source_identity):
            from .reference_inputs import reference_answer_already_delivered
            unresolved = []
            language = ctx.get("language")
            reference_context = ReferenceContext(language if isinstance(language, str) else "")
            for request in accepted:
                if request.kind == "language_reference":
                    answer = lookup(request.request_id, request.subject, reference_context, entry_id=request.entry_id)
                    if reference_answer_already_delivered(answer, delivered_references):
                        with self._lock:
                            self._request_status[request.request_id] = {"state": "already_delivered",
                                "reason": "identical_reference_entries_already_in_this_prompt"}
                            self._events.append({"event": "reference_already_delivered",
                                "request_id": request.request_id, "pass_id": origin.pass_id,
                                "entries": [entry.entry_id for entry in answer.entries]})
                        continue
                unresolved.append(request)
            accepted = unresolved
        active_batch = KnowledgeBatch(tuple(accepted), batch.rejected)
        with self._lock:
            self._events.append({"event": "requests_registered", "origin": asdict(origin),
                                 "accepted": [asdict(r) for r in batch.accepted],
                                 "rejected": [asdict(r) for r in batch.rejected]})
            if not accepted:
                return
            cycle = self._cycles.get(key)
            if cycle is None:
                cycle = KnowledgeCycle(origin, active_batch, deadline=self.deadline,
                                       admit_study=self.bindings.admit, admit_caller_context=self._admit_caller_context,
                                       **self._policy)
                self._cycles[key] = cycle
                created = True
            else:
                created = False
            closed = self._closed
            source_closed = self._sources_closed
            unknown_calls = key in self._unknown_calls
        # Never hold the runtime lock across cycle/binding callbacks.
        if not created and not cycle.add_requests(active_batch):
            for request in accepted:
                self._defer_source(request, cycle, "different_review_snapshot")
            return
        reason = ("runtime_closed" if closed else
                  "source_identity_unavailable" if origin.source_identity is None else
                  "source_changed_during_review" if current != origin.source_identity else
                  "model_call_count_unavailable" if unknown_calls else
                  "study_consumer_closed" if source_closed else "")
        language = ctx.get("language")
        context = ReferenceContext(language if isinstance(language, str) else "")
        for request in accepted:
            if request.kind == "language_reference":
                answer = lookup(request.request_id, request.subject, context, entry_id=request.entry_id)
                cycle.reference(answer, now=monotonic())
                with self._lock:
                    self._request_status[request.request_id] = {"state": "context_available" if answer.entries else "unavailable",
                                                               "answer_status": answer.status, "reason": answer.reason}
                    self._events.append({"event": "reference_answer", "answer": asdict(answer)})
            elif reason:
                self._defer_source(request, cycle, reason)
            else:
                # Register before enqueue: the consumer may finish immediately.
                with self._lock:
                    self._pending_sources.add(request.request_id)
                    self._request_status[request.request_id] = {"state": "queued"}
                if not self.study_queue.enqueue_knowledge(request):
                    self._defer_source(request, cycle, "study_queue_closed")
        self.notify()

    def _admit_caller_context(self, answer: CallerContextAnswer) -> tuple[bool, str]:
        with self._lock:
            request = self._caller_requests.get(answer.request_id)
            owned = self._caller_answers.get(answer.request_id)
        material = answer.material
        if (request is None or owned is not answer or answer.origin != request.origin
                or material is None or (material.file, material.function, material.line_start) !=
                (request.caller_file, request.caller_function, request.caller_line)):
            return False, "caller_context_request_mismatch"
        try:
            return validate_caller_context(answer, self.target_root)
        except Exception:
            return False, "caller_context_validation_error"

    def _register_binary_callers(self, origin: BinaryKnowledgeOrigin, ctx: dict | None, batch) -> None:
        """Resolve recorded binary related code without source caller packets."""
        from .binary_callers import BinaryCallerContext, resolve_binary_callers
        from .continuation_context import context_version

        key = self._key(origin)
        with self._lock:
            self._events.append({"event": "caller_requests_registered", "origin": asdict(origin),
                                 "accepted": [asdict(r) for r in batch.accepted],
                                 "rejected": [asdict(r) for r in batch.rejected]})
            for request in batch.accepted:
                self._caller_requests[request.request_id] = request
            owned = next((scope for scope, original in self._binary_review_scopes.values()
                          if original == origin), None)
            refusal = ("runtime_closed" if self._closed else
                       "deadline" if monotonic() >= self.deadline else
                       "model_call_count_unavailable" if key in self._unknown_calls else "")
        addressed = []
        for request in batch.accepted:
            reason = ("binary_context_binding_unavailable" if request.caller_address is None else
                      refusal or ("binary_original_input_unavailable" if ctx is None or owned is None
                                  or not owned.current(self.target_root) else ""))
            if reason:
                answer = CallerContextAnswer(request.request_id, origin, None, "deferred", reason)
                with self._lock:
                    self._caller_answers[request.request_id] = answer
                    self._request_status[request.request_id] = {"state": "deferred", "reason": reason}
                    self._events.append({"event": "caller_context_answer", "answer": asdict(answer),
                                         "changed_information": False})
            else:
                addressed.append(request)
        if not addressed or ctx is None or owned is None:
            return
        resolved = resolve_binary_callers(tuple(addressed), ctx, owned)
        if resolved is None:
            with self._lock:
                for request in addressed:
                    self._request_status[request.request_id] = {
                        "state": "deferred", "reason": "binary_original_input_unavailable"}
            return
        with self._lock:
            for binary_answer in resolved.answers:
                self._request_status[binary_answer.request_id] = {
                    "state": "resolved_partial" if binary_answer.status == "partial" else "unavailable",
                    "reason": binary_answer.reason}
                request = self._caller_requests[binary_answer.request_id]
                self._events.append({"event": "binary_caller_answer", "origin": asdict(request.origin),
                    "request_id": binary_answer.request_id, "status": binary_answer.status, "reason": binary_answer.reason,
                    "material": binary_answer.material, "role": "binary_related_code_context_not_evidence"})
            caller_lock = self._binary_caller_locks.setdefault(key, Lock())

        def defer_union(why: str) -> None:
            with self._lock:
                for request in addressed:
                    self._request_status[request.request_id] = {"state": "deferred", "reason": why}
                    self._events.append({"event": "binary_caller_context_deferred",
                        "request_id": request.request_id, "origin": asdict(request.origin), "reason": why})

        # Keep fresh initial contexts untouched while retaining all ready views.
        # Serializing union plus offer prevents a slower earlier registration
        # from replacing a newer packet. No global lock covers read callbacks.
        with caller_lock:
            previous = self._binary_caller_pending.get(key, ctx.get("binary_caller_context"))
            if isinstance(previous, BinaryCallerContext) and previous.current(ctx):
                requests = {request.request_id: request for request in previous.requests}
                answers = {answer.request_id: answer for answer in previous.answers}
                for request in resolved.requests:
                    if request.request_id in requests and requests[request.request_id] != request:
                        defer_union("binary_caller_observation_conflict")
                        return
                    requests[request.request_id] = request
                for binary_answer in resolved.answers:
                    if binary_answer.request_id in answers and answers[binary_answer.request_id] != binary_answer:
                        defer_union("binary_caller_observation_conflict")
                        return
                    answers[binary_answer.request_id] = binary_answer
                combined = BinaryCallerContext(origin, owned, tuple(requests.values()), tuple(answers.values()))
                if not combined.render():
                    defer_union("binary_caller_context_budget")
                    return
                merged = resolve_binary_callers(combined.requests, ctx, owned)
                if merged is None:
                    defer_union("binary_caller_context_changed")
                    return
                resolved = merged
            rendered = resolved.render()
            if not rendered or not resolved.current(ctx):
                return
            self._binary_caller_pending[key] = resolved
            offered = dict(ctx)
            offered["binary_caller_context"] = resolved
            self.offer_context_delta(offered, kind="binary_callers", version=context_version(rendered))

    def _register_caller_requests(self, origin: KnowledgeOrigin, review_result, *, ctx: dict | None = None) -> None:
        batch = register_caller_context_requests(review_result, origin)
        if not batch.accepted and not batch.rejected:
            return
        if isinstance(origin, BinaryKnowledgeOrigin):
            self._register_binary_callers(origin, ctx, batch)
            return
        key = self._key(origin)
        with self._lock:
            self._events.append({"event": "caller_requests_registered", "origin": asdict(origin),
                                 "accepted": [asdict(r) for r in batch.accepted],
                                 "rejected": [asdict(r) for r in batch.rejected]})
            for request in batch.accepted:
                self._caller_requests[request.request_id] = request
            if not batch.accepted:
                return
            cycle = self._cycles.get(key)
            if cycle is None:
                cycle = KnowledgeCycle(origin, KnowledgeBatch((), ()), deadline=self.deadline,
                    admit_study=self.bindings.admit, admit_caller_context=self._admit_caller_context, **self._policy)
                self._cycles[key] = cycle
            closed = self._closed
            unknown_calls = key in self._unknown_calls
            calls = self._calls.get(key, 0)
        if not cycle.add_caller_requests(batch.accepted):
            with self._lock:
                for request in batch.accepted:
                    self._request_status[request.request_id] = {
                        "state": "deferred", "reason": "different_review_snapshot"}
            return
        current = capture_source_identity(self.target_root, origin.file)
        for request in batch.accepted:
            reason = ("runtime_closed" if closed else
                      "binary_context_binding_unavailable" if origin.file.startswith("binary:")
                      or request.caller_file.startswith("binary:") else
                      "source_identity_unavailable" if origin.source_identity is None else
                      "source_changed_during_review" if current != origin.source_identity else
                      "model_call_count_unavailable" if unknown_calls else
                      "deadline" if monotonic() >= self.deadline else
                      "continuation_limit" if cycle.started >= cycle.max_continuations else
                      "model_call_limit" if calls >= cycle.max_model_calls else "")
            try:
                answer = (CallerContextAnswer(request.request_id, request.origin, None, "deferred", reason)
                          if reason else resolve_caller_context(request, self.target_root, self._caller_inventory))
            except Exception:
                answer = CallerContextAnswer(request.request_id, request.origin, None, "deferred",
                                             "caller_context_resolution_error")
            signature = (key, origin_input_identity(origin), request.caller_file,
                         request.caller_function, request.caller_line)
            with self._lock:
                prior_id = self._caller_semantic.get(signature)
                prior = self._caller_answers.get(prior_id) if prior_id else None
                unchanged = (prior is not None and prior.material == answer.material
                             and prior.status == answer.status and prior.reason == answer.reason)
                self._caller_semantic[signature] = request.request_id
                self._caller_answers[request.request_id] = answer
                self._request_status[request.request_id] = {
                    "state": "duplicate" if unchanged else "context_available"
                    if answer.material is not None else "deferred" if answer.status == "deferred" else "unavailable",
                    "answer_status": answer.status, "reason": answer.reason,
                    **({"duplicate_of": prior_id} if unchanged else {}),
                }
                self._events.append({"event": "caller_context_answer", "answer": asdict(answer),
                                     "changed_information": not unchanged})
            cycle.caller_context(answer, now=monotonic(), changed=not unchanged)
        self.notify()

    def _defer_source(self, request: KnowledgeRequest, cycle: KnowledgeCycle, reason: str) -> None:
        cycle.finished(request.request_id)
        with self._lock:
            self._pending_sources.discard(request.request_id)
            self._request_status[request.request_id] = {"state": "deferred", "reason": reason}
            self._events.append({"event": "study_deferred", "request_id": request.request_id, "reason": reason})

    def admit_source_attempt(self, requests: tuple[KnowledgeRequest, ...], *,
                             dispatch_lease: StudyDispatchLease | None = None) -> bool:
        """Count an owned structured dispatch, after the shared throttle admits it.

        Hidden provider retries remain the budget client's responsibility. A
        shared call contributes once to every unit whose request it contains.
        """
        packet_reason = ""
        if self._study_jobs is not None:
            from .knowledge_calls import KnowledgeCallRefused
            try:
                self.source_dispatch_valid(dispatch_lease)
            except KnowledgeCallRefused as error:
                packet_reason = error.reason
        current = {r.origin.file: capture_source_identity(self.target_root, r.origin.file)
                   for r in requests}
        keys = {(r.origin.file, r.origin.function, r.origin.line_start) for r in requests}
        with self._lock:
            reason = ("runtime_closed" if self._closed or self._sources_closed else
                      "empty_study_packet" if not requests else
                      "deadline" if monotonic() >= self.deadline else
                      "unowned_study_request" if any(self._requests.get(r.request_id) != r for r in requests) else
                      "source_changed_before_study" if any(
                          r.origin.source_identity is None or current[r.origin.file] != r.origin.source_identity
                          for r in requests) else
                      packet_reason if packet_reason else
                      "study_dispatch_participants_mismatch" if self._study_jobs is not None and (
                          type(dispatch_lease) is not StudyDispatchLease
                          or dispatch_lease.request_ids != tuple(r.request_id for r in requests)
                          or self._source_dispatch_units.get(dispatch_lease.lease_id) != tuple(sorted(keys))) else
                      "model_call_count_unavailable" if keys & self._unknown_calls else
                      "model_call_limit" if any(
                          key not in self._cycles or self._calls.get(key, 0) >= self._cycles[key].max_model_calls
                          for key in keys) else
                      "review_call_reserve" if self._study_jobs is not None and any(
                          self._calls.get(key, 0) + 1 + self._study_reserved_calls(key)
                          > self._cycles[key].max_model_calls for key in keys) else "")
            if not reason and self._study_jobs is not None:
                reason = (self._study_jobs.admission_rejection(dispatch_lease)
                          if dispatch_lease is not None else "study_job_lease_unavailable") or ""
            if reason:
                self._events.append({"event": "study_dispatch_refused", "reason": reason,
                                     "request_ids": [r.request_id for r in requests]})
                return False
            if self._study_jobs is not None:
                assert dispatch_lease is not None
                self._study_jobs.debit(dispatch_lease)
            for key in keys:
                self._calls[key] = self._calls.get(key, 0) + 1
            self._events.append({"event": "study_attempt",
                                 "request_ids": [r.request_id for r in requests]})
            return True

    def track_source_job(self, subjects: StudySubjects) -> None:
        """Expose the existing phase's result stream to the owner thread."""
        with self._lock:
            self._source_jobs.append(subjects)
        self.notify()

    def poll_source_updates(self) -> None:
        # Clear before reading: concurrent writes either enter this drain or
        # leave a wake-up set, never disappear between drain and clear.
        self._wakeup.clear()
        with self._lock:
            jobs = tuple(self._source_jobs)
        for subjects in jobs:
            self.record_source_answers(subjects.drain_updates())
        self._queue_retired_source_dispatches()

    def finish_source_job(self, subjects: StudySubjects) -> None:
        self.record_source_answers(subjects.drain_updates())
        with self._lock:
            owner = self._source_job_owners.get(id(subjects))
            if self._study_jobs is not None and owner is not None:
                self._study_jobs.owner_finished(owner[1])
            if subjects in self._source_jobs:
                self._source_jobs.remove(subjects)
        self.notify()

    def record_source_answers(self, answers: tuple[SubjectExplanation, ...]) -> None:
        """Retain explanations as context and notify their existing unit cycle."""
        for answer in answers:
            rejected = False
            cycle = None
            with self._lock:
                request = self._requests.get(answer.request_id)
                if request is None or request.kind != "target_study":
                    self._events.append({"event": "source_answer_rejected", "reason": "unknown_request"})
                    continue
                key = (request.origin.file, request.origin.function, request.origin.line_start)
                if (self._study_jobs is not None and answer.reason == "study_job_dispatch_live"
                        and answer.status == "unavailable" and answer.producer == "pipeline"
                        and answer.request_id in self._transient_source_refusal_ids):
                    # The attempted packet never entered a provider. Keep the
                    # original request and cycle pending for its own replay.
                    self._events.append({"event": "semantic_study_dispatch_still_pending",
                                         "request_id": answer.request_id, "reason": answer.reason})
                    continue
                if (self._study_jobs is not None and answer.status in {"answered", "partial"}
                        and not self._study_answer_scope_owned(answer)):
                    reason = "semantic_study_attempt_scope_unavailable"
                    self._events.append({"event": "source_answer_rejected", "request_id": answer.request_id,
                                         "reason": reason})
                    if answer.request_id in self._pending_sources:
                        self._pending_sources.discard(answer.request_id)
                        self._request_status[answer.request_id] = {"state": "deferred", "reason": reason}
                        cycle = self._cycles.get(key)
                    rejected = True
                else:
                    cycle = self._cycles.get(key)
                    prior = self._source_answers.setdefault(answer.request_id, [])
                    if answer in prior:
                        continue
                    prior.append(answer)
                    self._pending_sources.discard(answer.request_id)
                    self._request_status[answer.request_id] = {
                        "state": "context_available" if answer.status in ("answered", "partial") else "unavailable",
                        "answer_status": answer.status, "reason": answer.reason}
                    self._events.append({"event": "source_answer", "answer": asdict(answer)})
                for ids in tuple(self._deferred_source_dispatches):
                    if not any(request_id in self._pending_sources for request_id in ids):
                        self._deferred_source_dispatches.pop(ids, None)
                        self._deferred_source_dispatch_states.pop(ids, None)
            if cycle is not None:
                if not rejected:
                    cycle.explanation(answer, now=monotonic())
                cycle.finished(answer.request_id)
        if answers:
            self.notify()

    def requests(self) -> tuple[KnowledgeRequest, ...]:
        with self._lock:
            return tuple(self._requests.values())

    def caller_requests(self) -> tuple[CallerContextRequest, ...]:
        with self._lock:
            return tuple(self._caller_requests.values())

    def events(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(deepcopy(self._events))

    def ready_continuations(self, *, admission: Callable[[], bool], now: float | None = None,
                            required_calls: int = 1) -> tuple[KnowledgeReservation, ...]:
        if type(required_calls) is not int or required_calls < 1:
            raise ValueError("a continuation requires a positive known dispatch count")
        self.poll_source_updates()
        now = monotonic() if now is None else now
        with self._lock:
            if self._closed:
                return ()
            self._required_calls = required_calls
            candidates = tuple((key, cycle, self._calls.get(key, 0) if key not in self._unknown_calls else None)
                               for key, cycle in self._cycles.items()
                               if key not in self._busy and key not in self._active_units and key not in self._reserving)
        ready = []
        for key, cycle, calls in candidates:
            reservation = self._reserve_cycle(key, cycle, calls, now=now,
                                              admission=admission, required_calls=required_calls)
            if reservation is not None:
                ready.append(reservation)
        return tuple(ready)

    def _current_binary_cycle_input(self, origin: BinaryKnowledgeOrigin):
        with self._lock:
            owned = self._binary_cycle_scopes.get(self._key(origin))
        if owned is None:
            return None
        scope, original = owned
        return (origin.binary_identity if self._same_snapshot(origin, original)
                and scope.current(self.target_root) else None)

    def publication_binary_scope(self, reservation: KnowledgeReservation, outcome):
        """Bind exact historical contributors only to their original live owner."""
        from .binary_context_inputs import binary_context_record_digest
        from .review_claims import read_history
        from core.json import dumps_canonical

        if not isinstance(reservation.origin, BinaryKnowledgeOrigin) or not self.can_publish(reservation):
            return None
        history = read_history((outcome.review_result or {}).get("review_claims"))
        record = history.get("binary_inputs") if history is not None else None
        digest = binary_context_record_digest(record)
        if digest is None or not isinstance(record, dict):
            return None
        if "inputs" in record:
            if record.get("complete") is not True:
                return None
            members = record["inputs"]
        else:
            members = [record]
        with self._lock:
            owned = self._binary_cycle_scopes.get(self._key(reservation.origin))
            allowed = {dumps_canonical(row) for pass_id, rows in self._binary_context_records.items()
                       if pass_id in self._binary_context_origins
                       and self._same_snapshot(self._binary_context_origins[pass_id], reservation.origin)
                       for row in rows}
            fresh = {dumps_canonical(row) for row in self._binary_context_records.get(reservation.packet.pass_id, ())}
            fresh_scopes = [scope for (pass_id, _attempt), (scope, original) in self._binary_review_scopes.items()
                            if pass_id == reservation.packet.pass_id
                            and self._same_snapshot(original, reservation.origin)]
        encoded = {dumps_canonical(row) for row in members}
        if (owned is None or not encoded or not encoded <= allowed or not fresh or not fresh <= encoded
                or not fresh_scopes or not all(scope.current(self.target_root) for scope in fresh_scopes)):
            return None
        scope, original = owned
        if not self._same_snapshot(original, reservation.origin) or not scope.current(self.target_root):
            return None
        return replace(fresh_scopes[0], context_digest=digest)

    def offer_context_delta(self, ctx: dict, *, kind: str, version: str) -> bool:
        """Offer an exact pipeline-owned rendered-input version, not a claim."""
        from .continuation_context import context_spec

        spec = context_spec(ctx, kind=kind, version=version)
        if spec is None:
            return False
        origin = self._origin(ctx)
        key = self._key(origin)
        binary_owned = None
        external_payload: tuple[str, object] | None = None
        if isinstance(origin, BinaryKnowledgeOrigin):
            if kind not in ("disagreement", "binary_target_semantics", "binary_callers", "binary_callee_assessments"):
                return False
            with self._lock:
                binary_owned = next(((scope, original) for scope, original in self._binary_review_scopes.values()
                    if self._same_snapshot(origin, original)), None)
            if binary_owned is None or not binary_owned[0].current(self.target_root):
                return False
            # Empty-request initial passes still need their original owned
            # observation. Never create a fresh binary epoch on a late offer.
            origin = binary_owned[1]
            field = spec["context_key"]
            if kind == "binary_target_semantics":
                from .binary_subjects import BinarySubjectContext
                value = ctx.get(field)
                if not isinstance(value, BinarySubjectContext) or not value.current(ctx):
                    return False
                payload: object = value
            elif kind == "binary_callee_assessments":
                from .binary_callee_assessments import BinaryCalleeAssessmentContext
                value = ctx.get(field)
                if not isinstance(value, BinaryCalleeAssessmentContext) or not value.current(ctx):
                    return False
                payload = value
            elif kind == "binary_callers":
                from .binary_callers import BinaryCallerContext
                value = ctx.get(field)
                if not isinstance(value, BinaryCallerContext) or not value.current(ctx):
                    return False
                payload = value
            else:
                value = ctx.get(field)
                if not isinstance(value, dict):
                    return False
                # Retain only the renderer's validated primitive inputs, not
                # arbitrary producer metadata or aliases to a shared panel dict.
                payload = {"resolution": value.get("resolution", ""),
                           "mechanical_reachable": value.get("mechanical_reachable"),
                           "mechanical_has_flow": value.get("mechanical_has_flow")}
            captured_ctx = dict(ctx)
            captured_ctx[field] = payload
            if context_spec(captured_ctx, kind=kind, version=version) != spec:
                return False
            external_payload = field, payload
        elif origin.source_identity is None:
            return False
        with self._lock:
            if self._closed:
                return False
            cycle = self._cycles.get(key)
            if cycle is None:
                cycle = KnowledgeCycle(origin, KnowledgeBatch((), ()), deadline=self.deadline,
                    admit_study=self.bindings.admit, admit_caller_context=self._admit_caller_context, **self._policy)
                self._cycles[key] = cycle
            if not self._same_snapshot(origin, cycle.origin):
                return False
            if binary_owned is not None:
                self._binary_cycle_scopes.setdefault(key, binary_owned)
            self._context_deltas[(key, spec["context_id"])] = spec
            if external_payload is not None:
                # Install the original input before notifying the coordinator.
                self._binary_external_payloads[(key, spec["context_id"])] = external_payload
        offered = cycle.context_delta(spec["context_id"], now=monotonic(), kind=kind)
        if offered:
            with self._lock:
                self._events.append({"event": "context_delta_offered", "origin": asdict(origin), **spec})
            self.notify()
        return offered

    def reserve_context_continuation(self, ctx: dict, *, admission: Callable[[], bool],
                                     required_calls: int = 1,
                                     required_context_id: str | None = None) -> KnowledgeReservation | None:
        """Use the same round, call and source gates as knowledge continuations."""
        origin = self._origin(ctx)
        key = self._key(origin)
        with self._lock:
            cycle = self._cycles.get(key)
            if cycle is None or not self._same_snapshot(origin, cycle.origin):
                return None
            calls = self._calls.get(key, 0) if key not in self._unknown_calls else None
            spec = self._context_deltas.get((key, required_context_id)) if required_context_id is not None else None
            spec = dict(spec) if spec is not None else None
        if required_context_id is not None:
            from .continuation_context import context_spec

            # Rendering can consult original observation/canonical-owner
            # callbacks. Never invoke those while holding the Runtime lock.
            if spec is None or context_spec(ctx, kind=spec["kind"], version=spec["version"]) != spec:
                return None
            with self._lock:
                if (self._cycles.get(key) is not cycle
                        or self._context_deltas.get((key, required_context_id)) != spec):
                    return None
                calls = self._calls.get(key, 0) if key not in self._unknown_calls else None
        return self._reserve_cycle(key, cycle, calls, now=monotonic(),
                                   admission=admission, required_calls=required_calls,
                                   required_context_ids=(() if required_context_id is None else (required_context_id,)))

    def _reserve_cycle(self, key, cycle, calls, *, now, admission, required_calls, required_context_ids=()):
        with self._lock:
            if self._closed or key in self._busy or key in self._active_units or key in self._reserving:
                return None
            self._reserving.add(key)
        reservation = None
        previous_pass_id = None
        previous_pass_known = False
        try:
            previous_pass_id = cycle.state_record()["active_pass_id"]
            previous_pass_known = True
            packet = cycle.reserve(now=now, current_source=capture_source_identity(self.target_root, key[0]),
                                   current_binary=(self._current_binary_cycle_input(cycle.origin)
                                       if isinstance(cycle.origin, BinaryKnowledgeOrigin) else None),
                                   admission=admission, all_model_calls=calls, required_calls=required_calls,
                                   required_context_ids=required_context_ids)
            if packet is None:
                return None
            reservation = KnowledgeReservation(cycle.origin, packet)
            with self._lock:
                closed = self._closed
                if not closed:
                    self._active[packet.pass_id] = reservation
                    self._active_units[key] = reservation
                    if self._study_jobs is not None:
                        self._study_review_reservations[key] = (
                            required_calls, frozenset(self._study_review_credits.get(key, ())))
                    self._events.append({"event": "continuation_reserved", "origin": asdict(cycle.origin),
                                         "pass_id": packet.pass_id, "delta_ids": list(packet.delta_ids),
                                         "pending_ids": list(packet.pending_ids), "required_calls": required_calls})
            if closed:
                cycle.failed(packet.pass_id, reason="runtime_closed")
                return None
            return reservation
        except BaseException as error:
            try:
                try:
                    if previous_pass_known:
                        active_pass_id = cycle.state_record()["active_pass_id"]
                        if active_pass_id is not None and active_pass_id != previous_pass_id:
                            cycle.failed(active_pass_id, reason="reservation_install_interrupted")
                finally:
                    if reservation is not None:
                        self._release(reservation)
            except BaseException as cleanup_error:
                error.add_note("Reservation cleanup also failed: " + type(cleanup_error).__name__)
            raise
        finally:
            with self._lock:
                self._reserving.discard(key)

    def _owned_reservation(self, reservation: KnowledgeReservation) -> bool:
        with self._lock:
            return self._active.get(reservation.packet.pass_id) is reservation

    def enrich_context(self, ctx: dict, reservation: KnowledgeReservation) -> bool:
        if not self._owned_reservation(reservation):
            return False
        if not self._same_snapshot(self._origin(ctx), reservation.origin) or not self.can_publish(reservation):
            return False
        with self._lock:
            cycle = self._cycles[self._key(reservation.origin)]
        with self._lock:
            ctx["continuation_context_inputs"] = tuple(deepcopy(self._context_deltas[(self._key(reservation.origin), cid)])
                for cid in reservation.packet.external_context_ids
                if (self._key(reservation.origin), cid) in self._context_deltas)
        from .continuation_context import context_spec
        for spec in ctx["continuation_context_inputs"]:
            if isinstance(reservation.origin, BinaryKnowledgeOrigin):
                from .binary_subjects import BinarySubjectContext
                with self._lock:
                    retained = self._binary_external_payloads.get(
                        (self._key(reservation.origin), spec["context_id"]))
                if retained is None or retained[0] != spec["context_key"]:
                    return False
                field, payload = retained
                if spec["kind"] == "binary_target_semantics":
                    if not isinstance(payload, BinarySubjectContext) or not payload.current(ctx):
                        return False
                    ctx[field] = payload
                elif spec["kind"] == "binary_callee_assessments":
                    from .binary_callee_assessments import BinaryCalleeAssessmentContext
                    if not isinstance(payload, BinaryCalleeAssessmentContext) or not payload.current(ctx):
                        return False
                    ctx[field] = payload
                elif spec["kind"] == "binary_callers":
                    from .binary_callers import BinaryCallerContext
                    if not isinstance(payload, BinaryCallerContext) or not payload.current(ctx):
                        return False
                    ctx[field] = payload
                elif spec["kind"] == "disagreement" and type(payload) is dict:
                    ctx[field] = dict(payload)
                else:
                    return False
            if context_spec(ctx, kind=spec["kind"], version=spec["version"]) != spec:
                return False
        ctx["knowledge_requests"] = tuple(cycle.requests.values())
        ctx["language_reference_answers"] = reservation.packet.references
        ctx["study_explanations"] = reservation.packet.explanations
        caller_requests = tuple(cycle.caller_requests.values())
        admitted_ids = {answer.request_id for answer in reservation.packet.caller_contexts}
        missing_answers = []
        with self._lock:
            for request in caller_requests:
                if request.request_id in admitted_ids:
                    continue
                answer = self._caller_answers.get(request.request_id)
                if answer is None or answer.material is not None:
                    answer = CallerContextAnswer(request.request_id, request.origin, None, "deferred",
                                                 "caller_context_not_admitted_to_this_pass")
                missing_answers.append(answer)
        ctx["caller_context_requests"] = caller_requests
        ctx["caller_context_answers"] = (*reservation.packet.caller_contexts, *missing_answers)
        return True

    def _binary_selected_payloads_current(self, reservation: KnowledgeReservation,
                                      fresh_scopes: list[BinaryReviewPublicationScope]) -> bool:
        """Recheck original advisory contributors, including after journal append.

        Post-dispatch checks use the invocation's retained payload, not a later
        same-version offer. Callbacks run outside the Runtime lock.
        """
        from .binary_callee_assessments import BinaryCalleeAssessmentContext
        from .binary_subjects import BinarySubjectContext
        from .continuation_context import context_spec

        key = self._key(reservation.origin)
        with self._lock:
            selected = []
            for context_id in reservation.packet.external_context_ids:
                spec = self._context_deltas.get((key, context_id))
                if spec is not None and spec["kind"] in ("binary_callee_assessments", "binary_target_semantics"):
                    selected.append((dict(spec), self._binary_external_payloads.get((key, context_id))))
            cycle_input = self._binary_cycle_scopes.get(key)
        if not selected:
            return True
        if cycle_input is None:
            return False
        for spec, retained in selected:
            if retained is None or retained[0] != spec["context_key"]:
                return False
            for scope in fresh_scopes or [cycle_input[0]]:
                original_ctx = scope.view_context
                if not isinstance(original_ctx, dict):
                    return False
                payload = original_ctx.get(spec["context_key"]) if fresh_scopes else retained[1]
                payload_type = (BinaryCalleeAssessmentContext if spec["kind"] == "binary_callee_assessments"
                                else BinarySubjectContext)
                if not isinstance(payload, payload_type):
                    return False
                ctx = dict(original_ctx)
                ctx[spec["context_key"]] = payload
                if (not payload.current(ctx)
                        or context_spec(ctx, kind=spec["kind"], version=spec["version"]) != spec):
                    return False
        return True

    def can_publish(self, reservation: KnowledgeReservation) -> bool:
        if not self._owned_reservation(reservation):
            return False
        origin = reservation.origin
        if isinstance(origin, BinaryKnowledgeOrigin):
            with self._lock:
                invalid = reservation.packet.pass_id in self._live_input_errors
                fresh_scopes = [scope for (pass_id, _attempt), (scope, original) in self._binary_review_scopes.items()
                                if pass_id == reservation.packet.pass_id and self._same_snapshot(original, origin)]
            return (not invalid and self._current_binary_cycle_input(origin) is not None
                    and self._binary_selected_payloads_current(reservation, fresh_scopes)
                    and all(scope.current(self.target_root) for scope in fresh_scopes)
                    and not reservation.packet.references and not reservation.packet.explanations
                    and not reservation.packet.caller_contexts and bool(reservation.packet.external_context_ids))
        current = capture_source_identity(self.target_root, origin.file)
        reason = ""
        if origin.source_identity is None or current != origin.source_identity:
            reason = "review_source_changed"
        else:
            for answer in reservation.packet.explanations:
                admitted, why = self.bindings.admit(answer)
                if not admitted:
                    reason = why
                    break
            if not reason:
                for caller_answer in reservation.packet.caller_contexts:
                    admitted, why = self._admit_caller_context(caller_answer)
                    if not admitted:
                        reason = why
                        break
            if not reason and reservation.packet.explanations:
                # Re-admit the union after all explanation/caller callbacks.
                # A later explanation's check must not leave an earlier
                # explanation stale while the primary source is unchanged.
                admitted, why = self.bindings.admit_inputs(tuple(
                    material for answer in reservation.packet.explanations for material in answer.inputs))
                if not admitted:
                    reason = why
            if not reason:
                for caller_answer in reservation.packet.caller_contexts:
                    material = caller_answer.material
                    if material is None or capture_source_identity(self.target_root, material.file) != material.source_identity:
                        reason = "caller_source_changed_after_admission"
                        break
            if not reason and capture_source_identity(self.target_root, origin.file) != current:
                reason = "review_source_changed"
        if reason:
            with self._lock:
                key = (reservation.packet.pass_id, reason)
                if key not in self._publication_rejections:
                    self._publication_rejections.add(key)
                    self._events.append({"event": "continuation_publication_refused", "pass_id": key[0], "reason": reason})
            return False
        return True

    def _delivery(self, reservation: KnowledgeReservation, ctx: dict | None) -> tuple[str, ...]:
        # Only records frozen from completed owned invocations count. Shared
        # context fields may belong to another renderer or a later re-entry.
        with self._lock:
            assessments = deepcopy(self._knowledge_deliveries.get(reservation.packet.pass_id, ()))
        allowed = ({a.request_id for a in reservation.packet.references}
                   | {a.request_id for a in reservation.packet.explanations}
                   | {a.request_id for a in reservation.packet.caller_contexts})
        delivered = set()
        rows = []
        for assessment in assessments:
            for field, records in assessment.items():
                for row in records:
                    if isinstance(row, dict) and row.get("request_id") in allowed:
                        rows.append({"field": field, **row})
                        if row.get("delivered") is True:
                            delivered.add(row["request_id"])
        with self._lock:
            caller_deliveries = deepcopy(self._caller_deliveries.get(reservation.packet.pass_id, ()))
        for caller_assessment in caller_deliveries:
            for row in caller_assessment:
                if isinstance(row, dict) and row.get("request_id") in allowed:
                    rows.append({"field": "caller_context_delivery", **row})
                    if row.get("delivered") is True:
                        delivered.add(row["request_id"])
        with self._lock:
            external_deliveries = deepcopy(self._external_deliveries.get(reservation.packet.pass_id, ()))
        for external_assessment in external_deliveries:
            for external_row in external_assessment:
                if isinstance(external_row, dict) and external_row.get("context_id") in reservation.packet.external_context_ids:
                    rows.append({"field": "external_context_delivery", **external_row})
                    if external_row.get("delivered") is True:
                        delivered.add(external_row["context_id"])
        with self._lock:
            self._events.append({"event": "review_prompt_context", "pass_id": reservation.packet.pass_id,
                                 "records": rows, "renderer_observed": bool(rows),
                                 "meaning": "fitted into review prompt; not provider acknowledgement or model use"})
        return tuple(sorted(delivered))

    def context_was_delivered(self, reservation: KnowledgeReservation) -> bool:
        """Require completed, owned renderer receipts for external context."""
        if not self._owned_reservation(reservation) or not reservation.packet.external_context_ids:
            return False
        return set(reservation.packet.external_context_ids) <= set(self._delivery(reservation, None))

    def _release(self, reservation: KnowledgeReservation) -> None:
        with self._lock:
            current = self._active.get(reservation.packet.pass_id)
            if current is not None and current is not reservation:
                return
            self._active.pop(reservation.packet.pass_id, None)
            key = self._key(reservation.origin)
            if self._active_units.get(key) is reservation:
                self._active_units.pop(key, None)
                self._study_review_reservations.pop(key, None)
            self._knowledge_deliveries.pop(reservation.packet.pass_id, None)
            self._external_deliveries.pop(reservation.packet.pass_id, None)
            self._caller_deliveries.pop(reservation.packet.pass_id, None)
            self._live_input_sets.pop(reservation.packet.pass_id, None)
            self._live_input_errors.discard(reservation.packet.pass_id)
        self.notify()

    def complete(self, reservation: KnowledgeReservation, ctx: dict, *, published_status: str = "",
                 reason: str = "completed") -> bool:
        if not self._owned_reservation(reservation):
            return False
        if not self.can_publish(reservation):
            return self.fail(reservation, reason="source_changed", ctx=ctx)
        delivered = self._delivery(reservation, ctx)
        with self._lock:
            cycle = self._cycles[self._key(reservation.origin)]
        try:
            if not cycle.complete(reservation.packet.pass_id, delivered):
                return False
            with self._lock:
                for answer in reservation.packet.caller_contexts:
                    self._request_status[answer.request_id] = {
                        "state": "review_completed" if answer.request_id in delivered else "deferred",
                        "reason": "context_delivered_for_review" if answer.request_id in delivered else "context_not_delivered",
                        "adjudication": "unverified", "pass_id": reservation.packet.pass_id,
                    }
                self._events.append({"event": "continuation_completed", "pass_id": reservation.packet.pass_id,
                                     "published_status": published_status, "reason": reason,
                                     "delivered_request_ids": list(delivered)})
            return True
        finally:
            # A cancellation may arrive after the cycle commits its terminal
            # state but before the call returns. Retire only that finished owner.
            if cycle.state_record()["active_pass_id"] != reservation.packet.pass_id:
                self._release(reservation)

    def fail(self, reservation: KnowledgeReservation, reason: str = "review_failed", ctx: dict | None = None) -> bool:
        if not self._owned_reservation(reservation):
            return False
        self._delivery(reservation, ctx)
        with self._lock:
            cycle = self._cycles[self._key(reservation.origin)]
        try:
            if not cycle.failed(reservation.packet.pass_id, reason=reason):
                return False
            with self._lock:
                for answer in reservation.packet.caller_contexts:
                    self._request_status[answer.request_id] = {
                        "state": "deferred", "reason": reason, "adjudication": "unverified",
                    }
                self._events.append({"event": "continuation_failed", "pass_id": reservation.packet.pass_id,
                                     "reason": reason, "published_status": ""})
            return True
        finally:
            if cycle.state_record()["active_pass_id"] != reservation.packet.pass_id:
                self._release(reservation)

    def wake_interval(self) -> float | None:
        with self._lock:
            if self._closed:
                return None
            idle = [(key, cycle, None if key in self._unknown_calls else self._calls.get(key, 0))
                    for key, cycle in self._cycles.items()
                    if key not in self._busy and key not in self._active_units]
            pending = any(self._key(self._requests[r].origin) not in self._busy
                          and self._key(self._requests[r].origin) not in self._active_units
                          for r in self._pending_sources)
        delays = [delay for _, cycle, calls in idle
                  if (delay := cycle.wake_after(now=monotonic(), all_model_calls=calls, required_calls=self._required_calls)) is not None]
        if pending:
            delays.append(0.25)
        return min(delays) if delays else None

    def has_pending_work(self) -> bool:
        with self._lock:
            if self._pending_sources or self._source_jobs or self._active:
                return True
        return self.wake_interval() is not None

    def close_sources(self, reason: str = "source_worker_closed") -> None:
        with self._lock:
            self._sources_closed = True
            if self._study_jobs is not None:
                self._study_jobs.close()
            self._deferred_source_dispatches.clear()
            self._deferred_source_dispatch_states.clear()
            pending = tuple(self._pending_sources)
        self.record_source_answers(tuple(SubjectExplanation(
            request_id, "unavailable", "", reason, (), producer="pipeline") for request_id in pending))
        self.notify()

    def close(self, reason: str = "audit_finished") -> None:
        self.close_sources(reason)
        with self._lock:
            if self._closed:
                return
            self._closed = True
            active = tuple(self._active.values())
            self._events.append({"event": "runtime_closed", "reason": reason})
        for reservation in active:
            self.fail(reservation, reason)
        self.notify()

    def write_artifacts(self, out_dir: Path) -> None:
        from core.json import dumps_canonical, save_json
        from .record import append_audit_log

        out_dir = Path(out_dir)
        with self._write_lock:
            with self._lock:
                events = deepcopy(self._events)
                requests = [{**asdict(r), "processing": deepcopy(self._request_status.get(r.request_id, {}))}
                            for r in self._requests.values()]
                caller_requests = [{**asdict(r), "processing": deepcopy(self._request_status.get(r.request_id, {}))}
                                   for r in self._caller_requests.values()]
                cycles = tuple(self._cycles.items())
                counts = dict(self._calls)
                unknown = set(self._unknown_calls)
                study_jobs = self._study_jobs.snapshot() if self._study_jobs is not None else None
                if study_jobs is not None:
                    study_jobs["dispatch_scopes"] = [
                        {"lease_id": lease_id, "subjects": [asdict(subject) for subject in packet.subjects],
                         "input_binding_ids": [material.binding_id for material in packet.materials],
                         "excluded_inputs": [asdict(material) for material in packet.excluded_materials],
                         "extra_context_excluded": packet.extra_context_excluded}
                        for lease_id, packet in self._source_dispatch_packets.items()]
            materials = {}
            for event in events:
                answer = event.get("answer")
                if event.get("event") != "source_answer" or not isinstance(answer, dict):
                    continue
                for field in ("materials", "inputs", "excluded_inputs"):
                    refs = []
                    for material in answer.get(field, ()):
                        import hashlib
                        material_id = material.get("binding_id") or hashlib.sha256(
                            dumps_canonical(material).encode("utf-8")).hexdigest()
                        materials[material_id] = material
                        refs.append(material_id)
                    answer[field] = refs
            payload = {"schema_version": 1, "role": "context_provenance_not_verification_evidence",
                       "requests": requests, "caller_context_requests": caller_requests,
                       "events": events, "materials": materials,
                       "bindings": self.bindings.records(),
                       "units": [{"unit": list(key), "owned_dispatch_attempts": counts.get(key, 0),
                                  "all_model_calls": None if key in unknown else counts.get(key, 0),
                                  "cycle": cycle.state_record()} for key, cycle in cycles]}
            if study_jobs is not None:
                payload["shared_study_jobs"] = study_jobs
            save_json(out_dir / "knowledge-results.json", payload)
            path_key = str(out_dir.resolve())
            for index in range(self._written_events.get(path_key, 0), len(events)):
                append_audit_log(out_dir, {"action": "audit_knowledge", "sequence": index,
                                          "role": payload["role"], "knowledge_event": events[index]})
                self._written_events[path_key] = index + 1

    def client_lifetime_valid(self) -> bool:
        """Observe existing runtime lifetime; no counters, events or source admission."""
        with self._lock:
            return not self._closed and monotonic() < self.deadline

    def has_owned_model_attempts(self, gap: dict) -> bool:
        """Routing hint only; existing atomic admission still owns dispatch.

        Unknown or malformed state never becomes an unattempted first review.
        No registry scan, source read, counter reset or evidence is produced.
        """
        key = self._gap_key(gap)
        if (not isinstance(key[0], str) or not key[0]
                or not isinstance(key[1], str) or not key[1]
                or type(gap.get("line_start")) is not int or gap["line_start"] < 1):
            return True
        with self._lock:
            calls = self._calls.get(key, 0)
            return (key in self._unknown_calls or type(calls) is not int or calls != 0
                    or key in self._busy or key in self._active_units or key in self._reserving)

    def admit_client_call(self, gap: dict, purpose: str, method: str) -> bool:
        return self._admit_client_key(self._gap_key(gap), purpose, method)

    def _admit_client_key(self, key: tuple[str, str, int], purpose: str, method: str, *,
                          review_attempt_id: str | None = None) -> bool:
        # Ownership and admission use the same scheduled key throughout the
        # unit lifetime, even when helpers annotate the mutable gap object.
        with self._lock:
            cycle = self._cycles.get(key)
            limit = cycle.max_model_calls if cycle else self._policy["max_model_calls"]
            reason = ("runtime_closed" if self._closed else "deadline" if monotonic() >= self.deadline
                      else "model_call_limit" if self._calls.get(key, 0) >= limit else "")
            if reason:
                self._events.append({"event": "client_call_refused", "unit": list(key),
                                     "purpose": purpose, "method": method, "reason": reason})
                return False
            self._calls[key] = self._calls.get(key, 0) + 1
            if purpose == "review" and review_attempt_id is not None:
                self._study_review_credit(key, review_attempt_id)
            self._events.append({"event": "client_call_attempt", "unit": list(key),
                                 "purpose": purpose, "method": method})
            return True
