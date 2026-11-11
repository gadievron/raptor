"""One owner's bounded knowledge-continuation decisions for a review unit.

The caller retains shared model admission, attempt accounting and outcome
publication. Reserving a packet neither removes an earlier finding nor
turns language/source explanations into evidence. Legacy review stages are
not counted or controlled here until their adapters supply those events.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import asdict, dataclass
from threading import RLock
from types import MappingProxyType
from uuid import uuid4

from core.concepts.subject_study import SubjectExplanation
from core.language_reference import ReferenceAnswer

from .caller_review_context import CallerContextAnswer, CallerContextRequest
from .knowledge_requests import KnowledgeBatch, KnowledgeOrigin
from .refutation_source import SourceIdentity


@dataclass(frozen=True)
class KnowledgeContinuation:
    pass_id: str
    references: tuple[ReferenceAnswer, ...]
    explanations: tuple[SubjectExplanation, ...]
    delta_ids: tuple[str, ...]
    pending_ids: tuple[str, ...]
    caller_contexts: tuple[CallerContextAnswer, ...] = ()
    external_context_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class KnowledgeCycleEvent:
    event: str
    request_ids: tuple[str, ...] = ()
    reason: str = ""
    pass_id: str = ""


class KnowledgeCycle:
    """Coalesce information without a model router or another model thread.

    Ready data may arrive from study threads, but only the coordinator calls
    ``reserve`` and ``complete``. The absolute coalescing window never moves
    on a duplicate result or a heartbeat. A failed dispatch consumes its
    reserved continuation; it cannot reset counters by asking again.
    """

    def __init__(
        self, origin: KnowledgeOrigin, batch: KnowledgeBatch, *, deadline: float,
        admit_study: Callable[[SubjectExplanation], tuple[bool, str]],
        window: float = 10.0, max_continuations: int = 2, max_model_calls: int = 6,
        admit_caller_context: Callable[[CallerContextAnswer], tuple[bool, str]] | None = None,
    ):
        if any(request.origin != origin for request in batch.accepted):
            raise ValueError("request origin differs from the reviewed snapshot")
        if len({r.request_id for r in batch.accepted}) != len(batch.accepted):
            raise ValueError("duplicate request identity")
        if (not math.isfinite(window) or window < 0 or math.isnan(deadline)
                or type(max_continuations) is not int or max_continuations < 0
                or type(max_model_calls) is not int or max_model_calls < 1):
            raise ValueError("invalid continuation policy")
        self.origin = origin
        self.requests = MappingProxyType({r.request_id: r for r in batch.accepted})
        self.deadline = deadline
        self.window = window
        self.max_continuations = max_continuations
        self.max_model_calls = max_model_calls
        self.started = 0
        self._admit_study = admit_study
        self._admit_caller_context = admit_caller_context
        self.caller_requests: MappingProxyType[str, CallerContextRequest] = MappingProxyType({})
        self._caller_answers: dict[str, CallerContextAnswer] = {}
        self._lock = RLock()
        self._references: dict[str, ReferenceAnswer] = {}
        self._explanations: dict[str, list[SubjectExplanation]] = {}
        self._terminal: set[str] = set()
        self._delta: set[str] = set()
        self._first_ready: float | None = None
        self._active: KnowledgeContinuation | None = None
        self._completed: dict[str, tuple[str, tuple[str, ...], str]] = {}
        self._events: list[KnowledgeCycleEvent] = []
        self._deferred: set[str] = set()
        self._retired = False
        self._external_context: set[str] = set()
        self._external_latest: dict[str, str] = {}

    def _changed(self, request_id: str, now: float) -> None:
        self._delta.add(request_id)
        if self._first_ready is None:
            self._first_ready = now

    def add_requests(self, batch: KnowledgeBatch) -> bool:
        """Attach follow-up requests without renewing a unit's allowance.

        Pass identities remain on individual requests. A different occurrence
        or source snapshot belongs to another review, never this live cycle.
        Admission is atomic so a mixed batch cannot partially change ownership.
        """
        with self._lock:
            origin = self.origin
            for request in batch.accepted:
                candidate = request.origin
                if (self._retired or
                        (candidate.file, candidate.function, candidate.line_start,
                         candidate.line_end, candidate.source_identity) !=
                        (origin.file, origin.function, origin.line_start,
                         origin.line_end, origin.source_identity)):
                    self._events.append(KnowledgeCycleEvent(
                        "rejected_requests", reason="different_review_snapshot"))
                    return False
            additions = {r.request_id: r for r in batch.accepted}
            if len(additions) != len(batch.accepted) or set(additions) & set(self.caller_requests) or any(
                key in self.requests and self.requests[key] != request
                for key, request in additions.items()
            ):
                self._events.append(KnowledgeCycleEvent(
                    "rejected_requests", reason="conflicting_request_identity"))
                return False
            new_ids = tuple(sorted(set(additions) - set(self.requests)))
            self.requests = MappingProxyType({**self.requests, **additions})
            if new_ids:
                self._events.append(KnowledgeCycleEvent("requests_added", new_ids))
            return True

    def context_delta(self, context_id: str, *, now: float, kind: str = "") -> bool:
        """Offer pipeline-owned context once; never confer evidence authority."""
        if not context_id or not math.isfinite(now):
            raise ValueError("invalid context delta")
        with self._lock:
            if self._retired:
                return False
            if context_id in self._external_context:
                return False
            self._external_context.add(context_id)
            if kind:
                previous = self._external_latest.get(kind)
                if previous is not None:
                    self._delta.discard(previous)
                self._external_latest[kind] = context_id
            self._changed(context_id, now)
            self._events.append(KnowledgeCycleEvent("context_delta", (context_id,)))
            return True

    def _request_ids(self) -> set[str]:
        return set(self.requests) | set(self.caller_requests)

    def add_caller_requests(self, requests: tuple[CallerContextRequest, ...]) -> bool:
        """Share round ownership without treating code requests as knowledge."""
        with self._lock:
            origin = self.origin
            if self._retired or any(
                (r.origin.file, r.origin.function, r.origin.line_start, r.origin.line_end, r.origin.source_identity) !=
                (origin.file, origin.function, origin.line_start, origin.line_end, origin.source_identity)
                for r in requests
            ):
                self._events.append(KnowledgeCycleEvent("rejected_caller_requests", reason="different_review_snapshot"))
                return False
            additions = {r.request_id: r for r in requests}
            if (len(additions) != len(requests) or set(additions) & set(self.requests)
                    or any(key in self.caller_requests and self.caller_requests[key] != request
                           for key, request in additions.items())):
                self._events.append(KnowledgeCycleEvent("rejected_caller_requests", reason="conflicting_request_identity"))
                return False
            new_ids = tuple(sorted(set(additions) - set(self.caller_requests)))
            self.caller_requests = MappingProxyType({**self.caller_requests, **additions})
            if new_ids:
                self._events.append(KnowledgeCycleEvent("caller_requests_added", new_ids))
            return True

    def caller_context(self, answer: CallerContextAnswer, *, now: float, changed: bool = True) -> bool:
        """Accept locally supplied code as context, never a review verdict."""
        if not math.isfinite(now):
            raise ValueError("invalid coordinator clock")
        with self._lock:
            request = self.caller_requests.get(answer.request_id)
            if request is None or answer.origin != request.origin:
                self._events.append(KnowledgeCycleEvent("rejected_caller_context", reason="unknown_or_wrong_origin"))
                return False
            if (answer.material is not None
                    and (answer.material.file, answer.material.function, answer.material.line_start) !=
                    (request.caller_file, request.caller_function, request.caller_line)):
                self._events.append(KnowledgeCycleEvent("rejected_caller_context", reason="requested_endpoint_mismatch"))
                return False
            self._terminal.add(answer.request_id)
            previous = self._caller_answers.get(answer.request_id)
            self._caller_answers[answer.request_id] = answer
            if answer.status in ("ready", "partial") and answer.material is not None:
                if self._admit_caller_context is None:
                    self._events.append(KnowledgeCycleEvent(
                        "rejected_caller_context", (answer.request_id,), "caller_context_admission_unavailable"))
                    return False
                admitted, reason = self._admit_caller_context(answer)
                if not admitted:
                    self._events.append(KnowledgeCycleEvent("rejected_caller_context", (answer.request_id,), reason))
                    return False
                if changed and answer != previous:
                    self._changed(answer.request_id, now)
            return True

    def reference(self, answer: ReferenceAnswer, *, now: float) -> bool:
        if not math.isfinite(now):
            raise ValueError("invalid coordinator clock")
        with self._lock:
            request = self.requests.get(answer.request_id)
            if request is None or request.kind != "language_reference":
                self._events.append(KnowledgeCycleEvent("rejected_reference", reason="unknown_or_wrong_kind"))
                return False
            previous = self._references.get(answer.request_id)
            self._references[answer.request_id] = answer
            self._terminal.add(answer.request_id)
            if answer.entries and answer != previous:
                self._changed(answer.request_id, now)
            elif not answer.entries:
                # A withdrawn answer cannot leave useful-work credit behind.
                self._delta.discard(answer.request_id)
                if not self._delta:
                    self._first_ready = None
            return True

    def explanation(self, answer: SubjectExplanation, *, now: float) -> bool:
        if not math.isfinite(now):
            raise ValueError("invalid coordinator clock")
        with self._lock:
            request = self.requests.get(answer.request_id)
            if request is None or request.kind != "target_study":
                self._events.append(KnowledgeCycleEvent("rejected_explanation", reason="unknown_or_wrong_kind"))
                return False
            prior = self._explanations.setdefault(answer.request_id, [])
            if answer in prior:
                return True
            prior.append(answer)
            if answer.status in ("answered", "partial") and answer.explanation and answer.materials:
                admitted, reason = self._admit_study(answer)
                if not admitted:
                    self._events.append(KnowledgeCycleEvent("rejected_explanation", (answer.request_id,), reason))
                    return False
                self._changed(answer.request_id, now)
            return True

    def finished(self, request_id: str) -> bool:
        with self._lock:
            if request_id not in self._request_ids():
                self._events.append(KnowledgeCycleEvent("rejected_completion", reason="unknown_request"))
                return False
            self._terminal.add(request_id)
            return True

    def _defer(self, reason: str) -> None:
        if reason not in self._deferred:
            self._deferred.add(reason)
            self._events.append(KnowledgeCycleEvent("continuation_deferred", tuple(sorted(self._delta)), reason))

    def reserve(
        self, *, now: float, current_source: SourceIdentity | None,
        admission: Callable[[], bool], all_model_calls: int | None, required_calls: int = 1,
        required_context_ids: tuple[str, ...] = (),
    ) -> KnowledgeContinuation | None:
        if type(required_calls) is not int or required_calls < 1:
            raise ValueError("invalid required call count")
        with self._lock:
            if not set(required_context_ids) <= (self._delta & self._external_context):
                return None
            if self._active is not None or not self._delta or self._retired:
                return None
            if not math.isfinite(now):
                raise ValueError("invalid coordinator clock")
            if now >= self.deadline:
                self._defer("deadline")
                return None
            if self.started >= self.max_continuations:
                self._defer("continuation_limit")
                return None
            if type(all_model_calls) is not int or all_model_calls < 0:
                self._defer("attempt_count_unavailable")
                return None
            if max(all_model_calls, 1 + self.started) + required_calls > self.max_model_calls:
                self._defer("model_call_limit")
                return None
            if self.origin.source_identity is None:
                self._defer("source_identity_unavailable")
                return None
            if current_source != self.origin.source_identity:
                self._events.append(KnowledgeCycleEvent("source_changed", tuple(sorted(self._delta))))
                self._retired = True
                return None
            first_ready = self._first_ready
            if first_ready is None:
                return None
            pending = tuple(sorted(self._request_ids() - self._terminal))
            if pending and now < first_ready + self.window:
                return None
            explanations = []
            for request_id, answers in self._explanations.items():
                valid = []
                for answer in answers:
                    if answer.status not in ("answered", "partial") or not answer.explanation or not answer.materials:
                        continue
                    admitted, reason = self._admit_study(answer)
                    if admitted:
                        valid.append(answer)
                    else:
                        self._events.append(KnowledgeCycleEvent("rejected_explanation", (request_id,), reason))
                if not valid:
                    self._delta.discard(request_id)
                explanations.extend(valid)
            caller_contexts: list[CallerContextAnswer] = []
            for request_id, caller_answer in self._caller_answers.items():
                if caller_answer.status not in ("ready", "partial") or caller_answer.material is None:
                    continue
                if self._admit_caller_context is None:
                    self._delta.discard(request_id)
                    continue
                admitted, reason = self._admit_caller_context(caller_answer)
                if admitted:
                    caller_contexts.append(caller_answer)
                else:
                    self._delta.discard(request_id)
                    self._events.append(KnowledgeCycleEvent("rejected_caller_context", (request_id,), reason))
            if not self._delta:
                self._first_ready = None
                return None
            if not admission():
                self._defer("shared_admission")
                return None
            packet = KnowledgeContinuation(
                uuid4().hex, tuple(self._references.values()),
                tuple(explanations), tuple(sorted(self._delta)), pending, tuple(caller_contexts),
                tuple(sorted(self._delta & self._external_context)),
            )
            self.started += 1
            self._active = packet
            self._delta.clear()
            self._first_ready = None
            self._events.append(KnowledgeCycleEvent("continuation_reserved", packet.delta_ids, pass_id=packet.pass_id))
            return packet

    def complete(self, pass_id: str, delivered_request_ids: tuple[str, ...]) -> bool:
        """Record prompt delivery, not an assertion that the model used it."""
        delivered = tuple(sorted(set(delivered_request_ids)))
        with self._lock:
            if pass_id in self._completed:
                if self._completed[pass_id] == ("completed", delivered, ""):
                    return True
                self._events.append(KnowledgeCycleEvent("rejected_completion", reason="conflicting_replay", pass_id=pass_id))
                return False
            if self._active is None or self._active.pass_id != pass_id:
                self._events.append(KnowledgeCycleEvent("rejected_completion", reason="inactive_pass", pass_id=pass_id))
                return False
            candidates = ({a.request_id for a in self._active.references if a.entries}
                          | {a.request_id for a in self._active.explanations}
                          | {a.request_id for a in self._active.caller_contexts}
                          | set(self._active.external_context_ids))
            if not set(delivered) <= candidates:
                self._events.append(KnowledgeCycleEvent("rejected_completion", reason="unknown_information", pass_id=pass_id))
                return False
            self._events.append(KnowledgeCycleEvent("prompt_delivered", delivered, pass_id=pass_id))
            omitted = tuple(sorted(candidates - set(delivered)))
            if omitted:
                self._events.append(KnowledgeCycleEvent("prompt_omitted", omitted, pass_id=pass_id))
            self._completed[pass_id] = ("completed", delivered, "")
            self._active = None
            return True

    def failed(self, pass_id: str, *, reason: str = "review_failed") -> bool:
        """Finish a failed reservation without calling it a prompt omission.

        Failure still consumes the reserved round. Retry requires a separately
        admitted information delta; a queue tick cannot buy the same call again.
        """
        disposition = ("failed", (), reason)
        with self._lock:
            if pass_id in self._completed:
                if self._completed[pass_id] == disposition:
                    return True
                self._events.append(KnowledgeCycleEvent("rejected_completion", reason="conflicting_replay", pass_id=pass_id))
                return False
            if self._active is None or self._active.pass_id != pass_id:
                self._events.append(KnowledgeCycleEvent("rejected_completion", reason="inactive_pass", pass_id=pass_id))
                return False
            self._events.append(KnowledgeCycleEvent("continuation_failed", self._active.delta_ids, reason, pass_id))
            self._completed[pass_id] = disposition
            self._active = None
            return True

    def events(self) -> tuple[KnowledgeCycleEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def wake_after(self, *, now: float, all_model_calls: int | None, required_calls: int = 1) -> float | None:
        with self._lock:
            if (self._retired or self._active or not self._delta or now >= self.deadline
                    or self.started >= self.max_continuations
                    or type(all_model_calls) is not int
                    or max(all_model_calls, 1 + self.started) + required_calls > self.max_model_calls):
                return None
            first_ready = self._first_ready
            if first_ready is None:
                return None
            pending = self._request_ids() - self._terminal
            return max(0.05, min(1.0, first_ready + self.window - now)) if pending else 0.05

    def state_record(self) -> dict:
        with self._lock:
            return {"origin": asdict(self.origin), "started": self.started,
                    "deadline": self.deadline if math.isfinite(self.deadline) else None,
                    "max_continuations": self.max_continuations, "max_model_calls": self.max_model_calls,
                    "pending_ids": sorted(self._request_ids() - self._terminal),
                    "delta_ids": sorted(self._delta), "retired": self._retired,
                    "caller_request_ids": sorted(self.caller_requests),
                    "active_pass_id": self._active.pass_id if self._active else None,
                    "events": [asdict(event) for event in self._events]}
