"""Normal-review request capture and ownership for the knowledge loop.

The orchestrator owns dispatch and verdict publication. This adapter retains
pre-call origins, local reference answers and typed source requests; none of
these objects supplies confirmation or refutation authority.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import asdict, dataclass
from functools import wraps
from pathlib import Path
from threading import Event, Lock, RLock
from time import monotonic
from uuid import UUID, uuid4, uuid5
from typing import TypedDict

from core.concepts.subject_study import StudySubjects, SubjectExplanation
from core.language_reference import ReferenceContext, lookup
from core.source.lines import split_lines

from .caller_review_context import (CallerContextAnswer, CallerContextRequest, register_caller_context_requests,
                                    resolve_caller_context, validate_caller_context)
from .knowledge_requests import KnowledgeBatch, KnowledgeOrigin, KnowledgeRequest, register_requests
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


class AuditKnowledgeRuntime:
    """One audit's knowledge ownership, using its existing study queue.

    Call counts cover owned review dispatch attempts. Unknown custom review
    producers remain explicitly unknown; these are not counts of hidden
    provider retries or unmigrated verification calls. The shared budget client
    still owns all paid spend and transport retry admission.
    """

    def __init__(self, target_root: Path, study_queue, *, deadline: float, window: float = 10.0,
                 max_continuations: int = 2, max_model_calls: int = 6, caller_inventory: dict | None = None):
        self.target_root = Path(target_root)
        self.study_queue = study_queue
        self.deadline = deadline
        self.bindings = StudyInputBindings(self.target_root)
        self._lock = RLock()
        self._foundation_namespace = uuid4().hex
        self._write_lock = Lock()
        self._wakeup = Event()
        self._required_calls = 1
        self._policy: _CyclePolicy = dict(window=window, max_continuations=max_continuations, max_model_calls=max_model_calls)
        self._busy: dict[tuple[str, str, int], int] = {}
        self._pending_sources: set[str] = set()
        self._request_status: dict[str, dict] = {}
        self._semantic_requests: dict[tuple, str] = {}
        self._source_answers: dict[str, list[SubjectExplanation]] = {}
        self._active: dict[str, KnowledgeReservation] = {}
        self._active_units: dict[tuple[str, str, int], KnowledgeReservation] = {}
        self._knowledge_deliveries: dict[str, list[dict[str, list[dict]]]] = {}
        self._caller_deliveries: dict[str, list[list[dict]]] = {}
        self._live_input_sets: dict[str, list[tuple[CapturedReviewInput, ...]]] = {}
        self._live_input_errors: set[str] = set()
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

    @staticmethod
    def _key(origin: KnowledgeOrigin) -> tuple[str, str, int]:
        return origin.file, origin.function, origin.line_start

    @staticmethod
    def _gap_key(gap: dict) -> tuple[str, str, int]:
        return gap.get("file", ""), gap.get("name", gap.get("function", "")), gap.get("line_start", 0)

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
            try:
                from .knowledge_calls import owned_call_scope
                with owned_call_scope(lambda purpose, method: self.admit_client_call(gap, purpose, method)):
                    return review_one_fn(gap, *args, **kwargs)
            finally:
                with self._lock:
                    self._busy[key] -= 1
                    if not self._busy[key]:
                        del self._busy[key]
                self.notify()

        setattr(unit, "_knowledge_unit_owner", self)
        return unit

    def mark_call_count_unknown(self, gap: dict, reason: str = "unowned_model_helper") -> None:
        key = self._gap_key(gap)
        with self._lock:
            self._unknown_calls.add(key)
            self._events.append({"event": "attempt_count_unknown", "unit": list(key), "reason": reason})
        self.notify()

    @staticmethod
    def _same_snapshot(left: KnowledgeOrigin, right: KnowledgeOrigin) -> bool:
        return (left.file, left.function, left.line_start, left.line_end, left.source_identity) == (
            right.file, right.function, right.line_start, right.line_end, right.source_identity)

    def _origin(self, ctx: dict) -> KnowledgeOrigin:
        # Reuse the exact inverse of the normal numbered review view. A stale
        # or unrecognised view cannot acquire a fresh whole-file identity.
        from .orchestrator import _raw_ihv_review_source

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
            captured = self._origin(ctx)
            key = self._key(captured)
            with self._lock:
                reservation = self._active_units.get(key)
            if reservation is not None:
                if not self._same_snapshot(captured, reservation.origin) or not self.can_publish(reservation):
                    raise ValueError("knowledge continuation source changed before review")
                origin = KnowledgeOrigin(reservation.packet.pass_id, captured.file, captured.function,
                                         captured.line_start, captured.line_end, captured.source_identity)
            else:
                origin = captured
            from .reference_foundation import foundation_answers, foundation_required_for_file
            owned_references = reservation.packet.references if reservation is not None else ()
            if origin.source_identity is not None and foundation_required_for_file(origin.file):
                foundation_id = "foundation:" + uuid5(UUID(self._foundation_namespace),
                    repr((self._key(origin), origin.source_identity))).hex
                initial_answers = foundation_answers(ctx.get("language"), request_id=foundation_id)
                owned_references = (*owned_references, *initial_answers)
            # These immutable answers have stable identities across the unit's
            # panel. Shared compatibility fields never establish delivery.
            ctx["language_reference_answers"] = owned_references
            attempt_id = uuid4().hex
            with self._lock:
                if getattr(review_fn, "_knowledge_observed_client_contract", None) is not True:
                    self._calls[key] = self._calls.get(key, 0) + 1
                if getattr(review_fn, "_knowledge_observed_client_contract", None) is not True:
                    self._unknown_calls.add(key)
                self._events.append({"event": "review_attempt", "attempt_id": attempt_id, "origin": asdict(origin)})
            try:
                from .knowledge_calls import owned_call_scope
                with owned_call_scope(lambda purpose, method: self.admit_client_call(
                        {"file": origin.file, "name": origin.function, "line_start": origin.line_start}, purpose, method)):
                    outcome = review_fn(ctx, config)
            except BaseException:
                with self._lock:
                    self._events.append({"event": "review_failed", "attempt_id": attempt_id,
                                         "pass_id": origin.pass_id})
                self.notify()
                raise
            from .review_claims import begin_review
            # Pipeline-owned: a model cannot supply the original source stamp.
            outcome.review_result = dict(outcome.review_result or {})
            history = begin_review(origin, attempt_id)
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
            with self._lock:
                self._events.append({"event": "review_assessment", "attempt_id": attempt_id,
                    "pass_id": origin.pass_id, "status": outcome.status,
                    "body": (outcome.body or "")[:4000],
                    "body_omitted_chars": max(0, len(outcome.body or "") - 4000),
                    "hypothesis": outcome.hypothesis, "hypotheses": deepcopy(outcome.hypotheses),
                    "model": outcome.model, "cost_usd": outcome.cost_usd,
                    "source_unchanged_after_call": origin.source_identity is not None and current == origin.source_identity})
            self._register(origin, ctx, outcome.review_result, delivered_references=reference_manifest)
            self._register_caller_requests(origin, outcome.review_result)
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

    def bind_review_input_scope(self, outcome) -> None:
        """Attach the combined pass scope after panel reconstruction."""
        from .review_claims import read_history

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

    def source_roots(self) -> dict[str, Path]:
        return self.bindings.registered_roots()

    def _signature(self, request: KnowledgeRequest, ctx: dict) -> tuple:
        language = ctx.get("language") if isinstance(ctx.get("language"), str) else ""
        return (self._key(request.origin), request.origin.source_identity, request.kind, request.subject,
                request.context, request.resolution, request.entry_id, request.source_line,
                language if request.kind == "language_reference" else "")

    def _duplicate_is_reusable(self, request_id: str) -> bool:
        with self._lock:
            answers = tuple(self._source_answers.get(request_id, ()))
        # A changed dependency may make a previously answered subject useful
        # again, without renewing the unit's round/model-call allowance.
        return (not answers or not any(a.materials for a in answers)
                or any(self.bindings.admit(a)[0] for a in answers if a.materials))

    def _register(self, origin: KnowledgeOrigin, ctx: dict, review_result, *, delivered_references=None) -> None:
        batch = register_requests(review_result, origin)
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

    def _register_caller_requests(self, origin: KnowledgeOrigin, review_result) -> None:
        batch = register_caller_context_requests(review_result, origin)
        if not batch.accepted and not batch.rejected:
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
            signature = (key, origin.source_identity, request.caller_file,
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

    def admit_source_attempt(self, requests: tuple[KnowledgeRequest, ...]) -> bool:
        """Count an owned structured dispatch, after the shared throttle admits it.

        Hidden provider retries remain the budget client's responsibility. A
        shared call contributes once to every unit whose request it contains.
        """
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
                      "model_call_count_unavailable" if keys & self._unknown_calls else
                      "model_call_limit" if any(
                          key not in self._cycles or self._calls.get(key, 0) >= self._cycles[key].max_model_calls
                          for key in keys) else "")
            if reason:
                self._events.append({"event": "study_dispatch_refused", "reason": reason,
                                     "request_ids": [r.request_id for r in requests]})
                return False
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

    def finish_source_job(self, subjects: StudySubjects) -> None:
        self.record_source_answers(subjects.drain_updates())
        with self._lock:
            if subjects in self._source_jobs:
                self._source_jobs.remove(subjects)
        self.notify()

    def record_source_answers(self, answers: tuple[SubjectExplanation, ...]) -> None:
        """Retain explanations as context and notify their existing unit cycle."""
        for answer in answers:
            with self._lock:
                request = self._requests.get(answer.request_id)
                if request is None or request.kind != "target_study":
                    self._events.append({"event": "source_answer_rejected", "reason": "unknown_request"})
                    continue
                key = (request.origin.file, request.origin.function, request.origin.line_start)
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
            if cycle is not None:
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
                               if key not in self._busy and key not in self._active_units)
        ready = []
        for key, cycle, calls in candidates:
            packet = cycle.reserve(now=now, current_source=capture_source_identity(self.target_root, key[0]),
                                   admission=admission, all_model_calls=calls, required_calls=required_calls)
            if packet is None:
                continue
            reservation = KnowledgeReservation(cycle.origin, packet)
            with self._lock:
                self._active[packet.pass_id] = reservation
                self._active_units[key] = reservation
                self._events.append({"event": "continuation_reserved", "origin": asdict(cycle.origin),
                                     "pass_id": packet.pass_id, "delta_ids": list(packet.delta_ids),
                                     "pending_ids": list(packet.pending_ids), "required_calls": required_calls})
            ready.append(reservation)
        return tuple(ready)

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

    def can_publish(self, reservation: KnowledgeReservation) -> bool:
        if not self._owned_reservation(reservation):
            return False
        origin = reservation.origin
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
            self._events.append({"event": "review_prompt_context", "pass_id": reservation.packet.pass_id,
                                 "records": rows, "renderer_observed": bool(rows),
                                 "meaning": "fitted into review prompt; not provider acknowledgement or model use"})
        return tuple(sorted(delivered))

    def _release(self, reservation: KnowledgeReservation) -> None:
        with self._lock:
            self._active.pop(reservation.packet.pass_id, None)
            self._active_units.pop(self._key(reservation.origin), None)
            self._knowledge_deliveries.pop(reservation.packet.pass_id, None)
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
        self._release(reservation)
        return True

    def fail(self, reservation: KnowledgeReservation, reason: str = "review_failed", ctx: dict | None = None) -> bool:
        if not self._owned_reservation(reservation):
            return False
        self._delivery(reservation, ctx)
        with self._lock:
            cycle = self._cycles[self._key(reservation.origin)]
        if not cycle.failed(reservation.packet.pass_id, reason=reason):
            return False
        with self._lock:
            for answer in reservation.packet.caller_contexts:
                self._request_status[answer.request_id] = {
                    "state": "deferred", "reason": reason, "adjudication": "unverified",
                }
            self._events.append({"event": "continuation_failed", "pass_id": reservation.packet.pass_id,
                                 "reason": reason, "published_status": ""})
        self._release(reservation)
        return True

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
            save_json(out_dir / "knowledge-results.json", payload)
            path_key = str(out_dir.resolve())
            for index in range(self._written_events.get(path_key, 0), len(events)):
                append_audit_log(out_dir, {"action": "audit_knowledge", "sequence": index,
                                          "role": payload["role"], "knowledge_event": events[index]})
                self._written_events[path_key] = index + 1

    def admit_client_call(self, gap: dict, purpose: str, method: str) -> bool:
        key = self._gap_key(gap)
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
            self._events.append({"event": "client_call_attempt", "unit": list(key),
                                 "purpose": purpose, "method": method})
            return True
