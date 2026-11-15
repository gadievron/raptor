"""UNAPPLIED proposal: live-issued conditional candidates, shadow-only support.

Declarations request a registered conclusion; their fields are not evidence.
No legacy/history decoder can create an active revision or an executed handle.
"""
from dataclasses import asdict, dataclass
from pathlib import Path
from hashlib import sha256
from threading import RLock
from uuid import uuid4

from core.json import dumps_canonical

from .claims import ClaimRevision
from .knowledge_requests import KnowledgeOrigin
from .conditional_member_policy import POLICY_ID, POLICY_VERSION, STATEMENT, conclusion_signature
from .refutation_source import capture_source_identity

REQUEST_FIELD = "conditional_verification_requests"
DELIVERY_FIELD = "conditional_request_delivery"
MECHANISM = "unsigned-member-narrow-alloc-wide-copy-v1"
_FILES = ("protocol/parser.c", "protocol/message.c", "protocol/message.h")
_REQUEST_KEYS = {"statement", "mechanism_kind", "declared_cwe", "policy_id", "policy_version"}


def request_schema_for_context(ctx):
    """Optional request vocabulary for this bounded occurrence, not admission.

    Location selects which question can be asked; it confers no source truth,
    class, revision linkage or checker authority. Other schemas stay unchanged.
    """
    if (type(ctx) is not dict or (ctx.get("file"), ctx.get("function"), ctx.get("line_start"))
            != ("protocol/parser.c", "parse_header", 25)
            or type(ctx.get("language")) is not str or ctx.get("language") not in {"c", "C"}
            or type(ctx.get("source")) is not str or not 0 < len(ctx["source"]) <= 32768):
        return None
    return {"type": "array", "maxItems": 8,
            "description": "Optional separate conditional source-model requests. Omit unless you "
                "independently identify this mechanism and one per-mechanism CWE. Do not choose "
                "a class from a combined headline. A request is not verification, taxonomy proof "
                "or a verdict. Required conditional premises: " + "; ".join(conclusion_signature().conditions),
            "items": {"type": "object", "additionalProperties": False,
                      "properties": {"statement": {"type": "string", "enum": [STATEMENT]},
                                     "mechanism_kind": {"type": "string", "enum": [MECHANISM]},
                                     "declared_cwe": {"type": "string", "enum": ["CWE-190", "CWE-195", "CWE-680"]},
                                     "policy_id": {"type": "string", "enum": [POLICY_ID]},
                                     "policy_version": {"type": "string", "enum": [POLICY_VERSION]}},
                      "required": sorted(_REQUEST_KEYS)}}


def request_field_diagnostic(review):
    """Bounded availability metadata, with no model text or evidence authority."""
    if type(review) is not dict or REQUEST_FIELD not in review:
        return {"field_state": "missing", "valid_count": 0}
    raw = review[REQUEST_FIELD]
    state = ("null" if raw is None else "invalid-type" if type(raw) is not list
             else "empty" if not raw else "malformed")
    selected = declarations(review)
    if selected:
        return {"field_state": "closed-valid", "valid_count": len(selected)}
    return {"field_state": state, "valid_count": 0}


@dataclass(frozen=True)
class ConditionalMemberDeclaration:
    """Issuer-checked request selection, never checker authority."""
    declared_cwe: str

    def material(self):
        return {"mechanism": STATEMENT, "mechanism_kind": MECHANISM,
                "cwe": self.declared_cwe}


def declarations(review):
    """Closed, bounded new request field; no headline fallback or normalisation.

    None denotes malformed explicit input; () denotes no conditional requests.
    All duplicates refuse, rather than choosing a primary or first class.
    """
    if type(review) is not dict or REQUEST_FIELD not in review:
        return ()
    raw = review[REQUEST_FIELD]
    if type(raw) is not list or len(raw) > 8:
        return None
    result = []
    for row in raw:
        if type(row) is not dict or set(row) != _REQUEST_KEYS:
            return None
        if any(type(value) is not str or len(value) > 1024 for value in row.values()):
            return None
        if (row["statement"] != STATEMENT or row["mechanism_kind"] != MECHANISM
                or row["policy_id"] != POLICY_ID or row["policy_version"] != POLICY_VERSION
                or row["declared_cwe"] not in {"CWE-190", "CWE-195", "CWE-680"}):
            return None
        item = ConditionalMemberDeclaration(row["declared_cwe"])
        if item in result:
            return None
        result.append(item)
    return tuple(result)


def _occurrence(outcome):
    return outcome.file, outcome.function, outcome.line or 0


def _units(root):
    return tuple((name, capture_source_identity(root, name)) for name in _FILES)


@dataclass
class _Entry:
    revision: ClaimRevision
    outcome: object
    selection: tuple
    epoch: str
    origin: KnowledgeOrigin
    owner: object = None
    handle: str | None = None
    source_units: tuple = ()
    reason: str = "not-executed"


class ConditionalClaimRun:
    """One trusted live run. No JSON restore, stage-fact or generic adapter API."""
    def __init__(self, root: Path, out_dir: Path | None):
        self.root, self.out_dir = Path(root), out_dir
        self._lock = RLock()
        self._grants: dict[int, tuple] = {}
        self._epochs: dict[tuple, str] = {}
        self._active: dict[tuple, tuple[_Entry, ...]] = {}
        self._pending: dict[str, _Entry] = {}
        self._unavailable: dict[tuple, str] = {}
        self._budget_refused = False

    def phase_diagnostic(self, outcome):
        """Snapshot availability only; never expose handles or create grants."""
        with self._lock:
            grant = self._grants.get(id(outcome))
            occurrence = ((grant[1].file, grant[1].function, grant[1].line_start)
                          if grant is not None and grant[0] is outcome else _occurrence(outcome))
            entries = tuple(entry for entry in self._active.get(occurrence, ())
                            if entry.outcome is outcome)
            current_grant = (grant is not None and grant[0] is outcome
                             and grant[2] == self._epochs.get(occurrence))
            origin = grant[1] if current_grant else entries[0].origin if entries else None
            return {"grant_current": current_grant, "active_count": len(entries),
                    "pending_count": sum(entry.revision.revision_id in self._pending for entry in entries),
                    "availability_reason": self._unavailable.get(occurrence),
                    "entry_reasons": sorted({entry.reason for entry in entries}),
                    "pass_id": origin.pass_id if type(origin) is KnowledgeOrigin else None}

    def bind_live_review(self, outcome, origin):
        """Called only by the real review wrapper, not by history decoding.

        The run owns this exact outcome/origin pair. No model boolean/token,
        persisted IDs or caller-filled FactEvent can replace this grant.
        """
        # The normal review factory returns line=0; its caller stamps the
        # occurrence later. Bind only to the captured live origin here, never
        # a guessed/history-derived line. IHV must subsequently match exactly.
        occurrence = ((origin.file, origin.function, origin.line_start)
                      if type(origin) is KnowledgeOrigin else _occurrence(outcome))
        selected = declarations(outcome.review_result)
        with self._lock:
            if selected == () and occurrence not in self._epochs:
                return
        epoch = self._withdraw(occurrence)
        if epoch is None:
            return
        with self._lock:
            if self._epochs.get(occurrence) != epoch:
                return  # superseded bind cannot erase the newer grant
            # Withdraw old grants for this occurrence as well as old executions.
            self._grants = {key: grant for key, grant in self._grants.items()
                            if (grant[1].file, grant[1].function, grant[1].line_start) != occurrence}
            if selected == ():
                return
            if (type(origin) is not KnowledgeOrigin or origin.source_identity is None
                    or (outcome.file, outcome.function) != (origin.file, origin.function)
                    or type(outcome.line) is not int or outcome.line not in (0, origin.line_start)
                    or type(origin.line_start) is not int or origin.line_start < 1):
                self._unavailable[occurrence] = "live-review-origin-unavailable"
                return
            if len(self._grants) >= 64:
                self._unavailable[occurrence] = "live-review-grant-budget"
                return
            self._grants[id(outcome)] = (outcome, origin, epoch, declarations(outcome.review_result))

    def _withdraw(self, occurrence, expected_epoch=None):
        with self._lock:
            if expected_epoch is not None and self._epochs.get(occurrence) != expected_epoch:
                return None
            if occurrence not in self._epochs and len(self._epochs) >= 128:
                self._budget_refused = True
                return None
            epoch = uuid4().hex
            self._epochs[occurrence] = epoch
            entries = self._active.pop(occurrence, ())
            for entry in entries:
                self._pending.pop(entry.revision.revision_id, None)
            self._unavailable.pop(occurrence, None)
            return epoch

    def _unavailable_if_current(self, occurrence, epoch, reason):
        with self._lock:
            if self._epochs.get(occurrence) == epoch:
                self._unavailable[occurrence] = reason

    def _current(self, entry):
        occurrence = _occurrence(entry.outcome)
        with self._lock:
            current = (self._epochs.get(occurrence) == entry.epoch
                       and any(value is entry for value in self._active.get(occurrence, ())))
        if (not current or declarations(entry.outcome.review_result) != entry.selection
                or occurrence != (entry.revision.file, entry.revision.function,
                                  entry.revision.line_start)):
            return None
        return entry.revision

    def intake_live(self, outcome, *, enabled):
        """Called only by the live IHV issuer, before any early-return/validation.

        Empty/replaced/disabled intake invalidates the prior occurrence first.
        Conditional candidates get fresh independent IDs, never legacy parents.
        """
        occurrence = _occurrence(outcome)
        selected = declarations(outcome.review_result)
        with self._lock:
            if selected == () and occurrence not in self._epochs:
                return
            grant = self._grants.pop(id(outcome), None)
            if grant is None:
                # Reentry/disabled/changed intake can withdraw its own prior
                # candidate, but stale or copied outcomes cannot erase a newer
                # live review grant or execution at the same location.
                if any(entry.outcome is outcome for entry in self._active.get(occurrence, ())):
                    self._withdraw(occurrence)
                return
            if (grant[2] != self._epochs.get(occurrence)
                    or (grant[1].file, grant[1].function, grant[1].line_start) != occurrence):
                return
            epoch = self._withdraw(occurrence)
        if epoch is None:
            return
        if enabled is not True:
            return
        selected = declarations(outcome.review_result)
        if selected == ():
            return
        if selected is None:
            self._unavailable_if_current(occurrence, epoch, "explicit-conditional-declaration-unavailable")
            return
        if (grant is None or grant[0] is not outcome or grant[3] != selected
                or type(grant[1]) is not KnowledgeOrigin
                or capture_source_identity(self.root, occurrence[0]) != grant[1].source_identity):
            self._unavailable_if_current(occurrence, epoch, "live-review-grant-unavailable")
            return
        if self.out_dir is None:
            self._unavailable_if_current(occurrence, epoch, "durable-output-unavailable")
            return
        with self._lock:
            if sum(len(values) for values in self._active.values()) + len(selected) > 64:
                self._unavailable[occurrence] = "conditional-run-budget"
                return
            if self._epochs.get(occurrence) != epoch:
                return
            entries = tuple(_Entry(ClaimRevision(item.material(), pass_id=grant[1].pass_id,
                                  file=occurrence[0], function=occurrence[1],
                                  line_start=occurrence[2]), outcome, selected, epoch, grant[1])
                            for item in selected)
            self._active[occurrence] = entries
        try:
            # The real pipeline issues and records identities BEFORE checking.
            # These records never enter the legacy verdict aggregation list.
            from .check_trace import record_claim_observations
            from .claim_verification import ClaimVerification
            record_claim_observations(self.out_dir, file=occurrence[0],
                                      function=occurrence[1], line_start=occurrence[2],
                                      verifications=[ClaimVerification(entry.revision.hypothesis,
                                                     claim_revision=entry.revision)
                                                     for entry in entries])
            from .conditional_member_copy import (
                ConditionalMemberValidatorOwner, REGISTRATION_CANDIDATE,
            )
            for entry in entries:
                units = _units(self.root)
                if any(identity is None for _, identity in units):
                    entry.reason = "conditional-source-unavailable"
                    continue
                owner = ConditionalMemberValidatorOwner(REGISTRATION_CANDIDATE,
                            current_revision=lambda entry=entry: self._current(entry))
                handle = owner.validate(self.root, revision=entry.revision,
                                        requested_conclusion=conclusion_signature())
                if type(handle) is not str:
                    entry.reason = "conditional-validator-refused"
                    continue
                if self._current(entry) is None or _units(self.root) != units:
                    entry.reason = "conditional-intake-changed"
                    continue
                with self._lock:
                    if any(value is entry for value in self._active.get(occurrence, ())):
                        entry.owner, entry.handle, entry.source_units = owner, handle, units
                        entry.reason = "conditional-pending-publication"
                        self._pending[entry.revision.revision_id] = entry
        except BaseException:
            self._withdraw(occurrence, expected_epoch=epoch)
            raise

    @staticmethod
    def _indexed(entry, claim_index):
        rows = claim_index.get("claims", ()) if type(claim_index) is dict else ()
        matches = [row for row in rows if type(row) is dict
                   and row.get("claim_reference") == entry.revision.event_reference()]
        # Same canonical definition convention as index_claim_observations.
        # This binds statement correspondence, not semantic proof authority.
        expected = sha256(dumps_canonical({"definition": entry.revision.reference(),
                                          "hypothesis": entry.revision.hypothesis}).encode("utf-8")).hexdigest()
        return (len(matches) == 1
                and matches[0].get("definition") == entry.revision.reference()
                and matches[0].get("definition_sha256") == expected)

    def shadow_inputs(self, claim_index):
        """Consume pending exports once; no replay of previously issued facts.

        Authenticated claim indexing is an extra correspondence gate, not the
        semantic authority. Only our privately created owner can issue a fact.
        """
        with self._lock:
            pending = tuple(self._pending.values())
            self._pending.clear()  # before callbacks, source reads or retention
            unavailable = tuple(self._unavailable.items())
            budget_refused = self._budget_refused
        contexts, events, contracts = [], [], {}
        accepted = []
        availability = [{"claim_reference": None, "reason": reason,
                         "assessment": "shadow-only", "authoritative": False}
                        for _, reason in unavailable]
        if budget_refused:
            availability.append({"claim_reference": None, "reason": "conditional-occurrence-budget",
                                 "assessment": "shadow-only", "authoritative": False})
        try:
            for entry in pending:
                reference = entry.revision.reference()
                entry.reason = "conditional-publication-consumed"
                try:
                    if (self._current(entry) is None or not self._indexed(entry, claim_index)
                            or _units(self.root) != entry.source_units):
                        reason = "conditional-currentness-or-index-unavailable"
                    else:
                        from .conditional_member_copy import ConditionalMemberValidatorOwner
                        if type(entry.owner) is not ConditionalMemberValidatorOwner:
                            reason = "conditional-owner-unavailable"
                        else:
                            issued = entry.owner.shadow_inputs(entry.handle, root=self.root,
                                      revision=entry.revision, out_dir=self.out_dir)
                            if (type(issued) is not tuple or self._current(entry) is None
                                    or _units(self.root) != entry.source_units):
                                reason = "conditional-retention-or-currentness-unavailable"
                            else:
                                accepted.append((entry, issued))
                                reason = "retained-conditional-support"
                    availability.append({"claim_reference": reference, "reason": reason,
                                         "effect_scope": conclusion_signature().effect_scope,
                                         "requested_conclusion": asdict(conclusion_signature()),
                                         "assessment": "shadow-only", "authoritative": False,
                                         "issuer_cwe_verified": False})
                except Exception:
                    availability.append({"claim_reference": reference,
                                         "reason": "conditional-publication-unavailable",
                                         "assessment": "shadow-only", "authoritative": False})
                finally:
                    # No cached owner/handle is available for another publication.
                    entry.owner, entry.handle = None, None
        finally:
            for entry in pending:
                entry.owner, entry.handle = None, None
        # Recheck the common three-file baseline after ALL callbacks/retention,
        # so mutation while publishing a later candidate withdraws earlier ones.
        current_units = _units(self.root) if accepted else ()
        for entry, issued in accepted:
            if self._current(entry) is None or current_units != entry.source_units:
                for row in availability:
                    if row.get("claim_reference") == entry.revision.reference():
                        row["reason"] = "conditional-final-currentness-unavailable"
                continue
            c, e, k, _ = issued
            contexts.extend(c)
            events.extend(e)
            contracts.update(k)
        return contexts, events, contracts, availability
