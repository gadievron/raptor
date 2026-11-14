"""Owned preparation candidates with independent revalidation and closed defaults.

The real measurement source and production admission are deliberately absent.
Typed data, fresh read tokens, parent execution observations and synthetic
fixtures do not establish OS namespace closure or authenticate a target build.
No public constructor argument, JSON flag or environment switch activates them.
"""

from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
import hashlib
import json
import os
from threading import RLock
import weakref

from .claim_support_contracts import PreparedTargetBinding
from .claims import ClaimRevision
from .prepared_compilation_database import AcquiredDeclaration, CompilationDatabaseOwner
from .prepared_execution_inputs import ParentExecInputs, snapshot_parent_inputs
from .refutation_source import SourceIdentity
from .smt_claim_contracts import PreparedSMTAnchor
from .verification_results import VerificationScope


@dataclass(frozen=True)
class BuildCaptureUnavailable:
    reason: str


@dataclass(frozen=True)
class BuildCaptureReference:
    ordinal: int


@dataclass(frozen=True)
class BuildCaptureDescription:
    measurement_scope: str
    parent_input_digest: str
    namespace_digest: str
    source_digest: str

    @property
    def authenticated_build(self) -> bool:
        return False

    @property
    def observed_child_context(self) -> bool:
        return False


@dataclass(frozen=True, repr=False)
class _BuildMeasurements:
    issuer: object
    read_token: object
    challenge: object
    epoch: object
    declaration: AcquiredDeclaration
    declaration_identity: SourceIdentity
    declaration_content: bytes
    actual_translation_unit: str
    operation: object
    invocation: object
    attempt: object
    inputs: ParentExecInputs
    namespace_reference: object
    source_identity: SourceIdentity
    source_content: bytes
    byte_start: int
    byte_end: int


@dataclass(frozen=True, repr=False)
class _ClosedSearchNamespace:
    issuer: object
    reference: object
    read_token: object
    challenge: object
    epoch: object
    roots: tuple[str, ...]
    members: tuple[tuple[str, SourceIdentity], ...]
    absent_lookups: tuple[str, ...]


@dataclass(frozen=True, repr=False)
class _ProductionAdmission:
    owner: object
    reference: BuildCaptureReference
    claim_key: tuple
    epoch: object


@dataclass(frozen=True)
class _PipelineInputs:
    target: PreparedTargetBinding
    anchor: PreparedSMTAnchor = field(repr=False)
    current: object = field(repr=False)


@dataclass(repr=False)
class _Capture:
    reference: BuildCaptureReference
    claim: object
    claim_key: tuple
    declaration: AcquiredDeclaration
    operation: object
    facts: object
    namespace: _ClosedSearchNamespace
    signature: tuple
    target: PreparedTargetBinding
    anchor: PreparedSMTAnchor
    description: BuildCaptureDescription
    payload_bytes: int
    admission_seen: bool = False


@dataclass(frozen=True, repr=False)
class _ReadIdentity:
    read_token: object
    epoch: object
    invocation: object
    attempt: object
    namespace_reference: object

    @classmethod
    def from_facts(cls, facts):
        return cls(facts.read_token, facts.epoch, facts.invocation, facts.attempt, facts.namespace_reference)


class _Refused(ValueError):
    pass


def _production_measurement_source():
    # A future independent measurement owner needs concrete source/resource
    # review. Nothing in this module manufactures that capability from data.
    return None


def _production_admission(owner, reference):
    # Separate reviewed activation, not a caller-supplied boolean.
    return None


def _selected_execution(result):
    from core.sandbox.context import _read_execution_observation
    return _read_execution_observation(result)


def _claim_key(record):
    revision = record.claim_revision
    scope = record.binding
    if (type(revision) is not ClaimRevision or type(scope) is not VerificationScope
            or not _identity(scope.source_identity) or not scope.has_claim
            or not revision.matches_occurrence(file=scope.file, function=scope.function,
                                               line_start=scope.line_start, hypothesis=scope.hypothesis)):
        raise _Refused("claim_source_binding_unavailable")
    reference = revision.reference()
    return reference["claim_id"], reference["revision_id"], revision.pass_id, scope


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _identity(value):
    return (type(value) is SourceIdentity and type(value.sha256) is str
            and len(value.sha256) == 64 and all(c in "0123456789abcdef" for c in value.sha256)
            and type(value.version) is tuple and len(value.version) == 5
            and all(type(n) is int for n in value.version))


def _path(value):
    valid = (type(value) is str and 0 < len(value) <= 4096 and value.startswith("/")
            and "\0" not in value and "\\" not in value
            and (value == "/" or all(part not in ("", ".", "..") for part in value[1:].split("/"))))
    if not valid:
        return False
    try:
        return os.fsdecode(os.fsencode(value)) == value
    except UnicodeError:
        return False


class PreparedBuildCaptureOwner:
    """Bounded candidate custody; public use remains unavailable by default.

    A private reader must independently observe the selected operation, source
    and entire closed regular-file search image, including absent lookups. A
    typed manifest or a new token alone cannot prove that observation. Inert
    readers in tests explicitly use ``synthetic-fixture-only`` scope.

    Payload bounds count retained declaration/source/input/path bytes, not heap
    usage. Close revokes this owner's references, not the external declaration
    owner's resources. Neither public views nor candidates confer authority.
    """

    def __init__(self, declarations: CompilationDatabaseOwner, *, max_captures: int,
                 max_source_bytes: int, max_namespace_items: int, max_retained_bytes: int):
        if type(declarations) is not CompilationDatabaseOwner:
            raise ValueError("owned_declarations_required")
        if any(type(n) is not int or n < 1 for n in
               (max_captures, max_source_bytes, max_namespace_items, max_retained_bytes)):
            raise ValueError("invalid_build_capture_budget")
        self._declarations = declarations
        self._max_captures, self._max_source_bytes = max_captures, max_source_bytes
        self._max_namespace_items, self._max_retained_bytes = max_namespace_items, max_retained_bytes
        self._records = {}
        self._closed, self._active = False, False
        self._lock = RLock()
        try:
            self._reader = _production_measurement_source()
        except Exception:
            self._reader = None

    @contextmanager
    def _operation(self):
        with self._lock:
            if self._active:
                raise _Refused("capture_owner_reentered")
            try:
                self._active = True
                if self._closed:
                    raise _Refused("capture_owner_closed")
                yield
            finally:
                self._active = False

    def _owned(self, reference):
        record = self._records.get(id(reference))
        if (type(reference) is not BuildCaptureReference or record is None
                or record.reference is not reference):
            raise _Refused("unowned_capture_reference")
        return record

    def _snapshot(self, value):
        if (type(value) is not ParentExecInputs or type(value.argv) is not tuple
                or type(value.environment) is not tuple or not 0 < len(value.argv) <= 4096
                or len(value.environment) > 4096 or type(value.cwd) is not bytes
                or type(value.payload_bytes) is not int or type(value.sha256) is not str
                or len(value.sha256) != 64 or type(value.filesystem_encoding) is not str
                or type(value.filesystem_errors) is not str):
            raise _Refused("execution_inputs_unavailable")
        leaves = [*value.argv, value.cwd]
        for pair in value.environment:
            if type(pair) is not tuple or len(pair) != 2:
                raise _Refused("execution_inputs_unavailable")
            leaves.extend(pair)
        if (any(type(item) is not bytes or len(item) > 1024 * 1024 for item in leaves)
                or sum(map(len, leaves)) > min(4 * 1024 * 1024, self._max_retained_bytes)):
            raise _Refused("execution_input_budget")
        rebuilt = snapshot_parent_inputs(
            [os.fsdecode(a) for a in value.argv],
            {os.fsdecode(k): os.fsdecode(v) for k, v in value.environment}, os.fsdecode(value.cwd),
            max_args=4096, max_env=4096, max_item_bytes=1024 * 1024,
            max_total_bytes=min(4 * 1024 * 1024, self._max_retained_bytes),
        )
        if rebuilt != value:
            raise _Refused("execution_input_digest_mismatch")
        return rebuilt

    def _namespace(self, facts):
        challenge = object()
        namespace = self._reader.read_namespace(facts.namespace_reference, challenge=challenge)
        if (type(namespace) is not _ClosedSearchNamespace or namespace.issuer is not self._reader
                or namespace.challenge is not challenge
                or namespace.reference is not facts.namespace_reference
                or type(namespace.roots) is not tuple or not namespace.roots
                or type(namespace.members) is not tuple or not namespace.members
                or type(namespace.absent_lookups) is not tuple or not namespace.absent_lookups):
            raise _Refused("closed_search_namespace_unavailable")
        if len(namespace.roots) + len(namespace.members) + len(namespace.absent_lookups) > self._max_namespace_items:
            raise _Refused("namespace_item_budget")
        if any(not _path(p) for p in namespace.roots) or len(set(namespace.roots)) != len(namespace.roots):
            raise _Refused("namespace_roots_unavailable")
        if any(left.startswith(right.rstrip("/") + "/")
               for left in namespace.roots for right in namespace.roots if left != right):
            raise _Refused("namespace_roots_overlap")

        def inside(path):
            return _path(path) and any(path.startswith(root.rstrip("/") + "/") for root in namespace.roots)

        members = {}
        for item in namespace.members:
            if (type(item) is not tuple or len(item) != 2 or not inside(item[0])
                    or not _identity(item[1]) or item[0] in members):
                raise _Refused("namespace_inventory_unavailable")
            members[item[0]] = item[1]
        if tuple(members) != tuple(sorted(members)):
            raise _Refused("namespace_inventory_not_canonical")
        absent = namespace.absent_lookups
        if (any(not inside(path) or path in members for path in absent)
                or tuple(sorted(set(absent))) != absent):
            raise _Refused("negative_lookup_namespace_unavailable")
        encoded = json.dumps((namespace.roots, tuple((p, i.sha256, i.version) for p, i in members.items()),
                              absent), ensure_ascii=True, separators=(",", ":")).encode("ascii")
        return namespace, members, _digest(encoded), len(encoded)

    def _observe(self, claim, acquired, result, previous=None):
        if self._reader is None:
            raise _Refused("independent_build_measurements_unavailable")
        scope = self._reader.scope
        if scope not in ("synthetic-fixture-only", "production-measured"):
            raise _Refused("measurement_scope_unavailable")
        if not self._declarations.retains(acquired):
            raise _Refused("declaration_custody_unavailable")
        challenge = object()
        facts = self._reader.read(claim, acquired, result, challenge=challenge)
        if (type(facts) is not _BuildMeasurements or facts.issuer is not self._reader
                or facts.challenge is not challenge
                or facts.declaration is not acquired or facts.operation is not result
                or type(facts.read_token) is not object or type(facts.epoch) is not object
                or type(facts.namespace_reference) is not object):
            raise _Refused("owned_build_measurements_unavailable")
        raw = acquired.selected.capture.database_bytes
        if (not _identity(facts.declaration_identity)
                or facts.declaration_identity != acquired.source_identity
                or type(facts.declaration_content) is not bytes
                or facts.declaration_content != raw):
            raise _Refused("current_declaration_measurement_mismatch")
        execution = _selected_execution(result)
        inputs = self._snapshot(facts.inputs)
        if (execution is None or execution.invocation is not facts.invocation
                or execution.attempt is not facts.attempt
                or execution.parent_input_digest != inputs.sha256
                or execution.status_observation != (None, "read-eof", 2, True)
                or execution.wait_origin not in ("capture-poll-waitpid", "final-poll-waitpid", "final-blocking-waitpid")
                or execution.caller_kill_exemption_applied is not False
                or result.returncode != 0):
            raise _Refused("selected_execution_inputs_unavailable")
        invocation = acquired.selected.invocation
        if (type(facts.actual_translation_unit) is not str
                or facts.actual_translation_unit != invocation.translation_unit
                or invocation.translation_unit != claim.binding.file):
            raise _Refused("measured_translation_unit_mismatch")
        if (inputs.argv != tuple(os.fsencode(a) for a in invocation.ordered_arguments)
                or inputs.cwd != os.fsencode(invocation.declared_directory)):
            raise _Refused("declaration_execution_mismatch")
        namespace, members, namespace_digest, namespace_bytes = self._namespace(facts)
        if type(namespace.read_token) is not object or type(namespace.epoch) is not object:
            raise _Refused("namespace_epoch_unavailable")
        if previous is not None and (
            facts.read_token is previous.facts.read_token or namespace.read_token is previous.namespace.read_token
            or facts.issuer is not previous.namespace.issuer
            or facts.epoch is not previous.facts.epoch or namespace.epoch is not previous.namespace.epoch
            or facts.namespace_reference is not previous.facts.namespace_reference
            or facts.invocation is not previous.facts.invocation or facts.attempt is not previous.facts.attempt
        ):
            raise _Refused("measurement_epoch_changed_or_read_echoed")
        source = facts.source_content
        if (type(source) is not bytes or not 0 < len(source) <= self._max_source_bytes
                or not _identity(facts.source_identity) or _digest(source) != facts.source_identity.sha256
                or facts.source_identity != claim.binding.source_identity
                or facts.source_identity.version[2] != len(source)
                or type(facts.byte_start) is not int or type(facts.byte_end) is not int
                or not 0 <= facts.byte_start < facts.byte_end <= len(source)):
            raise _Refused("exact_source_anchor_unavailable")
        unit = invocation.translation_unit
        source_path = unit if unit.startswith("/") else invocation.declared_directory.rstrip("/") + "/" + unit
        if not _path(source_path) or members.get(source_path) != facts.source_identity:
            raise _Refused("source_namespace_binding_unavailable")
        compiler = os.fsdecode(inputs.argv[0])
        if compiler not in members:
            raise _Refused("compiler_namespace_binding_unavailable")
        selected = acquired.selected.selected_entry_bytes
        signature = (scope, acquired.source_identity, raw, acquired.selected.selected_interval, selected,
                     inputs, namespace.roots, namespace.members, namespace.absent_lookups,
                     facts.source_identity, source, facts.byte_start, facts.byte_end)
        build_digest = _digest(json.dumps((_digest(raw), _digest(selected), inputs.sha256,
                                          namespace_digest, facts.source_identity.sha256),
                                         separators=(",", ":")).encode("ascii"))
        target = PreparedTargetBinding(
            unit, scope + ":" + facts.source_identity.sha256, scope + ":" + build_digest,
            ("declaration:" + _digest(raw), "parent-exec-inputs:" + inputs.sha256,
             "closed-search-namespace:" + namespace_digest, "compiler-material:" + members[compiler].sha256),
            ("measurement-scope:" + scope,), "source", "source-language",
        )
        anchor = PreparedSMTAnchor(claim.binding.file, facts.source_identity, source,
                                   facts.byte_start, facts.byte_end, source[facts.byte_start:facts.byte_end])
        description = BuildCaptureDescription(scope, inputs.sha256, namespace_digest, facts.source_identity.sha256)
        payload_bytes = len(raw) + len(source) + len(anchor.expected_span) + inputs.payload_bytes + namespace_bytes
        return facts, namespace, signature, target, anchor, description, payload_bytes

    def capture(self, claim, acquired, operation_result):
        reference = None
        try:
            with self._operation():
                key = _claim_key(claim)
                if len(self._records) >= self._max_captures:
                    raise _Refused("capture_count_budget")
                observed = self._observe(claim, acquired, operation_result)
                if observed[-1] > self._max_retained_bytes - sum(r.payload_bytes for r in self._records.values()):
                    raise _Refused("capture_retained_byte_budget")
                reference = BuildCaptureReference(len(self._records))
                self._records[id(reference)] = _Capture(
                    reference, claim, key, acquired, weakref.ref(operation_result),
                    _ReadIdentity.from_facts(observed[0]), *observed[1:],
                )
                return reference
        except BaseException as error:
            if reference is not None:
                with suppress(BaseException):
                    self._records.pop(id(reference), None)
            if isinstance(error, Exception):
                return BuildCaptureUnavailable(str(error) if isinstance(error, _Refused) else "build_measurement_unavailable")
            raise

    def _refresh(self, record):
        try:
            result = record.operation()
            if result is None or _claim_key(record.claim) != record.claim_key:
                raise _Refused("capture_binding_retired")
            observed = self._observe(record.claim, record.declaration, result, record)
            if observed[2] != record.signature:
                raise _Refused("complete_measurement_epoch_changed")
            record.facts, record.namespace = _ReadIdentity.from_facts(observed[0]), observed[1]
            return record.target, record.anchor
        except BaseException as error:
            self._records.pop(id(record.reference), None)
            if isinstance(error, Exception):
                return None
            raise

    def current(self, reference):
        try:
            with self._operation():
                return self._refresh(self._owned(reference))
        except _Refused:
            return None

    def describe(self, reference):
        try:
            with self._operation():
                record = self._owned(reference)
                return record.description if self._refresh(record) is not None else BuildCaptureUnavailable("capture_revoked")
        except _Refused as error:
            return BuildCaptureUnavailable(str(error))

    def _admitted_current(self, claim, reference):
        try:
            with self._operation():
                record = self._owned(reference)
                if _claim_key(claim) != record.claim_key or self._refresh(record) is None:
                    return None
                try:
                    admission = _production_admission(self, reference)
                except BaseException as error:
                    self._records.pop(id(reference), None)
                    if isinstance(error, Exception):
                        return None
                    raise
                if (record.description.measurement_scope != "production-measured"
                        or type(admission) is not _ProductionAdmission or admission.owner is not self
                        or admission.reference is not reference or admission.claim_key != record.claim_key
                        or admission.epoch is not record.facts.epoch):
                    if record.admission_seen:
                        self._records.pop(id(reference), None)
                    return None
                record.admission_seen = True
                return record.target, record.anchor
        except _Refused:
            return None

    def for_pipeline(self, claim, reference):
        try:
            pair = self._admitted_current(claim, reference)
        except Exception:
            pair = None
        if pair is None:
            return BuildCaptureUnavailable("production_measurement_activation_unavailable")
        return _PipelineInputs(*pair, lambda: self._admitted_current(claim, reference))

    def close(self):
        with self._lock:
            if self._active:
                raise _Refused("capture_owner_reentered")
            self._closed = True
            self._records.clear()
