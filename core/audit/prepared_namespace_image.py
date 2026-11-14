"""Owned image-lease protocol; production acquisition is unavailable.

A digest, supplied inventory, read-only mount, or fresh token is not an OS
snapshot. A future private provider must independently establish consistent
acquisition, retained write/grow/shrink exclusion, complete directory and path
resolution closure, and final same-attempt consumption. No backend or activation
is installed here. Synthetic fixtures exercise protocol rules only.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import math
import posixpath
import subprocess
from threading import RLock
import time
import weakref

from .prepared_build_capture import _claim_key, _identity, _path
from .prepared_compilation_database import AcquiredDeclaration, CompilationDatabaseOwner
from .prepared_execution_attempt import ExecutionAttemptReference
from .refutation_source import SourceIdentity


def _production_image_source():
    return None


def _now():
    return time.monotonic()


@dataclass(frozen=True)
class SuppliedImageTarget:
    target_key: str
    artifact_sha256: str


@dataclass(frozen=True)
class NamespaceImageUnavailable:
    reason: str


@dataclass(frozen=True, eq=False)
class NamespaceImageReference:
    pass


@dataclass(frozen=True, eq=False)
class NamespaceImageHandoff:
    pass


@dataclass(frozen=True)
class NamespaceImageDescription:
    measurement_scope: str
    artifact_sha256: str
    files: int
    directories: int
    state: str
    authenticated_build: bool = field(default=False, init=False)
    observed_child_context: bool = field(default=False, init=False)


@dataclass(frozen=True, repr=False)
class _ImageFile:
    path: str
    content: bytes
    identity: SourceIdentity


@dataclass(frozen=True, repr=False)
class _ImageFacts:
    issuer: object
    challenge: object
    target: SuppliedImageTarget
    lease: object
    acquisition: object
    retention: object
    closure: object
    epoch: object
    artifact: bytes
    parent_root: str
    child_root: str
    directories: tuple[str, ...]
    files: tuple[_ImageFile, ...]
    unclosed_inputs: tuple[str, ...]


@dataclass(frozen=True, repr=False)
class _BindingFacts:
    issuer: object
    challenge: object
    lease: object
    epoch: object
    claim: object
    declaration: object
    source_path: str
    declaration_path: str


@dataclass(frozen=True, repr=False)
class _ConsumptionFacts:
    issuer: object
    challenge: object
    lease: object
    epoch: object
    handoff: object
    result: object
    invocation: object
    attempt: object
    final_view: object


@dataclass
class _Binding:
    claim: object
    declaration_owner: object
    declaration: object
    key: tuple
    source_path: str
    declaration_path: str
    payload_bytes: int


@dataclass
class _Selection:
    result: object
    handoff: NamespaceImageHandoff
    final_view: object


@dataclass
class _Record:
    reference: NamespaceImageReference
    target: SuppliedImageTarget
    lease: object
    acquisition: object
    retention: object
    closure: object
    epoch: object
    signature: tuple
    files: dict
    created: float
    payload_bytes: int
    metadata_bytes: int
    scope: str
    binding: _Binding | None = None
    pending: NamespaceImageHandoff | None = None
    selection: _Selection | None = None


@dataclass
class _Attempt:
    handoff: NamespaceImageHandoff
    image: NamespaceImageReference
    invocation: object
    attempt: ExecutionAttemptReference
    used: bool = False


class _Unavailable(ValueError):
    pass


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


class NamespaceImageOwner:
    """Bounded private lease custody, not a filesystem acquisition engine.

    Budgets count retained payload/encoded metadata, not Python RSS. The private
    provider's acquire is transactional: failure must retire unpublished leases.
    refresh/binding/consumption borrow an existing lease and issue fresh replies;
    release must revoke its logical lease even if physical cleanup reports an
    error. The lifetime budget limits eligibility on access, not autonomous
    physical retirement; actual provider expiry and explicit close remain required.
    There is no public provider, trust,
    enforcement or production-admission switch.
    """

    def __init__(self, *, max_images: int, max_artifact_bytes: int,
                 max_expanded_bytes: int, max_entries: int, max_metadata_bytes: int,
                 max_retained_bytes: int, max_handoffs: int, max_lifetime_seconds: int):
        limits = (max_images, max_artifact_bytes, max_expanded_bytes, max_entries,
                  max_metadata_bytes, max_retained_bytes, max_handoffs, max_lifetime_seconds)
        if any(type(value) is not int or value <= 0 for value in limits):
            raise ValueError("explicit positive integer image budgets required")
        self._limits = limits
        self._records, self._handoffs = {}, {}
        self._lock, self._active, self._closed = RLock(), False, False
        try:
            self._provider = _production_image_source()
        except Exception:
            self._provider = None

    @contextmanager
    def _operation(self):
        with self._lock:
            if self._closed or self._active:
                raise _Unavailable("image_owner_closed_or_busy")
            self._active = True
            try:
                yield
            finally:
                self._active = False

    def _owned(self, reference):
        record = self._records.get(id(reference))
        if record is None or record.reference is not reference:
            raise _Unavailable("image_reference_unavailable")
        return record

    def _time(self, created):
        now = _now()
        if (type(created) not in (int, float) or not math.isfinite(created)
                or type(now) not in (int, float) or not math.isfinite(now)
                or now < created or now - created >= self._limits[7]):
            raise _Unavailable("image_lifetime_unavailable")
        return now

    def _release(self, lease):
        self._provider.release(lease)

    def _revoke(self, record):
        self._records.pop(id(record.reference), None)
        record.selection = record.pending = record.binding = None
        self._release(record.lease)

    def _guard(self, record):
        self._time(record.created)
        if self._provider.scope != record.scope:
            raise _Unavailable("image_provider_scope_changed")

    def _failed_release(self, lease, primary):
        try:
            self._release(lease)
        except BaseException as cleanup:
            if isinstance(primary, Exception) and not isinstance(cleanup, Exception):
                raise

    def _failed_revoke(self, record, primary):
        try:
            self._revoke(record)
        except BaseException as cleanup:
            if isinstance(primary, Exception) and not isinstance(cleanup, Exception):
                raise

    def _facts(self, facts, target, challenge):
        if (type(facts) is not _ImageFacts or facts.issuer is not self._provider
                or facts.challenge is not challenge or facts.target is not target
                or any(type(token) is not object for token in
                       (facts.lease, facts.acquisition, facts.retention, facts.closure, facts.epoch))
                or facts.acquisition is facts.retention):
            raise _Unavailable("independent_image_lease_unavailable")
        if (type(facts.artifact) is not bytes or not facts.artifact
                or len(facts.artifact) > self._limits[1] or _digest(facts.artifact) != target.artifact_sha256
                or not _path(facts.parent_root) or facts.child_root != "/"
                or type(facts.unclosed_inputs) is not tuple or facts.unclosed_inputs):
            raise _Unavailable("image_artifact_or_enclosure_unavailable")
        if (type(facts.files) is not tuple or not facts.files
                or type(facts.directories) is not tuple or "/" not in facts.directories
                or len(facts.files) + len(facts.directories) > self._limits[3]):
            raise _Unavailable("image_inventory_budget_or_shape")
        dirs = set(facts.directories)
        if (len(dirs) != len(facts.directories) or any(not _path(path) for path in dirs)
                or facts.directories != tuple(sorted(dirs))):
            raise _Unavailable("image_directory_resolution_unavailable")
        for path in dirs - {"/"}:
            if posixpath.dirname(path) not in dirs:
                raise _Unavailable("image_directory_parent_unavailable")
        files, inodes, expanded, metadata = {}, set(), 0, []
        for entry in facts.files:
            if (type(entry) is not _ImageFile or not _path(entry.path)
                    or entry.path in dirs or entry.path in files
                    or posixpath.dirname(entry.path) not in dirs
                    or type(entry.content) is not bytes or not _identity(entry.identity)
                    or len(entry.content) > self._limits[2] - expanded
                    or entry.identity.sha256 != _digest(entry.content)
                    or entry.identity.version[2] != len(entry.content)):
                raise _Unavailable("image_regular_file_or_identity_unavailable")
            inode = entry.identity.version[:2]
            if inode in inodes:
                raise _Unavailable("image_alias_unavailable")
            inodes.add(inode)
            files[entry.path] = entry
            expanded += len(entry.content)
            if expanded > self._limits[2]:
                raise _Unavailable("image_expanded_byte_budget")
            metadata.append((entry.path, entry.identity.sha256, entry.identity.version))
        if tuple(files) != tuple(sorted(files)):
            raise _Unavailable("image_entry_order_unavailable")
        encoded = json.dumps((facts.parent_root, facts.child_root, facts.directories, metadata),
                             ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
        if len(encoded) > self._limits[4]:
            raise _Unavailable("image_metadata_budget")
        signature = (facts.artifact, facts.parent_root, facts.child_root, facts.directories, facts.files)
        return signature, files, len(facts.artifact) + expanded + len(encoded), len(encoded)

    def _refresh(self, record):
        self._guard(record)
        challenge = object()
        facts = self._provider.refresh(record.lease, record.target, challenge=challenge)
        signature, _, _, _ = self._facts(facts, record.target, challenge)
        if (signature != record.signature or facts.lease is not record.lease
                or facts.acquisition is not record.acquisition or facts.retention is not record.retention
                or facts.closure is not record.closure or facts.epoch is not record.epoch):
            raise _Unavailable("image_epoch_or_contents_changed")
        self._guard(record)

    def acquire(self, target):
        facts = reference = None
        try:
            with self._operation():
                scope = None if self._provider is None else self._provider.scope
                if scope not in ("synthetic-fixture-only", "independently-enforced-image"):
                    raise _Unavailable("image_acquisition_unavailable")
                if (type(target) is not SuppliedImageTarget or type(target.target_key) is not str
                        or not 0 < len(target.target_key) <= 128 or type(target.artifact_sha256) is not str
                        or len(target.artifact_sha256) != 64
                        or any(c not in "0123456789abcdef" for c in target.artifact_sha256)):
                    raise _Unavailable("explicit_image_target_required")
                if len(self._records) >= self._limits[0]:
                    raise _Unavailable("image_count_budget")
                created = _now()
                self._time(created)
                challenge = object()
                facts = self._provider.acquire(target, challenge=challenge)
                signature, files, payload, metadata_bytes = self._facts(facts, target, challenge)
                if any(r.lease is facts.lease for r in self._records.values()):
                    raise _Unavailable("image_lease_already_owned")
                self._time(created)
                if self._provider.scope != scope:
                    raise _Unavailable("image_provider_scope_changed")
                if payload > self._limits[5] - sum(r.payload_bytes + (r.binding.payload_bytes if r.binding else 0) for r in self._records.values()):
                    raise _Unavailable("image_retained_byte_budget")
                reference = NamespaceImageReference()
                self._records[id(reference)] = _Record(reference, target, facts.lease, facts.acquisition,
                    facts.retention, facts.closure, facts.epoch, signature, files, created, payload, metadata_bytes, scope)
                return reference
        except BaseException as error:
            if reference is not None:
                self._records.pop(id(reference), None)
            if (type(facts) is _ImageFacts and facts.issuer is self._provider and type(facts.lease) is object
                    and not any(r.lease is facts.lease for r in self._records.values())):
                self._failed_release(facts.lease, error)
            if isinstance(error, Exception):
                return NamespaceImageUnavailable(str(error) if isinstance(error, _Unavailable) else "image_acquisition_failed")
            raise

    def _binding(self, record, binding):
        self._guard(record)
        claim, owner, declaration = binding.claim(), binding.declaration_owner(), binding.declaration()
        if (claim is None or type(owner) is not CompilationDatabaseOwner
                or type(declaration) is not AcquiredDeclaration or not owner.retains(declaration)
                or _claim_key(claim) != binding.key):
            raise _Unavailable("same_view_binding_retired")
        source, database = record.files.get(binding.source_path), record.files.get(binding.declaration_path)
        if (source is None or database is None or claim.binding.source_identity != source.identity
                or declaration.source_identity != database.identity
                or declaration.selected.capture.database_bytes != database.content
                or claim.binding.file != declaration.selected.invocation.translation_unit
                or posixpath.join(declaration.selected.invocation.declared_directory, claim.binding.file) != binding.source_path):
            raise _Unavailable("same_view_physical_identity_unavailable")
        challenge = object()
        facts = self._provider.read_binding(record.lease, claim, declaration, challenge=challenge)
        if (type(facts) is not _BindingFacts or facts.issuer is not self._provider or facts.challenge is not challenge
                or facts.lease is not record.lease or facts.epoch is not record.epoch
                or facts.claim is not claim or facts.declaration is not declaration
                or facts.source_path != binding.source_path or facts.declaration_path != binding.declaration_path):
            raise _Unavailable("independent_same_view_binding_unavailable")
        self._guard(record)

    def bind_inputs(self, reference, claim, declaration_owner, declaration, *, source_path, declaration_path):
        record = None
        try:
            with self._operation():
                record = self._owned(reference)
                record.binding = record.pending = record.selection = None
                if not _path(source_path) or not _path(declaration_path):
                    raise _Unavailable("image_binding_paths_unavailable")
                self._refresh(record)
                key = _claim_key(claim)
                scope = claim.binding
                encoded = json.dumps((key[:3], scope.file, scope.function, scope.line_start, scope.hypothesis,
                                      source_path, declaration_path), ensure_ascii=True, allow_nan=False).encode("ascii")
                retained = sum(r.payload_bytes + (r.binding.payload_bytes if r.binding else 0)
                               for r in self._records.values())
                if (len(encoded) > self._limits[4] - record.metadata_bytes
                        or len(encoded) > self._limits[5] - retained):
                    raise _Unavailable("image_binding_metadata_budget")
                binding = _Binding(weakref.ref(claim), weakref.ref(declaration_owner), weakref.ref(declaration),
                                   key, source_path, declaration_path, len(encoded))
                self._binding(record, binding)
                record.binding = binding
                return None
        except BaseException as error:
            if record is not None:
                self._failed_revoke(record, error)
            if isinstance(error, Exception):
                return NamespaceImageUnavailable(str(error) if isinstance(error, _Unavailable) else "image_binding_failed")
            raise

    def handoff(self, reference, invocation, attempt):
        record = token = None
        try:
            with self._operation():
                record = self._owned(reference)
                record.pending = record.selection = None
                self._refresh(record)
                if record.binding is None:
                    raise _Unavailable("same_view_binding_unavailable")
                self._binding(record, record.binding)
                if (type(invocation) is not object or type(attempt) is not ExecutionAttemptReference
                        or type(attempt.ordinal) is not int or attempt.ordinal < 0
                        or len(self._handoffs) >= self._limits[6]):
                    raise _Unavailable("image_attempt_budget_or_identity")
                token = NamespaceImageHandoff()
                self._handoffs[id(token)] = _Attempt(token, reference, invocation, attempt)
                record.pending = token
                return token
        except BaseException as error:
            if token is not None:
                self._handoffs.pop(id(token), None)
            if record is not None:
                self._failed_revoke(record, error)
            if isinstance(error, Exception):
                return NamespaceImageUnavailable(str(error) if isinstance(error, _Unavailable) else "image_handoff_failed")
            raise

    def _consumption(self, record, token, result, final_view=None):
        self._guard(record)
        attempt = self._handoffs.get(id(token))
        if attempt is None or attempt.handoff is not token or attempt.image is not record.reference:
            raise _Unavailable("image_handoff_unavailable")
        challenge = object()
        facts = self._provider.read_consumption(record.lease, token, result, challenge=challenge)
        if (type(facts) is not _ConsumptionFacts or facts.issuer is not self._provider
                or facts.challenge is not challenge or facts.lease is not record.lease
                or facts.epoch is not record.epoch or facts.handoff is not token or facts.result is not result
                or facts.invocation is not attempt.invocation or facts.attempt is not attempt.attempt
                or type(facts.final_view) is not object
                or (final_view is not None and facts.final_view is not final_view)):
            raise _Unavailable("selected_final_image_consumption_unavailable")
        self._guard(record)
        return facts.final_view

    def select(self, token, result):
        record = None
        try:
            with self._operation():
                attempt = self._handoffs.get(id(token))
                if attempt is None or attempt.handoff is not token or attempt.used:
                    raise _Unavailable("image_handoff_used_or_foreign")
                attempt.used = True
                record = self._owned(attempt.image)
                if record.pending is not token or type(result) is not subprocess.CompletedProcess:
                    raise _Unavailable("image_selected_attempt_unavailable")
                self._refresh(record)
                self._binding(record, record.binding)
                view = self._consumption(record, token, result)
                record.selection = _Selection(weakref.ref(result), token, view)
                record.pending = None
                return self._description(record)
        except BaseException as error:
            if record is not None:
                self._failed_revoke(record, error)
            if isinstance(error, Exception):
                return NamespaceImageUnavailable(str(error) if isinstance(error, _Unavailable) else "image_selection_failed")
            raise

    def _description(self, record):
        return NamespaceImageDescription(record.scope, record.target.artifact_sha256,
            len(record.files), len(record.signature[3]), "selected-protocol" if record.selection else "acquired-protocol")

    def current(self, reference):
        record = None
        try:
            with self._operation():
                record = self._owned(reference)
                self._refresh(record)
                if record.binding is not None:
                    self._binding(record, record.binding)
                if record.selection is not None:
                    result = record.selection.result()
                    if result is None:
                        raise _Unavailable("selected_result_retired")
                    self._consumption(record, record.selection.handoff, result, record.selection.final_view)
                return self._description(record)
        except BaseException as error:
            if record is not None:
                self._failed_revoke(record, error)
            if isinstance(error, Exception):
                return None
            raise

    def retire(self, reference):
        with self._operation():
            self._revoke(self._owned(reference))

    def close(self):
        with self._lock:
            if self._active:
                raise _Unavailable("image_owner_busy")
            self._closed = True
            self._handoffs.clear()
            error = None
            while self._records:
                _, record = self._records.popitem()
                try:
                    self._release(record.lease)
                except BaseException as caught:
                    if error is None or (isinstance(error, Exception) and not isinstance(caught, Exception)):
                        error = caught
            if error is not None:
                raise error
