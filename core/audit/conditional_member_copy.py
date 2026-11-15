"""UNAPPLIED/UNQUALIFIED local validator proposal; shadow-only integration.

The run owner executes source validation itself and retains private results.
Neither a supplied observation/hash, condition string nor build-ID placeholder
can issue a fact. This proves only the registered conditional size statement.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from threading import Lock
from uuid import uuid4

from core.atomic_fs import write_bytes_atomically
from core.source import open_regular_beneath
from core.inventory.extractors import _ts_parser_for
from core.inventory._ts_cache import parse_budget_s

from .claim_adjudication import ClaimContext, ClaimContract, FactEvent
from .claims import ClaimRevision, hypothesis_material_key
from .conditional_member_policy import POLICY_ID, POLICY_VERSION, STATEMENT, conclusion_signature
from .integer_literals import integer_literal_value
from .member_copy_observation import (
    MemberCopyObservation, _check_tree, _named, _text,
    observe_member_copy,
)
from .refutation_source import capture_source_identity

CONTRACT_ID = "conditional-member-narrow-alloc-copy-v1"
OBLIGATION = "closed-conditional-pre-copy-size-relation"
MECHANISM = "unsigned-member-narrow-alloc-wide-copy-v1"
# Preserved issuer taxonomy only: this validator never proves CWE classification.
# In particular unsigned narrowing supplies no signed-input CWE-195 argument.
_FILES = ("protocol/parser.c", "protocol/message.c", "protocol/message.h")
# Candidate registration, not installed in any live registry by this proposal.
REGISTRATION_CANDIDATE = ClaimContract("conditional-member-copy", "1", frozenset({OBLIGATION}), frozenset())


@dataclass(frozen=True)
class ValidationUnavailable:
    reason: str


@dataclass(frozen=True)
class _Validated:
    revision_reference: dict
    material_key: tuple
    context: ClaimContext
    conclusion: object
    observation: MemberCopyObservation
    request_id: str
    invocation_id: str
    magic_value: int
    allocated: int
    copied: int


def _current(root, units):
    return tuple((file, capture_source_identity(root, file)) for file in _FILES) == units


def _magic_value(root, observation):
    """Validate an additional guard premise; no byte-order/packet-layout guess."""
    stream = open_regular_beneath(root, _FILES[0], "rb")
    if stream is None:
        return None
    with stream:
        raw = stream.read(32769)
    expected = dict(observation.source_units)[_FILES[0]]
    if len(raw) > 32768 or hashlib.sha256(raw).hexdigest() != expected.sha256:
        return None
    if parse_budget_s() <= 0:
        return None
    parser = _ts_parser_for("c")
    # The preceding real observation enforced configured/native parser bounds;
    # recheck the native bound before the additional parse, without mutating it.
    if parser is None or type(getattr(parser, "timeout_micros", None)) is not int or parser.timeout_micros <= 0:
        return None
    tree = parser.parse(raw)
    _check_tree(tree.root_node, 4096, 64)
    functions = [n for n in _named(tree.root_node) if n.type == "function_definition"]
    if len(functions) != 1:
        return None
    statements = _named(functions[0].child_by_field_name("body"))
    condition = statements[3].child_by_field_name("condition")
    stack = [condition] if condition is not None else []
    values = []
    while stack:
        node = stack.pop()
        if node.type == "number_literal":
            values.append(integer_literal_value(_text(node, raw)))
        stack.extend(node.children)
    return values[0] if len(values) == 1 and type(values[0]) is int and 0 <= values[0] < 1 << 32 else None


class ConditionalMemberValidatorOwner:
    """Project-owned run-local execution/retention boundary, not JSON ingress.

    The owner must be selected explicitly by reviewed project registration.
    No existing pipeline factory, publication switch or export is changed.
    """
    def __init__(self, registration, *, current_revision):
        if registration is not REGISTRATION_CANDIDATE:
            raise ValueError("project registration required")
        if not callable(current_revision):
            raise TypeError("pipeline-owned current revision accessor required")
        self._current_revision = current_revision
        self._validated = {}
        self._reference_lock = Lock()

    def validate(self, root, *, revision, requested_conclusion, size_max_refinement=None):
        if type(revision) is not ClaimRevision or self._current_revision() is not revision:
            return ValidationUnavailable("pipeline-revision-required")
        try:
            expected = conclusion_signature(size_max_refinement=size_max_refinement)
        except ValueError:
            return ValidationUnavailable("model-size-refinement-unavailable")
        if requested_conclusion != expected:
            return ValidationUnavailable("closed-conclusion-or-condition-mismatch")
        material = revision.hypothesis
        if set(material) != {"mechanism", "mechanism_kind", "cwe"}:
            return ValidationUnavailable("claim-shape-outside-closed-contract")
        if (material.get("mechanism") != STATEMENT or material.get("mechanism_kind") != MECHANISM
                or type(material.get("cwe")) is not str
                or material["cwe"] not in {"CWE-190", "CWE-195", "CWE-680"}):
            return ValidationUnavailable("explicit-per-claim-class-and-mechanism-unavailable")
        key = hypothesis_material_key(material)
        if key is None or any(len(value.encode("utf-8")) > 4096 for value in key):
            return ValidationUnavailable("claim-material-unavailable")
        # H remains symbolic and positive. The known size_t16 refinement cannot
        # satisfy SIZE_MAX >= H+65537 and cannot preserve memcpy's count.
        if size_max_refinement is not None and size_max_refinement <= 65537:
            return ValidationUnavailable("conditional-size-domain-inconsistent")
        request_id, invocation_id = uuid4().hex, uuid4().hex
        try:
            observed = observe_member_copy(root, claim_revision=revision)
            if type(observed) is not MemberCopyObservation:
                return ValidationUnavailable("source-premises-unavailable")
            if (observed.declared_cwe != material["cwe"]
                    or observed.claim_reference != (revision.claim_id, revision.revision_id)):
                return ValidationUnavailable("claim-occurrence-mismatch")
            magic = _magic_value(root, observed)
            if magic is None:
                return ValidationUnavailable("accepted-magic-domain-unavailable")
            # The registered rule justifies these numeric roles under the
            # explicit standard typedef/effect conditions, not observed ABI.
            copied = 65537
            allocated = copied % (1 << 16)
            if not 0 < allocated < copied < 1 << 32:
                return ValidationUnavailable("conditional-relation-not-established")
            dependencies = tuple(f"source:{file}:{identity.sha256}:{identity.version}"
                                 for file, identity in observed.source_units)
            context = ClaimContext(revision.claim_id, revision.revision_id,
                                   dict(observed.source_units)[_FILES[0]], CONTRACT_ID,
                                   dependencies + (f"policy:{POLICY_ID}:{POLICY_VERSION}",),
                                   expected.conditions, (_FILES[0], "parse_header", revision.line_start),
                                   revision.parent_revision)
            result = _Validated(revision.reference(), key, context, expected, observed,
                                request_id, invocation_id, magic, allocated, copied)
            if self._current_revision() is not revision or not _current(root, observed.source_units):
                return ValidationUnavailable("source-changed")
        except Exception:
            return ValidationUnavailable("conditional-validation-unavailable")
        reference = uuid4().hex
        with self._reference_lock:
            self._validated[reference] = result
        return reference

    def shadow_inputs(self, reference, *, root, revision, out_dir: Path):
        """Retain/recheck an owner's executed result before constructing facts.

        No caller-filled raw-reference string, observation object or deserialized
        proof can enter here. Unresolved external conditions remain on context.
        """
        # Burn on attempt: atomically remove BEFORE any caller callback or I/O.
        # Failed/cancelled retention never restores this handle. A new validation
        # execution is required; no automatic retry or cached-result resurrection.
        with self._reference_lock:
            result = self._validated.pop(reference, None) if type(reference) is str else None
        if result is None or type(revision) is not ClaimRevision:
            return ValidationUnavailable("owned-executed-result-unavailable")
        if (self._current_revision() is not revision
                or revision.reference() != result.revision_reference
                or hypothesis_material_key(revision.hypothesis) != result.material_key
                or not _current(root, result.observation.source_units)):
            return ValidationUnavailable("claim-or-source-changed")
        raw = json.dumps({"schema_version": 1, "policy": [POLICY_ID, POLICY_VERSION],
                          "meaning": "conditional-source-model-only", "actual_build_admitted": False,
                          "declared_cwe_role": "issuer-provenance-only", "issuer_cwe_verified": False,
                          "result": asdict(result)}, allow_nan=False, sort_keys=True).encode("utf-8")
        if len(raw) > 65536:
            return ValidationUnavailable("result-retention-budget")
        relative = f"conditional-member-results/{uuid4().hex}.json"
        try:
            write_bytes_atomically(out_dir / relative, raw, root=out_dir, replace=False, mode=0o600)
            stream = open_regular_beneath(out_dir, relative, "rb")
            if stream is None:
                return ValidationUnavailable("retained-result-unavailable")
            with stream:
                if stream.read(65537) != raw:
                    return ValidationUnavailable("retained-result-mismatch")
            if self._current_revision() is not revision or not _current(root, result.observation.source_units):
                return ValidationUnavailable("source-changed-after-retention")
        except Exception:
            return ValidationUnavailable("result-retention-unavailable")
        event = FactEvent(uuid4().hex, result.context, OBLIGATION,
                          REGISTRATION_CANDIDATE.adapter, REGISTRATION_CANDIDATE.version,
                          "completed", "supports_fact", result.request_id, result.request_id,
                          True, relative)
        # This tuple is for explicit shadow inspection only. No call to the
        # publisher/reducer/legacy verdict or export mutation is introduced.
        return ([result.context], [event], {CONTRACT_ID: REGISTRATION_CANDIDATE}, [])
