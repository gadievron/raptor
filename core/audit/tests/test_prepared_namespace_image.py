"""Synthetic lease protocol controls; no mount, seal, image builder or native run."""
from dataclasses import replace
import gc
import hashlib
import json
from types import SimpleNamespace
import subprocess
import weakref

import pytest

from core.audit import prepared_namespace_image as module
from core.audit.claims import ClaimRevision
from core.audit.claim_verification import ClaimVerification
from core.audit.prepared_compilation_database import CompilationDatabaseOwner
from core.audit.prepared_execution_attempt import ExecutionInputOwner
from core.audit.prepared_dependency_material import DependencyReference
from core.audit.refutation_source import capture_source_identity
from core.audit.verification_results import VerificationScope

BUDGETS = dict(max_images=4, max_artifact_bytes=4096, max_expanded_bytes=8192,
               max_entries=32, max_metadata_bytes=4096, max_retained_bytes=32768,
               max_handoffs=8, max_lifetime_seconds=60)
PRODUCTION_FACTORY = module._production_image_source


class SyntheticImageProvider:
    scope = "synthetic-fixture-only"

    def __init__(self, root, clock):
        self.root, self.clock = root, clock
        self.leases, self.released, self.consumers = {}, [], {}
        self.alter_image = self.alter_binding = self.alter_consumption = lambda value: value
        self.release_error = None
        self.reuse = False
        self.reads = self.binding_reads = self.consumption_reads = 0

    def acquire(self, target, *, challenge):
        if self.reuse and self.leases:
            return replace(next(iter(self.leases.values())), challenge=challenge, target=target)
        files = tuple(module._ImageFile(path, (self.root / path[1:]).read_bytes(),
                       capture_source_identity(self.root, path[1:]))
                      for path in ("/src/compile_commands.json", "/src/unit.c", "/toolchain/cc"))
        lease = object()
        facts = module._ImageFacts(self, challenge, target, lease, object(), object(), object(), object(),
            b"synthetic immutable-image bytes, not a mounted filesystem", str(self.root), "/",
            ("/", "/src", "/toolchain"), files, ())
        self.leases[lease] = facts
        return self.alter_image(facts)

    def refresh(self, lease, target, *, challenge):
        self.reads += 1
        if lease in self.released:
            return None
        return self.alter_image(replace(self.leases[lease], target=target, challenge=challenge))

    def read_binding(self, lease, claim, declaration, *, challenge):
        self.binding_reads += 1
        return self.alter_binding(module._BindingFacts(self, challenge, lease, self.leases[lease].epoch,
            claim, declaration, "/src/unit.c", "/src/compile_commands.json"))

    def register_consumer(self, token, result, invocation, attempt):
        self.consumers[token] = weakref.ref(result), invocation, attempt, object()

    def read_consumption(self, lease, token, result, *, challenge):
        self.consumption_reads += 1
        registered = self.consumers.get(token)
        if registered is None or registered[0]() is not result:
            return None
        return self.alter_consumption(module._ConsumptionFacts(self, challenge, lease, self.leases[lease].epoch,
            token, result, registered[1], registered[2], registered[3]))

    def release(self, lease):
        self.released.append(lease)
        self.leases.pop(lease, None)
        if self.release_error is not None:
            raise self.release_error


@pytest.fixture
def image_case(tmp_path, monkeypatch):
    root = tmp_path / "view"
    (root / "src").mkdir(parents=True)
    (root / "toolchain").mkdir()
    (root / "src/unit.c").write_text("int f(int x) { return x + 1; }\n")
    (root / "toolchain/cc").write_bytes(b"synthetic compiler material, never executed")
    (root / "src/compile_commands.json").write_text(json.dumps([
        {"directory": "/src", "file": "unit.c", "arguments": ["/toolchain/cc", "-c", "unit.c"]}]))
    declarations = CompilationDatabaseOwner({"view": root / "src"}, max_retained_bytes=8192,
                                           max_captures=4, max_selections=4)
    declaration = declarations.acquire(DependencyReference("view", "compile_commands.json"), "unit.c",
        declared_build_association="synthetic-image-only", max_database_bytes=4096,
        max_entries=4, max_entry_bytes=2048, max_depth=8)
    source = capture_source_identity(root / "src", "unit.c")
    hypothesis = "integer overflow in x + 1"
    revision = ClaimRevision({"mechanism": hypothesis}, pass_id="synthetic-image-pass",
                             file="unit.c", function="f", line_start=1)
    claim = ClaimVerification(revision.hypothesis,
        binding=VerificationScope("unit.c", "f", 1, hypothesis, source), claim_revision=revision)
    clock = [1.0]
    provider = SyntheticImageProvider(root, clock)
    monkeypatch.setattr(module, "_production_image_source", lambda: provider)
    monkeypatch.setattr(module, "_now", lambda: clock[0])
    owner = module.NamespaceImageOwner(**BUDGETS)
    input_owner = ExecutionInputOwner(max_attempts=8, max_retained_bytes=8192)
    artifact = b"synthetic immutable-image bytes, not a mounted filesystem"
    target = module.SuppliedImageTarget("explicit-synthetic-image", hashlib.sha256(artifact).hexdigest())
    case = SimpleNamespace(root=root, clock=clock, provider=provider, owner=owner, target=target,
                           claim=claim, declarations=declarations, declaration=declaration, input_owner=input_owner)
    try:
        yield case
    finally:
        provider.release_error = None
        owner.close()
        input_owner.close()
        declarations.close()


def _acquire(c):
    reference = c.owner.acquire(c.target)
    assert type(reference) is module.NamespaceImageReference
    return reference


def _bind(c, reference):
    return c.owner.bind_inputs(reference, c.claim, c.declarations, c.declaration,
                              source_path="/src/unit.c", declaration_path="/src/compile_commands.json")


def _attempt(c):
    reference = c.input_owner.reserve(["/toolchain/cc", "-c", "unit.c"], {"LANG": "C"}, "/src",
        max_args=8, max_env=4, max_item_bytes=256, max_total_bytes=2048)
    return c.input_owner.handoff_for_dispatch(reference).attempt


def _selected(c):
    reference = _acquire(c)
    assert _bind(c, reference) is None
    invocation, attempt = object(), _attempt(c)
    token = c.owner.handoff(reference, invocation, attempt)
    assert type(token) is module.NamespaceImageHandoff
    result = subprocess.CompletedProcess(["synthetic-not-executed"], 0, b"", b"")
    c.provider.register_consumer(token, result, invocation, attempt)
    assert c.owner.select(token, result).state == "selected-protocol"
    return reference, token, result


def test_production_default_refuses_metadata_and_has_no_trust_switch(image_case, monkeypatch):
    c = image_case
    assert PRODUCTION_FACTORY() is None
    monkeypatch.setattr(module, "_production_image_source", PRODUCTION_FACTORY)
    owner = module.NamespaceImageOwner(**BUDGETS)
    assert isinstance(owner.acquire(c.target), module.NamespaceImageUnavailable)
    assert isinstance(owner.acquire({"trusted": True, "complete": True}), module.NamespaceImageUnavailable)
    with pytest.raises(TypeError):
        module.NamespaceImageOwner(**BUDGETS, trusted=True)
    owner.close()


def test_synthetic_same_view_selection_revalidates_with_false_flags(image_case):
    c = image_case
    reference, _, result = _selected(c)
    before = c.provider.reads, c.provider.binding_reads, c.provider.consumption_reads
    view = c.owner.current(reference)
    assert view.state == "selected-protocol" and view.measurement_scope == "synthetic-fixture-only"
    assert view.authenticated_build is view.observed_child_context is False
    assert (c.provider.reads, c.provider.binding_reads, c.provider.consumption_reads) == tuple(n + 1 for n in before)
    assert result.returncode == 0


def test_expiry_during_final_consumption_cannot_publish_selected_lease(image_case):
    c = image_case
    reference, _, result = _selected(c)

    def expire(facts):
        c.clock[0] += BUDGETS["max_lifetime_seconds"] + 1
        return facts

    c.provider.alter_consumption = expire
    assert c.owner.current(reference) is None
    assert c.provider.released
    assert result.returncode == 0


def test_fresh_release_cancellation_propagates_over_ordinary_refusal(image_case):
    c = image_case
    reference = _acquire(c)
    c.provider.alter_image = lambda facts: replace(facts, epoch=object())
    c.provider.release_error = KeyboardInterrupt("synthetic retirement interrupted")
    with pytest.raises(KeyboardInterrupt):
        c.owner.current(reference)
    c.provider.release_error = None
    assert c.owner.current(reference) is None


@pytest.mark.parametrize("field", list(BUDGETS))
@pytest.mark.parametrize("value", [0, True])
def test_budgets_are_explicit_positive_integers(field, value):
    with pytest.raises(ValueError):
        module.NamespaceImageOwner(**{**BUDGETS, field: value})


@pytest.mark.parametrize("case", ["directory", "outside-input", "hash", "file-type", "alias", "mapping"])
def test_partial_aliased_or_unenclosed_image_is_unavailable_and_lease_retires(image_case, case):
    c = image_case

    def alter(facts):
        if case == "directory":
            return replace(facts, directories=("/", "/toolchain"))
        if case == "outside-input":
            return replace(facts, unclosed_inputs=("stdin", "mutable output search overlap"))
        if case == "hash":
            return replace(facts, artifact=b"different bytes")
        if case == "file-type":
            return replace(facts, files=({"kind": "symlink", "path": "/src/unit.c"},))
        if case == "alias":
            entry = replace(facts.files[0], path="/src/alias")
            return replace(facts, files=tuple(sorted((*facts.files, entry), key=lambda x: x.path)))
        return replace(facts, child_root="/new-root")

    c.provider.alter_image = alter
    assert isinstance(c.owner.acquire(c.target), module.NamespaceImageUnavailable)
    assert len(c.provider.released) == 1
    assert not c.provider.leases


@pytest.mark.parametrize("change", ["contents", "directory", "epoch", "scope"])
def test_retained_epoch_changes_revoke_even_when_reference_is_retained(image_case, change):
    c = image_case
    reference = _acquire(c)
    if change == "scope":
        c.provider.scope = "independently-enforced-image"
    elif change == "contents":
        c.provider.alter_image = lambda facts: replace(facts, artifact=b"new image")
    elif change == "directory":
        c.provider.alter_image = lambda facts: replace(facts, directories=("/", "/src", "/src/new", "/toolchain"))
    else:
        c.provider.alter_image = lambda facts: replace(facts, epoch=object())
    assert c.owner.current(reference) is None
    assert c.owner.current(reference) is None
    assert len(c.provider.released) == 1


def test_equal_bytes_new_physical_source_identity_cannot_reuse_old_claim(image_case, tmp_path):
    c = image_case
    reference = _acquire(c)
    host = tmp_path / "old-host"
    host.mkdir()
    (host / "unit.c").write_bytes((c.root / "src/unit.c").read_bytes())
    host_identity = capture_source_identity(host, "unit.c")
    assert host_identity.sha256 == c.claim.binding.source_identity.sha256
    assert host_identity.version != c.claim.binding.source_identity.version
    c.claim = c.claim.with_observation(binding=replace(c.claim.binding, source_identity=host_identity))
    refused = _bind(c, reference)
    assert isinstance(refused, module.NamespaceImageUnavailable)
    assert refused.reason == "same_view_physical_identity_unavailable"
    assert c.owner.current(reference) is None


def test_declaration_custody_release_revokes_same_view_binding(image_case):
    c = image_case
    reference = _acquire(c)
    assert _bind(c, reference) is None
    c.declarations.release(c.declaration)
    assert c.owner.current(reference) is None


def test_cloned_foreign_reference_and_result_attributes_grant_nothing(image_case):
    c = image_case
    reference = _acquire(c)
    assert c.owner.current(module.NamespaceImageReference()) is None
    assert _bind(c, reference) is None
    invocation, attempt = object(), _attempt(c)
    token = c.owner.handoff(reference, invocation, attempt)
    result = subprocess.CompletedProcess([], 0)
    result.authenticated_build = result.observed_child_context = True
    result.namespace_lease = reference
    assert isinstance(c.owner.select(token, result), module.NamespaceImageUnavailable)
    assert c.owner.current(reference) is None


def test_one_use_handoff_and_terminal_result_identity(image_case):
    c = image_case
    reference, token, result = _selected(c)
    assert isinstance(c.owner.select(token, result), module.NamespaceImageUnavailable)
    assert c.owner.current(reference).state == "selected-protocol"
    new_token = c.owner.handoff(reference, object(), _attempt(c))
    assert type(new_token) is module.NamespaceImageHandoff
    assert c.owner.current(reference).state == "acquired-protocol"
    copied = subprocess.CompletedProcess(result.args, result.returncode, result.stdout, result.stderr)
    assert isinstance(c.owner.select(new_token, copied), module.NamespaceImageUnavailable)
    assert c.owner.current(reference) is None


def test_completed_result_lifetime_is_not_artificially_extended(image_case):
    c = image_case
    reference, _, result = _selected(c)
    borrowed = weakref.ref(result)
    del result
    gc.collect()
    assert borrowed() is None
    assert c.owner.current(reference) is None


def test_older_image_reply_replay_is_rejected_by_fresh_challenge(image_case):
    c = image_case
    reference = _acquire(c)
    old = next(iter(c.provider.leases.values()))
    assert c.owner.current(reference) is not None
    c.provider.alter_image = lambda facts: old
    assert c.owner.current(reference) is None


def test_creation_clock_nan_and_scope_change_during_acquisition_are_unavailable(image_case, monkeypatch):
    c = image_case
    reads = iter([float("nan"), 1.0, 1.0, 1.0])
    monkeypatch.setattr(module, "_now", lambda: next(reads, 1.0))
    assert isinstance(c.owner.acquire(c.target), module.NamespaceImageUnavailable)
    monkeypatch.setattr(module, "_now", lambda: 1.0)

    def scope_change(facts):
        c.provider.scope = "independently-enforced-image"
        return facts

    c.provider.alter_image = scope_change
    assert isinstance(c.owner.acquire(c.target), module.NamespaceImageUnavailable)
    assert not c.provider.leases


def test_duplicate_acquisition_lease_does_not_retire_existing_lease(image_case):
    c = image_case
    reference = _acquire(c)
    c.provider.reuse = True
    assert isinstance(c.owner.acquire(c.target), module.NamespaceImageUnavailable)
    assert not c.provider.released
    assert c.owner.current(reference) is not None


def test_close_attempts_all_owned_releases_then_propagates_cancellation(image_case):
    c = image_case
    first, second = _acquire(c), _acquire(c)
    c.provider.release_error = KeyboardInterrupt("synthetic retirement cancellation")
    with pytest.raises(KeyboardInterrupt):
        c.owner.close()
    assert len(c.provider.released) == 2
    assert c.owner.current(first) is None and c.owner.current(second) is None
    assert not c.provider.leases


def test_failed_binding_replacement_cannot_reuse_prior_candidate(image_case):
    c = image_case
    reference, _, result = _selected(c)
    assert isinstance(c.owner.bind_inputs(reference, c.claim, c.declarations, c.declaration,
        source_path="/src/../unit.c", declaration_path="/src/compile_commands.json"), module.NamespaceImageUnavailable)
    assert c.owner.current(reference) is None
    assert result.returncode == 0


def test_reentry_is_refused_without_publishing_another_image(image_case):
    c = image_case
    seen = []

    def reenter(facts):
        seen.append(c.owner.acquire(c.target))
        return facts

    c.provider.alter_image = reenter
    reference = _acquire(c)
    assert len(seen) == 1 and isinstance(seen[0], module.NamespaceImageUnavailable)
    assert c.owner.current(reference) is not None


@pytest.mark.parametrize("field,value", [("max_artifact_bytes", 1), ("max_expanded_bytes", 1),
                                        ("max_entries", 1), ("max_metadata_bytes", 1),
                                        ("max_retained_bytes", 1)])
def test_whole_image_budget_refusal_retires_unpublished_lease(image_case, field, value):
    c = image_case
    owner = module.NamespaceImageOwner(**{**BUDGETS, field: value})
    assert isinstance(owner.acquire(c.target), module.NamespaceImageUnavailable)
    assert not c.provider.leases
    owner.close()


def test_expiry_during_binding_cannot_publish_inputs(image_case):
    c = image_case
    reference = _acquire(c)

    def expire(facts):
        c.clock[0] += BUDGETS["max_lifetime_seconds"] + 1
        return facts

    c.provider.alter_binding = expire
    assert isinstance(_bind(c, reference), module.NamespaceImageUnavailable)
    assert c.owner.current(reference) is None


@pytest.mark.parametrize("now", [0.0, float("nan"), 61.0])
def test_elapsed_or_invalid_clock_revokes_without_renewing_lifetime(image_case, now):
    c = image_case
    reference = _acquire(c)
    c.clock[0] = now
    assert c.owner.current(reference) is None
    assert len(c.provider.released) == 1


def test_image_count_limit_does_not_release_existing_image(image_case):
    c = image_case
    owner = module.NamespaceImageOwner(**{**BUDGETS, "max_images": 1})
    try:
        reference = owner.acquire(c.target)
        assert type(reference) is module.NamespaceImageReference
        assert isinstance(owner.acquire(c.target), module.NamespaceImageUnavailable)
        assert owner.current(reference) is not None
        assert not c.provider.released
    finally:
        owner.close()


def test_existing_execution_attempt_reference_can_bind_namespace_handoff(image_case):
    c = image_case
    reference = _acquire(c)
    assert _bind(c, reference) is None
    inputs = ExecutionInputOwner(max_attempts=1, max_retained_bytes=4096)
    try:
        attempt = inputs.reserve(["/toolchain/cc", "-c", "unit.c"], {"LANG": "C"}, "/src",
                                 max_args=8, max_env=4, max_item_bytes=256, max_total_bytes=2048)
        dispatched = inputs.handoff_for_dispatch(attempt)
        token = c.owner.handoff(reference, object(), dispatched.attempt)
        assert type(token) is module.NamespaceImageHandoff
    finally:
        inputs.close()


def test_equal_ordinal_attempt_copy_cannot_replace_selected_attempt(image_case):
    from core.audit.prepared_execution_attempt import ExecutionAttemptReference

    c = image_case
    reference, _, result = _selected(c)
    c.provider.alter_consumption = lambda facts: replace(facts, attempt=ExecutionAttemptReference(facts.attempt.ordinal))
    assert c.owner.current(reference) is None
    assert result.returncode == 0
