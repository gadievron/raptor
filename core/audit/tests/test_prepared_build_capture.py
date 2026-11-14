"""Owned tiny files plus explicitly synthetic measurement/namespace readers.

No compiler, target, provider, solver or normal Sandbox module is executed or
imported. Candidate success is synthetic-only; production admission stays off.
"""

from copy import copy
from dataclasses import replace
import gc
import json
import subprocess
from types import SimpleNamespace
import weakref

import pytest

from core.audit import prepared_build_capture as module
from core.audit.claim_verification import ClaimVerification
from core.audit.claims import ClaimRevision
from core.audit.prepared_claim_context import PreparationUnavailable
from core.audit.prepared_claim_pipeline import PreparedClaimPipeline
from core.audit.prepared_compilation_database import CompilationDatabaseOwner
from core.audit.prepared_dependency_material import DependencyReference
from core.audit.prepared_execution_inputs import snapshot_parent_inputs
from core.audit.refutation_source import capture_source_identity
from core.audit.verification_results import VerificationScope


BUDGETS = dict(max_captures=4, max_source_bytes=4096, max_namespace_items=32, max_retained_bytes=65536)
INPUT_BUDGETS = dict(max_args=16, max_env=16, max_item_bytes=4096, max_total_bytes=16384)
PRODUCTION_MEASUREMENT_SOURCE = module._production_measurement_source
PRODUCTION_ADMISSION = module._production_admission


class SyntheticFixtureReader:
    """Synthetic protocol ownership and owned-file drift, not a real namespace."""

    scope = "synthetic-fixture-only"

    def __init__(self, root, tools, result, inputs):
        self.root, self.tools = root, tools
        self.result = weakref.ref(result)
        self.inputs = inputs
        self.epoch, self.namespace_epoch, self.namespace_reference = object(), object(), object()
        self.invocation, self.attempt = object(), object()
        self.retired = False
        self.echo_measurement = self.echo_namespace = False
        self.last_measurement_token = self.last_namespace_token = None
        self.alter_measurement = self.alter_namespace = lambda value: value
        self.read_calls = self.namespace_calls = 0

    def read_execution(self, result):
        if self.retired or self.result() is not result:
            return None
        return SimpleNamespace(
            invocation=self.invocation, attempt=self.attempt, parent_input_digest=self.inputs.sha256,
            status_observation=(None, "read-eof", 2, True), wait_origin="capture-poll-waitpid",
            caller_kill_exemption_applied=False, authenticated_build=False, observed_child_context=False,
        )

    def read(self, claim, acquired, result, *, challenge):
        self.read_calls += 1
        if self.retired or self.result() is not result:
            return None
        token = self.last_measurement_token if self.echo_measurement else object()
        self.last_measurement_token = token
        source = (self.root / "unit.c").read_bytes()
        facts = module._BuildMeasurements(
            issuer=self, read_token=token, challenge=challenge, epoch=self.epoch, declaration=acquired,
            declaration_identity=capture_source_identity(self.root, "compile_commands.json"),
            declaration_content=(self.root / "compile_commands.json").read_bytes(),
            actual_translation_unit="unit.c", operation=result, invocation=self.invocation,
            attempt=self.attempt, inputs=self.inputs, namespace_reference=self.namespace_reference,
            source_identity=capture_source_identity(self.root, "unit.c"), source_content=source,
            byte_start=0, byte_end=len(source),
        )
        return self.alter_measurement(facts)

    def read_namespace(self, reference, *, challenge):
        self.namespace_calls += 1
        if self.retired or reference is not self.namespace_reference:
            return None
        members = []
        for root in (self.root, self.tools):
            for path in root.rglob("*"):
                if path.is_symlink():
                    return None
                if path.is_file():
                    members.append((str(path), capture_source_identity(root, str(path.relative_to(root)))))
        absent = tuple(sorted(str(self.root / name) for name in ("optional.h", "never.h")
                              if not (self.root / name).exists()))
        token = self.last_namespace_token if self.echo_namespace else object()
        self.last_namespace_token = token
        snapshot = module._ClosedSearchNamespace(
            self, reference, token, challenge, self.namespace_epoch, (str(self.root), str(self.tools)),
            tuple(sorted(members)), absent,
        )
        return self.alter_namespace(snapshot)


@pytest.fixture
def capture_case(tmp_path, monkeypatch):
    root, tools = tmp_path / "owned", tmp_path / "tools"
    root.mkdir()
    tools.mkdir()
    source = b"int Read(int Value) { return Value + 1; }\n"
    (root / "unit.c").write_bytes(source)
    compiler = tools / "cc"
    compiler.write_bytes(b"synthetic compiler material; never executed")
    argv = [str(compiler), "-c", "unit.c"]
    database = [{"directory": str(root), "file": "unit.c", "arguments": argv}]
    (root / "compile_commands.json").write_text(json.dumps(database))
    declarations = CompilationDatabaseOwner({"fixture": root}, max_retained_bytes=16384,
                                           max_captures=4, max_selections=4)
    acquired = declarations.acquire(
        DependencyReference("fixture", "compile_commands.json"), "unit.c",
        declared_build_association="synthetic-fixture-build", max_database_bytes=8192,
        max_entries=8, max_entry_bytes=4096, max_depth=8,
    )
    identity = capture_source_identity(root, "unit.c")
    statement = "integer overflow in `Value + 1`"
    revision = ClaimRevision({"mechanism": statement}, pass_id="synthetic-fixture-pass",
                             file="unit.c", function="Read", line_start=1)
    scope = VerificationScope("unit.c", "Read", 1, statement, identity)
    claim = ClaimVerification(revision.hypothesis, binding=scope, claim_revision=revision)
    inputs = snapshot_parent_inputs(argv, {"HOME": str(tmp_path / "home"), "LANG": "C"},
                                    str(root), **INPUT_BUDGETS)
    result = subprocess.CompletedProcess(argv, 0, b"", b"")
    reader = SyntheticFixtureReader(root, tools, result, inputs)
    monkeypatch.setattr(module, "_production_measurement_source", lambda: reader)
    monkeypatch.setattr(module, "_selected_execution", reader.read_execution)
    owner = module.PreparedBuildCaptureOwner(declarations, **BUDGETS)
    case = SimpleNamespace(root=root, tools=tools, declarations=declarations, acquired=acquired,
                           claim=claim, result=result, reader=reader, owner=owner, inputs=inputs)
    del result  # The case owns the only strong result reference during the test.
    try:
        yield case
    finally:
        owner.close()
        declarations.close()


def capture(case, *, owner=None, claim=None, acquired=None, result=None):
    return (owner or case.owner).capture(claim or case.claim, acquired or case.acquired,
                                         case.result if result is None else result)


def test_synthetic_owned_candidate_revalidates_instead_of_echoing(capture_case):
    c = capture_case
    reference = capture(c)
    assert type(reference) is module.BuildCaptureReference
    calls = c.reader.read_calls
    target, anchor = c.owner.current(reference)
    assert c.reader.read_calls == calls + 1
    assert target.build_identity.startswith("synthetic-fixture-only:")
    assert anchor.prepared_content == (c.root / "unit.c").read_bytes()
    description = c.owner.describe(reference)
    assert description.measurement_scope == "synthetic-fixture-only"
    assert description.authenticated_build is False and description.observed_child_context is False
    assert "HOME" not in repr(description) and str(c.root) not in repr(description)


def test_production_default_has_no_measurement_factory_or_public_trust_switch(capture_case, monkeypatch):
    c = capture_case
    assert PRODUCTION_MEASUREMENT_SOURCE() is None
    assert PRODUCTION_ADMISSION(c.owner, object()) is None
    monkeypatch.setattr(module, "_production_measurement_source", PRODUCTION_MEASUREMENT_SOURCE)
    owner = module.PreparedBuildCaptureOwner(c.declarations, **BUDGETS)
    result = capture(c, owner=owner)
    assert result == module.BuildCaptureUnavailable("independent_build_measurements_unavailable")
    with pytest.raises(TypeError):
        module.PreparedBuildCaptureOwner(c.declarations, trusted=True, **BUDGETS)
    owner.close()


@pytest.mark.parametrize("kind", ["clone", "foreign", "json", "unknown"])
def test_capture_references_are_identity_owned(capture_case, kind):
    c = capture_case
    reference = capture(c)
    if kind == "clone":
        tested = copy(reference)
    elif kind == "foreign":
        other = module.PreparedBuildCaptureOwner(c.declarations, **BUDGETS)
        tested = capture(c, owner=other)
        other.close()
    elif kind == "json":
        tested = {"ordinal": reference.ordinal, "trusted": True}
    else:
        tested = module.BuildCaptureReference(999)
    assert c.owner.current(tested) is None
    assert c.owner.current(reference) is not None


@pytest.mark.parametrize("change", ["new-header", "negative-now-present", "source", "database", "compiler"])
def test_entire_namespace_and_declaration_epoch_drift_revokes(capture_case, change):
    c = capture_case
    reference = capture(c)
    if change == "new-header":
        (c.root / "unqueried-new.h").write_text("new header")
    elif change == "negative-now-present":
        (c.root / "optional.h").write_text("formerly absent")
    elif change == "source":
        (c.root / "unit.c").write_text("int Read(void) { return 0; }\n")
    elif change == "database":
        (c.root / "compile_commands.json").write_text("[]")
    else:
        (c.tools / "cc").write_text("changed synthetic compiler")
    assert c.owner.current(reference) is None
    assert isinstance(c.owner.describe(reference), module.BuildCaptureUnavailable)


@pytest.mark.parametrize("field", ["echo_measurement", "echo_namespace"])
def test_cached_read_token_is_not_an_independent_current_accessor(capture_case, field):
    c = capture_case
    reference = capture(c)
    setattr(c.reader, field, True)
    assert c.owner.current(reference) is None
    setattr(c.reader, field, False)
    assert c.owner.current(reference) is None


def test_older_a_b_a_reply_cannot_hide_a_new_namespace_member(capture_case):
    c = capture_case
    original_read, original_namespace = c.reader.read, c.reader.read_namespace
    saved = {}
    replay = False

    def read(*args, **kwargs):
        if replay:
            return saved["measurement"]
        facts = original_read(*args, **kwargs)
        saved.setdefault("measurement", facts)
        return facts

    def namespace(*args, **kwargs):
        if replay:
            return saved["namespace"]
        observed = original_namespace(*args, **kwargs)
        saved.setdefault("namespace", observed)
        return observed

    c.reader.read, c.reader.read_namespace = read, namespace
    reference = capture(c)
    assert type(reference) is module.BuildCaptureReference
    assert c.owner.current(reference) is not None  # B after initial A.
    (c.root / "not-previously-queried.h").write_text("new namespace member")
    replay = True
    assert c.owner.current(reference) is None


@pytest.mark.parametrize("field", ["epoch", "namespace_epoch", "namespace_reference", "invocation", "attempt"])
def test_owned_epoch_and_selected_attempt_identity_cannot_be_replaced(capture_case, field):
    c = capture_case
    reference = capture(c)
    setattr(c.reader, field, object())
    assert c.owner.current(reference) is None


def test_declaration_release_and_owner_retirement_revoke(capture_case):
    c = capture_case
    reference = capture(c)
    c.declarations.release(c.acquired)
    assert c.owner.current(reference) is None
    assert isinstance(capture(c), module.BuildCaptureUnavailable)
    c.owner.close()
    assert c.owner.current(reference) is None


def test_completed_result_lifetime_is_not_artificially_extended(capture_case):
    c = capture_case
    reference = capture(c)
    result = weakref.ref(c.result)
    del c.result
    gc.collect()
    assert result() is None
    assert c.owner.current(reference) is None


@pytest.mark.parametrize("kind", ["dict", "duplicate", "positive-negative", "outside", "traversal", "overlap"])
def test_partial_or_aliased_namespace_data_is_not_complete_evidence(capture_case, kind):
    c = capture_case

    def alter(namespace):
        if kind == "dict":
            return {"complete": True, "trusted": True}
        if kind == "duplicate":
            return replace(namespace, members=namespace.members + namespace.members[:1])
        if kind == "positive-negative":
            return replace(namespace, absent_lookups=(namespace.members[0][0],))
        if kind == "outside":
            return replace(namespace, absent_lookups=("/outside/header.h",))
        if kind == "traversal":
            return replace(namespace, absent_lookups=(str(c.root) + "/../header.h",))
        return replace(namespace, roots=(str(c.root), str(c.root / "nested")))

    c.reader.alter_namespace = alter
    assert isinstance(capture(c), module.BuildCaptureUnavailable)


@pytest.mark.parametrize("kind", ["digest", "bytes", "declaration", "unit", "snapshot-cwd"])
def test_declared_and_actual_input_relation_is_checked(capture_case, kind):
    c = capture_case

    def alter(facts):
        if kind == "digest":
            return replace(facts, inputs=replace(facts.inputs, sha256="0" * 64))
        if kind == "bytes":
            return replace(facts, inputs=replace(facts.inputs, argv=(b"/other-compiler",)))
        if kind == "declaration":
            return replace(facts, declaration=copy(facts.declaration))
        if kind == "unit":
            return replace(facts, actual_translation_unit="other.c")
        return replace(facts, inputs=replace(facts.inputs, cwd=b"/other"))

    c.reader.alter_measurement = alter
    assert isinstance(capture(c), module.BuildCaptureUnavailable)


def test_copied_completed_process_cannot_borrow_selected_operation(capture_case):
    c = capture_case
    assert isinstance(capture(c, result=copy(c.result)), module.BuildCaptureUnavailable)


def test_synthetic_candidate_and_boolean_admission_cannot_activate_pipeline(capture_case, monkeypatch, tmp_path):
    c = capture_case
    reference = capture(c)
    pipeline = PreparedClaimPipeline(c.root, tmp_path / "out")
    target, anchor = c.owner.current(reference)
    # This is only a pre-existing synthetic staging fixture, not a measured build.
    pipeline.stage(c.claim, target=target, anchor=anchor, current_prepared=lambda: (target, anchor))
    assert pipeline._staged
    monkeypatch.setattr(module, "_production_admission", lambda *args: True)
    refusal = pipeline.stage_from_capture(c.claim, c.owner, reference)
    assert isinstance(refusal, PreparationUnavailable)
    assert refusal.reason == "production_measurement_activation_unavailable"
    assert not pipeline._staged
    assert isinstance(pipeline.prepare(c.claim, integer_abi="lp64"), PreparationUnavailable)


def test_pipeline_never_falls_back_to_current_on_missing_admission(capture_case, monkeypatch, tmp_path):
    c = capture_case
    reference = capture(c)
    pipeline = PreparedClaimPipeline(c.root, tmp_path / "out")
    monkeypatch.setattr(c.owner, "current", lambda *args: pytest.fail("unadmitted current fallback"))
    assert isinstance(pipeline.stage_from_capture(c.claim, c.owner, reference), PreparationUnavailable)
    assert not pipeline._staged


def test_interrupted_revalidation_revokes_before_propagating(capture_case):
    c = capture_case
    reference = capture(c)
    original = c.reader.read

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt("synthetic measurement interrupted")

    c.reader.read = interrupted
    with pytest.raises(KeyboardInterrupt):
        c.owner.current(reference)
    c.reader.read = original
    assert c.owner.current(reference) is None


@pytest.mark.parametrize("field", list(BUDGETS))
@pytest.mark.parametrize("value", [True, 0, -1, 1.5])
def test_capture_budgets_are_explicit_positive_integers(capture_case, field, value):
    with pytest.raises(ValueError):
        module.PreparedBuildCaptureOwner(capture_case.declarations, **{**BUDGETS, field: value})


def test_count_and_retained_payload_limits_refuse_whole_capture(capture_case):
    c = capture_case
    limited = module.PreparedBuildCaptureOwner(c.declarations, **{**BUDGETS, "max_captures": 1})
    assert type(capture(c, owner=limited)) is module.BuildCaptureReference
    assert capture(c, owner=limited) == module.BuildCaptureUnavailable("capture_count_budget")
    limited.close()
    small = module.PreparedBuildCaptureOwner(c.declarations, **{**BUDGETS, "max_retained_bytes": 1})
    assert isinstance(capture(c, owner=small), module.BuildCaptureUnavailable)
    small.close()
