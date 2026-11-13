"""Binary view input origins remain distinct from source-file identities."""
from __future__ import annotations

import hashlib

import pytest

from core.audit.binary_context import assemble_binary_context
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.audit.review_claims import read_history
from core.audit.tests.test_binary_review_availability import _reviewer
from core.inventory.binary_builder import binary_path_key
from packages.ghidra.model import REDatabase, REFunction


@pytest.fixture
def binary_inputs(tmp_path):
    target = tmp_path / "owned.bin"
    target.write_bytes(b"owned module bytes, not an executable")
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    def context(source="unsigned f(unsigned n) { return n + 1; }"):
        database = REDatabase(source_tool="ghidra", binary_path=str(target), functions=[
            REFunction(name="f", address=4096, size=32, source_tool="ghidra", decompilation=source)])
        return assemble_binary_context(target_path=target, file_path=binary_path_key(target),
                                       function_name="f", db=database)
    try:
        yield target, runtime, context
    finally:
        runtime.close("test_complete")


def test_actual_binary_review_history_retains_original_module_and_view_identity(binary_inputs, tmp_path):
    target, runtime, context = binary_inputs
    ctx = context()
    review, calls = _reviewer()
    outcome = runtime.wrap_review(review)(ctx, OrchestratorConfig(target_path=target, out_dir=tmp_path / "out"))
    assert len(calls) == 1
    history = read_history(outcome.review_result["review_claims"])
    origin = history["review"]["origin"]
    assert origin["source_identity"] is None and origin["line_start"] == 0
    identity = origin.get("binary_identity")
    assert isinstance(identity, dict), "available binary review collapsed to an unknown source-only origin"
    assert identity["module_sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert identity["view_sha256"] == hashlib.sha256(ctx["source"].encode("utf-8")).hexdigest()
    assert identity["representation"] == "decompilation"
    assert identity["address"] == 4096 and identity["size"] == 32


def test_different_binary_views_and_restored_modules_do_not_share_snapshot(binary_inputs):
    from core.audit.binary_review_scope import BinaryKnowledgeOrigin
    target, runtime, context = binary_inputs
    first_context = context()
    first = runtime._origin(first_context)
    same = runtime._origin(first_context)
    other_view = runtime._origin(context("unsigned f(unsigned n) { return n + 2; }"))
    assert isinstance(first, BinaryKnowledgeOrigin) and isinstance(same, BinaryKnowledgeOrigin)
    assert first.pass_id != same.pass_id and runtime._same_snapshot(first, same)
    assert not runtime._same_snapshot(first, other_view)
    original = target.read_bytes()
    target.write_bytes(b"owned changed module")
    target.write_bytes(original)
    restored = runtime._origin(context())
    assert isinstance(restored, BinaryKnowledgeOrigin)
    assert restored.binary_identity.module_sha256 == first.binary_identity.module_sha256
    assert restored.binary_identity.module_version != first.binary_identity.module_version
    assert not runtime._same_snapshot(first, restored)
    assert not runtime._same_snapshot(first, runtime._origin(first_context))


def test_source_origin_serialization_and_snapshot_rules_remain_unchanged(tmp_path):
    from dataclasses import asdict
    from core.audit.knowledge_requests import KnowledgeOrigin
    source = "int f(int n) { return n + 1; }\n"
    path = tmp_path / "unit.c"
    path.write_text(source)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"), window=0)
    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "source": source}
    try:
        first, second = runtime._origin(ctx), runtime._origin(ctx)
        assert type(first) is KnowledgeOrigin
        assert set(asdict(first)) == {"pass_id", "file", "function", "line_start", "line_end", "source_identity"}
        assert first.source_identity is not None
        assert first.source_identity.sha256 == hashlib.sha256(source.encode()).hexdigest()
        assert runtime._same_snapshot(first, second)
        path.write_text("int f(int n) { return n + 2; }\n")
        assert not runtime._same_snapshot(first, runtime._origin(dict(ctx, source=path.read_text())))
    finally:
        runtime.close("test_complete")


def test_binary_origin_cannot_mix_source_identity_or_be_restored_from_context_json(binary_inputs, tmp_path):
    from dataclasses import asdict, replace
    from core.audit.binary_review_scope import BinaryKnowledgeOrigin
    from core.audit.knowledge_requests import KnowledgeOrigin
    from core.audit.refutation_source import capture_source_identity
    target, runtime, context = binary_inputs
    ctx = context()
    origin = runtime._origin(ctx)
    assert isinstance(origin, BinaryKnowledgeOrigin)
    source = tmp_path / "source.c"
    source.write_text("int f(void) { return 1; }\n")
    source_identity = capture_source_identity(tmp_path, "source.c")
    assert source_identity is not None
    with pytest.raises(ValueError):
        replace(origin, source_identity=source_identity)
    with pytest.raises(ValueError):
        replace(origin, line_start=1, line_end=1)
    unbound = KnowledgeOrigin(origin.pass_id, origin.file, origin.function, 0, 0, None)
    assert not runtime._same_snapshot(origin, unbound)
    ctx["binary_identity"] = {"module_sha256": "0" * 64}
    assert runtime._origin(ctx).binary_identity == origin.binary_identity
    ctx["_binary_module_snapshot"] = asdict(ctx["_binary_module_snapshot"])
    assert type(runtime._origin(ctx)) is KnowledgeOrigin


def test_cycle_rejects_foreign_binary_view_without_consuming_admission(binary_inputs):
    from core.audit.knowledge_requests import KnowledgeBatch, register_requests
    from core.audit.review_cycle import KnowledgeCycle
    target, runtime, context = binary_inputs
    first = runtime._origin(context())
    other = runtime._origin(context("unsigned f(unsigned n) { return n + 2; }"))
    batch = register_requests({"language_reference_requests": [{"topic": "integer shifts",
                              "needed_for": "Interpret this view", "priority": "normal"}]}, other)
    assert len(batch.accepted) == 1
    def forbidden_study(*args):
        pytest.fail("negative binary context control reached source-study admission")
    cycle = KnowledgeCycle(first, KnowledgeBatch((), ()), deadline=10, window=0,
                           admit_study=forbidden_study)
    assert cycle.add_requests(batch) is False
    # Binary continuation support is intentionally still unavailable. A
    # known binary origin must not turn absent source identity into credit.
    assert cycle.context_delta("owned-negative-control", now=0, kind="disagreement")
    admitted = []
    assert cycle.reserve(now=1, current_source=None, admission=lambda: admitted.append(1) or True,
                         all_model_calls=1) is None
    assert admitted == []


@pytest.mark.parametrize("change", ["view_sha256", "module_sha256", "float_address", "float_version", "bool_version", "wrong_domain"])
def test_binary_panel_history_cannot_change_its_original_input_identity(binary_inputs, tmp_path, change):
    from copy import deepcopy
    from core.audit.orchestrator import ReviewOutcome, _outcome_to_panel_result
    target, runtime, context = binary_inputs
    review, calls = _reviewer()
    outcome = runtime.wrap_review(review)(context(), OrchestratorConfig(target_path=target, out_dir=tmp_path / "out"))
    raw = deepcopy(_outcome_to_panel_result(outcome, "captured"))
    raw["review_claims"] = read_history(raw["review_claims"])
    identity = raw["review_claims"]["review"]["origin"]["binary_identity"]
    if change in ("view_sha256", "module_sha256"):
        identity[change] = "0" * 64
    elif change == "float_address":
        identity["address"] = float(identity["address"])
    elif change == "float_version":
        identity["module_version"][0] = float(identity["module_version"][0])
    elif change == "bool_version":
        identity["module_version"][0] = bool(identity["module_version"][0])
    else:
        identity["domain"] = "source"
    reconstructed = ReviewOutcome(outcome.file, outcome.function, outcome.status, outcome.body, review_result=raw)
    runtime.bind_review_input_scope(reconstructed)
    assert reconstructed.binary_publication_scope is None
    assert reconstructed.review_result["binary_review_binding"] is None


def test_unencodable_binary_view_refuses_before_callback(binary_inputs, tmp_path):
    from core.audit.knowledge_calls import KnowledgeCallRefused
    target, runtime, context = binary_inputs
    ctx = context()
    ctx["source"] = "unencodable \ud800 view"
    calls = []
    def forbidden(*args):
        calls.append(1)
        raise AssertionError("unidentified view reached callback")
    with pytest.raises(KnowledgeCallRefused, match="binary_view_identity_unavailable"):
        runtime.wrap_review(forbidden)(ctx, OrchestratorConfig(target_path=target, out_dir=tmp_path / "out"))
    assert calls == [] and sum(runtime._calls.values()) == 0
