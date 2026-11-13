"""Original binary observations bound advisory callee assessment material."""
from __future__ import annotations

from copy import copy
import hashlib
import json
from types import SimpleNamespace

import pytest

from core.audit import binary_context
from core.audit.binary_callee_assessments import build_binary_callee_assessment_context
from core.audit.callee_assessment_context import MAX_CALLEE_ASSESSMENTS
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue, _build_context
from core.audit.review_context_inputs import MAX_SNAPSHOT_BYTES
from core.inventory.binary_builder import build_binary_checklist
from core.llm.providers import StructuredResponse
from packages.ghidra.model import REDatabase, REFunction, REXref


@pytest.fixture
def assessment_case(tmp_path, monkeypatch):
    import core.inventory.binary_builder as builder

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(binary_context, "_lazy_decompile",
                        lambda *a, **k: pytest.fail("advisory fixture dispatched a backend"))
    monkeypatch.setattr(builder, "_binary_provenance_block", lambda *a: {"probe": "not_requested"})
    monkeypatch.setattr(builder, "_module_identity_block", lambda *a: {})
    runtimes = []

    def create(*, count=1, edges=True, duplicate_address=False, callee_abi=None, advisory_body="Recorded callee may omit a bound"):
        directory = tmp_path / f"case-{len(runtimes)}"
        directory.mkdir()
        target = directory / "owned.bin"
        image = b"owned binary assessment metadata, not executable"
        target.write_bytes(image)
        functions = [REFunction(name="caller", address=8192, size=64, source_tool="fixture",
                                decompilation="long caller(long n) { return f0(n); }")]
        functions.extend(REFunction(name=f"f{index}", address=4096 + index * 64, size=32,
            source_tool="fixture", decompilation=f"long f{index}(long n) {{ return n + 1; }}")
            for index in range(count))
        if duplicate_address:
            functions.append(REFunction(name="other", address=4096, size=32,
                source_tool="fixture", decompilation="long other(long n) { return n; }"))
        database = REDatabase(source_tool="fixture", binary_path=str(target), functions=functions,
            metadata={"binary_sha256": hashlib.sha256(image).hexdigest()},
            xrefs=[REXref(from_addr=8196 + index, to_addr=4096 + index * 64,
                         kind="call", source_tool="fixture") for index in range(count)] if edges else [])
        monkeypatch.setattr(binary_context, "find_redb_snapshot", lambda *a: (directory / "accepted.json", database))
        checklist = build_binary_checklist(database, binary_path=target)
        entry, = checklist["files"]
        items = {item["name"]: item for item in entry["items"]}
        config = OrchestratorConfig(target_path=target, out_dir=directory / "out",
            enable_session_context=False, immediate_verify=False, sweep_validate_findings=False)
        runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
        runtimes.append(runtime)
        state = {"status": "clean"}

        class Client:
            _attempt_admission_protocol = 1

            def generate_structured(self, prompt, schema, **kwargs):
                assert kwargs.pop("accounting_attempt_admission")() is True
                result = {"status": state["status"], "body": advisory_body}
                if state["status"] == "clean":
                    result["relies_on"] = [{"callee": "f0", "file": entry["path"], "line_start": 0,
                                            "assumption": "callee checks the bound"}]
                return StructuredResponse(result=result, raw="", cost=.1, model="scripted")

        review = runtime.wrap_review(make_review_fn(Client(), schema={"type": "object"}, escalate_clean=False))

        def context(name):
            gap = {**items[name], "file": entry["path"], "line_start": 0, "line_end": None}
            return _build_context(config, gap, checklist, None, {})

        caller_ctx = context("caller")
        caller = review(caller_ctx, config)
        callees = []
        if callee_abi is not None:
            config.integer_abi = callee_abi
        for index in range(count):
            state["status"] = "suspicious" if index == 0 else "clean"
            callees.append(review(context(f"f{index}"), config))
        canonical = [caller, *callees]

        def build(*, observer=None, include_graph=True):
            return build_binary_callee_assessment_context(caller, caller_ctx, tuple(canonical),
                owned_observation=observer or runtime.binary_assessment_observation,
                current_outcomes=lambda: tuple(canonical), include_graph=include_graph)

        return SimpleNamespace(build=build, caller=caller, callees=callees, ctx=caller_ctx,
                               canonical=canonical, runtime=runtime, database=database, target=target)

    yield create
    for runtime in runtimes:
        runtime.close("test_complete")


def _payload(context):
    lines = context.render().splitlines()
    start = next(index for index, line in enumerate(lines) if line.endswith("json") and line.startswith("```"))
    fence = lines[start][:-4]
    end = next(index for index in range(start + 1, len(lines)) if lines[index] == fence)
    return json.loads("\n".join(lines[start + 1:end]))


def test_recorded_edge_and_actual_runtime_observations_supply_advisory_context(assessment_case):
    case = assessment_case()
    context = case.build()
    assert context is not None and context.current(case.ctx)
    assert context.contributor_outcomes == tuple(case.callees)
    assert context.scope is case.caller.binary_publication_scope
    payload = _payload(context)
    row, = payload["assessments"]
    assert row["address"] == 4096 and row["size"] == 32 and row["status"] == "suspicious"
    assert row["recorded_call_site"] == 8196
    assert row["assumptions"] == ["callee checks the bound"]
    assert row["assessment_role"] == "prior_model_assessment_not_verification"
    assert row["relationship"] == "recorded_direct_call_xref_not_execution"
    assert payload["coverage"] == "not_exhaustive"
    assert payload["indirect_and_external_relationships"] == "unknown"
    assert "source_identity" not in row and "line_start" not in row
    assert context.origin.pass_id not in context.render()
    assert case.runtime.binary_assessment_observation(case.callees[0])[1].pass_id not in context.render()


@pytest.mark.parametrize("change", ["no_edge", "ambiguous_address", "missing_ownership", "source_shaped"])
def test_unbound_or_ambiguous_binary_relation_cannot_supply_context(assessment_case, change):
    case = assessment_case(edges=change != "no_edge", duplicate_address=change == "ambiguous_address")
    if change == "source_shaped":
        case.callees[0].line = 1
        assert case.build() is None
    elif change == "missing_ownership":
        observer = lambda outcome: (case.runtime.binary_assessment_observation(outcome)
                                    if outcome is case.caller else None)
        assert case.build(observer=observer) is None
    else:
        assert case.build() is None


@pytest.mark.parametrize("change", ["module", "analysis", "view", "canonical", "assessment", "ambiguous_outcome"])
def test_original_inputs_and_canonical_assessment_are_rechecked(assessment_case, change):
    case = assessment_case()
    context = case.build()
    assert context is not None and context.current(case.ctx)
    if change == "module":
        case.target.write_bytes(case.target.read_bytes() + b"changed")
    elif change == "analysis":
        case.database.functions[1].signature = "changed recovered signature"
    elif change == "view":
        case.ctx["source"] += "\nchanged caller view"
    elif change == "canonical":
        case.canonical[1] = copy(case.callees[0])
    elif change == "assessment":
        case.callees[0].body += " changed assessment"
    else:
        case.canonical.append(copy(case.callees[0]))
    assert not context.current(case.ctx)


def test_unchanged_material_has_stable_novelty_and_lost_owner_refuses(assessment_case):
    case = assessment_case()
    first = case.build()
    assert first is not None
    case.caller.review_result["relies_on"][0]["reason"] = "Rewording is not a new assessment"
    second = case.build()
    assert second is not None and first.render() == second.render()
    assert first.current(case.ctx)
    case.runtime.close("owned_review_ended")
    assert not first.current(case.ctx)


def test_assessment_and_byte_caps_disclose_omissions_without_losing_trigger(assessment_case):
    case = assessment_case(count=MAX_CALLEE_ASSESSMENTS + 2)
    context = case.build()
    assert context is not None
    payload = _payload(context)
    assert 1 <= len(payload["assessments"]) <= MAX_CALLEE_ASSESSMENTS
    assert payload["limitations"]["omitted_assessments"] >= 2
    assert any(row["status"] == "suspicious" and row["address"] == 4096 for row in payload["assessments"])
    assert len(context.render().encode("utf-8")) <= MAX_SNAPSHOT_BYTES
    assert context.current(case.ctx)


def test_independently_current_different_conditional_abi_cannot_be_combined(assessment_case):
    case = assessment_case(callee_abi="llp64")
    caller = case.runtime.binary_assessment_observation(case.caller)
    callee = case.runtime.binary_assessment_observation(case.callees[0])
    assert caller is not None and callee is not None
    assert caller[0].current(case.target) and callee[0].current(case.target)
    assert caller[1].binary_identity.analysis_sha256 == callee[1].binary_identity.analysis_sha256
    assert caller[1].binary_identity.integer_abi_sha256 != callee[1].binary_identity.integer_abi_sha256
    assert case.build() is None


def test_truncated_assessment_tracks_full_material_and_discloses_loss(assessment_case):
    case = assessment_case(advisory_body="x" * 500 + "left")
    context = case.build()
    assert context is not None and context.current(case.ctx)
    case.callees[0].body = "x" * 500 + "rght"
    assert case.callees[0].binary_publication_scope.current(case.target)
    assert not context.current(case.ctx)
    row, = _payload(context)["assessments"]
    assert row["body_truncated"] is True
    assert row["body_characters_total"] == 504 and row["body_characters_shown"] == 500
    assert row["body"] == "x" * 500
    assert len(row["assessment_material_sha256"]) == 64


def test_reservation_checks_observation_callbacks_outside_runtime_lock(assessment_case):
    from core.audit.continuation_context import context_version

    case = assessment_case()
    original_lock = case.runtime._lock
    entered = []
    under_lock = []

    class OwnedLockProbe:
        def __enter__(self):
            original_lock.__enter__()
            entered.append(True)
            return self

        def __exit__(self, *args):
            entered.pop()
            return original_lock.__exit__(*args)

    def observe(outcome):
        if entered:
            under_lock.append(True)
            raise AssertionError("foreign observation callback under Runtime lock")
        return case.runtime.binary_assessment_observation(outcome)

    case.runtime._lock = OwnedLockProbe()
    try:
        context = case.build(observer=observe)
        assert context is not None
        ctx = {**case.ctx, "binary_callee_assessment_context": context}
        version = context_version(context.render())
        assert case.runtime.offer_context_delta(ctx, kind="binary_callee_assessments", version=version)
        reservation = case.runtime.reserve_context_continuation(ctx, admission=lambda: True,
            required_context_id=f"context:binary_callee_assessments:{version}")
        assert not under_lock
        assert reservation is not None
        assert case.runtime.fail(reservation, "owned_control_finished", ctx=ctx)
    finally:
        case.runtime._lock = original_lock


@pytest.mark.parametrize("change", ["missing", "source_line", "foreign_file", "invalid_assumption"])
def test_graph_opt_out_requires_valid_explicit_recorded_dependency(assessment_case, change):
    case = assessment_case()
    dependency = case.caller.review_result["relies_on"][0]
    if change == "missing":
        case.caller.review_result.pop("relies_on")
    elif change == "source_line":
        dependency["line_start"] = 1
    elif change == "foreign_file":
        dependency["file"] = "binary:foreign"
    else:
        dependency["assumption"] = 1
    assert case.build(include_graph=False) is None
    # The same recorded edge remains available when graph propagation is on.
    assert case.build(include_graph=True) is not None


def test_graph_opt_out_keeps_explicit_dependency_and_rechecks_its_presence(assessment_case):
    case = assessment_case()
    # A declared relation need not pretend an assumption was supplied.
    case.caller.review_result["relies_on"][0]["assumption"] = ""
    context = case.build(include_graph=False)
    assert context is not None and context.current(case.ctx)
    case.caller.review_result.pop("relies_on")
    assert case.callees[0].binary_publication_scope.current(case.target)
    assert not context.current(case.ctx)
