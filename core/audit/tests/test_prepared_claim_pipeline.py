"""Inert existing-result integration, without parser/solver/build execution."""

from copy import deepcopy
from dataclasses import asdict, replace
import json
import pytest
from core.audit import orchestrator
from core.audit.claim_verification import ClaimVerification
from core.audit.claim_support_contracts import PreparedTargetBinding
from core.audit.smt_claim_contracts import PreparedSMTAnchor
from core.audit.check_trace import record_claim_observations
from core.audit.findings_export import write_graded_findings
from core.audit.prepared_claim_pipeline import PreparedClaimPipeline
from core.audit.refutation_source import capture_source_identity
from .test_prepared_claim_context import case  # noqa: F401, F811


@pytest.fixture
def pipeline_case(case, tmp_path, monkeypatch):  # noqa: F811 -- imported pytest fixture
    root = tmp_path / "target"
    root.mkdir()
    (root / "unit.c").write_bytes(case.anchor.prepared_content)
    out = tmp_path / "out"
    out.mkdir()
    identity = capture_source_identity(root, "unit.c")
    case.scope = replace(case.scope, source_identity=identity)
    case.anchor = replace(case.anchor, source=identity)
    case.record = ClaimVerification(
        case.revision.hypothesis, binding=case.scope, claim_revision=case.revision
    )
    # Independently saved fixture build/dependency manifest, never a live build receipt.
    manifest = tmp_path / "fixture-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "target": asdict(case.target),
                "source_sha256": identity.sha256,
                "byte_start": 0,
                "byte_end": len(case.anchor.prepared_content),
            }
        )
    )

    def reload_current():
        data = json.loads(manifest.read_text())
        target = dict(data["target"])
        for key in ("dependencies", "assumptions", "correspondence_ids"):
            target[key] = tuple(target[key])
        content = (root / "unit.c").read_bytes()
        current_identity = capture_source_identity(root, "unit.c")
        if current_identity.sha256 != data["source_sha256"]:
            return None
        anchor = PreparedSMTAnchor(
            "unit.c",
            current_identity,
            content,
            data["byte_start"],
            data["byte_end"],
            content[data["byte_start"] : data["byte_end"]],
        )
        return PreparedTargetBinding(**target), anchor

    staged_target, staged_anchor = reload_current()
    case.pipeline = PreparedClaimPipeline(root, out)
    case.pipeline.stage(
        case.record,
        target=staged_target,
        anchor=staged_anchor,
        current_prepared=reload_current,
    )
    case.manifest = manifest
    case.config = orchestrator.OrchestratorConfig(
        root, out, integer_abi="ilp32", prepared_claim_pipeline=case.pipeline
    )
    case.root, case.out, case.calls = root, out, []

    def inert(**kwargs):
        case.calls.append(kwargs)
        return deepcopy(case.result)

    monkeypatch.setattr(orchestrator, "run_smt_verb_direct", inert)
    from core.audit import literal_call_observation

    monkeypatch.setattr(
        literal_call_observation,
        "complete_literal_overflow_observation",
        lambda result, **kwargs: result,
    )
    return case


def publish(c):
    write_graded_findings({"findings": []}, c.out, prepared_claim_pipeline=c.pipeline)
    return json.loads((c.out / "claim-adjudication-shadow.json").read_text())


def run(c):
    receipts = orchestrator._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-overflow"}}],
        config=c.config,
        file_path="unit.c",
        function_name="Read",
        source=c.anchor.prepared_content.decode(),
        hypothesis=c.scope.hypothesis,
        line_start=1,
        claim_revision=c.revision,
    )
    record_claim_observations(
        c.out, file="unit.c", function="Read", line_start=1, verifications=[c.record]
    )
    return receipts, publish(c)


def test_existing_result_durable_shadow(pipeline_case):
    c = pipeline_case
    receipts, shadow = run(c)
    assert len(c.calls) == 1 and receipts == ["smt:check-overflow"]
    assert shadow["authoritative"] is False
    event = shadow["preparation_availability"][0]["fact_event"]
    assert event["event_id"] in shadow["claims"][0]["accepted_event_ids"]
    assert event["request_id"] == event["executed_request_id"] == "actual-request"
    assert (c.out / event["raw_reference"]).is_file()
    availability = shadow["preparation_availability"][0]
    assert availability["prepared_target"]["build_identity"] == c.target.build_identity
    assert (
        availability["requested_conclusion"]["effect_scope"]
        == "function-entry-source-model"
    )
    assert shadow["claims"][0]["supported_obligations"] == [
        "entry-arithmetic-out-of-range"
    ]
    assert shadow["preparation_availability"][0]["reason"] == "retained-supports_fact"


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "build",
        "dependencies",
        "assumptions",
        "source",
        "artifact",
        "status",
        "model",
        "execution",
        "ack",
    ],
)
def test_unknown_on_missing_or_changed_inputs(pipeline_case, change, monkeypatch):
    c = pipeline_case
    if change == "missing":
        c.pipeline = PreparedClaimPipeline(c.root, c.out)
        c.config.prepared_claim_pipeline = c.pipeline
    elif change == "status":
        c.result.outcome = "inconclusive"
    elif change == "model":
        c.result.details["model"] = {"Value": 0}
    elif change == "execution":
        c.result.details["smt_execution"]["executed_request_id"] = "different"
    elif change == "ack":
        from core.audit import prepared_result_retention

        monkeypatch.setattr(
            prepared_result_retention, "retain_smt_result", lambda *a: None
        )
    _, shadow = run(c)
    if change in {"build", "dependencies", "assumptions", "source", "artifact"}:
        if change == "source":
            (c.root / "unit.c").write_bytes(c.anchor.prepared_content + b"\n")
        elif change == "artifact":
            next((c.out / "prepared-smt-results").glob("*.json")).write_text("{}")
        else:
            fields = {
                "build": {"build_identity": "changed"},
                "dependencies": {"dependencies": ("changed",)},
                "assumptions": {"assumptions": ("changed",)},
            }
            data = json.loads(c.manifest.read_text())
            data["target"].update(fields[change])
            c.manifest.write_text(json.dumps(data))
        shadow = publish(c)
    assert shadow["claims"][0]["state"] == "unresolved"
    assert not shadow["claims"][0]["supported_obligations"]
    assert len(c.calls) == 1


def test_no_output_config_still_constructs(pipeline_case):
    c = pipeline_case
    config = orchestrator.OrchestratorConfig(c.root, None)
    assert (
        config.prepared_claim_pipeline.prepare(c.record, integer_abi="ilp32").reason
        == "durable-output-unavailable"
    )
