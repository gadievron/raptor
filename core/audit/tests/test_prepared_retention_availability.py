"""Known retained-result loss stays distinct from an unadjudicated checker result."""
from dataclasses import asdict

from .test_prepared_claim_context import case  # noqa: F401 -- imported pytest fixture
from .test_prepared_claim_pipeline import pipeline_case, run  # noqa: F401 -- imported pytest fixture


def test_actual_retention_directory_failure_is_disclosed(pipeline_case):  # noqa: F811 -- imported fixture
    c = pipeline_case
    path = c.out / "prepared-smt-results"
    path.write_bytes(b"owned non-directory")
    before = asdict(c.result)
    receipts, shadow = run(c)
    assert receipts == ["smt:check-overflow"] and len(c.calls) == 1
    assert path.read_bytes() == b"owned non-directory" and asdict(c.result) == before
    assert shadow["claims"][0]["supported_obligations"] == []
    availability = shadow["preparation_availability"][0]
    assert availability["fact_event"] is None
    assert availability["authoritative"] is False
    assert availability["reason"] == "result-retention-unavailable"


def test_unknown_checker_result_does_not_invent_retention_failure(pipeline_case):  # noqa: F811 -- imported fixture
    c = pipeline_case
    c.result.outcome = "inconclusive"
    _, shadow = run(c)
    row = shadow["preparation_availability"][0]
    assert row["reason"] == "unknown-result"
    assert row["fact_event"] is None and len(c.calls) == 1
    assert shadow["claims"][0]["supported_obligations"] == []


def test_healthy_retention_disclosure_is_unchanged(pipeline_case):  # noqa: F811 -- imported fixture
    c = pipeline_case
    _, shadow = run(c)
    row = shadow["preparation_availability"][0]
    assert row["reason"] == "retained-supports_fact"
    assert row["fact_event"] is not None and len(c.calls) == 1
    assert shadow["claims"][0]["supported_obligations"] == ["entry-arithmetic-out-of-range"]


def test_current_preparation_refusal_keeps_precedence_after_recording_loss(pipeline_case):  # noqa: F811 -- imported fixture
    import json
    from core.audit.prepared_claim_context import PreparationUnavailable
    from .test_prepared_claim_pipeline import publish

    c = pipeline_case
    (c.out / "prepared-smt-results").write_bytes(b"owned non-directory")
    run(c)
    manifest = json.loads(c.manifest.read_text())
    manifest["target"]["build_identity"] = "changed-fixture-build"
    c.manifest.write_text(json.dumps(manifest))
    current = c.pipeline.prepare(c.record, integer_abi="ilp32")
    assert isinstance(current, PreparationUnavailable)
    shadow = publish(c)
    row = shadow["preparation_availability"][0]
    assert row["reason"] == current.reason
    assert row["reason"] != "result-retention-unavailable"
    assert row["fact_event"] is None and len(c.calls) == 1
    assert shadow["claims"][0]["supported_obligations"] == []


def test_missing_acknowledgement_does_not_invent_a_write_exception(pipeline_case, monkeypatch):  # noqa: F811 -- imported fixture
    from core.audit import prepared_result_retention

    c = pipeline_case
    monkeypatch.setattr(prepared_result_retention, "retain_smt_result", lambda *args: None)
    _, shadow = run(c)
    row = shadow["preparation_availability"][0]
    assert row["reason"] == "unknown-result"
    assert row["fact_event"] is None and len(c.calls) == 1
    assert shadow["claims"][0]["supported_obligations"] == []


def test_retention_interrupt_is_not_converted_to_availability(pipeline_case, monkeypatch):  # noqa: F811 -- imported fixture
    import pytest
    from core.audit import prepared_result_retention

    c = pipeline_case
    primary = KeyboardInterrupt("owned retention interrupted")
    reached = []

    def interrupt(out_dir, result):
        reached.append(asdict(result))
        raise primary

    monkeypatch.setattr(prepared_result_retention, "retain_smt_result", interrupt)
    prepared = c.pipeline.prepare(c.record, integer_abi="ilp32")
    with pytest.raises(KeyboardInterrupt) as caught:
        c.pipeline.observe(c.record, c.result, prepared=prepared, integer_abi="ilp32")
    assert caught.value is primary and reached == [asdict(c.result)]
    assert c.calls == [] and c.pipeline.shadow_inputs() == ([], [], {}, [])
