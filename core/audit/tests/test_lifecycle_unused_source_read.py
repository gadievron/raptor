"""Lifecycle context-map analysis does not need a second source-text read."""

import json

import pytest

from core.analysis import lifecycle_audit_integration as lifecycle
from core.audit import evidence_grade as grade
from core.audit import orchestrator as orch

@pytest.fixture(autouse=True)
def _owned_lifecycle_empty_notice(monkeypatch):
    monkeypatch.setattr(lifecycle.check_lifecycle_at_function, "_logged_empty", False, raising=False)


SOURCE = "int Read(int count) { return count; }\n"
DISPATCHED = {"smt", "joern", "semgrep", "codeql", "cross_function", "coccinelle"}


def _field(file="record.c"):
    # Existing captured-context format, not a production discovery claim.
    return {
        "name": "ready", "struct_type": "OwnedState",
        "invariant": "ready requires owner", "cwe": "CWE-863",
        "write_sites": [{"file": "writer.c", "line": 4, "function": "Write",
                         "guards": [{"condition": "owner", "file": "writer.c", "line": 3}]}],
        "read_sites": [{"file": file, "line": 1, "function": "Read", "guards": []}],
    }


def _setup(tmp_path, monkeypatch, *, file="record.c", fields=None):
    target = tmp_path / "target"
    target.mkdir()
    (target / "record.c").write_text(SOURCE, encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    if fields is not None:
        (out / "context-map.json").write_text(json.dumps({"state_fields": fields}), encoding="utf-8")
    config = orch.OrchestratorConfig(target_path=target, out_dir=out)
    forbidden_calls = []

    def forbidden(*args, **kwargs):
        forbidden_calls.append((args, kwargs))
        raise AssertionError("lifecycle-only control must not run a tool or capture a verification identity")

    # Consumer bindings only: no native/provider modules are imported to patch them.
    for name in ("run_smt_verb_direct", "run_coccinelle_sweep", "_joern_live_query",
                 "_joern_coverage_probe", "_run_tool_chain", "capture_source_identity",
                 "_run_llm_client"):
        monkeypatch.setattr(orch, name, forbidden)
    monkeypatch.setattr(orch, "_codeql_db_for", lambda *args, **kwargs: None)
    outcome = orch.ReviewOutcome(file=file, function="Read", line=1,
                                status="finding", body="captured concern", hypothesis="captured concern")
    outcome.review_result = {"cwe_class": "CWE-190"}
    return config, outcome, forbidden_calls


def _validate(outcome, config):
    return orch._proactive_validate(outcome, config, dispatched_tools=set(DISPATCHED))


def _assert_no_new_source_authority(outcome):
    # A supplied context-map finding retains its existing lifecycle receipt.
    # It must not manufacture the review/source identity contract removed here.
    assert "review_claims" not in (outcome.review_result or {})
    assert outcome.review_input_scope is None
    assert not outcome.tools_dispatched
    assert not outcome.tools_errored
    assert not outcome.tools_skipped


def test_lifecycle_only_empty_map_does_not_read_source(tmp_path, monkeypatch):
    config, outcome, forbidden_calls = _setup(tmp_path, monkeypatch)
    reads = []
    read = orch._contained_source_text

    def observed_read(*args, **kwargs):
        reads.append((args, kwargs))
        return read(*args, **kwargs)

    monkeypatch.setattr(orch, "_contained_source_text", observed_read)
    result = _validate(outcome, config)
    assert result is outcome and result.status == "finding"
    assert result.hypothesis == "captured concern"
    assert not grade.is_verification_evidence(result.evidence_tool or "")
    assert forbidden_calls == []
    _assert_no_new_source_authority(result)
    assert reads == [], "unused lifecycle source read must not occur"


def test_populated_context_map_is_independent_of_source_text(tmp_path):
    context_map = {"state_fields": [_field()]}
    path = tmp_path / "context-map.json"
    path.write_text(json.dumps(context_map), encoding="utf-8")
    before = path.read_bytes()
    results = []
    for source in ("", SOURCE, "different supplied text with no field or guard"):
        findings = lifecycle.check_lifecycle_at_function(
            file_path="record.c", function_name="Read", source=source, out_dir=tmp_path)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.read_site.file == "record.c" and finding.read_site.function == "Read"
        assert finding.missing_guards == frozenset({"owner"})
        assert finding.confidence == "high"
        results.append(finding.to_dict())
        evidence = lifecycle.format_lifecycle_evidence(findings)
        assert "OwnedState.ready" in evidence and "context-map" in evidence
    assert results[0] == results[1] == results[2]
    assert path.read_bytes() == before
    assert lifecycle.check_lifecycle_at_function(
        file_path="record.c", function_name="Different", source=SOURCE, out_dir=tmp_path) == []


def test_existing_no_source_refusal_is_not_lifecycle_eligibility(tmp_path, monkeypatch):
    # The actual confined reader already returns None for these paths. The
    # lifecycle consumer still evaluates matching supplied context-map records.
    for index, file in enumerate(("missing.c", "../outside.c")):
        case = tmp_path / str(index)
        case.mkdir()
        with monkeypatch.context() as patch:
            config, outcome, forbidden_calls = _setup(case, patch, file=file, fields=[_field(file)])
            assert orch._contained_source_text(config.target_path, file) is None
            reads = []

            def forbidden_unused_read(*args, **kwargs):
                reads.append((args, kwargs))
                raise AssertionError("lifecycle must not request unused source")

            patch.setattr(orch, "_contained_source_text", forbidden_unused_read)
            result = _validate(outcome, config)
            assert result is outcome and result.status == "finding"
            assert result.evidence_tool == "lifecycle"
            assert reads == [] and forbidden_calls == []
            _assert_no_new_source_authority(result)


def test_removed_reader_failure_no_longer_skips_context_map_consumer(tmp_path, monkeypatch):
    config, outcome, forbidden_calls = _setup(tmp_path, monkeypatch, fields=[_field()])
    reads, consumer_calls = [], []
    consumer = lifecycle.check_lifecycle_at_function

    def failed_unused_read(*args, **kwargs):
        reads.append(True)
        raise RuntimeError("owned unused-reader fault")

    def observed_consumer(**kwargs):
        consumer_calls.append(kwargs)
        return consumer(**kwargs)

    monkeypatch.setattr(orch, "_contained_source_text", failed_unused_read)
    monkeypatch.setattr(lifecycle, "check_lifecycle_at_function", observed_consumer)
    result = _validate(outcome, config)
    # Intentional dependency-removal delta: an obsolete reader fault no longer
    # prevents supplied context-map analysis. This is not all-fault equivalence.
    assert reads == []
    assert len(consumer_calls) == 1 and consumer_calls[0]["source"] == ""
    assert result is outcome and result.status == "finding" and result.evidence_tool == "lifecycle"
    assert forbidden_calls == []
    _assert_no_new_source_authority(result)


def test_actual_consumer_failure_keeps_existing_error_boundary(tmp_path, monkeypatch):
    config, outcome, forbidden_calls = _setup(tmp_path, monkeypatch, fields=[_field()])
    loader_calls = []

    def failed_context_map(out_dir):
        loader_calls.append(out_dir)
        raise RuntimeError("owned context-map loader fault")

    monkeypatch.setattr(lifecycle, "load_state_fields", failed_context_map)
    result = _validate(outcome, config)
    assert loader_calls == [config.out_dir]
    assert result is outcome and result.status == "finding"
    assert not grade.is_verification_evidence(result.evidence_tool or "")
    assert forbidden_calls == []
    _assert_no_new_source_authority(result)


def test_supplied_context_map_keeps_existing_lifecycle_counter(tmp_path, monkeypatch):
    from dataclasses import asdict

    config, outcome, forbidden_calls = _setup(tmp_path, monkeypatch, fields=[_field()])
    counters = orch._make_tier_counters()
    before = {name: asdict(value) for name, value in counters.items()}
    result = orch._proactive_validate(outcome, config, dispatched_tools=set(DISPATCHED),
                                      tier_counters=counters)
    assert result is outcome and result.status == "finding"
    assert result.evidence_tool == "lifecycle"
    assert counters["lifecycle"].confirmed == 1
    after = {name: asdict(value) for name, value in counters.items()}
    before["lifecycle"]["confirmed"] = 1
    assert after == before
    assert forbidden_calls == []
    _assert_no_new_source_authority(result)
