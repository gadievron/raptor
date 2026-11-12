"""Panel width does not enlarge the default direct model-attempt allowance."""

import json

import httpx
import pytest

from core.audit import capabilities, orchestrator
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, run_orchestrator
from core.inventory import save_checklist
from core.llm.telemetry import TELEMETRY_FILENAME
from core.llm.tests.test_prepared_attempt_reservation import SCHEMA, sdk_clients as sdk_clients
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.slow
@pytest.mark.parametrize("width", [1, 2], ids=["single", "panel"])
def test_direct_attempt_allowance_does_not_scale_with_panel_width(tmp_path, monkeypatch, sdk_clients, width):
    import core.llm.client as client_module

    # This boundary is the real ready graph, Runtime and SDK request hook.
    # Optional detector/server/study work is outside this direct-review case.
    monkeypatch.setattr(orchestrator, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    monkeypatch.setattr(orchestrator, "_study_consumer", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "_check_layer_disagreement", lambda *a, **k: None)
    patch_module_attribute(monkeypatch, client_module, "time", "sleep", lambda _: None)

    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    source = "int f(int x) { return x + 1; }\n"
    path = target / "unit.c"
    path.write_text(source)
    save_checklist(out, {"target_path": str(target), "files": [{"path": "unit.c", "language": "c",
        "items": [{"name": "f", "kind": "function", "line_start": 1, "line_end": 1}]}]})
    client = sdk_clients(cap=20.0, token_cap=1000000, max_calls=20, retries=8)

    def lost_response(request):
        raise httpx.ReadError("owned captured response unavailable", request=request)

    client.state["handler"] = lost_response
    review = make_review_fn(client.client, schema=SCHEMA,
                            system_prompt="Review the owned function.", escalate_clean=False)
    config = OrchestratorConfig(target_path=target, out_dir=out, review_passes=width,
        resume=False, max_workers=1, batch_sloc_threshold=0, prefilter=False,
        prefilter_skip=False, triage=False, vendored_triage=False,
        validate=False, sweep_validate_findings=False, deepen_suspicious=False,
        clean_check=False, adversarial=False, enable_session_context=False,
        propagate_constraints=False, on_demand_synthesis=False, open_discovery=False,
        joern_overrides={"enabled": False}, no_binary_oracle=True,
        iris=False, sage_recall=False, domain_model_import=False,
        dynamic_validation=False, library_replay=False, cross_run_import=False,
        annotations_read=False)
    # The supplied reviewer owns the real governed client. No unrelated
    # initial-summary client is configured for this single-function case.
    result = run_orchestrator(config, review)
    history = json.loads((out / "knowledge-results.json").read_text())
    attempts = [e for e in history["events"] if e["event"] == "client_call_attempt"]
    refused = [e for e in history["events"] if e["event"] == "client_call_refused"]
    assert len(client.state["requests"]) == 6
    assert client.client._governed_calls == len(attempts) == 6
    assert any(e["reason"] == "model_call_limit" for e in refused)
    assert result.terminated_by != "llm_budget_exceeded"
    assert client.client._governed_calls < client.client.config.max_calls_per_scan
    assert not client.client.is_budget_exhausted(estimated_cost=0)
    # Unknown transport completion is not a free attempt or exact billing.
    pending = client.client.pending_usage_reservations
    assert len(pending) == 6
    assert all(row["reservation_usd"] > 0 and row["reservation_tokens"] > 16 for row in pending)
    # run_orchestrator owns its telemetry sink; the SDK fixture's earlier
    # sink is not the producer for this real run. Inspect retained run rows.
    recorded = [json.loads(line) for line in (out / TELEMETRY_FILENAME).read_text().splitlines()]
    recorded = [row for row in recorded if row.get("event") == "attempt_failed"]
    assert len(recorded) == len({row["attempt_id"] for row in recorded}) == 6
    actual_passes = {e["origin"]["pass_id"] for e in history["events"] if e["event"] == "review_attempt"}
    assert actual_passes
    assert all(row["work_id"] in {"review:" + p for p in actual_passes} for row in recorded)
    assert path.read_text() == source
