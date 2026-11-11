"""Resource deadlines reach each existing witness boundary unchanged.

The execution boundary is replaced with an inconclusive observation; no
provider, compiler, target code or sandbox operation is dispatched.
"""

import json
from time import monotonic

import pytest

from core.audit import dark_verify, orchestrator as orch


@pytest.mark.parametrize("stage", ["early", "late", "differential"])
@pytest.mark.parametrize("bounded", [False, True], ids=["no-deadline", "absolute-deadline"])
def test_existing_witness_callers_forward_the_same_run_deadline(
    tmp_path, monkeypatch, stage, bounded,
):
    deadline = monotonic() + 600 if bounded else None
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path,
        run_deadline_monotonic=deadline)
    observed = []

    def execute(spec, target_root, *, audit_run_dir, deadline_monotonic):
        observed.append((target_root, audit_run_dir, deadline_monotonic))
        return dark_verify.DarkVerifyResult(finding_key=spec.finding_key,
            verdict="inconclusive", oracle_reliability="unavailable")

    monkeypatch.setattr(dark_verify, "execute_witness", execute)
    if stage == "differential":
        from core.audit.tests.test_differential_orchestration import _lead, _VECTOR_JSON
        prior = orch.ReviewOutcome(file="pkg/dev.py", function="deviant", status="dark", body="Scripted observation only")
        result = orch.OrchestratorResult(outcomes=[prior], dormant=1)
        orch._run_differential_verification(result, config, {"leads": [_lead()]},
            llm_client=lambda *args: _VECTOR_JSON)
    else:
        prior = orch.ReviewOutcome(file="unit.py", function="unit", status="dark",
            body="Scripted diagnostic", hypothesis="Scripted observation only")
        result = orch.OrchestratorResult(outcomes=[prior], dormant=1)
        response = json.dumps({"module_path": "unit", "function": "unit", "args": [],
            "expected_exception": "ValueError", "rationale": "Scripted boundary fixture"})
        if stage == "early":
            _, futures, executor = orch._submit_dark_probes_early(result, config,
                llm_client=lambda *args: response, include_diagnostics=True)
            assert executor is not None
            try:
                for future in futures:
                    future.result(timeout=5)
            finally:
                executor.shutdown(wait=True, cancel_futures=True)
        else:
            orch._run_dark_verification(result, config, llm_client=lambda *args: response,
                include_diagnostics=True)
    assert observed
    assert all(row == (config.target_path, config.out_dir, deadline) for row in observed)
    assert result.outcomes == [prior] and prior.status == "dark"
    assert result.findings == 0
