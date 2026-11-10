"""Initial panel attempts retain selected material and actual fitting separately."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from threading import Barrier

from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.llm.providers import StructuredResponse


def test_initial_panel_artifacts_retain_each_attempts_actual_reference_fitting(tmp_path, monkeypatch):
    source = "unsigned short f(unsigned n) { return n; }"
    (tmp_path / "unit.c").write_text(source + "\n")
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"))
    monkeypatch.setattr("core.audit.llm_review._prompt_budget",
                        lambda _ctx, system: 100 if system == "small" else 100_000)
    barrier = Barrier(2)

    class Client:
        def __init__(self):
            self.prompts = []

        def generate_structured(self, prompt, schema, **kwargs):
            self.prompts.append(prompt)
            barrier.wait(timeout=10)
            return StructuredResponse(result={"status": "clean", "body": "Same panel assessment"},
                                      raw="", cost=0, model="scripted")

    small_client, full_client = Client(), Client()
    small = runtime.wrap_review(make_review_fn(small_client, system_prompt="small", escalate_clean=False))
    full = runtime.wrap_review(make_review_fn(full_client, system_prompt="full", escalate_clean=False))
    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": source, "language": "c"}
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            small_future = pool.submit(small, ctx, config)
            full_future = pool.submit(full, ctx, config)
            outcomes = (small_future.result(timeout=15), full_future.result(timeout=15))

        expected = {outcome.review_result["review_claims"]["review"]["attempt_id"]:
                    deepcopy(outcome.review_result["language_reference_delivery"])
                    for outcome in outcomes}
        assert len(expected) == 2
        small_rows, full_rows = expected.values()
        assert small_rows[0]["request_id"] == full_rows[0]["request_id"]
        assert small_rows[0]["delivered"] is False
        assert small_rows[0]["reason"] == "reference_too_large"
        assert full_rows[0]["delivered"] is True
        assert full_rows[0]["reason"] == "delivered"
        assert len(small_client.prompts) == len(full_client.prompts) == 1
        for entry_id in ("c.integer-promotion", "c.integer-conversion"):
            assert f"{entry_id} v1:" not in small_client.prompts[0]
            assert f"{entry_id} v1:" in full_client.prompts[0]

        # Later outcome decoration cannot rewrite the already captured attempt.
        for outcome in outcomes:
            row = outcome.review_result["language_reference_delivery"][0]
            row["delivered"] = not row["delivered"]
            row["reason"] = "later outcome decoration"
            row["entries"][0]["id"] = "later.entry"

        out = tmp_path / "out"
        out.mkdir()
        runtime.write_artifacts(out)
        payload = json.loads((out / "knowledge-results.json").read_text())
        snapshots = {event["attempt_id"]: event for event in payload["events"]
                     if event["event"] == "initial_reference_answer"}
        assessments = {event["attempt_id"]: event for event in payload["events"]
                       if event["event"] == "review_assessment"}
        assert set(snapshots) == set(assessments) == set(expected)
        for attempt_id, rows in expected.items():
            assessment, selected = assessments[attempt_id], snapshots[attempt_id]
            assert assessment["language_reference_delivery"] == rows
            assert assessment["pass_id"] == selected["origin"]["pass_id"]
            assert rows[0]["request_id"] == selected["answer"]["request_id"]
            assert rows[0]["entries"] == [
                {"id": entry["entry_id"], "version": entry["version"]}
                for entry in selected["answer"]["entries"]]
            assert "delivered" not in selected
        assert payload["role"] == "context_provenance_not_verification_evidence"
    finally:
        runtime.close()
