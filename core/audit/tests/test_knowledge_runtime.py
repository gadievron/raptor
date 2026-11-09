"""Review-boundary provenance is captured before the configured model runs."""

import pytest

from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.audit.refutation_source import capture_source_identity
from core.llm.providers import StructuredResponse
from core.source.lines import number_lines


def test_actual_reviewer_requests_retain_pre_call_source_and_pass(tmp_path):
    source = "typedef struct { unsigned length; } foo_t;\nunsigned f(foo_t item) { return item.length; }\n"
    (tmp_path / "owned.c").write_text(source)
    identity = capture_source_identity(tmp_path, "owned.c")
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    queue = StudyQueue()
    runtime = AuditKnowledgeRuntime(tmp_path, queue, deadline=float("inf"))

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            # Deliberately change the target after the actual prompt is sent.
            # Registration must not bind this response to the new source.
            (tmp_path / "owned.c").write_text(source + "/* edited during review */\n")
            return StructuredResponse(result={"status": "clean", "body": "provisional",
                "reading_list": [{"subject": "foo_t", "resolution": "identifier", "context": "role of this type"}],
                "language_reference_requests": [{"topic": "integer promotion"}]},
                raw="", cost=0, model="scripted")

    review = runtime.wrap_review(make_review_fn(Client(), escalate_clean=False))
    ctx = {"file": "owned.c", "function": "f", "line_start": 2, "line_end": 2,
           "source": number_lines([source.splitlines()[1]], start_line=2)[0], "language": "c"}
    outcome = review(ctx, config)
    requests = runtime.requests()
    assert len(requests) == 2
    assert all(r.origin.source_identity == identity for r in requests)
    assert all(r.origin.pass_id for r in requests)
    assert len({r.origin.pass_id for r in requests}) == 1
    assert capture_source_identity(tmp_path, "owned.c") != identity
    assert queue.dequeue_batch(timeout=0) == []
    assert any(e.get("reason") == "source_changed_during_review" for e in runtime.events())
    assert outcome.status == "clean" and not outcome.evidence_tool
    assert not outcome.review_result.get("immediate_verified")


def test_current_review_queues_source_and_resolves_reference_without_an_extra_call(tmp_path):
    source = "typedef struct { unsigned length; } foo_t;\nunsigned f(foo_t item) { return item.length; }\n"
    (tmp_path / "owned.c").write_text(source)
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    queue = StudyQueue()
    runtime = AuditKnowledgeRuntime(tmp_path, queue, deadline=float("inf"))
    calls = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(kwargs["task_type"])
            return StructuredResponse(result={"status": "suspicious", "body": "provisional",
                "reading_list": [{"subject": "foo_t", "resolution": "identifier", "context": "role of this type"}],
                "language_reference_requests": [{"topic": "integer promotion"}]},
                raw="", cost=0, model="scripted")

    review = runtime.wrap_review(make_review_fn(Client(), escalate_clean=False))
    outcome = review({"file": "owned.c", "function": "f", "line_start": 2,
                     "source": source.splitlines()[1], "language": "c"}, config)
    requests = runtime.requests()
    assert calls == ["audit"]
    assert queue.dequeue_batch(timeout=0) == [requests[0]]
    references = [event["answer"] for event in runtime.events() if event["event"] == "reference_answer"]
    assert len(references) == 1 and references[0]["entries"]
    assert references[0]["status"] == "needs_target_facts"
    assert "language edition" in references[0]["missing_facts"]
    assert outcome.status == "suspicious" and not outcome.evidence_tool


def _source_study_case(tmp_path):
    from core.audit import orchestrator as orch

    declaration = "typedef struct { unsigned length; } foo_t;"
    source = '#include "types.h"\nunsigned f(foo_t item) { return item.length; }\n'
    (tmp_path / "types.h").write_text(declaration + "\n")
    (tmp_path / "owned.c").write_text(source)
    out = tmp_path / "out"
    out.mkdir()
    config = OrchestratorConfig(target_path=tmp_path, out_dir=out)
    queue = StudyQueue()
    runtime = AuditKnowledgeRuntime(tmp_path, queue, deadline=float("inf"))
    calls = []
    request_ids = []

    class Client:
        fail_study = False
        _call_cost_history = None

        def is_budget_exhausted(self):
            return False

        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(kwargs["task_type"])
            if kwargs["task_type"] == "audit":
                return StructuredResponse(result={"status": "suspicious", "body": "provisional",
                    "reading_list": [{"subject": "foo_t", "resolution": "identifier", "context": "role of this type"}]},
                    raw="", cost=0, model="scripted")
            self._call_cost_history = {"study": (1, 0.25)}
            if self.fail_study:
                raise RuntimeError("scripted source-study failure")
            assert schema["required"] == ["subject_answers"]
            assert declaration in prompt
            assert "return item.length" in prompt
            return {"subject_answers": [{"request_id": request_ids[0], "status": "partial",
                "explanation": "The target type carries length; ownership is not established.",
                "reason": "Other users are not supplied", "material_ids": ["material-0"]}]}

    client = Client()
    config.llm_budget_client = client
    review = runtime.wrap_review(make_review_fn(client, escalate_clean=False))
    review({"file": "owned.c", "function": "f", "line_start": 2,
            "source": source.splitlines()[1], "language": "c"}, config)
    requests = queue.dequeue_batch(timeout=0)
    request_ids.extend(r.request_id for r in requests)
    return orch, config, queue, runtime, review, requests, calls, client


def _consume_source_case(case):
    from time import monotonic
    from core.audit.shared_state import SharedState
    from core.testing.audit_shutdown import isolated_audit_shutdown
    from core.testing.wallclock import wall_deadline

    orch, config, queue, runtime, review, requests, calls, client = case
    result = orch.OrchestratorResult()
    for request in requests:
        assert queue.enqueue_knowledge(request)
    queue.signal_producer_done()
    with isolated_audit_shutdown(orch), wall_deadline(10, code_bound_s=float("inf"), what="typed study consumer"):
        orch._study_consumer(queue, config, SharedState(), review, orch._LockedOutcomes(), result,
            checklist={"files": [{"path": "types.h"}, {"path": "owned.c"}]},
            context_map=None, evidence_index={}, sarif_cache=None, entry_points=set(),
            start_time=monotonic(), on_progress=None, knowledge_runtime=runtime)
    return result


def test_typed_study_batch_uses_existing_phase_and_retains_request_identity(tmp_path):
    case = _source_study_case(tmp_path)
    orch, config, queue, runtime, review, requests, calls, client = case
    result = _consume_source_case(case)
    assert calls == ["audit", "study"]
    answers = [e["answer"] for e in runtime.events() if e["event"] == "source_answer"]
    assert len(answers) == 1 and answers[0]["request_id"] == requests[0].request_id
    assert answers[0]["status"] == "partial"
    assert answers[0]["inputs"] and answers[0]["materials"]
    assert not result.findings and not result.clean
    assert result.total_cost_usd == 0.25
    assert runtime._source_jobs == []


def test_source_changed_after_queueing_does_not_buy_a_study_call(tmp_path):
    case = _source_study_case(tmp_path)
    runtime, calls = case[3], case[6]
    path = tmp_path / "owned.c"
    path.write_text(path.read_text() + "/* later revision */\n")
    result = _consume_source_case(case)
    assert calls == ["audit"]
    assert result.total_cost_usd == 0
    answers = [e["answer"] for e in runtime.events() if e["event"] == "source_answer"]
    assert answers and all(a["status"] == "unavailable"
                           and a["reason"] == "source_changed_before_study" for a in answers)
    assert runtime._source_jobs == []


def test_failed_source_study_books_ledger_delta_and_finishes_its_job(tmp_path):
    case = _source_study_case(tmp_path)
    runtime, calls, client = case[3], case[6], case[7]
    client.fail_study = True
    result = _consume_source_case(case)
    assert calls == ["audit", "study"]
    assert result.total_cost_usd == 0.25
    assert not result.findings and not result.clean
    answers = [e["answer"] for e in runtime.events() if e["event"] == "source_answer"]
    assert answers and all(a["status"] == "unavailable" for a in answers)
    assert runtime._source_jobs == []


@pytest.mark.parametrize("mode", ["normal", "blind"])
def test_actual_review_contract_separates_source_subjects_from_language_topics(tmp_path, mode):
    from core.audit.llm_review import REVIEW_SCHEMA_BLIND

    source = "unsigned f(unsigned n) { return n + 1; }"
    (tmp_path / "owned.c").write_text(source + "\n")
    seen = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            seen.append(kwargs["task_type"])
            fields = schema["properties"]
            item = fields["reading_list"]["items"]
            assert "subject" in item["properties"] and "question" not in item["properties"]
            assert "language_reference_requests" in fields
            assert "Empty is valid" in fields["reading_list"]["description"]
            assert "at least one external contract" not in kwargs["system_prompt"]
            return StructuredResponse(result={"status": "clean", "body": "provisional",
                "reading_list": [], "language_reference_requests": []}, raw="", cost=0, model="scripted")

    options = {"blind_schema": REVIEW_SCHEMA_BLIND} if mode == "blind" else {}
    review = make_review_fn(Client(), escalate_clean=False, **options)
    outcome = review({"file": "owned.c", "function": "f", "line_start": 1,
                      "source": source, "language": "c"},
                     OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"))
    assert seen == ["audit"] and outcome.status == "clean"
    assert not outcome.evidence_tool


def test_subject_labels_and_legacy_questions_survive_actual_journal_writer(tmp_path):
    from core.audit.collector import append_journal_for_outcome
    from core.audit.orchestrator import ReviewOutcome
    from core.coverage.journal import load_entries

    (tmp_path / "owned.c").write_text("int f(void) { return 0; }\n")
    out = tmp_path / "out"
    out.mkdir()
    outcome = ReviewOutcome("owned.c", "f", "suspicious", "provisional", line=1,
        review_result={"reading_list": [{"subject": "foo_t"}, {"question": "legacy question?"},
                                      {"subject": None}, {"subject": 7}]})
    acknowledged = append_journal_for_outcome(out_dir=out, target_path=tmp_path,
        run_id="study-labels", outcome=outcome,
        gap={"file": "owned.c", "name": "f", "line_start": 1, "line_end": 1})
    assert acknowledged is not None
    (entry,) = load_entries(out)
    assert entry.reading_list_items[:2] == ["foo_t", "legacy question?"]
    assert len(entry.reading_list_items) == 4
    assert all(isinstance(label, str) and label for label in entry.reading_list_items)
