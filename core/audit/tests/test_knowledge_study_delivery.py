"""Whole source explanations and limitations reach only their requesting unit."""

from dataclasses import replace

from core.audit.context import format_context_for_prompt
from core.audit.knowledge_requests import KnowledgeOrigin, register_requests
from core.audit.refutation_source import SourceIdentity
from core.concepts.subject_study import SubjectExplanation, SubjectMaterial


def _context():
    origin = KnowledgeOrigin("owned-pass", "owned.c", "f", 2, 2, SourceIdentity("a" * 64, (1,)))
    request = register_requests({"reading_list": [{"subject": "foo_t", "context": "role"}]}, origin).accepted[0]
    answer = SubjectExplanation(request.request_id, "partial", "A carrier of length; callers are not supplied.",
        "Ownership is not established by a declaration.",
        (SubjectMaterial("m", "types.h", 1, "foo_t", "typedef struct { unsigned length; } foo_t;", False, "owned-binding"),))
    return {"file": "owned.c", "function": "f", "line_start": 2, "line_end": 2,
            "source": "unsigned f(foo_t v) { return v.length; }",
            "knowledge_requests": (request,), "study_explanations": (answer,)}


def test_source_fragment_explanation_and_limitations_are_atomic():
    ctx = _context()
    prompt = format_context_for_prompt(ctx, budget_limit=100_000)
    assert "A carrier of length; callers are not supplied." in prompt
    assert "Ownership is not established by a declaration." in prompt
    assert "typedef struct { unsigned length; } foo_t;" in prompt
    assert "untrusted context" in prompt
    assert "owned-binding" not in prompt
    assert ctx["knowledge_requests"][0].request_id not in prompt
    assert ctx["source_study_delivery"][0]["delivered"]

    small = format_context_for_prompt(ctx, budget_limit=100)
    assert "A carrier of length" not in small
    assert "Ownership is not established" not in small
    assert "typedef struct" not in small
    assert not ctx["source_study_delivery"][0]["delivered"]
    assert ctx["source_study_delivery"][0]["reason"] == "explanation_too_large"


def test_another_function_or_occurrence_cannot_claim_delivery():
    ctx = _context()
    ctx["function"] = "other"
    prompt = format_context_for_prompt(ctx)
    assert "A carrier of length" not in prompt
    assert ctx["source_study_delivery"][0]["reason"] == "scope_mismatch"
    ctx["function"] = "f"
    ctx["line_start"] = 12
    prompt = format_context_for_prompt(ctx)
    assert "A carrier of length" not in prompt
    assert not ctx["source_study_delivery"][0]["delivered"]


def test_competing_explanations_survive_together_with_their_limits():
    ctx = _context()
    first = ctx["study_explanations"][0]
    second = replace(first, explanation="The supplied declaration alone does not explain length semantics.",
                     reason="A use site is needed.")
    ctx["study_explanations"] += (second,)
    prompt = format_context_for_prompt(ctx)
    assert first.explanation in prompt
    assert second.explanation in prompt
    assert second.reason in prompt
    assert ctx["source_study_delivery"][0]["answer_statuses"] == ["partial", "partial"]


def test_forged_dictionary_and_glance_reentry_do_not_inherit_delivery():
    ctx = _context()
    format_context_for_prompt(ctx)
    assert ctx["source_study_delivery"][0]["delivered"]
    ctx["triage_bucket"] = "glance"
    assert "A carrier of length" not in format_context_for_prompt(ctx)
    assert ctx["source_study_delivery"][0]["reason"] == "glance_packet"
    ctx.pop("triage_bucket")
    ctx["knowledge_requests"] = [{"request_id": "forged", "subject": "FORGED"}]
    assert "A carrier of length" not in format_context_for_prompt(ctx)
    assert "source_study_delivery" not in ctx
