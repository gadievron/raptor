"""Complete shared reference reading preserves the fitter's other choices."""

from dataclasses import replace

import pytest

from core.audit import knowledge_context
from core.audit.context import format_context_for_prompt
from core.language_reference import ReferenceContext, lookup
from core.llm import prompt_budget
from core.llm.prompt_budget import FitReport, PromptSection, SectionElision


def _answers():
    return (
        lookup("division-owned", "", ReferenceContext("c"), entry_id="c.integer-division"),
        lookup("shift-owned", "", ReferenceContext("c"), entry_id="c.integer-shift"),
    )


def _context():
    source = ('int f(int n, int d) { const char *padding="' + "x" * 15500
              + '"; return (n / d) << 1; }')
    return {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
            "source": source, "language_reference_answers": _answers()}


def test_complete_shared_reading_fits_without_restoring_other_shed_sections(monkeypatch, caplog):
    captured = []
    actual_fit = prompt_budget.fit_to_budget_report

    def capture(sections, *args, **kwargs):
        report = actual_fit(sections, *args, **kwargs)
        captured.append((list(sections), report))
        return report

    monkeypatch.setattr(prompt_budget, "fit_to_budget_report", capture)
    ctx = _context()
    snapshots = []
    caplog.set_level("DEBUG", logger="core.audit.context")
    prompt = format_context_for_prompt(ctx, budget_limit=6000, knowledge_delivery_sink=snapshots.append)
    assert len(captured) == 1
    original, baseline = captured[0]
    answers = ctx["language_reference_answers"]
    labels = {s.label for s in knowledge_context.reference_sections(answers)}
    before = knowledge_context.reference_delivery(answers, baseline.kept)
    assert not all(row["delivered"] for row in before), "fixture must reach reference shedding"
    assert all(row["delivered"] for row in ctx["language_reference_delivery"])
    assert snapshots[0]["language_reference_delivery"] == ctx["language_reference_delivery"]
    from core.audit.reference_inputs import reference_inputs_from_delivery, reference_inputs_current
    manifest = reference_inputs_from_delivery(snapshots[0]["language_reference_delivery"], answers)
    assert manifest["complete"] and reference_inputs_current(manifest)
    assert {row["id"] for row in manifest["entries"]} == {
        entry.entry_id for answer in answers for entry in answer.entries}
    assert not any("language_reference_" in record.message for record in caplog.records
                   if record.name == "core.audit.context" and record.message.startswith("prompt_budget: shed"))
    assert ctx["source"] in prompt
    for answer in answers:
        for entry in answer.entries:
            assert prompt.count(entry.render_core()) == 1
    for section in baseline.kept:
        if section.label not in labels:
            assert section.text in prompt
    for section in baseline.shed:
        if section.label not in labels:
            assert section.text not in prompt
    assert not baseline.elisions and not baseline.overshoot_tokens
    assert "prompt_budget_event" not in ctx
    assert len(original) > len(baseline.kept)


def _baseline():
    answers = _answers()
    missing = replace(answers[0], request_id="missing", entries=(), status="unavailable", reason="No rule")
    answers = (*answers, missing)
    rendered = knowledge_context.reference_sections(answers)
    source = PromptSection("source", "int f(int n, int d) { return (n / d) << 1; }", 0)
    evidence = PromptSection("evidence", "Retained checker input", 0)
    ordinary = [PromptSection(label, label * 10, 5) for label in (
        "tool_catalog", "caller_context_0", "source_study_0", "language_reference_unrelated")]
    sections = [source, evidence, *rendered, *ordinary]
    positive = rendered[:2]
    shared = knowledge_context.dedupe_reference_sections(answers[:2], positive, rendered_sections=positive)
    budget = sum(s.token_estimate for s in [source, evidence, *shared])
    report = prompt_budget.fit_to_budget_report(sections, budget, elide_priority0=True)
    assert report.shed and any(s in report.shed for s in positive)
    assert all(s in report.shed for s in [rendered[2], *ordinary])
    assert not report.elisions and not report.overshoot_tokens
    return answers, sections, rendered, budget, report


def _admit(answers, sections, rendered, budget, report):
    return knowledge_context.admit_complete_reference_reading(
        answers, sections, report, rendered_sections=rendered, budget_tokens=budget)


def test_admission_preserves_nonreferences_unavailable_notes_and_final_shed_disclosure():
    answers, sections, rendered, budget, baseline = _baseline()
    result = _admit(answers, sections, rendered, budget, baseline)
    assert result is not baseline
    positive_labels = {s.label for s in rendered[:2]}
    before = [s for s in baseline.kept if s.label not in positive_labels]
    after = [s for s in result.kept if s.label not in positive_labels]
    assert len(before) == len(after) and all(a is b for a, b in zip(before, after, strict=True))
    assert result.shed == [s for s in baseline.shed if s.label not in positive_labels]
    assert all(s.label not in positive_labels for s in result.shed)
    assert all(s.label != "language_reference_unrelated" for s in result.kept)
    assert sum(s.token_estimate for s in result.kept) <= budget
    rows = knowledge_context.reference_delivery(answers, result.kept)
    assert all(row["delivered"] for row in rows[:2])
    assert not rows[2]["delivered"] and not rows[2]["limitation_delivered"]
    assert not result.elisions and not result.overshoot_tokens


def test_kept_unavailable_note_remains_the_same_object():
    answers, sections, rendered, budget, baseline = _baseline()
    unavailable = rendered[2]
    kept = [s for s in sections if s in baseline.kept or s is unavailable]
    baseline = FitReport(kept, [s for s in baseline.shed if s is not unavailable], 0, [])
    result = _admit(answers, sections, rendered, budget + unavailable.token_estimate, baseline)
    assert result is not baseline
    assert any(s is unavailable for s in result.kept)
    assert knowledge_context.reference_delivery(answers, result.kept)[2]["limitation_delivered"]


@pytest.mark.parametrize("refusal", ["too_large", "elided_source", "overshoot"])
def test_refusal_retains_exact_baseline_report_and_delivery(refusal):
    answers, sections, rendered, budget, baseline = _baseline()
    if refusal == "too_large":
        budget -= 1
    elif refusal == "elided_source":
        baseline = replace(baseline, elisions=[SectionElision("source", 20)])
    else:
        baseline = replace(baseline, overshoot_tokens=1)
    before = knowledge_context.reference_delivery(answers, baseline.kept)
    result = _admit(answers, sections, rendered, budget, baseline)
    assert result is baseline
    assert knowledge_context.reference_delivery(answers, result.kept) == before


@pytest.mark.parametrize("difference", [
    "foreign_reference", "foreign_owner", "missing_supplier", "foreign_nonreference",
    "reordered_nonreferences", "duplicate_nonreference", "duplicate_label",
])
def test_ambiguous_or_foreign_reconstruction_inputs_retain_baseline(difference):
    answers, sections, rendered, budget, baseline = _baseline()
    if difference == "foreign_reference":
        sections = [replace(s, text="foreign nonce\n" + s.text) if s is rendered[0] else s for s in sections]
        baseline = prompt_budget.fit_to_budget_report(sections, budget, elide_priority0=True)
    elif difference == "foreign_owner":
        rendered = [replace(s, text="foreign nonce\n" + s.text) if s is rendered[0] else s for s in rendered]
    elif difference == "missing_supplier":
        sections = [s for s in sections if s is not rendered[0]]
        baseline = FitReport([s for s in baseline.kept if s is not rendered[0]],
                             [s for s in baseline.shed if s is not rendered[0]], 0, [])
    elif difference == "foreign_nonreference":
        baseline = replace(baseline, kept=[replace(s, text="foreign source") if s.label == "source" else s
                                          for s in baseline.kept])
    elif difference == "reordered_nonreferences":
        baseline = replace(baseline, kept=list(reversed(baseline.kept)))
    elif difference == "duplicate_nonreference":
        baseline = replace(baseline, kept=[*baseline.kept, baseline.kept[0]])
    else:
        extra = PromptSection("source", "Different source", 0)
        sections = [*sections, extra]
        baseline = replace(baseline, kept=[*baseline.kept, extra])
    assert _admit(answers, sections, rendered, budget, baseline) is baseline


@pytest.mark.parametrize("budget", [5000, 1000], ids=["compressed_too_large", "source_elided"])
def test_actual_formatter_refusal_preserves_baseline_prompt_and_records(monkeypatch, budget):
    captured = []
    actual_fit = prompt_budget.fit_to_budget_report

    def capture(sections, *args, **kwargs):
        report = actual_fit(sections, *args, **kwargs)
        captured.append((list(sections), report))
        return report

    monkeypatch.setattr(prompt_budget, "fit_to_budget_report", capture)
    ctx = _context()
    snapshots = []
    prompt = format_context_for_prompt(ctx, budget_limit=budget, knowledge_delivery_sink=snapshots.append)
    assert len(captured) == 1
    original, baseline = captured[0]
    answers = ctx["language_reference_answers"]
    labels = {s.label for s in knowledge_context.reference_sections(answers)}
    originals = [s for s in original if s.label in labels]
    kept = knowledge_context.dedupe_reference_sections(answers, baseline.kept, rendered_sections=originals)
    assert prompt == "\n".join(s.text for s in kept)
    expected = knowledge_context.reference_delivery(answers, kept)
    assert ctx["language_reference_delivery"] == expected
    assert snapshots[0]["language_reference_delivery"] == expected
    assert not all(row["delivered"] for row in expected)
    if budget == 1000:
        assert baseline.elisions
        assert ctx["prompt_budget_event"]["elisions"]


@pytest.mark.parametrize("budget", [100_000, 0], ids=["already_fits", "unlimited"])
def test_already_fit_and_unlimited_paths_retain_complete_reading(monkeypatch, budget):
    baseline_reports = []
    real_admit = knowledge_context.admit_complete_reference_reading

    def capture(answers, sections, report, **kwargs):
        result = real_admit(answers, sections, report, **kwargs)
        baseline_reports.append((report, result))
        return result

    monkeypatch.setattr(knowledge_context, "admit_complete_reference_reading", capture)
    ctx = _context()
    prompt = format_context_for_prompt(ctx, budget_limit=budget)
    assert ctx["source"] in prompt
    assert all(row["delivered"] for row in ctx["language_reference_delivery"])
    assert not baseline_reports if not budget else all(a is b for a, b in baseline_reports)


def test_review_consumer_records_actual_restored_reading_without_verification_credit(tmp_path, monkeypatch):
    from core.audit.llm_review import make_review_fn
    from core.audit.orchestrator import OrchestratorConfig
    from core.audit.reference_inputs import reference_inputs_from_delivery, reference_inputs_current
    from core.llm.providers import StructuredResponse

    ctx = _context()
    ctx["source"] = ctx["source"].replace("x" * 15500, "x" * 16500)
    (tmp_path / "unit.c").write_text(ctx["source"])
    answers = ctx["language_reference_answers"]
    monkeypatch.setattr("core.audit.llm_review._prompt_budget", lambda *args, **kwargs: 6000)
    captures = []
    real_fit = prompt_budget.fit_to_budget_report

    def capture(sections, *args, **kwargs):
        report = real_fit(sections, *args, **kwargs)
        captures.append(report)
        return report

    monkeypatch.setattr(prompt_budget, "fit_to_budget_report", capture)
    prompts = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            prompts.append(prompt)
            assert ctx["source"] in prompt
            assert all(entry.render_core() in prompt for answer in answers for entry in answer.entries)
            return StructuredResponse(result={"status": "clean", "body": "Scripted assessment"},
                                      raw="", cost=0, model="scripted")

    review = make_review_fn(Client(), escalate_clean=False)
    outcome = review(ctx, OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"))
    assert len(prompts) == len(captures) == 1
    assert not all(row["delivered"] for row in knowledge_context.reference_delivery(answers, captures[0].kept))
    rows = outcome.review_result["language_reference_delivery"]
    assert all(row["delivered"] for row in rows)
    manifest = reference_inputs_from_delivery(rows, answers)
    assert manifest["complete"] and reference_inputs_current(manifest)
    assert {row["id"] for row in manifest["entries"]} == {
        entry.entry_id for answer in answers for entry in answer.entries}
    assert not outcome.evidence_tool
    assert not outcome.review_result.get("immediate_verified")
