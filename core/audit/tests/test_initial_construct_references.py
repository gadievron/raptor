"""Parsed constructs select conditional reading, never applicability or proof."""

from dataclasses import replace

import pytest

from core.audit import orchestrator as orch
from core.audit.knowledge_context import reference_delivery, reference_sections
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.reference_foundation import foundation_answers
from core.audit.reference_inputs import reference_inputs_from_delivery, review_context_digest
from core.audit.source_anchor import make_context_source_anchor, parse_source_anchor
from core.audit.tests.test_foundation_rollout import _entry, _fold, _signed, _target
from core.llm.providers import StructuredResponse
from core.testing.treesitter import requires_ts


_ARITHMETIC = "unsigned f(unsigned short a, int b) { return (unsigned)(a + b) < a; }"
_COMPOUND_ARITHMETIC = "unsigned f(unsigned a, unsigned b) { a += b; return a; }"


@pytest.fixture(autouse=True)
def isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _ids(answers):
    return {entry.entry_id for answer in answers for entry in answer.entries}


@requires_ts("c")
@pytest.mark.parametrize("source", [_ARITHMETIC, _COMPOUND_ARITHMETIC], ids=["binary", "compound"])
def test_initial_arithmetic_review_receives_conditional_rules_without_request(tmp_path, source):
    (tmp_path / "unit.c").write_text(source + "\n")
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"), window=0)
    prompts = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            prompts.append(prompt)
            return StructuredResponse(result={"status": "clean", "body": "Scripted review",
                "reading_list": [], "language_reference_requests": []}, raw="", cost=0, model="scripted")

    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": source, "language": "c"}
    runtime.wrap_review(make_review_fn(Client(), escalate_clean=False))(
        ctx, orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"))
    assert len(prompts) == 1
    assert "c.integer-usual-conversions v1:" in prompts[0]
    assert "c.integer-definedness v1:" in prompts[0]
    assert "Target language edition is unknown" in prompts[0]


@pytest.mark.parametrize("source,extra", [
    (_ARITHMETIC, {"c.integer-usual-conversions", "c.integer-definedness"}),
    ("int f(int a, int b) { return a < b; }", {"c.integer-usual-conversions"}),
    ('int f(void) { /* a + b; a += b */ const char *s = "a * b; a *= b"; return 0; }', set()),
    ("int f(void) { return 0; }", set()),
])
@requires_ts("c")
def test_selection_uses_parsed_operators_not_comments_or_strings(source, extra):
    answers = foundation_answers("c", request_id="owned", source=source, file="unit.c")
    assert _ids(answers) == {"c.integer-promotion", "c.integer-conversion"} | extra


@pytest.mark.parametrize("operator", ["+=", "-=", "*=", "/=", "%="],
                         ids=["add", "subtract", "multiply", "divide", "remainder"])
@requires_ts("c")
def test_compound_arithmetic_selects_conditional_integer_reading(operator):
    source = f"unsigned f(unsigned a, unsigned b) {{ a {operator} b; return a; }}"
    answers = foundation_answers("c", request_id="owned", source=source, file="unit.c")
    assert _ids(answers) == {"c.integer-promotion", "c.integer-conversion",
                             "c.integer-usual-conversions", "c.integer-definedness"}


@pytest.mark.parametrize("operator", ["=", "<<=", "&="], ids=["plain", "shift", "bitwise"])
@requires_ts("c")
def test_other_assignments_do_not_imply_arithmetic_reading(operator):
    source = f"unsigned f(unsigned a, unsigned b) {{ a {operator} b; return a; }}"
    assert _ids(foundation_answers("c", request_id="owned", source=source, file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion"}


def test_missing_parser_keeps_foundation_without_claiming_construct_coverage(monkeypatch):
    monkeypatch.setattr("core.audit.ts_extract._parse_file", lambda *args: None)
    assert _ids(foundation_answers("c", request_id="owned", source=_ARITHMETIC, file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion"}


@requires_ts("c")
def test_parse_errors_keep_foundation():
    assert _ids(foundation_answers("c", request_id="owned", source="int f( { a +", file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion"}


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("source", [_ARITHMETIC, _COMPOUND_ARITHMETIC], ids=["binary", "compound"])
@requires_ts("c")
def test_prior_foundation_only_review_resurfaces_for_new_construct_reading(tmp_path, reuse, source):
    root = _target(tmp_path)
    (root / "unit.c").write_text(source + "\n")
    old = _signed(tmp_path / "old", _entry(root, current=True))
    assert not _fold(root, [old], reuse=reuse)[0]


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("source", [_ARITHMETIC, _COMPOUND_ARITHMETIC], ids=["binary", "compound"])
@requires_ts("c")
def test_actual_selected_rules_allow_same_source_reuse(tmp_path, reuse, source):
    root = _target(tmp_path)
    (root / "unit.c").write_text(source + "\n")
    row = _entry(root, current=True)
    answers = foundation_answers("c", request_id="owned", source=source, file="unit.c")
    references = reference_inputs_from_delivery(reference_delivery(answers, reference_sections(answers)), answers)
    history = {**row.review_claims, "reference_inputs": references}
    primary, span = parse_source_anchor(row.source_hash)
    row = replace(row, review_claims=history, source_hash=make_context_source_anchor(
        primary, span, review_context_digest(history["source_inputs"], references), context_version=3))
    signed = _signed(tmp_path / "current", row)
    assert _fold(root, [signed], reuse=reuse)[0] == {"unit.c:f"}


def test_oversized_source_keeps_bounded_foundation():
    source = " " * (256 * 1024 + 1)
    assert _ids(foundation_answers("c", request_id="owned", source=source, file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion"}
