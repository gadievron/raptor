"""Parsed constructs select conditional reading, never applicability or proof."""

from dataclasses import replace

import pytest

from core.audit import orchestrator as orch
from core.audit.knowledge_context import reference_delivery, reference_sections
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.reference_foundation import foundation_answers, review_has_current_foundation
from core.audit.reference_inputs import reference_inputs_from_delivery, review_context_digest
from core.audit.source_anchor import make_context_source_anchor, parse_source_anchor
from core.audit.tests.test_foundation_rollout import _entry, _fold, _signed, _target
from core.llm.providers import StructuredResponse
from core.llm.prompt_budget import fit_to_budget
from core.language_reference import ReferenceContext, lookup
from core.testing.treesitter import requires_ts


_ARITHMETIC = "unsigned f(unsigned short a, int b) { return (unsigned)(a + b) < a; }"
_COMPOUND_ARITHMETIC = "unsigned f(unsigned a, unsigned b) { a += b; return a; }"
_SHIFT = "unsigned f(unsigned a, unsigned n) { return a << n; }"
_BITWISE = "unsigned f(unsigned a, unsigned b) { return a & b; }"
_UPDATE = "int f(int a) { return a++; }"
_UNARY = "int f(short a) { return -a; }"
_DIVISION = "int f(int a, int b) { return a % b; }"


@pytest.fixture(autouse=True)
def isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _ids(answers):
    return {entry.entry_id for answer in answers for entry in answer.entries}


@requires_ts("c")
@pytest.mark.parametrize("source", [_ARITHMETIC, _COMPOUND_ARITHMETIC, _SHIFT, _BITWISE, _UPDATE, _UNARY,
                                   _DIVISION], ids=["binary", "compound", "shift", "bitwise", "update", "unary-sign", "division"])
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
    if source == _SHIFT:
        assert "c.integer-shift v1:" in prompts[0]
        assert "c.integer-usual-conversions v1:" not in prompts[0]
        assert "c.integer-definedness v1:" not in prompts[0]
    elif source == _UNARY:
        assert "c.integer-unary-sign v1:" in prompts[0]
        assert "c.integer-usual-conversions v1:" not in prompts[0]
        assert "c.integer-definedness v1:" not in prompts[0]
        assert "c.integer-update v1:" not in prompts[0]
    else:
        assert "c.integer-usual-conversions v1:" in prompts[0]
        if source == _BITWISE:
            assert "c.integer-definedness v1:" not in prompts[0]
            assert "c.integer-shift v1:" not in prompts[0]
        else:
            assert "c.integer-definedness v1:" in prompts[0]
            if source == _UPDATE:
                assert "c.integer-update v1:" in prompts[0]
            elif source == _DIVISION:
                assert "c.integer-division v1:" in prompts[0]
    assert "Target language edition is unknown" in prompts[0]


@pytest.mark.parametrize("source,extra", [
    (_ARITHMETIC, {"c.integer-usual-conversions", "c.integer-definedness"}),
    ("int f(int a, int b) { return a < b; }", {"c.integer-usual-conversions"}),
    ('int f(void) { /* a + b; a += b; a << n; a & b; a++; +a; a / b */ const char *s = "a * b; a *= b; a >>= n; a |= b; --a; -a; a %= b"; return 0; }', set()),
    ("int f(void) { return 0; }", set()),
])
@requires_ts("c")
def test_selection_uses_parsed_operators_not_comments_or_strings(source, extra):
    answers = foundation_answers("c", request_id="owned", source=source, file="unit.c")
    assert _ids(answers) == {"c.integer-promotion", "c.integer-conversion"} | extra


@pytest.mark.parametrize("operator,extra", [("+=", set()), ("-=", set()), ("*=", set()),
                                         ("/=", {"c.integer-division"}), ("%=", {"c.integer-division"})],
                         ids=["add", "subtract", "multiply", "divide", "remainder"])
@requires_ts("c")
def test_compound_arithmetic_selects_conditional_integer_reading(operator, extra):
    source = f"unsigned f(unsigned a, unsigned b) {{ a {operator} b; return a; }}"
    answers = foundation_answers("c", request_id="owned", source=source, file="unit.c")
    assert _ids(answers) == {"c.integer-promotion", "c.integer-conversion",
                             "c.integer-usual-conversions", "c.integer-definedness"} | extra


@pytest.mark.parametrize("expression", ["return a & b", "return a ^ b", "return a | b",
    "a &= b; return a", "a ^= b; return a", "a |= b; return a"],
    ids=["and", "xor", "or", "and-assignment", "xor-assignment", "or-assignment"])
@requires_ts("c")
def test_bitwise_operators_select_conversion_reading(expression):
    source = f"unsigned f(unsigned a, unsigned b) {{ {expression}; }}"
    assert _ids(foundation_answers("c", request_id="owned", source=source, file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion", "c.integer-usual-conversions"}


@pytest.mark.parametrize("expression", ["a++", "a--", "++a", "--a"],
                         ids=["post-increment", "post-decrement", "pre-increment", "pre-decrement"])
@requires_ts("c")
def test_update_syntax_selects_value_and_store_composition(expression):
    source = f"int f(int a) {{ return {expression}; }}"
    assert _ids(foundation_answers("c", request_id="owned", source=source, file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion", "c.integer-usual-conversions",
        "c.integer-definedness", "c.integer-update"}


@pytest.mark.parametrize("expression", ["+a", "-a"], ids=["plus", "minus"])
@requires_ts("c")
def test_unary_sign_selects_promoted_result_reading(expression):
    source = f"int f(short a) {{ return {expression}; }}"
    assert _ids(foundation_answers("c", request_id="owned", source=source, file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion", "c.integer-unary-sign"}


@pytest.mark.parametrize("expression", ["return a / b", "return a % b", "a /= b; return a", "a %= b; return a"],
                         ids=["division", "remainder", "division-assignment", "remainder-assignment"])
@requires_ts("c")
def test_division_syntax_selects_quotient_and_remainder_conditions(expression):
    source = f"int f(int a, int b) {{ {expression}; }}"
    assert _ids(foundation_answers("c", request_id="owned", source=source, file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion", "c.integer-usual-conversions",
        "c.integer-definedness", "c.integer-division"}


@pytest.mark.parametrize("source", [
    "int f(int a) { return ~a; }", "int f(int a) { return !a; }",
    "int *f(int *a) { return &*a; }", "int f(int *a) { return *a; }",
    "int f(int a) { return --a; }",
], ids=["complement", "logical-not", "address", "indirection", "decrement"])
@requires_ts("c")
def test_other_unary_syntax_does_not_select_sign_reading(source):
    assert "c.integer-unary-sign" not in _ids(foundation_answers(
        "c", request_id="owned", source=source, file="unit.c"))


@pytest.mark.parametrize("expression", ["+a", "-a", "~a", "!a"],
                         ids=["plus", "minus", "complement", "logical-not"])
@requires_ts("c")
def test_other_unary_operators_do_not_select_update_composition(expression):
    source = f"int f(int a) {{ return {expression}; }}"
    assert "c.integer-update" not in _ids(foundation_answers(
        "c", request_id="owned", source=source, file="unit.c"))


@pytest.mark.parametrize("expression", ["a && b", "a || b", "!a"], ids=["and", "or", "not"])
@requires_ts("c")
def test_logical_operators_do_not_select_bitwise_conversion_reading(expression):
    source = f"unsigned f(unsigned a, unsigned b) {{ return {expression}; }}"
    assert _ids(foundation_answers("c", request_id="owned", source=source, file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion"}


@pytest.mark.parametrize("expression", ["return a << n", "return a >> n", "a <<= n", "a >>= n"],
                         ids=["left", "right", "left-assignment", "right-assignment"])
@requires_ts("c")
def test_shift_syntax_selects_its_own_conditional_rule(expression):
    source = f"unsigned f(unsigned a, unsigned n) {{ {expression}; }}"
    assert _ids(foundation_answers("c", request_id="owned", source=source, file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion", "c.integer-shift"}


@pytest.mark.parametrize("budget", [1, 100_000], ids=["omitted", "delivered"])
@pytest.mark.parametrize("source,entry_ids", [
    (_SHIFT, {"c.integer-promotion", "c.integer-conversion", "c.integer-shift"}),
    (_UPDATE, {"c.integer-promotion", "c.integer-conversion", "c.integer-usual-conversions",
               "c.integer-definedness", "c.integer-update"}),
    (_UNARY, {"c.integer-promotion", "c.integer-conversion", "c.integer-unary-sign"}),
    (_DIVISION, {"c.integer-promotion", "c.integer-conversion", "c.integer-usual-conversions",
                 "c.integer-definedness", "c.integer-division"}),
], ids=["shift", "update", "unary-sign", "division"])
@requires_ts("c")
def test_operator_core_and_prerequisites_fit_as_one_bundle(budget, source, entry_ids):
    answers = foundation_answers("c", request_id="owned", source=source, file="unit.c")
    sections = reference_sections(answers)
    kept, shed = fit_to_budget(sections, budget_tokens=budget)
    delivery = reference_delivery(answers, kept)
    references = reference_inputs_from_delivery(delivery, answers)
    expected = budget > 1
    assert delivery[0]["delivered"] is expected
    assert review_has_current_foundation({"reference_inputs": references}, source=source, file="unit.c") is expected
    if expected:
        assert kept == sections and shed == []
        assert {row["id"] for row in references["entries"]} == entry_ids
    else:
        assert kept == [] and shed == sections and references is None


@pytest.mark.parametrize("operator,extra", [("=", set()), ("<<=", {"c.integer-shift"}),
                                         ("&=", {"c.integer-usual-conversions"})],
                         ids=["plain", "shift", "bitwise"])
@requires_ts("c")
def test_other_assignments_do_not_imply_arithmetic_reading(operator, extra):
    source = f"unsigned f(unsigned a, unsigned b) {{ a {operator} b; return a; }}"
    assert _ids(foundation_answers("c", request_id="owned", source=source, file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion"} | extra


def test_missing_parser_keeps_foundation_without_claiming_construct_coverage(monkeypatch):
    monkeypatch.setattr("core.audit.ts_extract._parse_file", lambda *args: None)
    assert _ids(foundation_answers("c", request_id="owned", source=_ARITHMETIC, file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion"}


@requires_ts("c")
def test_parse_errors_keep_foundation():
    assert _ids(foundation_answers("c", request_id="owned", source="int f( { a +", file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion"}


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("source", [_ARITHMETIC, _COMPOUND_ARITHMETIC, _SHIFT, _BITWISE, _UPDATE, _UNARY,
                                   _DIVISION], ids=["binary", "compound", "shift", "bitwise", "update", "unary-sign", "division"])
@requires_ts("c")
def test_prior_foundation_only_review_resurfaces_for_new_construct_reading(tmp_path, reuse, source):
    root = _target(tmp_path)
    (root / "unit.c").write_text(source + "\n")
    old = _signed(tmp_path / "old", _entry(root, current=True))
    assert not _fold(root, [old], reuse=reuse)[0]


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("source", [_ARITHMETIC, _COMPOUND_ARITHMETIC, _SHIFT, _BITWISE, _UPDATE, _UNARY,
                                   _DIVISION], ids=["binary", "compound", "shift", "bitwise", "update", "unary-sign", "division"])
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


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("source,missing_core", [(_UNARY, "c.integer-unary-sign"),
                                               (_DIVISION, "c.integer-division")], ids=["unary-sign", "division"])
@requires_ts("c")
def test_generic_arithmetic_reading_cannot_replace_operator_delivery(tmp_path, reuse, source, missing_core):
    root = _target(tmp_path)
    (root / "unit.c").write_text(source + "\n")
    row = _entry(root, current=True)
    answers = (
        lookup("prior-arithmetic", "", ReferenceContext("c"), entry_id="c.integer-definedness"),
        lookup("prior-conversion", "", ReferenceContext("c"), entry_id="c.integer-conversion"),
    )
    references = reference_inputs_from_delivery(reference_delivery(answers, reference_sections(answers)), answers)
    assert {entry["id"] for entry in references["entries"]} == {
        "c.integer-promotion", "c.integer-conversion", "c.integer-usual-conversions", "c.integer-definedness"}
    assert missing_core not in {entry["id"] for entry in references["entries"]}
    history = {**row.review_claims, "reference_inputs": references}
    primary, span = parse_source_anchor(row.source_hash)
    row = replace(row, review_claims=history, source_hash=make_context_source_anchor(
        primary, span, review_context_digest(history["source_inputs"], references), context_version=3))
    signed = _signed(tmp_path / "prior", row)
    assert _fold(root, [signed], reuse=reuse, require=False)[0] == {"unit.c:f"}
    assert not _fold(root, [signed], reuse=reuse)[0]


def test_oversized_source_keeps_bounded_foundation():
    source = " " * (256 * 1024 + 1)
    assert _ids(foundation_answers("c", request_id="owned", source=source, file="unit.c")) == {
        "c.integer-promotion", "c.integer-conversion"}
