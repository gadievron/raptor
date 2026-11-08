"""C lexical data must not hide state effects or change call structure."""

import pytest

from core.smt_solver import BV_C_UINT8
from core.smt_solver import path_feasibility as paths
from core.smt_solver.call_arguments import find_call_end, split_call_arguments
from core.smt_solver.canonicalise import canonicalise


@pytest.fixture
def native():
    pytest.importorskip("z3")


def verb_query(conditions, **kwargs):
    return paths.check_verb_feasibility([], conditions, {}, **kwargs)


ENTRIES = [paths.check_path_feasibility, paths.check_path_feasibility_dual, verb_query]
EFFECTS = [
    "update(1'000, &Value, 2'000) == 0",
    "update(0xA'B, &Value, 0xC'D) == 0",
    "update(/*'*/ &Value /*'*/) == 0",
    "update(1'000, Value++, 2'000) == 0",
    'update(/*"*/ &Value /*"*/) == 0',
    'update(R"tag("quoted")tag", &Value) == 0',
]


def guards(*texts):
    return [paths.PathCondition(text, n) for n, text in enumerate(texts)]


@pytest.mark.usefixtures("native")
@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("reduce", [False, True])
@pytest.mark.parametrize("call", EFFECTS, ids=["decimal-separators", "hex-separators", "comment-apostrophe", "hidden-increment", "comment-quote", "raw-literal"])
def test_lexical_data_cannot_hide_a_real_state_change(entry, reduce, call):
    result = entry(guards("Value == 0", call, "Value == 1"), profile=BV_C_UINT8, reduce_constraints=reduce)
    assert result.feasible is None, result
    assert result.unknown == [call]
    assert result.unknown_reasons[0].kind.value in {"assignment_shaped", "unmodeled_state_effect"}
    assert result.model == {} and result.wp_complete is False


@pytest.mark.parametrize("arguments,expected", [
    ("1'000, Data, 2'000", ("1'000", "Data", "2'000")),
    ("Data /* , ) */ , 4", ("Data /* , ) */", "4")),
    ('R"tag(a",b))tag", 4', ('R"tag(a",b))tag"', "4")),
    ("/* no arguments */", ()),
    ("Data, /* missing argument */", None),
], ids=["digit-separators", "comment-delimiters", "raw-delimiters", "comment-only", "comment-empty-slot"])
def test_call_arity_uses_code_tokens(arguments, expected):
    assert split_call_arguments(arguments) == expected


@pytest.mark.parametrize("call", ["probe(/* ) ] , */ Data)", 'probe(R"tag(a",b))tag")', "probe(1'000)"],
                         ids=["comment", "raw-literal", "single-separator"])
def test_call_boundary_ignores_lexical_data(call):
    text = call + " == 0"
    assert find_call_end(text, text.index("(")) == len(call)


def test_canonicalisation_preserves_comments_and_raw_literal_contents():
    text = 'probe(/* is null */ R"tag(" is null   ")tag") equals 0'
    assert canonicalise(text) == 'probe(/* is null */ R"tag(" is null   ")tag") == 0'


@pytest.mark.usefixtures("native")
@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("call", [
    'update("unfinished &Value)', "update(/* unfinished &Value)",
    "update(Value +\\\n+)", 'update(R"bad delimiter(body)bad delimiter", &Value)',
], ids=["unfinished-string", "unfinished-comment", "line-splice", "invalid-raw-delimiter"])
def test_unadmitted_lexical_structure_cannot_prove_unchanged_state(entry, call):
    result = entry(guards("Value == 0", call, "Value == 1"), profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is None
    assert result.unknown == [call]
    assert result.unknown_reasons[0].kind.value == "unmodeled_state_effect"


@pytest.mark.usefixtures("native")
@pytest.mark.parametrize("call", [
    "probe(1'000) == 0", "probe(/* Value++ &Value ' ) */ Data) == 0",
    'probe(R"tag("Value++ &Value")tag") == 0', "probe(L'&') == 0",
    'probe("/* not a comment */ &Value") == 0',
], ids=["digit-separator", "comment", "raw-string", "wide-character", "quoted-comment"])
def test_literal_and_comment_data_do_not_create_state_effects(call):
    result = paths.check_path_feasibility(guards(call), profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is True and result.unknown == []


@pytest.mark.usefixtures("native")
@pytest.mark.parametrize("expression", ['"min(Value, 4)" == 0', '/* min(Value, 4) */ Value == 0'],
                         ids=["quoted-call", "commented-call"])
def test_non_code_cannot_allocate_call_occurrences_or_theory(expression):
    variables, anonymous, axioms = {}, {}, []
    transformed = paths._substitute_calls(expression, variables, profile=BV_C_UINT8,
                                          anon_map=anonymous, axiom_sink=axioms)
    assert transformed == expression
    assert variables == {} and anonymous == {} and axioms == []


@pytest.mark.usefixtures("native")
@pytest.mark.parametrize("call", EFFECTS, ids=["decimal-separators", "hex-separators", "comment-apostrophe", "hidden-increment", "comment-quote", "raw-literal"])
def test_effectful_operands_decline_before_native_allocation(monkeypatch, call):
    def forbidden(*args, **kwargs):
        pytest.fail("lexically hidden effects reached native allocation")
    monkeypatch.setattr(paths, "make_anon_call_var", forbidden)
    with pytest.raises(ValueError, match="state effects"):
        paths.make_call_operand(call[:-5], {}, profile=BV_C_UINT8, model=paths.CallOperandModel())


@pytest.mark.usefixtures("native")
@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("before", [True, False])
def test_independent_segment_contradictions_remain_valid(entry, before):
    call = EFFECTS[0]
    contradiction = ["Value == 0", "Value == 1"]
    texts = [*contradiction, call] if before else [call, *contradiction]
    result = entry(guards(*texts), profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is False
    assert "mutation-free segment" in result.reasoning
    assert result.unknown == [call]


@pytest.mark.usefixtures("native")
def test_comment_only_arguments_cannot_satisfy_summary_arity():
    from core.smt_solver import BV_C_INT8

    wrong_arity = paths.check_path_feasibility(guards("strlen(/* nothing */) == -1"),
                                              profile=BV_C_INT8, reduce_constraints=False)
    assert wrong_arity.feasible is True and wrong_arity.summary_axioms == []
    actual_argument = paths.check_path_feasibility(guards('strlen(/* ) , */ "") == -1'),
                                                   profile=BV_C_INT8, reduce_constraints=False)
    assert actual_argument.feasible is False and actual_argument.summary_axioms


@pytest.mark.usefixtures("native")
@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("call", ["update(0 ??' 0, &Value, 1 ??' 0) == 0", "update(Value +\\ \n+) == 0"],
                         ids=["trigraph-quotes", "spliced-increment"])
def test_unresolved_translation_phases_cannot_hide_mutations(entry, call):
    result = entry(guards("Value == 0", call, "Value == 1"), profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is None
    assert result.unknown == [call]
    assert result.unknown_reasons[0].kind.value == "unmodeled_state_effect"


def test_call_boundary_walk_does_not_lex_the_remaining_input(monkeypatch):
    from core.smt_solver import call_arguments

    original = call_arguments._lexeme_at
    visited = []

    def observed(text, index):
        visited.append(index)
        return original(text, index)
    monkeypatch.setattr(call_arguments, "_lexeme_at", observed)
    call = "probe(Data)"
    text = call + " + " + "Other " * 10000
    assert call_arguments.find_call_end(text, call.index("(")) == len(call)
    assert max(visited) < len(call)


@pytest.mark.usefixtures("native")
def test_block_comment_floor_assignment_text_is_inert():
    result = paths.check_path_feasibility(guards("probe(/* //= &Value++ */ Data) == 0"),
                                          profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is True and result.unknown == []
