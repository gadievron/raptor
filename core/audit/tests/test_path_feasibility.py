"""Tests for core.audit.path_feasibility — SMT path condition extraction+checking."""

from __future__ import annotations

from core.audit.path_feasibility import (
    PathCondition,
    check_flow_trace_feasibility,
    check_path_feasibility,
    extract_conditions_from_annotation,
    extract_conditions_from_flow_trace,
    extract_conditions_from_hypothesis,
)


class TestExtractConditionsFromFlowTrace:
    def test_string_conditions(self):
        trace = {
            "steps": [
                {"file": "a.c", "path_conditions": ["size > 0", "buf != NULL"]},
                {"file": "b.c", "path_conditions": ["len < MAX"]},
            ],
        }
        conds = extract_conditions_from_flow_trace(trace)
        assert len(conds) == 3
        assert conds[0].text == "size > 0"
        assert conds[0].negated is False
        assert conds[2].text == "len < MAX"

    def test_dict_conditions(self):
        trace = {
            "steps": [
                {
                    "file": "a.c",
                    "path_conditions": [
                        {"text": "x > 0", "negated": False},
                        {"text": "y == NULL", "negated": True},
                    ],
                },
            ],
        }
        conds = extract_conditions_from_flow_trace(trace)
        assert len(conds) == 2
        assert conds[1].negated is True

    def test_hops_key(self):
        trace = {
            "hops": [
                {"file": "a.c", "path_conditions": ["x > 0"]},
            ],
        }
        conds = extract_conditions_from_flow_trace(trace)
        assert len(conds) == 1

    def test_definition_as_source(self):
        trace = {
            "steps": [
                {
                    "definition": "src/handler.c:42",
                    "path_conditions": ["auth_ok == true"],
                },
            ],
        }
        conds = extract_conditions_from_flow_trace(trace)
        assert conds[0].source == "src/handler.c:42"

    def test_top_level_conditions(self):
        trace = {
            "steps": [],
            "path_conditions": ["global_flag == 1"],
        }
        conds = extract_conditions_from_flow_trace(trace)
        assert len(conds) == 1
        assert conds[0].source == "trace"

    def test_no_conditions(self):
        trace = {"steps": [{"file": "a.c"}]}
        conds = extract_conditions_from_flow_trace(trace)
        assert conds == []

    def test_mixed_step_and_top_level(self):
        trace = {
            "steps": [
                {"file": "a.c", "path_conditions": ["x > 0"]},
            ],
            "path_conditions": ["y != NULL"],
        }
        conds = extract_conditions_from_flow_trace(trace)
        assert len(conds) == 2


class TestExtractConditionsFromHypothesis:
    def test_if_condition(self):
        hyp = "if (size > MAX_BUF) the buffer overflows"
        conds = extract_conditions_from_hypothesis(hyp)
        assert len(conds) >= 1
        assert any("size" in c.text and "MAX_BUF" in c.text for c in conds)

    def test_when_condition(self):
        hyp = "when len < 0 the function returns early"
        conds = extract_conditions_from_hypothesis(hyp)
        assert len(conds) >= 1
        assert any("len" in c.text for c in conds)

    def test_non_null(self):
        hyp = "assuming ptr is non-null, the dereference is safe"
        conds = extract_conditions_from_hypothesis(hyp)
        assert any(c.text == "ptr != NULL" for c in conds)

    def test_positive(self):
        hyp = "count must be positive for the loop to execute"
        conds = extract_conditions_from_hypothesis(hyp)
        assert any(c.text == "count > 0" for c in conds)

    def test_no_conditions(self):
        hyp = "the function is safe because it validates all inputs"
        conds = extract_conditions_from_hypothesis(hyp)
        assert conds == []

    def test_source_is_hypothesis(self):
        hyp = "if (x == 0) then crash"
        conds = extract_conditions_from_hypothesis(hyp)
        if conds:
            assert conds[0].source == "hypothesis"


class TestExtractConditionsFromAnnotation:
    def test_metadata_conditions(self):
        meta = {"path_conditions": "size > 0; buf != NULL"}
        conds = extract_conditions_from_annotation(meta)
        assert len(conds) == 2
        assert conds[0].text == "size > 0"
        assert conds[1].text == "buf != NULL"

    def test_body_conditions(self):
        meta = {}
        body = "if (len > MAX) the overflow occurs"
        conds = extract_conditions_from_annotation(meta, body)
        assert len(conds) >= 1

    def test_empty(self):
        conds = extract_conditions_from_annotation({})
        assert conds == []

    def test_metadata_semicolons_with_whitespace(self):
        meta = {"path_conditions": " a > 0 ; b < 10 ; "}
        conds = extract_conditions_from_annotation(meta)
        assert len(conds) == 2
        assert conds[0].text == "a > 0"


class TestPathCondition:
    def test_to_smt_simple(self):
        pc = PathCondition(text="x > 0")
        assert pc.to_smt_condition() == "x > 0"

    def test_to_smt_negated(self):
        pc = PathCondition(text="x > 0", negated=True)
        result = pc.to_smt_condition()
        assert result == {"text": "x > 0", "negated": True}


class TestCheckPathFeasibility:
    def test_all_empty_text_conditions(self):
        conds = [PathCondition(text=""), PathCondition(text="")]
        result = check_path_feasibility(conds)
        assert result.feasible is None
        assert "empty" in result.reasoning

    def test_empty_conditions(self):
        result = check_path_feasibility([])
        assert result.feasible is None
        assert "no conditions" in result.reasoning

    def test_with_conditions_calls_smt(self, monkeypatch):
        from core.audit import path_feasibility
        from core.audit.sweep import SweepResult

        def mock_sweep(*, file_path, function_name, verb, smt_args):
            assert verb == "validate-path"
            assert "conditions" in smt_args
            return SweepResult(
                tool="smt",
                file_path=file_path,
                function_name=function_name,
                outcome="confirmed",
                raw_output='{"result": "sat"}',
            )

        monkeypatch.setattr(path_feasibility, "check_path_feasibility",
                            check_path_feasibility)
        from core.audit import sweep
        monkeypatch.setattr(sweep, "run_smt_sweep", mock_sweep)

        conds = [PathCondition(text="x > 0"), PathCondition(text="y < 10")]
        result = check_path_feasibility(conds)
        assert result.feasible is True

    def test_refuted(self, monkeypatch):
        from core.audit import sweep
        from core.audit.sweep import SweepResult

        def mock_sweep(*, file_path, function_name, verb, smt_args):
            return SweepResult(
                tool="smt",
                file_path=file_path,
                function_name=function_name,
                outcome="refuted",
                raw_output='{"result": "unsat"}',
            )

        monkeypatch.setattr(sweep, "run_smt_sweep", mock_sweep)
        conds = [PathCondition(text="x > 0"), PathCondition(text="x < 0")]
        result = check_path_feasibility(conds)
        assert result.feasible is False

    def test_error_returns_none(self, monkeypatch):
        from core.audit import sweep
        from core.audit.sweep import SweepResult

        def mock_sweep(*, file_path, function_name, verb, smt_args):
            return SweepResult(
                tool="smt",
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=["solver not available"],
            )

        monkeypatch.setattr(sweep, "run_smt_sweep", mock_sweep)
        result = check_path_feasibility([PathCondition(text="x > 0")])
        assert result.feasible is None
        assert result.error


class TestCheckFlowTraceFeasibility:
    def test_no_conditions_in_trace(self):
        trace = {"steps": [{"file": "a.c"}]}
        result = check_flow_trace_feasibility(trace)
        assert result.feasible is None

    def test_with_conditions(self, monkeypatch):
        from core.audit import sweep
        from core.audit.sweep import SweepResult

        def mock_sweep(*, file_path, function_name, verb, smt_args):
            return SweepResult(
                tool="smt",
                file_path=file_path,
                function_name=function_name,
                outcome="confirmed",
            )

        monkeypatch.setattr(sweep, "run_smt_sweep", mock_sweep)

        trace = {
            "steps": [{"file": "a.c", "path_conditions": ["x > 0"]}],
        }
        result = check_flow_trace_feasibility(trace)
        assert result.feasible is True


class TestNonDictStepTolerated:
    def test_non_dict_step_skipped(self):
        from core.audit.path_feasibility import (
            extract_conditions_from_flow_trace,
        )

        # LLM-authored traces can carry malformed steps; a bare string
        # must not raise, and the well-formed steps still extract.
        trace = {
            "steps": [
                "malformed step",
                None,
                {"path_conditions": ["size > 0"], "file": "a.c"},
            ],
        }
        conds = extract_conditions_from_flow_trace(trace)
        assert [c.text for c in conds] == ["size > 0"]


class TestStrictConditionPolarity:
    def test_malformed_trace_polarity_declines_the_entire_check(self, monkeypatch):
        import pytest
        from core.audit import sweep

        monkeypatch.setattr(sweep, 'run_smt_sweep', lambda **kw: pytest.fail('invalid trace reached SMT'))
        for location in ('steps', 'top-level'):
            for polarity in ('false', 'true', '', 0, 1, None, [], {}):
                raw = ['Value == 0', {'text': 'Value == 0', 'negated': polarity}]
                trace = {'steps': [{'path_conditions': raw}]} if location == 'steps' else {'path_conditions': raw}
                with pytest.raises(ValueError, match='negated must be a boolean'):
                    extract_conditions_from_flow_trace(trace)
                result = check_flow_trace_feasibility(trace)
                assert result.feasible is None and result.error == 'negated must be a boolean'

    def test_mutated_direct_condition_is_inconclusive_before_sweep(self, monkeypatch):
        import pytest
        from core.audit import sweep

        monkeypatch.setattr(sweep, 'run_smt_sweep', lambda **kw: pytest.fail('invalid condition reached SMT'))
        condition = PathCondition('Value == 0')
        condition.negated = 'false'
        result = check_path_feasibility([PathCondition('Value == 0'), condition])
        assert result.feasible is None and result.error == 'negated must be a boolean'

    def test_direct_constructor_requires_a_real_boolean(self):
        import pytest

        with pytest.raises(ValueError, match='negated must be a boolean'):
            PathCondition('Value == 0', negated='false')

    def test_real_booleans_survive_trace_extraction_and_serialization(self):
        conditions = extract_conditions_from_flow_trace({'path_conditions': [
            {'text': 'Value == 0'}, {'text': 'Value == 1', 'negated': False},
            {'text': 'Value == 2', 'negated': True},
        ]})
        assert [condition.to_smt_condition() for condition in conditions] == [
            'Value == 0', 'Value == 1', {'text': 'Value == 2', 'negated': True},
        ]


class TestHypothesisPredicateMeaning:
    def test_non_negative_includes_zero_in_both_phrases_and_cases(self):
        for phrase in ('Count is non-negative', 'Count must be non-negative', 'Count is NON-NEGATIVE'):
            conditions = extract_conditions_from_hypothesis(phrase)
            assert [condition.text for condition in conditions] == ['Count >= 0']
            assert all(condition.source == 'hypothesis' for condition in conditions)

    def test_strict_positive_phrases_keep_the_zero_exclusion(self):
        for phrase in ('Count is positive', 'Count must be positive',
                       'Count is greater than zero', 'Count must be greater than zero'):
            assert [condition.text for condition in extract_conditions_from_hypothesis(phrase)] == ['Count > 0']

    def test_qualifier_prefixes_do_not_create_predicates(self):
        for phrase in ('Count is positively bounded', 'Count is positive_count',
                       'Count is positive-definite', 'Count is non-negatively bounded',
                       'Count is non-negative_count', 'Ptr is non-nullable',
                       'Ptr is not nullified', 'Ptr is non-null_field'):
            assert extract_conditions_from_hypothesis(phrase) == []

    def test_atomic_comparisons_preserve_all_supported_operator_spellings(self):
        for keyword in ('if', 'when', 'where', 'provided that', 'assuming'):
            for operator in ('<', '<=', '>', '>=', '==', '!='):
                for right in ('Limit', '12', '0x10'):
                    condition = f'Count {operator} {right}'
                    for fragment in (f'({condition})', f'{condition} then continue'):
                        extracted = extract_conditions_from_hypothesis(f'{keyword} {fragment}')
                        assert [item.text for item in extracted] == [condition]

    def test_compound_rhs_is_declined_without_backtracking_to_a_shorter_atom(self):
        for right in ('Limit + 1', 'Limit - 1', 'Limit * 2', 'Limit / 2', 'Limit % 2',
                      'Limit & 1', 'Limit | 1', 'Limit ^ 1', 'Limit >> 1', 'Limit << 1',
                      'Limit ? A : B', 'Limit()', 'Limit (Other)', 'Limit[0]',
                      'Limit.Field', 'Limit . Field', 'Limit->Field', 'Limit::Field',
                      '0.5', '0x10 + 1', 'Limit && Other', 'Limit || Other',
                      'Limit and Other', 'Limit or Other'):
            for fragment in (f'(Count > {right})', f'Count > {right}'):
                assert extract_conditions_from_hypothesis(f'if {fragment}') == []

    def test_invalid_operator_spellings_are_not_normalized_into_predicates(self):
        for operator in ('=', '===', '><', '=>', '=<', '<>', '!=='):
            assert extract_conditions_from_hypothesis(f'if (Count {operator} Limit)') == []

    def test_parenthesized_conditions_require_their_closing_delimiter(self):
        assert extract_conditions_from_hypothesis('if (Count > Limit') == []
        assert extract_conditions_from_hypothesis('if (Count > Limit trailing prose)') == []
        assert extract_conditions_from_hypothesis('if ( Count > Limit ) then continue')[0].text == 'Count > Limit'

    def test_completed_predicates_and_following_conditions_remain_independent(self):
        conditions = extract_conditions_from_hypothesis('if (Count > Limit), when (Other == 0).')
        assert [condition.text for condition in conditions] == ['Count > Limit', 'Other == 0']
        assert extract_conditions_from_hypothesis('when Count > 0.')[0].text == 'Count > 0'

    def test_annotation_metadata_is_preserved_while_body_translation_includes_zero(self):
        conditions = extract_conditions_from_annotation({'path_conditions': 'Count == 0'}, 'Count is non-negative')
        assert [(condition.text, condition.source) for condition in conditions] == [
            ('Count == 0', 'annotation'), ('Count >= 0', 'hypothesis'),
        ]

    def test_non_negative_zero_is_satisfiable_through_the_real_math_adapter(self, monkeypatch):
        import pytest
        pytest.importorskip('z3')
        from core.audit import sweep
        from core.audit.sweep import SweepResult
        from packages.exploit_feasibility.smt_path import validate_path

        def math_sweep(*, file_path, function_name, verb, smt_args):
            assert verb == 'validate-path'
            result = validate_path(smt_args['conditions'], profile='int32')
            return SweepResult(tool='smt', file_path=file_path, function_name=function_name,
                               outcome='inconclusive', details={**result, 'oracle_scope': 'supplied-predicates'})

        monkeypatch.setattr(sweep, 'run_smt_sweep', math_sweep)
        for phrase, expected in (('Count is non-negative', True), ('Count is positive', False)):
            conditions = extract_conditions_from_annotation({'path_conditions': 'Count == 0'}, phrase)
            result = check_path_feasibility(conditions)
            assert result.feasible is expected and not result.error
