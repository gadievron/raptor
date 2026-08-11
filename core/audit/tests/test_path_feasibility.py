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
