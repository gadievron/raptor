from core.smt_solver import BV_C_UINT8
from packages.hypothesis_validation.adapters.smt import SMTAdapter


def test_adapter_solves_stored_rule(tmp_path):
    class Rule(str):
        def splitlines(self, *args, **kwargs):
            return ["Value == 0", "Value == 1"]

    evidence = SMTAdapter(bv_profile=BV_C_UINT8).run(Rule("Value == 1"), tmp_path, timeout=1)
    assert evidence.success is True
    assert evidence.predicate_verdict == "sat", evidence
    assert evidence.empty_matches_conclusive is False


def test_rule_line_positions_and_polarity_use_stored_text():
    from packages.hypothesis_validation.adapters.smt import _parse_conditions

    class Rule(str):
        def splitlines(self, *args, **kwargs):
            raise AssertionError("custom lines must not replace conditions")
        def __str__(self):
            raise AssertionError("custom conversion must not replace conditions")

    conditions = _parse_conditions(Rule("# comment\n\n ! Value == 1\r\nValue == 2"))
    assert [(condition.text, condition.step_index, condition.negated) for condition in conditions] == [
        ("Value == 1", 2, True), ("Value == 2", 3, False),
    ]


def test_stored_contradiction_remains_conclusive(tmp_path):
    class Rule(str):
        def splitlines(self, *args, **kwargs):
            return ["Value == 1"]

    evidence = SMTAdapter(bv_profile=BV_C_UINT8).run(
        Rule("Value == 0\nValue == 1"), tmp_path, timeout=1,
    )
    assert evidence.success is True
    assert evidence.predicate_verdict == "unsat"
    assert evidence.empty_matches_conclusive is True
