"""Uniform guard models cannot refute source paths with unbound C semantics."""

from copy import deepcopy

import pytest

from core.audit.codeql_validation import _path_conditions, _smt_prune_sarif_matches


def flow(steps):
    locations = [{'location': {'physicalLocation': {
        'artifactLocation': {'uri': 'read.c'}, 'region': {'startLine': line}}}} for line in steps]
    return {'runs': [{'results': [{'ruleId': 'test/value-flow', 'codeFlows': [
        {'threadFlows': [{'locations': locations}]}]}]}]}


def test_live_32_bit_conversion_path_survives_the_real_guard_model(tmp_path):
    pytest.importorskip('z3')
    from packages.exploit_feasibility.smt_path import validate_path

    text = ('int Read(int Value){\n'
            ' if (Value == 0xffffffff) {\n'
            '  int Copy=Value;\n'
            '  if (Value < 0) {\n'
            '   return Copy;\n'
            '  }\n }\n return 0;\n}\n')
    (tmp_path / 'read.c').write_text(text)
    steps = [('read.c', 3), ('read.c', 5)]
    conditions = _path_conditions(steps, tmp_path, {})
    assert [c['text'] for c in conditions] == ['Value == 0xffffffff', 'Value < 0']
    actual32 = validate_path(conditions, profile='int32', reduce_constraints=False)
    assert actual32['feasible'] is True and actual32['model']['Value'] == -1
    # On an admitted 32-bit-int C target, the hexadecimal constant is
    # unsigned int. Equality converts -1 to UINT_MAX; the next test is signed.
    assert (-1) % (1 << 32) == 0xffffffff and -1 < 0
    assert_conditional_only(flow([3, 5]), tmp_path)


def test_mixed_variable_types_retain_the_existing_core_refusal(tmp_path):
    z3 = pytest.importorskip('z3')
    from core.smt_solver import new_solver
    from packages.exploit_feasibility.smt_path import validate_path

    text = ('int Read(int Signed,unsigned Unsigned){\n'
            ' if (Signed < 0) {\n'
            '  int Copy=Signed;\n'
            '  if (Unsigned > 0) {\n'
            '   int Copy2=Copy;\n'
            '   if (Signed == Unsigned) {\n'
            '    return Copy2;\n'
            '   }\n  }\n }\n return 0;\n}\n')
    (tmp_path / 'read.c').write_text(text)
    signed, unsigned = z3.BitVecs('Signed Unsigned', 32)
    solver = new_solver()
    solver.add(signed == -1, unsigned == 0xffffffff,
               signed < 0, z3.UGT(unsigned, 0), signed == unsigned)
    assert solver.check() == z3.sat
    conditions = _path_conditions([('read.c', n) for n in [3, 5, 7]], tmp_path, {})
    assert [c['text'] for c in conditions] == ['Signed < 0', 'Unsigned > 0', 'Signed == Unsigned']
    model = validate_path(conditions, profile=None, reduce_constraints=False)
    assert model['feasible'] is None
    assert 'mixed-signedness shape' in model['reasoning']
    assert _smt_prune_sarif_matches(flow([3, 5, 7]), tmp_path) == (1, 0, [])


def test_mutation_between_steps_cannot_share_one_scalar_value(tmp_path):
    pytest.importorskip('z3')
    text = ('int Read(int Value){\n'
            ' if (Value < 0) {\n'
            '  int Copy=Value;\n'
            '  Value=1;\n'
            '  if (Value > 0) {\n'
            '   return Copy;\n'
            '  }\n }\n return 0;\n}\n')
    (tmp_path / 'read.c').write_text(text)
    conditions = _path_conditions([('read.c', n) for n in [3, 6]], tmp_path, {})
    assert [c['text'] for c in conditions] == ['Value < 0', 'Value > 0']
    before, after = -1, 1
    assert before < 0 and after > 0
    assert_conditional_only(flow([3, 6]), tmp_path)


def assert_conditional_only(sarif, target):
    original = deepcopy(sarif)
    kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
    assert (kept, pruned) == (1, 0)
    assert sarif == original
    assert len(receipts) == 1  # Real model UNSAT still reaches the diagnostic.
    assert receipts[0]['verdict'] == 'smt_model_infeasible'
    assert receipts[0]['proof_scope'] == 'conditional-untyped-guard-model'
    assert receipts[0]['source_bound'] is False
    assert receipts[0]['paths'] and all(row['reasoning'] for row in receipts[0]['paths'])
