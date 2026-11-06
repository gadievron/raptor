"""Only an operation-bound source disproof can demote an overflow finding."""

import pytest

from core.audit import orchestrator as orch
from core.audit.overflow_demotion import source_overflow_demotion_reason


HYPOTHESIS = 'integer overflow in `Count + Step`'
UNSAFE_SOURCES = [
    pytest.param('unsigned Read(unsigned size, unsigned Count, unsigned Step) { if(size < size) return 0; return Count + Step; }', id='unrelated-dead-branch'),
    pytest.param('unsigned Neighbor(unsigned size) { if(size < size) return 0; return 1; }\nunsigned Read(unsigned Count, unsigned Step) { return Count + Step; }', id='neighbor-in-broad-span'),
    pytest.param('/* if (size < size) return 0; */\nunsigned Read(unsigned Count, unsigned Step) { return Count + Step; }', id='comment'),
    pytest.param('const char *Note = "if (size < size)";\nunsigned Read(unsigned Count, unsigned Step) { return Count + Step; }', id='string'),
]
SAFE_SOURCE = 'unsigned Read(unsigned Count, unsigned Step) { if(Count <= 10 && Step <= 10) return Count + Step; return 0; }'


def require_solver():
    pytest.importorskip('tree_sitter_c')
    pytest.importorskip('z3')


def review(tmp_path, source, abi):
    (tmp_path / 'record.c').write_text(source)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out', integer_abi=abi)
    outcome = orch.ReviewOutcome(file='record.c', function='Read', status='finding', body='review',
                                 hypothesis=HYPOTHESIS, line=1)
    outcome.review_result = {'cwe_class': 'CWE-190', 'hypothesis': HYPOTHESIS}
    checklist = {'files': [{'path': 'record.c', 'items': [
        {'name': 'Read', 'kind': 'function', 'line_start': 1, 'line_end': source.count('\n') + 1},
    ]}]}
    return outcome, config, checklist


@pytest.mark.parametrize('source', UNSAFE_SOURCES)
@pytest.mark.parametrize('abi', [None, 'ilp32', 'lp64'])
def test_flat_guard_unsat_cannot_demote_a_different_operation(tmp_path, source, abi):
    require_solver()
    outcome, config, checklist = review(tmp_path, source, abi)
    assert orch._smt_demotion_reason(outcome, config, checklist) is None


@pytest.mark.parametrize('abi', ['ilp32', 'lp64'])
def test_scoped_typed_overflow_disproof_still_demotes(tmp_path, abi):
    require_solver()
    outcome, config, checklist = review(tmp_path, SAFE_SOURCE, abi)
    assert orch._smt_demotion_reason(outcome, config, checklist) == (
        '[smt-disproof: integer overflow impossible (Z3 UNSAT)]')


def test_missing_target_abi_cannot_authorize_a_disproof(tmp_path):
    require_solver()
    outcome, config, checklist = review(tmp_path, SAFE_SOURCE, None)
    assert orch._smt_demotion_reason(outcome, config, checklist) is None


def test_claimed_expression_must_exist_in_the_selected_function():
    require_solver()
    source = 'unsigned Read(unsigned Count, unsigned Step) { if(Count <= 10) return Count; return 0; }'
    assert source_overflow_demotion_reason(HYPOTHESIS, source, file_path='record.c',
                                           function_name='Read', integer_abi='ilp32') is None
    assert source_overflow_demotion_reason(HYPOTHESIS, SAFE_SOURCE, file_path='record.c',
                                           function_name='Missing', integer_abi='ilp32') is None


@pytest.mark.parametrize('hypothesis,source', [('', SAFE_SOURCE), (HYPOTHESIS, '')])
def test_missing_obligation_does_not_invoke_a_solver(monkeypatch, hypothesis, source):
    def forbidden(*args, **kwargs):
        pytest.fail('missing source or hypothesis must not dispatch')
    monkeypatch.setattr('core.audit.condition_smt.disprove_integer_overflow', forbidden)
    assert source_overflow_demotion_reason(hypothesis, source, file_path='record.c',
                                           function_name='Read', integer_abi='ilp32') is None


def test_solver_failure_stays_inconclusive(monkeypatch):
    def unavailable(*args, **kwargs):
        raise RuntimeError('owned failure')
    monkeypatch.setattr('core.audit.condition_smt.disprove_integer_overflow', unavailable)
    assert source_overflow_demotion_reason(HYPOTHESIS, SAFE_SOURCE, file_path='record.c',
                                           function_name='Read', integer_abi='ilp32') is None
